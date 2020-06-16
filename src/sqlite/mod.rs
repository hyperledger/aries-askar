use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use async_trait::async_trait;

use futures_channel::mpsc::{channel, Receiver, Sender};
use futures_util::stream::{Stream, StreamExt};

use rusqlite::{params, Connection, Row, ToSql};

use super::error::{KvError, KvResult};
use super::pool::Managed;
use super::types::{
    ClientId, KeyId, KvEntry, KvFetchOptions, KvKeySelect, KvLockOperation, KvLockToken,
    KvScanToken, KvTag, KvUpdateEntry,
};
use super::wql::{self, sql::TagSqlEncoder, tags::TagQuery};
use super::{KvProvisionStore, KvStore};

mod context;
mod pool;

use context::{BatchProcessor, BatchQuery, ConnectionContext, QueryResults};
use pool::{SqlitePool, SqlitePoolConfig};

const COUNT_QUERY: &'static str = "SELECT COUNT(*) FROM items i
    WHERE key_id = ?1 AND category = ?2
    AND (expiry IS NULL OR expiry > CURRENT_TIME)";
const FETCH_QUERY: &'static str = "SELECT id, value FROM items i
    WHERE key_id = ?1 AND category = ?2 AND name = ?3
    AND (expiry IS NULL OR expiry > CURRENT_TIME)";
const SCAN_QUERY: &'static str = "SELECT id, name, value FROM items i WHERE key_id = ?1
    AND category = ?2 AND (expiry IS NULL OR expiry > CURRENT_TIME)";
const TAG_QUERY: &'static str = "SELECT name, value, plaintext FROM items_tags WHERE item_id = ?1";

struct ScanQuery {
    key_id: KeyId,
    category: Vec<u8>,
    retrieve_tags: bool,
}

impl BatchProcessor for ScanQuery {
    type Row = (i64, Vec<u8>, Vec<u8>);
    type Result = Vec<KvEntry>;
    fn process_row(&mut self, row: &Row) -> KvResult<Self::Row> {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    }
    fn process_batch(&mut self, rows: Vec<Self::Row>, conn: &Connection) -> KvResult<Self::Result> {
        let mut result = vec![];
        for (row_id, name, value) in rows {
            let tags = if self.retrieve_tags {
                // FIXME fetch tags in batches for efficiency
                Some(retrieve_tags(&conn, row_id)?)
            } else {
                None
            };
            result.push(KvEntry {
                key_id: self.key_id.clone(),
                category: self.category.clone(),
                name,
                value,
                tags,
            });
        }
        Ok(result)
    }
}

fn replace_arg_placeholders(filter: &str, start_index: i64) -> (String, i64) {
    let mut index = start_index;
    let mut s: String = filter.to_owned();
    while let Some(pos) = s.find("$$") {
        let arg_str = format!("?{}", index);
        s.replace_range(pos..(pos + 2), &arg_str);
        index = index + 1;
    }
    (s, index)
}

fn extend_query<'a>(
    query: &str,
    params: &mut SqlParams,
    tag_filter: Option<wql::Query>,
    limit: Option<(i64, i64)>,
) -> KvResult<String> {
    let mut query = query.to_string();
    let mut last_idx = params.len() as i64 + 1;

    if let Some(tag_filter) = tag_filter {
        let tag_query = TagQuery::from_query(tag_filter)?;
        let mut enc = TagSqlEncoder::new();
        let filter = tag_query.encode(&mut enc)?;
        let (filter, next_idx) = replace_arg_placeholders(&filter, last_idx);
        last_idx = next_idx;
        params.extend(enc.arguments);
        query.push_str(" AND "); // assumes WHERE already occurs
        query.push_str(&filter);
    };
    if let Some((offs, limit)) = limit {
        params.push(offs);
        params.push(limit);
        let (limit, _next_idx) = replace_arg_placeholders(" LIMIT $$, $$", last_idx);
        // last_idx = next_idx;
        query.push_str(&limit);
    };
    Ok(query)
}

pub struct SqlParams<'a> {
    items: Vec<Box<dyn ToSql + Send + 'a>>,
}

impl<'a> SqlParams<'a> {
    pub fn new() -> Self {
        Self { items: vec![] }
    }

    pub fn from_iter<I, T>(items: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: ToSql + Send + 'a,
    {
        let mut s = Self::new();
        s.extend(items);
        s
    }

    pub fn push<T>(&mut self, item: T)
    where
        T: ToSql + Send + 'a,
    {
        self.items.push(Box::new(item))
    }

    pub fn extend<I, T>(&mut self, items: I)
    where
        I: IntoIterator<Item = T>,
        T: ToSql + Send + 'a,
    {
        self.items.extend(
            items
                .into_iter()
                .map(|item| Box::new(item) as Box<dyn ToSql + Send>),
        )
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }
}

impl<'a> IntoIterator for SqlParams<'a> {
    type Item = Box<dyn ToSql + Send + 'a>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

pub struct KvSqlite {
    conn_pool: SqlitePool,
}

impl KvSqlite {
    pub fn open_in_memory() -> KvResult<Self> {
        let config = SqlitePoolConfig::in_memory();
        let conn_pool = config.into_pool(0, 5);
        Ok(Self { conn_pool })
    }
}

#[async_trait]
impl KvProvisionStore for KvSqlite {
    async fn provision(&self) -> KvResult<()> {
        let mut ctx = self.conn_pool.acquire().await?;
        ctx.enter(|conn| {
            conn.execute_batch(
                r#"
            PRAGMA locking_mode=EXCLUSIVE;
            PRAGMA foreign_keys=ON;
            BEGIN EXCLUSIVE TRANSACTION;

            CREATE TABLE items(
                id INTEGER NOT NULL,
                key_id INTEGER NOT NULL,
                category NOT NULL,
                name NOT NULL,
                value NOT NULL,
                expiry NULL,
                PRIMARY KEY(id)
            );
            CREATE UNIQUE INDEX ux_items_uniq ON items(key_id, category, name);

            CREATE TABLE items_tags(
                item_id INTEGER NOT NULL,
                name NOT NULL,
                value NOT NULL,
                plaintext BOOLEAN NOT NULL,
                PRIMARY KEY(name, item_id, plaintext),
                FOREIGN KEY(item_id)
                    REFERENCES items(id)
                    ON DELETE CASCADE
                    ON UPDATE CASCADE
            );
            CREATE INDEX ix_items_tags_item_id ON items_tags(item_id);
            CREATE INDEX ix_items_tags_value ON items_tags(value) WHERE plaintext;

            END TRANSACTION;
        "#,
            )?;
            Ok(())
        })
        .await
    }
}

async fn get_key_id(k: KvKeySelect) -> KeyId {
    b"1".to_vec()
}

fn retrieve_tags(conn: &Connection, row_id: i64) -> KvResult<Vec<KvTag>> {
    let mut tag_q = conn.prepare_cached(TAG_QUERY)?;
    let rows = tag_q
        .query_map(&[&row_id], |row| {
            let name = row.get(0)?;
            let value = row.get(1)?;
            let plaintext = row.get(2)?;
            match plaintext {
                0 => Ok(KvTag::Encrypted(name, value)),
                _ => Ok(KvTag::Plaintext(name, value)),
            }
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub struct Scan {
    // FIXME only holding on to ctx to prevent it from being released
    // back to the pool while the query is pending
    // the real fix is to detect active connections during pool.on_release
    ctx: Managed<ConnectionContext>,
    query: QueryResults<(Vec<KvEntry>, bool)>,
}
impl Scan {
    pub async fn next(&mut self) -> KvResult<Option<(Vec<KvEntry>, bool)>> {
        self.query.next().await.transpose()
    }
}

impl KvScanToken for Scan {}

#[derive(Clone, Debug)]
pub struct Lock {}
impl KvLockToken for Lock {}

#[async_trait]
impl KvStore for KvSqlite {
    type ScanToken = Scan;
    type LockToken = Lock;

    async fn count(
        &self,
        client_key: KvKeySelect,
        category: &[u8],
        tag_filter: Option<wql::Query>,
    ) -> KvResult<u64> {
        let key_id = get_key_id(client_key).await;
        let category = category.to_vec();
        let mut ctx = self.conn_pool.acquire().await?;
        let count: i64 = ctx
            .enter(move |conn| {
                let mut params = SqlParams::from_iter(vec![&key_id, &category]);
                let query = extend_query(COUNT_QUERY, &mut params, tag_filter, None)?;
                let count = conn.query_row(query.as_str(), params, |row| Ok(row.get(0)?))?;
                KvResult::Ok(count)
            })
            .await?;
        Ok(count as u64)
    }

    async fn fetch(
        &self,
        client_key: KvKeySelect,
        category: &[u8],
        name: &[u8],
        options: KvFetchOptions,
    ) -> KvResult<Option<KvEntry>> {
        let key_id = get_key_id(client_key).await;
        let category = category.to_vec();
        let name = name.to_vec();
        let mut ctx = self.conn_pool.acquire().await?;
        ctx.enter(move |conn| {
            let q_key_id = key_id.clone();
            let q_category = category.clone();
            let q_name = name.clone();

            let mut fetch_q = conn.prepare_cached(FETCH_QUERY)?;
            let result = fetch_q.query_row(&[&q_key_id, &q_category, &q_name], |row| {
                Ok((row.get::<_, i64>(0)?, row.get(1)?))
            });
            match result {
                Ok((row_id, value)) => {
                    let tags = if options.retrieve_tags {
                        Some(retrieve_tags(&conn, row_id)?)
                    } else {
                        None
                    };
                    Ok(Some(KvEntry {
                        key_id,
                        category,
                        name,
                        value,
                        tags,
                    }))
                }
                Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
                Err(err) => Err(err.into()),
            }
        })
        .await
    }

    async fn scan_start(
        &self,
        client_key: KvKeySelect,
        category: &[u8],
        options: KvFetchOptions,
        tag_filter: Option<wql::Query>,
        // offset
        max_rows: Option<u64>,
    ) -> KvResult<Self::ScanToken> {
        let category = category.to_vec();
        let key_id = get_key_id(client_key).await;
        let mut ctx = self.conn_pool.acquire().await?;
        let limit = Some((0i64, max_rows.map(|r| r as i64).unwrap_or(-1)));
        let mut params = SqlParams::new();
        params.push(key_id.clone());
        params.push(category.clone());
        let sql = extend_query(SCAN_QUERY, &mut params, tag_filter, limit)?;
        let scan = ScanQuery {
            key_id,
            category,
            retrieve_tags: options.retrieve_tags,
        };
        let query = ctx
            .process_query(sql, params, BatchQuery::new(20, scan))
            .await?;
        Ok(Scan { ctx, query })
    }

    async fn scan_next(
        &self,
        mut scan_token: Self::ScanToken,
    ) -> KvResult<(Vec<KvEntry>, Option<Self::ScanToken>)> {
        match scan_token.next().await? {
            Some((rows, done)) => Ok((rows, if done { None } else { Some(scan_token) })),
            None => Ok((vec![], None)),
        }
    }

    async fn update(
        &self,
        entries: Vec<KvUpdateEntry>,
        with_lock: Option<KvLockOperation<Self::LockToken>>,
    ) -> KvResult<()> {
        let mut updates = vec![];
        for entry in entries {
            let key_id = get_key_id(entry.client_key.clone()).await;
            updates.push((key_id, entry))
        }

        let mut ctx = self.conn_pool.acquire().await?;
        ctx.enter(move |conn| {
            let txn = conn.transaction()?; // rusqlite::TransactionBehavior::Deferred
            {
                let mut fetch_id = txn.prepare_cached(
                    "SELECT id FROM items WHERE key_id=?1 AND category=?2 AND name=?3",
                )?;
                let mut add_item = txn.prepare_cached(
                    "INSERT INTO items(key_id, category, name, value)
                    VALUES(?1, ?2, ?3, ?4)",
                )?;
                // FIXME - might well be faster to delete the row
                // (and its associated tags through cascade), and insert a new row
                let mut upd_item = txn.prepare_cached("UPDATE items SET value=?1 WHERE id=?2")?;
                let mut add_item_tag = txn.prepare_cached(
                    "INSERT INTO items_tags(item_id, name, value, plaintext)
                        VALUES(?1, ?2, ?3, ?4)",
                )?;
                for (key_id, entry) in updates {
                    let row: Result<i64, rusqlite::Error> = fetch_id
                        .query_row(&[&key_id, &entry.category, &entry.name], |row| row.get(0));
                    let row_id = match row {
                        Ok(row_id) => {
                            upd_item.execute(params![&row_id, &entry.value])?;
                            txn.execute("DELETE FROM items_tags WHERE item_id=?1", &[&row_id])?;
                            row_id
                        }
                        Err(rusqlite::Error::QueryReturnedNoRows) => {
                            add_item.execute(&[
                                &key_id,
                                &entry.category,
                                &entry.name,
                                &entry.value,
                            ])?;
                            txn.last_insert_rowid()
                        }
                        Err(err) => return Err(err.into()),
                    };
                    if let Some(tags) = entry.tags.as_ref() {
                        for tag in tags {
                            let (name, value, plaintext) = match tag {
                                KvTag::Encrypted(name, value) => (name, value, 0),
                                KvTag::Plaintext(name, value) => (name, value, 1),
                            };
                            add_item_tag.execute(params![&row_id, name, value, plaintext])?;
                        }
                    }
                }
            }
            txn.commit()?;
            Ok(())
        })
        .await
    }

    async fn create_lock(
        &self,
        client_id: ClientId,
        category: &[u8],
        name: &[u8],
        max_duration_ms: Option<u64>,
        acquire_timeout_ms: Option<u64>,
    ) -> KvResult<(Self::LockToken, Option<KvEntry>)> {
        Ok((Lock {}, None))
    }

    async fn refresh_lock(
        &self,
        token: Self::LockToken,
        max_duration_ms: Option<u64>,
    ) -> KvResult<Self::LockToken> {
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smol::block_on;

    #[test]
    fn sqlite_init() {
        let db = KvSqlite::open_in_memory().unwrap();
        block_on(db.provision()).unwrap();
    }

    #[test]
    fn sqlite_fetch_fail() {
        let db = KvSqlite::open_in_memory().unwrap();
        block_on(db.provision()).unwrap();

        let client_key = KvKeySelect::ForClient(vec![]);
        let options = KvFetchOptions::default();
        let row = db.fetch(client_key, b"cat", b"name", options);
        let result = block_on(row).unwrap();
        assert!(result.is_none())
    }

    #[test]
    fn sqlite_add_fetch() {
        let db = KvSqlite::open_in_memory().unwrap();
        block_on(db.provision()).unwrap();

        let client_key = KvKeySelect::ForClient(vec![]);
        let options = KvFetchOptions::new(true, true);

        let test_row = KvEntry {
            key_id: b"1".to_vec(),
            category: b"cat".to_vec(),
            name: b"name".to_vec(),
            value: b"value".to_vec(),
            tags: None,
        };

        let updates = vec![KvUpdateEntry {
            client_key: client_key.clone(),
            category: test_row.category.clone(),
            name: test_row.name.clone(),
            value: test_row.value.clone(),
            tags: None,
            expiry: None,
        }];
        block_on(db.update(updates, None)).unwrap();

        let row = db.fetch(
            client_key.clone(),
            &test_row.category,
            &test_row.name,
            options,
        );
        let result = block_on(row).unwrap();
        assert!(result.is_some());
        let found = result.unwrap();
        assert_eq!(found, test_row)
    }

    #[test]
    fn sqlite_add_fetch_tags() {
        let db = KvSqlite::open_in_memory().unwrap();
        block_on(db.provision()).unwrap();

        let client_key = KvKeySelect::ForClient(vec![]);
        let options = KvFetchOptions::new(true, true);

        let test_row = KvEntry {
            key_id: b"1".to_vec(),
            category: b"cat".to_vec(),
            name: b"name".to_vec(),
            value: b"value".to_vec(),
            tags: Some(vec![
                KvTag::Encrypted(b"t1".to_vec(), b"v1".to_vec()),
                KvTag::Plaintext(b"t2".to_vec(), b"v2".to_vec()),
            ]),
        };

        let updates = vec![KvUpdateEntry {
            client_key: client_key.clone(),
            category: test_row.category.clone(),
            name: test_row.name.clone(),
            value: test_row.value.clone(),
            tags: test_row.tags.clone(),
            expiry: None,
        }];
        block_on(db.update(updates, None)).unwrap();

        let row = db.fetch(
            client_key.clone(),
            &test_row.category,
            &test_row.name,
            options,
        );
        let result = block_on(row).unwrap();
        assert!(result.is_some());
        let found = result.unwrap();
        assert_eq!(found, test_row)
    }

    #[test]
    fn sqlite_count() {
        let db = KvSqlite::open_in_memory().unwrap();
        block_on(db.provision()).unwrap();

        let category = b"cat".to_vec();
        let test_rows = vec![KvEntry {
            key_id: b"1".to_vec(),
            category: category.clone(),
            name: b"name".to_vec(),
            value: b"value".to_vec(),
            tags: None,
        }];

        let client_key = KvKeySelect::ForClient(vec![]);
        let updates = test_rows
            .iter()
            .map(|row| KvUpdateEntry {
                client_key: client_key.clone(),
                category: row.category.clone(),
                name: row.name.clone(),
                value: row.value.clone(),
                tags: row.tags.clone(),
                expiry: None,
            })
            .collect();
        block_on(db.update(updates, None)).unwrap();

        let tag_filter = None;
        let count = block_on(db.count(client_key.clone(), &category, tag_filter)).unwrap();
        assert_eq!(count, 1);

        let tag_filter = Some(wql::Query::Eq("sometag".to_string(), "someval".to_string()));
        let count = block_on(db.count(client_key.clone(), &category, tag_filter)).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn sqlite_scan() {
        let db = KvSqlite::open_in_memory().unwrap();
        block_on(db.provision()).unwrap();

        let category = b"cat".to_vec();
        let test_rows = vec![KvEntry {
            key_id: b"1".to_vec(),
            category: category.clone(),
            name: b"name".to_vec(),
            value: b"value".to_vec(),
            tags: None,
        }];

        let client_key = KvKeySelect::ForClient(vec![]);
        let updates = test_rows
            .iter()
            .map(|row| KvUpdateEntry {
                client_key: client_key.clone(),
                category: row.category.clone(),
                name: row.name.clone(),
                value: row.value.clone(),
                tags: row.tags.clone(),
                expiry: None,
            })
            .collect();
        block_on(db.update(updates, None)).unwrap();

        let options = KvFetchOptions::default();
        let tag_filter = None;
        let max_rows = None;
        let scan_token =
            block_on(db.scan_start(client_key.clone(), &category, options, tag_filter, max_rows))
                .unwrap();
        let (rows, scan_next) = block_on(db.scan_next(scan_token)).unwrap();
        assert_eq!(rows, test_rows);
        assert!(scan_next.is_none());

        let options = KvFetchOptions::default();
        let tag_filter = Some(wql::Query::Eq("sometag".to_string(), "someval".to_string()));
        let scan_token =
            block_on(db.scan_start(client_key.clone(), &category, options, tag_filter, max_rows))
                .unwrap();
        let (rows, scan_next) = block_on(db.scan_next(scan_token)).unwrap();
        assert_eq!(rows, vec![]);
        assert!(scan_next.is_none());
    }

    #[test]
    fn sqlite_simple_and_convert_args_works() {
        assert_eq!(
            replace_arg_placeholders("This $$ is $$ a $$ string!", 3),
            ("This ?3 is ?4 a ?5 string!".to_string(), 6),
        );
        assert_eq!(
            replace_arg_placeholders("This is a string!", 1),
            ("This is a string!".to_string(), 1),
        );
    }
}
