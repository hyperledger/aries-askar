use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use async_resource::Managed;

use async_trait::async_trait;

use futures_util::stream::{Stream, StreamExt};

use postgres_types::ToSql;
use tokio_postgres::{Connection, Row};

use super::error::{KvError, KvResult};
use super::types::{
    KeyId, KvEntry, KvFetchOptions, KvKeySelect, KvLockOperation, KvTag, KvUpdateEntry, ProfileId,
};
use super::wql::{
    self,
    sql::TagSqlEncoder,
    tags::{tag_query, TagQueryEncoder},
};
use super::{KvProvisionStore, KvStore};

mod pool;

use pool::{Client, Error, PostgresPool, PostgresPoolConfig};

const COUNT_QUERY: &'static str = "SELECT COUNT(*) FROM items i
    WHERE key_id = ?1 AND category = ?2
    AND (expiry IS NULL OR expiry > CURRENT_TIME)";
const FETCH_QUERY: &'static str = "SELECT id, value, value_key FROM items i
    WHERE key_id = ?1 AND category = ?2 AND name = ?3
    AND (expiry IS NULL OR expiry > CURRENT_TIME)";
const SCAN_QUERY: &'static str = "SELECT id, name, value, value_key FROM items i WHERE key_id = ?1
    AND category = ?2 AND (expiry IS NULL OR expiry > CURRENT_TIME)";
const TAG_QUERY: &'static str =
    "SELECT 0 as encrypted, name, value FROM tags_plaintext WHERE item_id = ?1
    UNION ALL
    SELECT 1 as encrypted, name, value FROM tags_encrypted WHERE item_id = ?1";

struct ScanQuery {
    key_id: KeyId,
    category: Vec<u8>,
    retrieve_tags: bool,
}

/*
impl BatchProcessor for ScanQuery {
    type Row = (i64, Vec<u8>, Vec<u8>, Vec<u8>);
    type Result = Vec<KvEntry>;
    fn process_row(&mut self, row: &Row) -> KvResult<Self::Row> {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(2)?))
    }
    fn process_batch(&mut self, rows: Vec<Self::Row>, conn: &Connection) -> KvResult<Self::Result> {
        let mut result = vec![];
        for (row_id, name, value, value_key) in rows {
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
*/

fn replace_arg_placeholders(filter: &str, start_index: i64) -> (String, i64) {
    let mut index = start_index;
    let mut s: String = filter.to_owned();
    while let Some(pos) = s.find("$$") {
        let arg_str = format!("${}", index);
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
        let tag_query = tag_query(tag_filter)?;
        let mut enc = TagSqlEncoder::new();
        let filter: String = enc.encode_query(&tag_query)?;
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
    items: Vec<Box<dyn ToSql + Send + Sync + 'a>>,
}

impl<'a> SqlParams<'a> {
    pub fn new() -> Self {
        Self { items: vec![] }
    }

    pub fn from_iter<I, T>(items: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: ToSql + Send + Sync + 'a,
    {
        let mut s = Self::new();
        s.extend(items);
        s
    }

    pub fn push<T>(&mut self, item: T)
    where
        T: ToSql + Send + Sync + 'a,
    {
        self.items.push(Box::new(item))
    }

    pub fn extend<I, T>(&mut self, items: I)
    where
        I: IntoIterator<Item = T>,
        T: ToSql + Send + Sync + 'a,
    {
        self.items.extend(
            items
                .into_iter()
                .map(|item| Box::new(item) as Box<dyn ToSql + Send + Sync>),
        )
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn as_refs(&self) -> Vec<&(dyn ToSql + Sync)> {
        self.items
            .iter()
            .map(|b| b.as_ref() as &(dyn ToSql + Sync))
            .collect()
    }
}

pub struct KvPostgres {
    conn_pool: PostgresPool,
}

impl KvPostgres {
    pub fn open(config: String) -> KvResult<Self> {
        let config = PostgresPoolConfig::new(config);
        let conn_pool = config.into_pool(0, 5);
        Ok(Self { conn_pool })
    }
}

#[async_trait]
impl KvProvisionStore for KvPostgres {
    async fn provision(&self) -> KvResult<()> {
        let client = self.conn_pool.acquire().await?;
        client
            .batch_execute(
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
                value_key NULL,
                expiry NULL,
                PRIMARY KEY(id)
            );
            CREATE UNIQUE INDEX ux_items_uniq ON items(key_id, category, name);

            CREATE TABLE tags_encrypted(
                name NOT NULL,
                value NOT NULL,
                item_id INTEGER NOT NULL,
                PRIMARY KEY(name, item_id),
                FOREIGN KEY(item_id)
                    REFERENCES items(id)
                    ON DELETE CASCADE
                    ON UPDATE CASCADE
            );
            CREATE INDEX ix_tags_encrypted_item_id ON tags_encrypted(item_id);

            CREATE TABLE tags_plaintext(
                name NOT NULL,
                value NOT NULL,
                item_id INTEGER NOT NULL,
                PRIMARY KEY(name, item_id),
                FOREIGN KEY(item_id)
                    REFERENCES items(id)
                    ON DELETE CASCADE
                    ON UPDATE CASCADE
            );
            CREATE INDEX ix_tags_plaintext_value ON tags_plaintext(value);
            CREATE INDEX ix_tags_plaintext_item_id ON tags_plaintext(item_id);
            END TRANSACTION;
        "#,
            )
            .await?;
        Ok(())
    }
}

async fn get_key_id(k: KvKeySelect) -> KeyId {
    b"1".to_vec()
}

async fn retrieve_tags(client: &Client, row_id: i64) -> KvResult<Vec<KvTag>> {
    let tag_q = client.prepare(TAG_QUERY).await?;
    let rows = client
        .query(&tag_q, &[&row_id])
        .await?
        .into_iter()
        .map(|row| {
            let enc: i32 = row.try_get(0)?;
            if enc == 1 {
                KvResult::Ok(KvTag::Encrypted(row.try_get(1)?, row.try_get(2)?))
            } else {
                KvResult::Ok(KvTag::Plaintext(row.try_get(1)?, row.try_get(2)?))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub struct Scan {
    // FIXME only holding on to ctx to prevent it from being released
    // back to the pool while the query is pending
    client: Managed<Client>,
}
impl Scan {
    pub async fn next(&mut self) -> KvResult<Option<(Vec<KvEntry>, bool)>> {
        //self.query.next().await.transpose()
        Ok(None)
    }
}

#[derive(Clone, Debug)]
pub struct Lock {}

#[async_trait]
impl KvStore for KvPostgres {
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
        let client = self.conn_pool.acquire().await?;
        let mut params = SqlParams::from_iter(vec![&key_id, &category]);
        let query = extend_query(COUNT_QUERY, &mut params, tag_filter, None)?;
        let stmt = client.prepare(&query).await?;
        let count: i64 = client
            .query_one(&stmt, &params.as_refs()[..])
            .await
            .map(|row| row.get(0))?;
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
        let client = self.conn_pool.acquire().await?;
        let fetch_q = client.prepare(&FETCH_QUERY).await?;

        let result = client.query(&fetch_q, &[&key_id, &category, &name]).await?;
        if let Some(row) = result.iter().next() {
            let (row_id, value, value_key) = (
                row.try_get(0)?,
                row.try_get(1)?,
                row.try_get::<_, Vec<u8>>(2)?,
            );
            let tags = if options.retrieve_tags {
                Some(retrieve_tags(&client, row_id).await?)
            } else {
                None
            };
            Ok(Some(KvEntry {
                key_id,
                category,
                name,
                value,
                tags,
                locked: None,
            }))
        } else {
            Ok(None)
        }
    }

    async fn scan_start(
        &self,
        client_key: KvKeySelect,
        category: &[u8],
        options: KvFetchOptions,
        tag_filter: Option<wql::Query>,
        offset: Option<u64>,
        max_rows: Option<u64>,
    ) -> KvResult<Self::ScanToken> {
        /*let category = category.to_vec();
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
        Ok(Scan { ctx, query })*/
        let client = self.conn_pool.acquire().await?;
        Ok(Scan { client })
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
        let mut updates: Vec<(Vec<u8>, Vec<u8>, _)> = vec![];
        for entry in entries {
            let key_id = get_key_id(entry.profile_key.clone()).await;
            updates.push((key_id, vec![], entry))
        }

        let mut client = self.conn_pool.acquire().await?;
        let fetch_id = client
            .prepare("SELECT id FROM items WHERE key_id=?1 AND category=?2 AND name=?3")
            .await?;
        let add_item = client
            .prepare(
                "INSERT INTO items(key_id, category, name, value, value_key)
                VALUES(?1, ?2, ?3, ?4, ?5)",
            )
            .await?;
        // FIXME - might be faster to delete the row
        // (and its associated tags through cascade), and insert a new row
        let upd_item = client
            .prepare("UPDATE items SET value=?1, value_key=?2 WHERE id=?3")
            .await?;
        let add_enc_tag = client
            .prepare(
                "INSERT INTO tags_encrypted(item_id, name, value)
                    VALUES(?1, ?2, ?3)",
            )
            .await?;
        let add_plain_tag = client
            .prepare(
                "INSERT INTO tags_plaintext(item_id, name, value)
                    VALUES(?1, ?2, ?3)",
            )
            .await?;
        let txn = client.transaction().await?;
        for (key_id, value_key, entry) in updates {
            let found = txn
                .query(&fetch_id, &[&key_id, &entry.category, &entry.name])
                .await?;
            let row_id = if let Some(row) = found.iter().next() {
                let row_id = row.try_get(0)?;
                txn.execute(&upd_item, &[&row_id, &entry.value, &value_key])
                    .await?;
                // FIXME should be prepared statements?
                txn.execute("DELETE FROM tags_encrypted WHERE item_id=?1", &[&row_id])
                    .await?;
                txn.execute("DELETE FROM tags_plaintext WHERE item_id=?1", &[&row_id])
                    .await?;
                row_id
            } else {
                txn.execute(
                    &add_item,
                    &[
                        &key_id,
                        &entry.category,
                        &entry.name,
                        &entry.value,
                        &value_key,
                    ],
                )
                .await?;
                // client.execute(statement, params).last_insert_rowid()
                // FIXME fetch last inserted ID??
                1i64
            };
            if let Some(tags) = entry.tags.as_ref() {
                for tag in tags {
                    match tag {
                        KvTag::Encrypted(name, value) => {
                            txn.execute(&add_enc_tag, &[&row_id, name, value]).await?;
                        }
                        KvTag::Plaintext(name, value) => {
                            txn.execute(&add_plain_tag, &[&row_id, name, value]).await?;
                        }
                    }
                }
            }
        }
        txn.commit().await?;
        Ok(())
    }

    async fn create_lock(
        &self,
        _entry: KvUpdateEntry,
        _acquire_timeout_ms: Option<u64>,
    ) -> KvResult<(Option<Self::LockToken>, KvEntry)> {
        Err(KvError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use suspend::block_on;

    /*
        #[test]
        fn sqlite_init() {
            let db = KvSqlite::open_in_memory(EnclaveHandle {}).unwrap();
            block_on(db.provision()).unwrap();
        }

        #[test]
        fn sqlite_fetch_fail() {
            let db = KvSqlite::open_in_memory(EnclaveHandle {}).unwrap();
            block_on(db.provision()).unwrap();

            let client_key = KvKeySelect::ForClient(vec![]);
            let options = KvFetchOptions::default();
            let row = db.fetch(client_key, b"cat", b"name", options);
            let result = block_on(row).unwrap();
            assert!(result.is_none())
        }

        #[test]
        fn sqlite_add_fetch() {
            let db = KvSqlite::open_in_memory(EnclaveHandle {}).unwrap();
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
            let db = KvSqlite::open_in_memory(EnclaveHandle {}).unwrap();
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
            let db = KvSqlite::open_in_memory(EnclaveHandle {}).unwrap();
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
            let db = KvSqlite::open_in_memory(EnclaveHandle {}).unwrap();
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
    */
}
