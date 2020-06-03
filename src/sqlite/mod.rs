mod pool;

use async_trait::async_trait;

use piper::Arc;
use smol::{blocking, Task};

use r2d2;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, ToSql};

use std::sync::{
    mpsc::{sync_channel, Receiver, SyncSender},
    Mutex,
};

use super::error::{KvError, KvResult};
use super::types::{
    ClientId, Enclave, EnclaveHandle, KeyId, KvEntry, KvFetchOptions, KvKeySelect, KvLockOperation,
    KvLockToken, KvScanToken, KvTag, KvUpdateEntry,
};
use super::wql::{self, sql::TagSqlEncoder, tags::TagQuery};
use super::{KvProvisionStore, KvStore};

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

fn replace_arg_placeholders(filter: &str, start_index: i64) -> (String, i64) {
    let mut index = start_index;
    let mut s: String = filter.to_owned();
    while s.find("$$") != None {
        let arg_str = format!("?{}", index);
        s = s.replacen("$$", &arg_str, 1);
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
    items: Vec<Box<dyn ToSql + 'a>>,
}

impl<'a> SqlParams<'a> {
    pub fn new() -> Self {
        Self { items: vec![] }
    }

    pub fn from_iter<I, T>(items: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: ToSql + 'a,
    {
        let mut s = Self::new();
        s.extend(items);
        s
    }

    pub fn push<T>(&mut self, item: T)
    where
        T: ToSql + 'a,
    {
        self.items.push(Box::new(item))
    }

    pub fn extend<I, T>(&mut self, items: I)
    where
        I: IntoIterator<Item = T>,
        T: ToSql + 'a,
    {
        self.items.extend(
            items
                .into_iter()
                .map(|item| Box::new(item) as Box<dyn ToSql>),
        )
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }
}

impl<'a> IntoIterator for SqlParams<'a> {
    type Item = Box<dyn ToSql + 'a>;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

pub struct KvSqlite {
    conn_pool: r2d2::Pool<SqliteConnectionManager>,
    enclave: EnclaveHandle,
}

impl KvSqlite {
    pub fn open_in_memory(enclave: EnclaveHandle) -> KvResult<Self> {
        let mgr = SqliteConnectionManager::memory();
        let conn_pool = r2d2::Pool::new(mgr).expect("Error creating connection pool");
        Ok(Self { conn_pool, enclave })
    }
}

impl From<rusqlite::Error> for KvError {
    fn from(err: rusqlite::Error) -> Self {
        KvError::BackendError(err.to_string())
    }
}

impl<T> From<std::sync::mpsc::SendError<T>> for KvError {
    fn from(_err: std::sync::mpsc::SendError<T>) -> Self {
        KvError::Disconnected
    }
}

impl KvProvisionStore for KvSqlite {
    fn provision(&self) -> KvResult<()> {
        let conn = self.conn_pool.get().expect("Error getting pool instance");
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
        )?;
        Ok(())
    }
}

async fn get_key_id(k: KvKeySelect) -> KeyId {
    b"1".to_vec()
}

fn run_scan(
    sender: SyncSender<KvResult<KvEntry>>,
    pool: r2d2::Pool<SqliteConnectionManager>,
    key_id: KeyId,
    category: Vec<u8>,
    options: KvFetchOptions,
    tag_filter: Option<wql::Query>,
    max_rows: Option<u64>,
) -> KvResult<()> {
    let conn = pool.get().expect("Error getting pool instance");
    let limit = Some((0i64, max_rows.map(|r| r as i64).unwrap_or(-1)));
    let mut params = SqlParams::from_iter(vec![&key_id, &category]);
    let query = extend_query(SCAN_QUERY, &mut params, tag_filter, limit)?;
    let mut scan_q = conn.prepare_cached(query.as_str())?;
    let result = scan_q.query_map(params, |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    for row in result {
        match row {
            Ok((row_id, name, value, value_key)) => {
                let tags = if options.retrieve_tags {
                    // FIXME fetch tags in batches
                    Some(retrieve_tags(&conn, row_id)?)
                } else {
                    None
                };
                sender.send(Ok(KvEntry {
                    key_id: key_id.clone(),
                    category: category.clone(),
                    name,
                    value,
                    tags,
                }))?;
            }
            Err(e) => {
                sender.send(Err(e.into()))?;
                return Ok(());
            }
        }
    }
    Ok(())
}

fn retrieve_tags(conn: &rusqlite::Connection, row_id: i64) -> KvResult<Vec<KvTag>> {
    let mut tag_q = conn.prepare_cached(TAG_QUERY)?;
    let rows = tag_q
        .query_map(&[&row_id], |row| {
            let enc: i32 = row.get(0)?;
            if enc == 1 {
                Ok(KvTag::Encrypted(row.get(1)?, row.get(2)?))
            } else {
                Ok(KvTag::Plaintext(row.get(1)?, row.get(2)?))
            }
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

#[derive(Debug)]
pub struct Scan {
    receiver: Receiver<KvResult<KvEntry>>,
    task: Task<KvResult<()>>,
}
impl Scan {
    pub fn new(
        pool: r2d2::Pool<SqliteConnectionManager>,
        key_id: KeyId,
        category: &[u8],
        options: KvFetchOptions,
        tag_filter: Option<wql::Query>,
        max_rows: Option<u64>,
    ) -> KvResult<Self> {
        let (sender, receiver) = sync_channel::<KvResult<KvEntry>>(100);
        let category = category.to_vec();
        let task = Task::blocking(async move {
            let result = run_scan(
                sender.clone(),
                pool,
                key_id,
                category,
                options,
                tag_filter,
                max_rows,
            );
            match result {
                Ok(r) => r,
                Err(e) => sender.send(Err(e.into()))?,
            }
            Ok(())
        });
        Ok(Self { receiver, task })
    }

    pub fn next(&self) -> KvResult<Option<KvEntry>> {
        match self.receiver.recv() {
            Ok(row) => row.map(Option::Some),
            Err(_) => Ok(None),
        }
    }
}
impl KvScanToken for Arc<Mutex<Scan>> {}

#[derive(Clone, Debug)]
pub struct Lock {}
impl KvLockToken for Lock {}

#[async_trait]
impl KvStore for KvSqlite {
    type ScanToken = Arc<Mutex<Scan>>;
    type LockToken = Lock;

    async fn count(
        &self,
        client_key: KvKeySelect,
        category: &[u8],
        tag_filter: Option<wql::Query>,
    ) -> KvResult<u64> {
        let pool = self.conn_pool.clone();
        let key_id = get_key_id(client_key).await;
        let category = category.to_vec();
        let count: i64 = blocking!(async move {
            let mut params = SqlParams::from_iter(vec![&key_id, &category]);
            let query = extend_query(COUNT_QUERY, &mut params, tag_filter, None)?;
            let conn = pool.get().expect("Error getting pool instance");
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
        let pool = self.conn_pool.clone();
        let key_id = get_key_id(client_key).await;
        let category = category.to_vec();
        let name = name.to_vec();
        let q_key_id = key_id.clone();
        let q_category = category.clone();
        let q_name = name.clone();
        blocking!(async move {
            let conn = pool.get().expect("Error getting pool instance");
            let mut fetch_q = conn.prepare_cached(FETCH_QUERY)?;
            let result = fetch_q.query_row(&[&q_key_id, &q_category, &q_name], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            });
            match result {
                Ok((row_id, value, value_key)) => {
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
        let key_id = get_key_id(client_key).await;
        let scan = Scan::new(
            self.conn_pool.clone(),
            key_id,
            category,
            options,
            tag_filter,
            max_rows,
        )?;
        Ok(Arc::new(Mutex::new(scan)))
    }

    async fn scan_next(
        &self,
        scan_token: Self::ScanToken,
    ) -> KvResult<(Vec<KvEntry>, Option<Self::ScanToken>)> {
        blocking!(async move {
            let (rows, done) = {
                let mut done = false;
                let mut rows = vec![];
                let scan = match scan_token.lock() {
                    Ok(lock) => lock,
                    Err(_) => return Err(KvError::Disconnected),
                };
                for _ in 0..20 {
                    match scan.next() {
                        Ok(Some(row)) => {
                            rows.push(row);
                        }
                        Ok(None) => {
                            done = true;
                            break;
                        }
                        Err(e) => return Err(e),
                    }
                }
                (rows, done)
            };
            Ok((rows, if done { None } else { Some(scan_token) }))
        })
        .await
    }

    async fn update(
        &self,
        entries: Vec<KvUpdateEntry>,
        with_lock: Option<KvLockOperation<Self::LockToken>>,
    ) -> KvResult<()> {
        let mut updates = vec![];
        for entry in entries {
            let key_id = get_key_id(entry.client_key.clone()).await;
            updates.push((key_id, vec![], entry))
        }

        let pool = self.conn_pool.clone();
        blocking!(async move {
            let mut conn = pool.get().expect("Error getting pool instance");
            let txn = conn.transaction()?; // rusqlite::TransactionBehavior::Deferred
            {
                let mut fetch_id = txn.prepare_cached(
                    "SELECT id FROM items WHERE key_id=?1 AND category=?2 AND name=?3",
                )?;
                let mut add_item = txn.prepare_cached(
                    "INSERT INTO items(key_id, category, name, value, value_key)
                    VALUES(?1, ?2, ?3, ?4, ?5)",
                )?;
                // FIXME - might be faster to delete the row
                // (and its associated tags through cascade), and insert a new row
                let mut upd_item =
                    txn.prepare_cached("UPDATE items SET value=?1, value_key=?2 WHERE id=?3")?;
                let mut add_enc_tag = txn.prepare_cached(
                    "INSERT INTO tags_encrypted(item_id, name, value)
                        VALUES(?1, ?2, ?3)",
                )?;
                let mut add_plain_tag = txn.prepare_cached(
                    "INSERT INTO tags_plaintext(item_id, name, value)
                        VALUES(?1, ?2, ?3)",
                )?;
                for (key_id, value_key, entry) in updates {
                    let row: Result<i64, rusqlite::Error> = fetch_id
                        .query_row(&[&key_id, &entry.category, &entry.name], |row| row.get(0));
                    let row_id = match row {
                        Ok(row_id) => {
                            upd_item.execute(params![&row_id, &entry.value, &value_key])?;
                            txn.execute("DELETE FROM tags_encrypted WHERE item_id=?1", &[&row_id])?;
                            txn.execute("DELETE FROM tags_plaintext WHERE item_id=?1", &[&row_id])?;
                            row_id
                        }
                        Err(rusqlite::Error::QueryReturnedNoRows) => {
                            add_item.execute(&[
                                &key_id,
                                &entry.category,
                                &entry.name,
                                &entry.value,
                                &value_key,
                            ])?;
                            txn.last_insert_rowid()
                        }
                        Err(err) => return Err(err.into()),
                    };
                    if let Some(tags) = entry.tags.as_ref() {
                        for tag in tags {
                            match tag {
                                KvTag::Encrypted(name, value) => {
                                    add_enc_tag.execute(params![&row_id, name, value])?;
                                }
                                KvTag::Plaintext(name, value) => {
                                    add_plain_tag.execute(params![&row_id, name, value])?;
                                }
                            }
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
    fn test_init() {
        let db = KvSqlite::open_in_memory(EnclaveHandle {}).unwrap();
        db.provision().unwrap();
    }

    #[test]
    fn test_fetch_fail() {
        let db = KvSqlite::open_in_memory(EnclaveHandle {}).unwrap();
        db.provision().unwrap();

        let client_key = KvKeySelect::ForClient(vec![]);
        let options = KvFetchOptions::default();
        let row = db.fetch(client_key, b"cat", b"name", options);
        let result = block_on(row).unwrap();
        assert!(result.is_none())
    }

    #[test]
    fn test_add_fetch() {
        let db = KvSqlite::open_in_memory(EnclaveHandle {}).unwrap();
        db.provision().unwrap();

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
    fn test_add_fetch_tags() {
        let db = KvSqlite::open_in_memory(EnclaveHandle {}).unwrap();
        db.provision().unwrap();

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
    fn test_count() {
        let db = KvSqlite::open_in_memory(EnclaveHandle {}).unwrap();
        db.provision().unwrap();

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
    fn test_scan() {
        let db = KvSqlite::open_in_memory(EnclaveHandle {}).unwrap();
        db.provision().unwrap();

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
    fn test_simple_and_convert_args_works() {
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
