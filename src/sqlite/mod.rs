use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use async_mutex::Mutex;
use async_stream::try_stream;
use async_trait::async_trait;
use futures_util::stream::{BoxStream, StreamExt};

use sqlx::{
    database::HasArguments,
    sqlite::{Sqlite, SqlitePool, SqlitePoolOptions, SqliteRow},
    Arguments, Database, Executor, IntoArguments, Row,
};

use super::error::{KvError, KvResult};
use super::types::{
    KeyId, KvEntry, KvFetchOptions, KvKeySelect, KvLockOperation, KvLockStatus, KvTag,
    KvUpdateEntry, ProfileId,
};
use super::wql::{
    self,
    sql::TagSqlEncoder,
    tags::{tag_query, TagQueryEncoder},
};
use super::{KvProvisionStore, KvStore};

const COUNT_QUERY: &'static str = "SELECT COUNT(*) FROM items i
    WHERE key_id = ?1 AND category = ?2
    AND (expiry IS NULL OR expiry > CURRENT_TIME)";
const FETCH_QUERY: &'static str = "SELECT id, value FROM items i
    WHERE key_id = ?1 AND category = ?2 AND name = ?3
    AND (expiry IS NULL OR expiry > CURRENT_TIME)";
const INSERT_QUERY: &'static str = "INSERT INTO items(key_id, category, name, value, expiry)
    VALUES(?1, ?2, ?3, ?4, ?5)";
const SCAN_QUERY: &'static str = "SELECT id, name, value FROM items i WHERE key_id = ?1
    AND category = ?2 AND (expiry IS NULL OR expiry > CURRENT_TIME)";
const TAG_QUERY: &'static str = "SELECT name, value, plaintext FROM items_tags WHERE item_id = ?1";

const PAGE_SIZE: usize = 5;

struct QueryParams<'q, DB: Database> {
    args: <DB as HasArguments<'q>>::Arguments,
    count: usize,
}

impl<'q, DB: Database> QueryParams<'q, DB> {
    pub fn new() -> Self {
        Self {
            args: Default::default(),
            count: 0,
        }
    }

    pub fn extend<I, T>(&mut self, vals: I)
    where
        I: IntoIterator<Item = T>,
        T: 'q + Send + sqlx::Encode<'q, DB> + sqlx::Type<DB>,
    {
        for item in vals {
            self.args.add(item);
            self.count += 1;
        }
    }

    pub fn push<T>(&mut self, val: T)
    where
        T: 'q + Send + sqlx::Encode<'q, DB> + sqlx::Type<DB>,
    {
        self.args.add(val);
        self.count += 1;
    }

    pub fn len(&self) -> usize {
        self.count
    }
}

impl<'q, DB> IntoArguments<'q, DB> for QueryParams<'q, DB>
where
    DB: Database,
    <DB as HasArguments<'q>>::Arguments: IntoArguments<'q, DB>,
{
    fn into_arguments(self) -> <DB as HasArguments<'q>>::Arguments {
        self.args.into_arguments()
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
    args: &mut QueryParams<'a, Sqlite>,
    tag_filter: Option<wql::Query>,
    limit: Option<(i64, i64)>,
) -> KvResult<String> {
    let mut query = query.to_string();
    let mut last_idx = args.len() as i64 + 1;

    if let Some(tag_filter) = tag_filter {
        let tag_query = tag_query(tag_filter)?;
        let mut enc = TagSqlEncoder::new();
        let filter: String = enc.encode_query(&tag_query)?;
        let (filter, next_idx) = replace_arg_placeholders(&filter, last_idx);
        last_idx = next_idx;
        args.extend(enc.arguments);
        query.push_str(" AND "); // assumes WHERE already occurs
        query.push_str(&filter);
    };
    if let Some((offs, limit)) = limit {
        args.push(offs);
        args.push(limit);
        let (limit, _next_idx) = replace_arg_placeholders(" LIMIT $$, $$", last_idx);
        // last_idx = next_idx;
        query.push_str(&limit);
    };
    Ok(query)
}

pub struct KvSqlite {
    conn_pool: SqlitePool,
    scans: Arc<Mutex<BTreeMap<ScanToken, Scan>>>,
    locks: Arc<Mutex<BTreeMap<LockToken, Lock>>>,
}

impl KvSqlite {
    pub async fn open_in_memory() -> KvResult<Self> {
        let conn_pool = SqlitePoolOptions::default()
            .min_connections(1)
            .max_connections(10)
            .connect(":memory:")
            .await?;
        Ok(Self {
            conn_pool,
            scans: Arc::new(Mutex::new(BTreeMap::new())),
            locks: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }
}

#[async_trait]
impl KvProvisionStore for KvSqlite {
    async fn provision(&self) -> KvResult<()> {
        sqlx::query(
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
                expiry DATETIME NULL,
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

            CREATE TABLE items_locks(
                key_id INTEGER NOT NULL,
                category NOT NULL,
                name NOT NULL,
                value NOT NULL,
                expiry DATETIME NULL,
                PRIMARY KEY(key_id, category, name)
            );

            END TRANSACTION;
        "#,
        )
        .persistent(false)
        .execute(&self.conn_pool)
        .await?;
        Ok(())
    }
}

// FIXME mock implementation for development
async fn get_key_id(k: KvKeySelect) -> KeyId {
    b"1".to_vec()
}

async fn fetch_row_tags(pool: &SqlitePool, row_id: i64) -> KvResult<Option<Vec<KvTag>>> {
    let tags = sqlx::query(TAG_QUERY)
        .bind(row_id)
        .try_map(|row: SqliteRow| {
            let name = row.try_get(0)?;
            let value = row.try_get(1)?;
            let plaintext = row.try_get(2)?;
            match plaintext {
                0 => Ok(KvTag::Encrypted(name, value)),
                _ => Ok(KvTag::Plaintext(name, value)),
            }
        })
        .fetch_all(pool)
        .await?;
    Ok(if tags.is_empty() { None } else { Some(tags) })
}

type Scan = BoxStream<'static, KvResult<Vec<KvEntry>>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScanToken {
    pub id: usize,
}

impl ScanToken {
    const COUNT: AtomicUsize = AtomicUsize::new(0);

    fn next() -> Self {
        Self {
            id: Self::COUNT.fetch_add(1, Ordering::AcqRel),
        }
    }
}

#[derive(Debug)]
pub struct Lock {
    entry: KvEntry,
}

// FIXME pool instance will dispose of locks itself
// impl Drop for Lock<'_> {
//     fn drop(&mut self) {
//         // remove the lock
//         let entry = self.entry.clone();
//         self.ctx
//             .enter(move |conn| {
//                 conn.prepare_cached(
//                     "DELETE FROM items_locks WHERE
//                 key_id = ?1 AND category = ?2 AND name = ?3 AND value = ?4",
//                 )
//                 .and_then(|mut del_lock| {
//                     del_lock.execute(params![
//                         &entry.key_id,
//                         &entry.category,
//                         &entry.name,
//                         &entry.value
//                     ])
//                 })
//                 .map_err(|err| eprintln!("Error removing lock: {:?}", err))
//                 .unwrap_or(0);
//             })
//             // FIXME ensure error is logged on failure
//             .wait()
//             .unwrap_or(())
//     }
// }

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LockToken {
    pub id: usize,
}

impl LockToken {
    const COUNT: AtomicUsize = AtomicUsize::new(0);

    fn next() -> Self {
        Self {
            id: Self::COUNT.fetch_add(1, Ordering::AcqRel),
        }
    }
}

#[async_trait]
impl KvStore for KvSqlite {
    type ScanToken = ScanToken;
    type LockToken = LockToken;

    async fn count(
        &self,
        client_key: KvKeySelect,
        category: &[u8],
        tag_filter: Option<wql::Query>,
    ) -> KvResult<u64> {
        let key_id = get_key_id(client_key).await;
        let category = category.to_vec();
        let mut args = QueryParams::new();
        args.push(key_id);
        args.push(category);
        let query = extend_query(COUNT_QUERY, &mut args, tag_filter, None)?;
        let count = sqlx::query_with(query.as_str(), args)
            .fetch_one(&self.conn_pool)
            .await?;
        KvResult::Ok(count.get::<i64, _>(0) as u64)
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
        if let Some(row) = sqlx::query(FETCH_QUERY)
            .bind(key_id.clone())
            .bind(category.clone())
            .bind(name.clone())
            .fetch_optional(&self.conn_pool)
            .await?
        {
            let tags = if options.retrieve_tags {
                fetch_row_tags(&self.conn_pool, row.try_get(0)?).await?
            } else {
                None
            };
            Ok(Some(KvEntry {
                key_id,
                category,
                name,
                value: row.try_get(1)?,
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
        let pool = self.conn_pool.clone();
        let category = category.to_vec();
        let key_id = get_key_id(client_key).await;
        let limit = Some((0i64, max_rows.map(|r| r as i64).unwrap_or(-1)));
        let scan = try_stream! {
            let mut params = QueryParams::new();
            params.push(key_id.clone());
            params.push(category.clone());
            let query = extend_query(SCAN_QUERY, &mut params, tag_filter, limit)?;
            let mut batch = Vec::with_capacity(PAGE_SIZE);
            let mut rows = sqlx::query_with(query.as_str(), params).fetch(&pool);
            while let Some(row) = rows.next().await {
                let row = row?;
                let tags = if options.retrieve_tags {
                    // FIXME - fetch tags in batches
                    fetch_row_tags(&pool, row.try_get(0)?).await?
                } else {
                    None
                };
                let entry = KvEntry {
                    key_id: key_id.clone(),
                    category: category.clone(),
                    name: row.try_get(1)?,
                    value: row.try_get(2)?,
                    locked: None,
                    tags,
                };
                batch.push(entry);
                if batch.len() == PAGE_SIZE {
                    yield batch.split_off(0);
                }
            }
            if batch.len() > 0 {
                yield batch;
            }
        };
        let token = ScanToken::next();
        self.scans.lock().await.insert(token, scan.boxed());
        Ok(token)
    }

    async fn scan_next(
        &self,
        scan_token: Self::ScanToken,
    ) -> KvResult<(Vec<KvEntry>, Option<Self::ScanToken>)> {
        // FIXME handle lock error
        let scan = self.scans.lock().await.remove(&scan_token);
        if let Some(mut scan) = scan {
            match scan.next().await {
                Some(Ok(rows)) => {
                    let token = if rows.len() == PAGE_SIZE {
                        self.scans.lock().await.insert(scan_token, scan);
                        Some(scan_token)
                    } else {
                        None
                    };
                    Ok((rows, token))
                }
                Some(Err(err)) => Err(err),
                None => Ok((vec![], None)),
            }
        } else {
            Err(KvError::Timeout)
        }
    }

    async fn update(
        &self,
        entries: Vec<KvUpdateEntry>,
        with_lock: Option<KvLockOperation<Self::LockToken>>,
    ) -> KvResult<()> {
        let mut updates = vec![];
        for entry in entries {
            let key_id = get_key_id(entry.profile_key.clone()).await;
            updates.push((key_id, entry))
        }

        let mut txn = self.conn_pool.begin().await?; // deferred write txn
        for (key_id, entry) in updates {
            let row_id: Option<i64> = sqlx::query_scalar(FETCH_QUERY)
                .bind(&key_id)
                .bind(&entry.category)
                .bind(&entry.name)
                .fetch_optional(&mut txn)
                .await?;
            let row_id = if let Some(row_id) = row_id {
                sqlx::query("UPDATE items SET value=?1 WHERE id=?2")
                    .bind(row_id)
                    .bind(entry.value)
                    .execute(&mut txn)
                    .await?;
                sqlx::query("DELETE FROM items_tags WHERE item_id=?1")
                    .bind(row_id)
                    .execute(&mut txn)
                    .await?;
                row_id
            } else {
                sqlx::query(INSERT_QUERY)
                    .bind(&key_id)
                    .bind(entry.category)
                    .bind(entry.name)
                    .bind(entry.value)
                    .bind(entry.expiry.map(|i| i as i64))
                    .execute(&mut txn)
                    .await?
                    .last_insert_rowid()
            };
            if let Some(tags) = entry.tags.as_ref() {
                for tag in tags {
                    let (name, value, plaintext) = match tag {
                        KvTag::Encrypted(name, value) => (name, value, 0),
                        KvTag::Plaintext(name, value) => (name, value, 1),
                    };
                    sqlx::query(
                        "INSERT INTO items_tags(item_id, name, value, plaintext)
                             VALUES(?1, ?2, ?3, ?4)",
                    )
                    .bind(row_id)
                    .bind(name)
                    .bind(value)
                    .bind(plaintext)
                    .execute(&mut txn)
                    .await?;
                }
            }
        }
        Ok(txn.commit().await?)
    }

    async fn create_lock(
        &self,
        lock_info: KvUpdateEntry,
        acquire_timeout_ms: Option<u64>,
    ) -> KvResult<(Option<Self::LockToken>, KvEntry)> {
        let key_id = get_key_id(lock_info.profile_key.clone()).await;

        let mut txn = self.conn_pool.begin().await?;
        // start a write transaction to ensure we have only the latest state
        // (sqlx currently has no native support for BEGIN IMMEDIATE)
        txn.execute("DELETE FROM items_locks WHERE 0").await?;

        let locked: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM items_locks
            WHERE key_id = ?1 AND category = ?2 AND name = ?3
            AND expiry > CURRENT_TIME",
        )
        .bind(&key_id)
        .bind(&lock_info.category)
        .bind(&lock_info.name)
        .fetch_one(&mut txn)
        .await?;

        let mut entry = match sqlx::query(FETCH_QUERY)
            .bind(&key_id)
            .bind(&lock_info.category)
            .bind(&lock_info.name)
            .fetch_optional(&mut txn)
            .await?
        {
            Some(row) => {
                KvEntry {
                    key_id: key_id.clone(),
                    category: lock_info.category.clone(),
                    name: lock_info.name.clone(),
                    value: row.try_get(1)?,
                    tags: None, // FIXME optionally fetch tags
                    locked: Some(if locked > 0 {
                        KvLockStatus::Locked
                    } else {
                        KvLockStatus::Unlocked
                    }),
                }
            }
            None => {
                sqlx::query(INSERT_QUERY)
                    .bind(&key_id)
                    .bind(&lock_info.category)
                    .bind(&lock_info.name)
                    .bind(&lock_info.value)
                    .bind(&lock_info.expiry.map(|i| i as i64))
                    .execute(&mut txn)
                    .await?;
                KvEntry {
                    key_id: key_id.clone(),
                    category: lock_info.category.clone(),
                    name: lock_info.name.clone(),
                    value: lock_info.value.clone(),
                    tags: lock_info.tags.clone(),
                    locked: Some(KvLockStatus::Unlocked),
                }
            }
        };

        let lock_entry = if !entry.is_locked() {
            // FIXME generate a random value
            let lock_value = "lock-value".as_bytes().to_vec();
            sqlx::query(
                "INSERT INTO items_locks
                (key_id, category, name, value, expiry) VALUES (?1, ?2, ?3, ?4, ?5)",
            )
            .bind(&key_id)
            .bind(&entry.category)
            .bind(&entry.name)
            .bind(&lock_value)
            .bind(lock_info.expiry.map(|i| i as i64))
            .execute(&mut txn)
            .await?;
            entry.locked.replace(KvLockStatus::Locked);
            let mut lock_entry = entry.clone();
            lock_entry.value = lock_value;
            Some(lock_entry)
        } else {
            None
        };
        txn.commit().await?;

        let token = if let Some(lock_entry) = lock_entry {
            let token = LockToken::next();
            self.locks
                .lock()
                .await
                .insert(token, Lock { entry: lock_entry });
            Some(token)
        } else {
            None
        };
        Ok((token, entry))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use suspend::block_on;

    #[test]
    fn sqlite_init() {
        block_on(async {
            let db = KvSqlite::open_in_memory().await?;
            db.provision().await?;
            KvResult::Ok(())
        })
        .unwrap()
    }

    #[test]
    fn sqlite_fetch_fail() {
        let result = block_on(async {
            let db = KvSqlite::open_in_memory().await?;
            db.provision().await?;
            let profile_key = KvKeySelect::ForProfile(vec![]);
            let options = KvFetchOptions::default();
            KvResult::Ok(db.fetch(profile_key, b"cat", b"name", options).await?)
        });
        assert!(result.unwrap().is_none())
    }

    #[test]
    fn sqlite_add_fetch() {
        let test_row = KvEntry {
            key_id: b"1".to_vec(),
            category: b"cat".to_vec(),
            name: b"name".to_vec(),
            value: b"value".to_vec(),
            tags: None,
            locked: None,
        };

        let result = block_on(async {
            let db = KvSqlite::open_in_memory().await?;
            db.provision().await?;

            let profile_key = KvKeySelect::ForProfile(vec![]);
            let options = KvFetchOptions::new(true, true, false);

            let updates = vec![KvUpdateEntry {
                profile_key: profile_key.clone(),
                category: test_row.category.clone(),
                name: test_row.name.clone(),
                value: test_row.value.clone(),
                tags: None,
                expiry: None,
            }];
            db.update(updates, None).await?;

            let row = db
                .fetch(
                    profile_key.clone(),
                    &test_row.category,
                    &test_row.name,
                    options,
                )
                .await?;
            KvResult::Ok(row)
        })
        .unwrap();
        assert!(result.is_some());
        let found = result.unwrap();
        assert_eq!(found, test_row)
    }

    #[test]
    fn sqlite_add_fetch_tags() {
        let test_row = KvEntry {
            key_id: b"1".to_vec(),
            category: b"cat".to_vec(),
            name: b"name".to_vec(),
            value: b"value".to_vec(),
            tags: Some(vec![
                KvTag::Encrypted(b"t1".to_vec(), b"v1".to_vec()),
                KvTag::Plaintext(b"t2".to_vec(), b"v2".to_vec()),
            ]),
            locked: None,
        };

        let result = block_on(async {
            let db = KvSqlite::open_in_memory().await?;
            db.provision().await?;

            let profile_key = KvKeySelect::ForProfile(vec![]);
            let options = KvFetchOptions::new(true, true, false);

            let updates = vec![KvUpdateEntry {
                profile_key: profile_key.clone(),
                category: test_row.category.clone(),
                name: test_row.name.clone(),
                value: test_row.value.clone(),
                tags: test_row.tags.clone(),
                expiry: None,
            }];
            db.update(updates, None).await?;

            let row = db
                .fetch(
                    profile_key.clone(),
                    &test_row.category,
                    &test_row.name,
                    options,
                )
                .await?;
            KvResult::Ok(row)
        })
        .unwrap();
        assert!(result.is_some());
        let found = result.unwrap();
        assert_eq!(found, test_row);
    }

    #[test]
    fn sqlite_count() {
        let category = b"cat".to_vec();
        let test_rows = vec![KvEntry {
            key_id: b"1".to_vec(),
            category: category.clone(),
            name: b"name".to_vec(),
            value: b"value".to_vec(),
            tags: None,
            locked: None,
        }];

        block_on(async {
            let db = KvSqlite::open_in_memory().await?;
            db.provision().await?;

            let profile_key = KvKeySelect::ForProfile(vec![]);
            let updates = test_rows
                .iter()
                .map(|row| KvUpdateEntry {
                    profile_key: profile_key.clone(),
                    category: row.category.clone(),
                    name: row.name.clone(),
                    value: row.value.clone(),
                    tags: row.tags.clone(),
                    expiry: None,
                })
                .collect();
            db.update(updates, None).await?;

            let tag_filter = None;
            let count = db.count(profile_key.clone(), &category, tag_filter).await?;
            assert_eq!(count, 1);

            let tag_filter = Some(wql::Query::Eq("sometag".to_string(), "someval".to_string()));
            let count = db.count(profile_key.clone(), &category, tag_filter).await?;
            assert_eq!(count, 0);
            KvResult::Ok(())
        })
        .unwrap();
    }

    #[test]
    fn sqlite_scan() {
        let category = b"cat".to_vec();
        let test_rows = vec![KvEntry {
            key_id: b"1".to_vec(),
            category: category.clone(),
            name: b"name".to_vec(),
            value: b"value".to_vec(),
            tags: None,
            locked: None,
        }];

        block_on(async {
            let db = KvSqlite::open_in_memory().await?;
            db.provision().await?;

            let profile_key = KvKeySelect::ForProfile(vec![]);
            let updates = test_rows
                .iter()
                .map(|row| KvUpdateEntry {
                    profile_key: profile_key.clone(),
                    category: row.category.clone(),
                    name: row.name.clone(),
                    value: row.value.clone(),
                    tags: row.tags.clone(),
                    expiry: None,
                })
                .collect();
            db.update(updates, None).await?;

            let options = KvFetchOptions::default();
            let tag_filter = None;
            let offset = None;
            let max_rows = None;
            let scan_token = db
                .scan_start(
                    profile_key.clone(),
                    &category,
                    options,
                    tag_filter,
                    offset,
                    max_rows,
                )
                .await?;
            let (rows, scan_next) = db.scan_next(scan_token).await?;
            assert_eq!(rows, test_rows);
            assert!(scan_next.is_none());

            let options = KvFetchOptions::default();
            let tag_filter = Some(wql::Query::Eq("sometag".to_string(), "someval".to_string()));
            let scan_token = block_on(db.scan_start(
                profile_key.clone(),
                &category,
                options,
                tag_filter,
                offset,
                max_rows,
            ))?;
            let (rows, scan_next) = db.scan_next(scan_token).await?;
            assert_eq!(rows, vec![]);
            assert!(scan_next.is_none());
            KvResult::Ok(())
        })
        .unwrap();
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

    #[test]
    fn sqlite_create_lock_non_existing() {
        block_on(async {
            let db = KvSqlite::open_in_memory().await?;
            db.provision().await?;

            let update = KvUpdateEntry {
                profile_key: KvKeySelect::ForProfile(vec![]),
                category: b"cat".to_vec(),
                name: b"name".to_vec(),
                value: b"value".to_vec(),
                tags: None,
                expiry: None,
            };
            let lock_update = update.clone();
            let (opt_lock, entry) = db.create_lock(lock_update, None).await?;
            assert!(opt_lock.is_some());
            assert_eq!(entry.category, update.category);
            assert_eq!(entry.name, update.name);
            assert_eq!(entry.value, update.value);
            assert_eq!(entry.locked, Some(KvLockStatus::Locked));
            KvResult::Ok(())
        })
        .unwrap();
    }
}
