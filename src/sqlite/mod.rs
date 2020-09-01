use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_mutex::Mutex;
use async_stream::try_stream;
use async_trait::async_trait;
use futures_util::stream::StreamExt;

use sqlx::{
    sqlite::{Sqlite, SqlitePool, SqlitePoolOptions, SqliteRow},
    Done, Row,
};

use super::db_utils::{
    expiry_timestamp, extend_query, hash_lock_info, QueryParams, QueryPrepare, Scan, PAGE_SIZE,
};
use super::error::{Error, Result as KvResult};
use super::options::IntoOptions;
use super::store::{KvStore, LockToken, ScanToken};
use super::types::{KeyId, KvEntry, KvFetchOptions, KvKeySelect, KvTag, KvUpdateEntry, ProfileId};
use super::wql;
use super::KvProvisionStore;

const LOCK_EXPIRY: i64 = 120000; // 2 minutes
const COUNT_QUERY: &'static str = "SELECT COUNT(*) FROM items i
    WHERE key_id = ?1 AND category = ?2
    AND (expiry IS NULL OR expiry > datetime('now'))";
const FETCH_QUERY: &'static str = "SELECT id, value FROM items i
    WHERE key_id = ?1 AND category = ?2 AND name = ?3
    AND (expiry IS NULL OR expiry > datetime('now'))";
const INSERT_QUERY: &'static str = "INSERT INTO items(key_id, category, name, value, expiry)
    VALUES(?1, ?2, ?3, ?4, ?5)";
const SCAN_QUERY: &'static str = "SELECT id, name, value FROM items i WHERE key_id = ?1
    AND category = ?2 AND (expiry IS NULL OR expiry > datetime('now'))";
const TAG_QUERY: &'static str = "SELECT name, value, plaintext FROM items_tags WHERE item_id = ?1";

// FIXME mock implementation for development
async fn get_key_id(k: KvKeySelect) -> KeyId {
    1
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

#[derive(Debug)]
pub struct Lock {
    pub id: i64,
}

pub struct KvSqliteOptions<'a> {
    path: Cow<'a, str>,
    options: SqlitePoolOptions,
}

impl<'a> KvSqliteOptions<'a> {
    pub fn new<O>(options: O) -> KvResult<Self>
    where
        O: IntoOptions<'a>,
    {
        let opts = options.into_options()?;
        Ok(Self {
            path: opts.host,
            options: SqlitePoolOptions::default()
                // must maintain at least 1 connection to avoid dropping in-memory database
                .min_connections(1)
                .max_connections(10),
        })
    }

    pub fn in_memory() -> Self {
        Self::new(":memory:").unwrap()
    }
}

#[async_trait]
impl<'a> KvProvisionStore for KvSqliteOptions<'a> {
    type Store = KvSqlite;

    async fn provision_store(self) -> KvResult<Self::Store> {
        let conn_pool = self.options.connect(self.path.as_ref()).await?;

        let wallet_id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            BEGIN EXCLUSIVE TRANSACTION;

            CREATE TABLE config (
                name TEXT NOT NULL,
                value TEXT,
                PRIMARY KEY(name)
            );
            INSERT INTO config (name, value) VALUES
                ("uniq_id", ?1),
                ("version", "1");

            CREATE TABLE keys (
                id INTEGER NOT NULL,
                parent_id INTEGER NULL,
                profile_id INTEGER NOT NULL,
                reference TEXT NULL,
                value BLOB NULL,
                PRIMARY KEY(id),
                FOREIGN KEY(parent_id) REFERENCES keys(id)
                    ON DELETE CASCADE ON UPDATE CASCADE,
                FOREIGN KEY(profile_id) REFERENCES profiles(id)
                    ON DELETE CASCADE ON UPDATE CASCADE
            );

            CREATE TABLE profiles (
                id INTEGER NOT NULL,
                items_key_id INTEGER NULL,
                reference TEXT NULL,
                PRIMARY KEY(id),
                FOREIGN KEY(items_key_id) REFERENCES keys(id)
                    ON DELETE CASCADE ON UPDATE CASCADE
            );

            CREATE TABLE items (
                id INTEGER NOT NULL,
                key_id INTEGER NOT NULL,
                category NOT NULL,
                name NOT NULL,
                value NOT NULL,
                expiry DATETIME NULL,
                PRIMARY KEY(id),
                FOREIGN KEY(key_id) REFERENCES keys(id)
                    ON DELETE CASCADE ON UPDATE CASCADE
            );
            CREATE UNIQUE INDEX ux_items_uniq ON items(key_id, category, name);

            CREATE TABLE items_tags (
                item_id INTEGER NOT NULL,
                name NOT NULL,
                value NOT NULL,
                plaintext BOOLEAN NOT NULL,
                PRIMARY KEY(name, item_id, plaintext),
                FOREIGN KEY(item_id) REFERENCES items(id)
                    ON DELETE CASCADE ON UPDATE CASCADE
            );
            CREATE INDEX ix_items_tags_item_id ON items_tags(item_id);
            CREATE INDEX ix_items_tags_value ON items_tags(value) WHERE plaintext;

            CREATE TABLE items_locks (
                id INTEGER NOT NULL,
                expiry DATETIME NOT NULL,
                PRIMARY KEY(id)
            );

            COMMIT;

            -- for testing only
            INSERT INTO profiles (items_key_id) VALUES (NULL);
            INSERT INTO keys (profile_id) VALUES (1);

        "#,
        )
        .persistent(false)
        .bind(wallet_id)
        .execute(&conn_pool)
        .await?;

        Ok(KvSqlite::new(conn_pool))
    }
}

pub struct KvSqlite {
    conn_pool: SqlitePool,
    scans: Arc<Mutex<BTreeMap<ScanToken, Scan>>>,
    locks: Arc<Mutex<BTreeMap<LockToken, Lock>>>,
}

impl KvSqlite {
    pub(crate) fn new(conn_pool: SqlitePool) -> Self {
        Self {
            conn_pool,
            scans: Arc::new(Mutex::new(BTreeMap::new())),
            locks: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

impl QueryPrepare for KvSqlite {
    type DB = Sqlite;
}

#[async_trait]
impl KvStore for KvSqlite {
    async fn count(
        &self,
        client_key: KvKeySelect,
        category: &[u8],
        tag_filter: Option<wql::Query>,
    ) -> KvResult<i64> {
        let key_id = get_key_id(client_key).await;
        let category = category.to_vec();
        let mut args = QueryParams::new();
        args.push(key_id);
        args.push(category);
        let query = extend_query::<Self>(COUNT_QUERY, &mut args, tag_filter, None, None)?;
        let count = sqlx::query_scalar_with(query.as_str(), args)
            .fetch_one(&self.conn_pool)
            .await?;
        KvResult::Ok(count)
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
        offset: Option<i64>,
        max_rows: Option<i64>,
    ) -> KvResult<ScanToken> {
        let pool = self.conn_pool.clone();
        let category = category.to_vec();
        let key_id = get_key_id(client_key).await;
        let scan = try_stream! {
            let mut params = QueryParams::new();
            params.push(key_id.clone());
            params.push(category.clone());
            let query = extend_query::<KvSqlite>(SCAN_QUERY, &mut params, tag_filter, offset, max_rows)?;
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
        scan_token: ScanToken,
    ) -> KvResult<(Vec<KvEntry>, Option<ScanToken>)> {
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
            Err(Error::Timeout)
        }
    }

    async fn update(
        &self,
        entries: Vec<KvUpdateEntry>,
        with_lock: Option<LockToken>,
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
                    .bind(&entry.value)
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
                    .bind(&entry.category)
                    .bind(&entry.name)
                    .bind(&entry.value)
                    .bind(&entry.expire_ms.map(expiry_timestamp))
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
        options: KvFetchOptions,
        acquire_timeout_ms: Option<i64>,
    ) -> KvResult<Option<(LockToken, KvEntry)>> {
        let key_id = get_key_id(lock_info.profile_key.clone()).await;
        let hash = hash_lock_info(key_id, &lock_info);

        let mut txn = self.conn_pool.begin().await?;

        let interval = 10;
        let expire = acquire_timeout_ms.map(|offs| {
            Instant::now() + Duration::from_millis(std::cmp::max(0, offs - interval) as u64)
        });
        loop {
            let upserted = sqlx::query(
                "INSERT INTO items_locks (id, expiry) VALUES (?1, ?2)
                ON CONFLICT (id) DO UPDATE SET expiry=excluded.expiry
                WHERE expiry <= datetime('now')",
            )
            .bind(hash)
            .bind(expiry_timestamp(LOCK_EXPIRY))
            .execute(&mut txn)
            .await?
            .rows_affected();
            if upserted > 0 {
                println!("upserted: {}", upserted);
                break;
            }
            if expire
                .map(|exp| Instant::now().checked_duration_since(exp).is_some())
                .unwrap_or(false)
            {
                return Ok(None);
            }
            smol::Timer::after(Duration::from_millis(interval as u64)).await;
        }

        let entry = match sqlx::query(FETCH_QUERY)
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
                }
            }
            None => {
                sqlx::query(INSERT_QUERY)
                    .bind(&key_id)
                    .bind(&lock_info.category)
                    .bind(&lock_info.name)
                    .bind(&lock_info.value)
                    .bind(&lock_info.expire_ms.map(expiry_timestamp))
                    .execute(&mut txn)
                    .await?;
                KvEntry {
                    key_id: key_id.clone(),
                    category: lock_info.category.clone(),
                    name: lock_info.name.clone(),
                    value: lock_info.value.clone(),
                    tags: lock_info.tags.clone(),
                }
            }
        };
        txn.commit().await?;

        let token = LockToken::next();
        self.locks.lock().await.insert(token, Lock { id: hash });
        Ok(Some((token, entry)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db_utils::replace_arg_placeholders;

    #[test]
    fn sqlite_check_expiry_timestamp() {
        suspend::block_on(async {
            let db = KvSqliteOptions::in_memory().provision_store().await?;
            let ts = expiry_timestamp(LOCK_EXPIRY);
            let check = sqlx::query("SELECT datetime('now'), ?1, ?1 > datetime('now')")
                .bind(ts)
                .fetch_one(&db.conn_pool)
                .await?;
            let now: String = check.try_get(0)?;
            let cmp_ts: String = check.try_get(1)?;
            let cmp: bool = check.try_get(2)?;
            if !cmp {
                panic!("now ({}) > expiry timestamp ({})", now, cmp_ts);
            }
            KvResult::Ok(())
        })
        .unwrap();
    }

    #[test]
    fn sqlite_simple_and_convert_args_works() {
        assert_eq!(
            replace_arg_placeholders::<KvSqlite>("This $$ is $$ a $$ string!", 3),
            ("This ?3 is ?4 a ?5 string!".to_string(), 6),
        );
        assert_eq!(
            replace_arg_placeholders::<KvSqlite>("This is a string!", 1),
            ("This is a string!".to_string(), 1),
        );
    }
}
