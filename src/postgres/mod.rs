use std::collections::{hash_map::DefaultHasher, BTreeMap};
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use async_mutex::Mutex;
use async_stream::try_stream;
use async_trait::async_trait;

use futures_util::stream::StreamExt;

use sqlx::{
    postgres::{PgPool, PgRow, Postgres},
    Executor, Row,
};

use super::db_utils::{
    expiry_timestamp, extend_query, replace_arg_placeholders, LockToken, QueryParams, QueryPrepare,
    Scan, ScanToken, PAGE_SIZE,
};
use super::error::{KvError, KvResult};
use super::types::{
    KeyId, KvEntry, KvFetchOptions, KvKeySelect, KvLockOperation, KvLockStatus, KvTag,
    KvUpdateEntry, ProfileId,
};
use super::wql::{self};
use super::{KvProvisionStore, KvStore};

const COUNT_QUERY: &'static str = "SELECT COUNT(*) FROM items i
    WHERE key_id = $1 AND category = $2
    AND (expiry IS NULL OR expiry > CURRENT_TIMESTAMP)";
const FETCH_QUERY: &'static str = "SELECT id, value FROM items i
    WHERE key_id = $1 AND category = $2 AND name = $3
    AND (expiry IS NULL OR expiry > CURRENT_TIMESTAMP)";
const INSERT_QUERY: &'static str = "INSERT INTO items(key_id, category, name, value, expiry)
    VALUES($1, $2, $3, $4, $5) RETURNING id";
const SCAN_QUERY: &'static str = "SELECT id, name, value FROM items i WHERE key_id = $1
    AND category = $2 AND (expiry IS NULL OR expiry > CURRENT_TIMESTAMP)";
const TAG_QUERY: &'static str = "SELECT name, value, plaintext FROM items_tags WHERE item_id = $1";

impl QueryPrepare for KvPostgres {
    type DB = Postgres;

    fn placeholder(index: i64) -> String {
        format!("${}", index)
    }

    fn limit_query<'q>(
        mut query: String,
        args: &mut QueryParams<'q, Self::DB>,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> String
    where
        i64: for<'e> sqlx::Encode<'e, Self::DB> + sqlx::Type<Self::DB>,
    {
        if offset.is_some() || limit.is_some() {
            let last_idx = (args.len() + 1) as i64;
            args.push(limit);
            args.push(offset.unwrap_or(0));
            let (limit, _next_idx) =
                replace_arg_placeholders::<Self>(" LIMIT $$ OFFSET $$", last_idx);
            query.push_str(&limit);
        }
        query
    }
}

#[derive(Debug)]
struct Lock {
    txn: sqlx::Transaction<'static, Postgres>,
}

#[cfg(feature = "pg_test")]
pub struct TestDB<'t> {
    inst: KvPostgres,
    #[allow(unused)]
    txn: sqlx::Transaction<'t, Postgres>,
}

#[cfg(feature = "pg_test")]
impl std::ops::Deref for TestDB<'_> {
    type Target = KvPostgres;

    fn deref(&self) -> &Self::Target {
        &self.inst
    }
}

pub struct KvPostgres {
    conn_pool: PgPool,
    scans: Arc<Mutex<BTreeMap<ScanToken, Scan>>>,
    locks: Arc<Mutex<BTreeMap<LockToken, Lock>>>,
}

impl KvPostgres {
    pub async fn open(config: &str) -> KvResult<Self> {
        let conn_pool = PgPool::connect(config).await?;
        Ok(Self {
            conn_pool,
            scans: Arc::new(Mutex::new(BTreeMap::new())),
            locks: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    #[cfg(feature = "pg_test")]
    pub async fn open_test<'t>() -> KvResult<TestDB<'t>> {
        let path = match std::env::var("POSTGRES_URL") {
            Ok(p) if !p.is_empty() => p,
            _ => panic!("'POSTGRES_URL' must be defined"),
        };
        let slf = Self::open(path.as_str()).await?;

        // we hold a transaction open with a common advisory lock key.
        // this will block until any existing TestDB instance is dropped
        let mut txn = slf.conn_pool.begin().await?;
        txn.execute("SELECT pg_advisory_xact_lock(99999);").await?;

        slf.conn_pool
            .execute(
                "DROP TABLE IF EXISTS items_tags;
                DROP TABLE IF EXISTS items;",
            )
            .await?;
        Ok(TestDB { inst: slf, txn })
    }
}

#[async_trait]
impl KvProvisionStore for KvPostgres {
    async fn provision(&self) -> KvResult<()> {
        let mut txn = self.conn_pool.begin().await?;
        txn.execute(
            r#"
            CREATE TABLE items(
                id BIGSERIAL,
                key_id INTEGER NOT NULL,
                category BYTEA NOT NULL,
                name BYTEA NOT NULL,
                value BYTEA NOT NULL,
                expiry TIMESTAMP NULL,
                PRIMARY KEY(id)
            );
            CREATE UNIQUE INDEX ux_items_uniq ON items(key_id, category, name);

            CREATE TABLE items_tags(
                item_id BIGINT NOT NULL,
                name BYTEA NOT NULL,
                value BYTEA NOT NULL,
                plaintext INTEGER NOT NULL,
                PRIMARY KEY(name, item_id, plaintext),
                FOREIGN KEY(item_id)
                    REFERENCES items(id)
                    ON DELETE CASCADE
                    ON UPDATE CASCADE
            );
            CREATE INDEX ix_items_tags_item_id ON items_tags(item_id);
            CREATE INDEX ix_items_tags_value ON items_tags(value) WHERE plaintext = 1;
        "#,
        )
        .await?;
        txn.commit().await?;
        Ok(())
    }
}

async fn get_key_id(k: KvKeySelect) -> KeyId {
    1
}

async fn fetch_row_tags(pool: &PgPool, row_id: i64) -> KvResult<Option<Vec<KvTag>>> {
    let tags = sqlx::query(TAG_QUERY)
        .bind(row_id)
        .try_map(|row: PgRow| {
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

#[async_trait]
impl KvStore for KvPostgres {
    type ScanToken = ScanToken;
    type LockToken = LockToken;

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
            .bind(key_id)
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
        offset: Option<i64>,
        max_rows: Option<i64>,
    ) -> KvResult<Self::ScanToken> {
        let pool = self.conn_pool.clone();
        let category = category.to_vec();
        let key_id = get_key_id(client_key).await;
        let scan = try_stream! {
            let mut params = QueryParams::new();
            params.push(key_id);
            params.push(category.clone());
            let query = extend_query::<KvPostgres>(SCAN_QUERY, &mut params, tag_filter, offset, max_rows)?;
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
                    key_id,
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
                sqlx::query("UPDATE items SET value=$1 WHERE id=$2")
                    .bind(row_id)
                    .bind(&entry.value)
                    .execute(&mut txn)
                    .await?;
                sqlx::query("DELETE FROM items_tags WHERE item_id=$1")
                    .bind(row_id)
                    .execute(&mut txn)
                    .await?;
                row_id
            } else {
                sqlx::query_scalar(INSERT_QUERY)
                    .bind(&key_id)
                    .bind(&entry.category)
                    .bind(&entry.name)
                    .bind(&entry.value)
                    .bind(entry.expire_ms.map(expiry_timestamp))
                    .fetch_one(&mut txn)
                    .await?
            };
            if let Some(tags) = entry.tags.as_ref() {
                for tag in tags {
                    let (name, value, plaintext) = match tag {
                        KvTag::Encrypted(name, value) => (name, value, 0),
                        KvTag::Plaintext(name, value) => (name, value, 1),
                    };
                    sqlx::query(
                        "INSERT INTO items_tags(item_id, name, value, plaintext)
                             VALUES($1, $2, $3, $4)",
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
        acquire_timeout_ms: Option<i64>,
    ) -> KvResult<(Option<Self::LockToken>, KvEntry)> {
        let key_id = get_key_id(lock_info.profile_key.clone()).await;

        let mut hasher = DefaultHasher::new();
        Hash::hash(&key_id, &mut hasher);
        Hash::hash_slice(&lock_info.category, &mut hasher);
        Hash::hash_slice(&lock_info.name, &mut hasher);
        let hash = hasher.finish() as i64;

        let mut lock_txn = self.conn_pool.begin().await?;
        if let Some(timeout) = acquire_timeout_ms {
            if timeout > 0 {
                let set_timeout = format!("SET LOCAL lock_timeout = {}", timeout);
                lock_txn.execute(set_timeout.as_str()).await?;
            }
        }

        let lock = match sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(hash)
            .execute(&mut lock_txn)
            .await
        {
            Ok(_) => Some(Lock { txn: lock_txn }),
            // assuming failure due to lock timeout
            Err(_) => {
                drop(lock_txn);
                None
            }
        };
        let locked = Some(if lock.is_some() {
            KvLockStatus::Locked
        } else {
            KvLockStatus::Unlocked
        });

        let mut txn = self.conn_pool.begin().await?;
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
                    locked,
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
                txn.commit().await?;
                KvEntry {
                    key_id: key_id.clone(),
                    category: lock_info.category.clone(),
                    name: lock_info.name.clone(),
                    value: lock_info.value.clone(),
                    tags: lock_info.tags.clone(),
                    locked,
                }
            }
        };

        let token = if let Some(lock) = lock {
            let token = LockToken::next();
            self.locks.lock().await.insert(token, lock);
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
    use crate::db_utils::replace_arg_placeholders;

    #[test]
    fn postgres_simple_and_convert_args_works() {
        assert_eq!(
            replace_arg_placeholders::<KvPostgres>("This $$ is $$ a $$ string!", 3),
            ("This $3 is $4 a $5 string!".to_string(), 6),
        );
        assert_eq!(
            replace_arg_placeholders::<KvPostgres>("This is a string!", 1),
            ("This is a string!".to_string(), 1),
        );
    }
}
