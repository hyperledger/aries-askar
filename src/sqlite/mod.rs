use std::borrow::Cow;
use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::{Duration, Instant};

use async_stream::try_stream;
use async_trait::async_trait;
use futures_lite::stream::StreamExt;
use itertools::Itertools;

use sqlx::{
    sqlite::{Sqlite, SqliteConnectOptions, SqlitePool, SqlitePoolOptions, SqliteRow},
    Done, Row, Transaction,
};

use super::db_utils::{
    encode_tag_filter, expiry_timestamp, extend_query, hash_lock_info, prepare_update,
    PreparedUpdate, QueryParams, QueryPrepare, PAGE_SIZE,
};
use super::error::Result as KvResult;
use super::future::{sleep_ms, spawn_ok};
use super::keys::{store::StoreKey, AsyncEncryptor};
use super::options::IntoOptions;
use super::store::{EntryLock, EntryScan, KeyCache, ProvisionStore, ProvisionStoreSpec, Store};
use super::types::{
    EncEntryTag, Entry, EntryFetchOptions, EntryTag, Expiry, KeyId, ProfileId, UpdateEntry,
};
use super::wql;

const LOCK_EXPIRY: i64 = 120000; // 2 minutes
const COUNT_QUERY: &'static str = "SELECT COUNT(*) FROM items i
    WHERE store_key_id = ?1 AND category = ?2
    AND (expiry IS NULL OR expiry > datetime('now'))";
const DELETE_QUERY: &'static str = "DELETE FROM items
    WHERE store_key_id = ?1 AND category = ?2 AND name = ?3";
const FETCH_QUERY: &'static str = "SELECT id, value FROM items i
    WHERE store_key_id = ?1 AND category = ?2 AND name = ?3
    AND (expiry IS NULL OR expiry > datetime('now'))";
const INSERT_QUERY: &'static str = "INSERT INTO items(store_key_id, category, name, value, expiry)
    VALUES(?1, ?2, ?3, ?4, ?5)";
const SCAN_QUERY: &'static str = "SELECT id, name, value FROM items i WHERE store_key_id = ?1
    AND category = ?2 AND (expiry IS NULL OR expiry > datetime('now'))";
const TAG_QUERY: &'static str = "SELECT item_id, name, value, plaintext FROM items_tags";
const TAG_INSERT_QUERY: &'static str = "INSERT INTO items_tags(item_id, name, value, plaintext)
    VALUES(?1, ?2, ?3, ?4)";

struct TagRetriever {
    batch_size: usize,
    query: String,
}

impl TagRetriever {
    pub fn new(batch_size: usize) -> Self {
        let mut query = TAG_QUERY.to_owned();
        query.push_str(" WHERE item_id IN (");
        query.extend(std::iter::repeat("?").take(batch_size).intersperse(", "));
        query.push(')');
        Self { batch_size, query }
    }

    pub async fn fetch_row_tags(
        pool: &SqlitePool,
        row_id: i64,
        key: AsyncEncryptor<StoreKey>,
    ) -> KvResult<Vec<EntryTag>> {
        let mut query = TAG_QUERY.to_owned();
        query.push_str(" WHERE item_id=?1");
        let tags = sqlx::query(&query)
            .bind(row_id)
            .try_map(|row: SqliteRow| {
                Ok(EncEntryTag {
                    name: row.try_get(1)?,
                    value: row.try_get(2)?,
                    plaintext: row.try_get::<i32, _>(3)? != 0,
                })
            })
            .fetch_all(pool)
            .await?;
        key.decrypt_entry_tags(tags).await
    }

    pub async fn fetch_tags(
        &mut self,
        pool: &SqlitePool,
        key: &AsyncEncryptor<StoreKey>,
        results: &mut BTreeMap<i32, Entry>,
    ) -> KvResult<()> {
        let count = results.len();
        if count > self.batch_size {
            return Err(err_msg!(
                Unexpected,
                "Number of item ids exceeds batch size in tag retriever"
            ));
        }
        let mut enc_tags = BTreeMap::new();
        let mut stmt = sqlx::query(&self.query);
        for id in results.keys() {
            enc_tags.insert(*id, vec![]);
            stmt = stmt.bind(*id);
        }
        for _ in count..self.batch_size {
            stmt = stmt.bind(0i32);
        }
        let mut scan = stmt.fetch(pool);
        while let Some(tag_row) = scan.next().await {
            let tag_row = tag_row?;
            let row_id = tag_row.try_get(0)?;
            let entry = enc_tags
                .get_mut(&row_id)
                .ok_or_else(|| err_msg!(Unexpected, "Unexpected result for tag query"))?;
            entry.push(EncEntryTag {
                name: tag_row.try_get(1)?,
                value: tag_row.try_get(2)?,
                plaintext: tag_row.try_get::<i32, _>(3)? != 0,
            });
        }
        for (id, tags) in enc_tags {
            results
                .get_mut(&id)
                .unwrap()
                .tags
                .replace(key.decrypt_entry_tags(tags).await?);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct SqliteStoreOptions<'a> {
    path: Cow<'a, str>,
    options: SqlitePoolOptions,
}

impl<'a> SqliteStoreOptions<'a> {
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
                .max_connections(10), // FIXME - default to num_cpus?
        })
    }

    pub fn in_memory() -> Self {
        Self::new(":memory:").unwrap()
    }
}

#[async_trait]
impl<'a> ProvisionStore for SqliteStoreOptions<'a> {
    type Store = SqliteStore;

    async fn provision_store(self, spec: ProvisionStoreSpec) -> KvResult<Self::Store> {
        let conn_opts = SqliteConnectOptions::from_str(self.path.as_ref())?.create_if_missing(true);
        let conn_pool = self.options.connect_with(conn_opts).await?;
        let mut conn = conn_pool.acquire().await?;

        sqlx::query(
            r#"
            BEGIN EXCLUSIVE TRANSACTION;

            CREATE TABLE config (
                name TEXT NOT NULL,
                value TEXT,
                PRIMARY KEY(name)
            );
            INSERT INTO config (name, value) VALUES
                ("default_profile", ?1),
                ("wrap_key", ?2),
                ("version", "1");

            CREATE TABLE profiles (
                id INTEGER NOT NULL,
                active_key_id INTEGER NULL,
                name TEXT NOT NULL,
                reference TEXT NULL,
                PRIMARY KEY(id),
                FOREIGN KEY(active_key_id) REFERENCES store_keys(id)
                    ON DELETE SET NULL ON UPDATE CASCADE
            );
            CREATE UNIQUE INDEX ix_profile_name ON profiles(name);

            CREATE TABLE store_keys (
                id INTEGER NOT NULL,
                profile_id INTEGER NOT NULL,
                value BLOB NULL,
                PRIMARY KEY(id),
                FOREIGN KEY(profile_id) REFERENCES profiles(id)
                    ON DELETE CASCADE ON UPDATE CASCADE
            );

            CREATE TABLE keys (
                id INTEGER NOT NULL,
                store_key_id INTEGER NOT NULL,
                category NOT NULL,
                name NOT NULL,
                reference TEXT NULL,
                value BLOB NULL,
                PRIMARY KEY(id),
                FOREIGN KEY(store_key_id) REFERENCES store_keys(id)
                    ON DELETE CASCADE ON UPDATE CASCADE
            );
            CREATE UNIQUE INDEX ix_keys_uniq ON keys(store_key_id, category, name);

            CREATE TABLE items (
                id INTEGER NOT NULL,
                store_key_id INTEGER NOT NULL,
                category NOT NULL,
                name NOT NULL,
                value NOT NULL,
                expiry DATETIME NULL,
                PRIMARY KEY(id),
                FOREIGN KEY(store_key_id) REFERENCES store_keys(id)
                    ON DELETE CASCADE ON UPDATE CASCADE
            );
            CREATE UNIQUE INDEX ix_items_uniq ON items(store_key_id, category, name);

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

            INSERT INTO profiles (name) VALUES (?1);
            INSERT INTO store_keys (profile_id, value) VALUES (last_insert_rowid(), ?3);
            UPDATE profiles SET active_key_id = last_insert_rowid();

            COMMIT;
        "#,
        )
        .persistent(false)
        .bind(&spec.profile_id)
        .bind(spec.wrap_key_ref)
        .bind(spec.enc_store_key)
        .execute(&mut conn)
        .await?;

        let row = sqlx::query(
            r#"SELECT id, active_key_id FROM profiles WHERE name = ?1
        "#,
        )
        .persistent(false)
        .bind(spec.profile_id)
        .fetch_one(&mut conn)
        .await?;
        let default_profile = row.try_get(0)?;
        let key_id: i64 = row.try_get(1)?;
        let mut key_cache = KeyCache::new(spec.wrap_key);
        key_cache.set_profile_key(default_profile, key_id, spec.store_key);

        Ok(SqliteStore::new(conn_pool, default_profile, key_cache))
    }
}

pub struct SqliteStore {
    conn_pool: SqlitePool,
    default_profile: ProfileId,
    key_cache: KeyCache,
}

impl SqliteStore {
    pub(crate) fn new(
        conn_pool: SqlitePool,
        default_profile: ProfileId,
        key_cache: KeyCache,
    ) -> Self {
        Self {
            conn_pool,
            default_profile,
            key_cache,
        }
    }

    async fn get_profile_key(
        &self,
        pid: Option<ProfileId>,
    ) -> KvResult<(KeyId, AsyncEncryptor<StoreKey>)> {
        if let Some((kid, key)) = self
            .key_cache
            .get_profile_key(pid.unwrap_or(self.default_profile))
        {
            Ok((kid, AsyncEncryptor(key)))
        } else {
            // FIXME fetch from database
            unimplemented!()
        }
    }
}

impl QueryPrepare for SqliteStore {
    type DB = Sqlite;
}

#[async_trait]
impl Store for SqliteStore {
    async fn count(
        &self,
        profile_id: Option<ProfileId>,
        category: String,
        tag_filter: Option<wql::Query>,
    ) -> KvResult<i64> {
        let (key_id, key) = self.get_profile_key(profile_id).await?;
        let category = key.encrypt_entry_category(category).await?;
        let mut params = QueryParams::new();
        params.push(key_id);
        params.push(category);
        let tag_filter = encode_tag_filter::<Self>(tag_filter, key.0.clone(), params.len()).await?;
        let query = extend_query::<Self>(COUNT_QUERY, &mut params, tag_filter, None, None)?;
        let count = sqlx::query_scalar_with(query.as_str(), params)
            .fetch_one(&self.conn_pool)
            .await?;
        KvResult::Ok(count)
    }

    async fn fetch(
        &self,
        profile_id: Option<ProfileId>,
        category: String,
        name: String,
        options: EntryFetchOptions,
    ) -> KvResult<Option<Entry>> {
        let (key_id, key) = self.get_profile_key(profile_id).await?;
        let raw_category = category.clone();
        let raw_name = name.clone();
        let (category, name) = key.encrypt_entry_category_name(category, name).await?;
        if let Some(row) = sqlx::query(FETCH_QUERY)
            .bind(key_id)
            .bind(&category)
            .bind(&name)
            .fetch_optional(&self.conn_pool)
            .await?
        {
            let tags = if options.retrieve_tags {
                // FIXME use the same connection to fetch all tags
                Some(
                    TagRetriever::fetch_row_tags(&self.conn_pool, row.try_get(0)?, key.clone())
                        .await?,
                )
            } else {
                None
            };
            let value = key.decrypt_entry_value(row.try_get(1)?).await?;
            Ok(Some(Entry {
                category: raw_category,
                name: raw_name,
                value,
                tags,
            }))
        } else {
            Ok(None)
        }
    }

    async fn scan(
        &self,
        profile_id: Option<ProfileId>,
        category: String,
        options: EntryFetchOptions,
        tag_filter: Option<wql::Query>,
        offset: Option<i64>,
        max_rows: Option<i64>,
    ) -> KvResult<EntryScan> {
        let (key_id, key) = self.get_profile_key(profile_id).await?;
        let pool = self.conn_pool.clone();
        let raw_category = category.clone();
        let category = key.encrypt_entry_category(category).await?;

        let scan = try_stream! {
            let mut params = QueryParams::new();
            params.push(key_id.clone());
            params.push(category.clone());
            let tag_filter = encode_tag_filter::<Self>(tag_filter, key.0.clone(), params.len()).await?;
            let query = extend_query::<Self>(SCAN_QUERY, &mut params, tag_filter, offset, max_rows)?;
            let mut batch = BTreeMap::<i32, Entry>::new();
            let mut tag_retriever = if options.retrieve_tags {
                Some(TagRetriever::new(PAGE_SIZE))
            } else {
                None
            };

            let mut rows = sqlx::query_with(query.as_str(), params).fetch(&pool);
            while let Some(row) = rows.next().await {
                let row = row?;
                let row_id = row.try_get(0)?;
                let (name, value) = key.decrypt_entry_name_value(row.try_get(1)?, row.try_get(2)?).await?;
                batch.insert(row_id, Entry {
                    category: raw_category.clone(),
                    name,
                    value,
                    tags: None,
                });

                if batch.len() == PAGE_SIZE {
                    if let Some(retr) = tag_retriever.as_mut() {
                        retr.fetch_tags(&pool, &key, &mut batch).await?;
                    }
                    yield batch.into_iter().map(|(_, v)| v).collect();
                    batch = BTreeMap::new();
                }
            }
            drop(rows);

            if batch.len() > 0 {
                if let Some(retr) = tag_retriever.as_mut() {
                    retr.fetch_tags(&pool, &key, &mut batch).await?;
                }
                yield batch.into_iter().map(|(_, v)| v).collect();
            }
            drop(query);
        };
        Ok(EntryScan::new(scan, PAGE_SIZE))
    }

    async fn update(
        &self,
        profile_id: Option<ProfileId>,
        entries: Vec<UpdateEntry>,
    ) -> KvResult<()> {
        if entries.is_empty() {
            debug!("Skip update: no entries");
            return Ok(());
        }
        let (key_id, key) = self.get_profile_key(profile_id).await?;
        let updates = prepare_update(key_id, key, entries).await?;
        let mut txn = self.conn_pool.begin().await?; // deferred write txn
        txn = perform_update(txn, updates).await?;
        Ok(txn.commit().await?)
    }

    async fn create_lock(
        &self,
        profile_id: Option<ProfileId>,
        lock_info: UpdateEntry,
        acquire_timeout_ms: Option<i64>,
    ) -> KvResult<(Entry, EntryLock)> {
        let (key_id, key) = self.get_profile_key(profile_id).await?;
        let raw_entry = lock_info.entry.clone();
        let hash = hash_lock_info(key_id, &lock_info);
        let (enc_entry, enc_tags) = key.encrypt_entry(lock_info.entry).await?;
        let expiry = lock_info.expire_ms.map(expiry_timestamp).transpose()?;

        let interval = 50;
        let expire = acquire_timeout_ms.map(|offs| {
            Instant::now() + Duration::from_millis(std::cmp::max(0, offs - interval) as u64)
        });
        let lock_expiry = loop {
            let lock_expiry = expiry_timestamp(LOCK_EXPIRY)?;
            let upserted = sqlx::query(
                "INSERT INTO items_locks (id, expiry) VALUES (?1, ?2)
                ON CONFLICT (id) DO UPDATE SET expiry=excluded.expiry
                WHERE expiry <= datetime('now')",
            )
            .bind(hash)
            .bind(lock_expiry)
            .execute(&self.conn_pool)
            .await?
            .rows_affected();
            if upserted > 0 {
                break lock_expiry;
            }
            if expire
                .map(|exp| Instant::now().checked_duration_since(exp).is_some())
                .unwrap_or(false)
            {
                return Err(err_msg!(Timeout, "Timed out waiting for lock"));
            }
            sleep_ms(interval as u64).await;
        };

        struct LockHandle {
            expiry: Expiry,
            hash: i64,
            pool: Option<SqlitePool>,
        };

        impl Drop for LockHandle {
            fn drop(&mut self) {
                if let Some(pool) = self.pool.take() {
                    let (hash, expiry) = (self.hash, self.expiry);
                    spawn_ok(async move {
                        sqlx::query("DELETE FROM items_locks WHERE id=?1 AND expiry=?2")
                            .bind(hash)
                            .bind(expiry)
                            .execute(&pool)
                            .await
                            .ok();
                    })
                }
            }
        }

        let mut lock_handle = LockHandle {
            expiry: lock_expiry,
            hash,
            pool: Some(self.conn_pool.clone()),
        };

        let mut txn = self.conn_pool.begin().await?;

        let entry = match sqlx::query(FETCH_QUERY)
            .bind(&key_id)
            .bind(enc_entry.category.as_ref())
            .bind(enc_entry.name.as_ref())
            .fetch_optional(&mut txn)
            .await?
        {
            Some(row) => {
                let value = key.decrypt_entry_value(row.try_get(1)?).await?;
                Entry {
                    category: raw_entry.category.clone(),
                    name: raw_entry.name.clone(),
                    value,
                    tags: None, // FIXME fetch tags
                }
            }
            None => {
                let row_id = sqlx::query(INSERT_QUERY)
                    .bind(&key_id)
                    .bind(enc_entry.category.as_ref())
                    .bind(enc_entry.name.as_ref())
                    .bind(enc_entry.value.as_ref())
                    .bind(expiry)
                    .execute(&mut txn)
                    .await?
                    .last_insert_rowid();
                if let Some(tags) = enc_tags {
                    for tag in tags {
                        sqlx::query(TAG_INSERT_QUERY)
                            .bind(row_id)
                            .bind(&tag.name)
                            .bind(&tag.value)
                            .bind(tag.plaintext as i32)
                            .execute(&mut txn)
                            .await?;
                    }
                }
                txn.commit().await?;
                raw_entry
            }
        };

        Ok((
            entry,
            EntryLock::new(move |entries| async move {
                if entries.is_empty() {
                    debug!("Skip update: no entries");
                    return Ok(());
                }
                let updates = prepare_update(key_id, key, entries).await?;
                let mut txn = lock_handle.pool.as_ref().unwrap().begin().await?; // deferred write txn
                txn = perform_update(txn, updates).await?;
                if sqlx::query("DELETE FROM items_locks WHERE id=?1 AND expiry=?2")
                    .bind(lock_handle.hash)
                    .bind(lock_handle.expiry)
                    .execute(&mut txn)
                    .await?
                    .rows_affected()
                    != 1
                {
                    return Err(err_msg!(Lock, "Lock expired"));
                }
                txn.commit().await?;
                lock_handle.pool.take(); // cancel drop
                Ok(())
            }),
        ))
    }

    async fn close(&self) -> KvResult<()> {
        self.conn_pool.close().await;
        Ok(())
    }
}

async fn perform_update(
    mut txn: Transaction<'static, Sqlite>,
    updates: Vec<PreparedUpdate>,
) -> KvResult<Transaction<'static, Sqlite>> {
    for upd in updates {
        let PreparedUpdate {
            key_id,
            enc_entry,
            enc_tags,
            expire_ms,
        } = upd;
        sqlx::query(DELETE_QUERY)
            .bind(&key_id)
            .bind(enc_entry.category.as_ref())
            .bind(enc_entry.name.as_ref())
            .execute(&mut txn)
            .await?;

        if expire_ms != Some(0) {
            trace!("Insert entry");
            let row_id = sqlx::query(INSERT_QUERY)
                .bind(&key_id)
                .bind(enc_entry.category.as_ref())
                .bind(enc_entry.name.as_ref())
                .bind(enc_entry.value.as_ref())
                .bind(expire_ms.map(expiry_timestamp).transpose()?)
                .execute(&mut txn)
                .await?
                .last_insert_rowid();
            if let Some(tags) = enc_tags {
                for tag in tags {
                    sqlx::query(TAG_INSERT_QUERY)
                        .bind(row_id)
                        .bind(&tag.name)
                        .bind(&tag.value)
                        .bind(tag.plaintext as i32)
                        .execute(&mut txn)
                        .await?;
                }
            }
        }
    }
    Ok(txn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db_utils::replace_arg_placeholders;
    use crate::future::block_on;

    #[test]
    fn sqlite_check_expiry_timestamp() {
        block_on(async {
            let spec = ProvisionStoreSpec::create_default().await?;
            let db = SqliteStoreOptions::in_memory()
                .provision_store(spec)
                .await?;
            let ts = expiry_timestamp(LOCK_EXPIRY).unwrap();
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
            replace_arg_placeholders::<SqliteStore>("This $$ is $$ a $$ string!", 3),
            ("This ?3 is ?4 a ?5 string!".to_string(), 6),
        );
        assert_eq!(
            replace_arg_placeholders::<SqliteStore>("This is a string!", 1),
            ("This is a string!".to_string(), 1),
        );
    }
}
