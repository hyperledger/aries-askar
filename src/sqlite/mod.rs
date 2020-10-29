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
    Done, Executor, Row, Transaction,
};

use super::db_utils::{
    encode_tag_filter, expiry_timestamp, extend_query, hash_lock_info, prepare_single_update,
    prepare_update, PreparedUpdate, QueryParams, QueryPrepare, PAGE_SIZE,
};
use super::error::Result as KvResult;
use super::future::{sleep_ms, spawn_ok};
use super::keys::{store::StoreKey, wrap::WrapKeyReference, AsyncEncryptor};
use super::options::IntoOptions;
use super::store::{
    EntryLock, KeyCache, OpenStore, ProvisionStore, ProvisionStoreSpec, RawStore, Scan, Store,
};
use super::types::{
    EncEntryTag, Entry, EntryFetchOptions, EntryKind, EntryTag, Expiry, ProfileId, UpdateEntry,
};
use super::wql;

const LOCK_EXPIRY: i64 = 120000; // 2 minutes
const COUNT_QUERY: &'static str = "SELECT COUNT(*) FROM items i
    WHERE profile_id = ?1 AND kind = ?2 AND category = ?3
    AND (expiry IS NULL OR expiry > datetime('now'))";
const DELETE_QUERY: &'static str = "DELETE FROM items
    WHERE profile_id = ?1 AND kind = ?2 AND category = ?3 AND name = ?4";
const FETCH_QUERY: &'static str = "SELECT id, value FROM items i
    WHERE profile_id = ?1 AND kind = ?2 AND category = ?3 AND name = ?4
    AND (expiry IS NULL OR expiry > datetime('now'))";
const INSERT_QUERY: &'static str =
    "INSERT INTO items (profile_id, kind, category, name, value, expiry)
    VALUES(?1, ?2, ?3, ?4, ?5, ?6)";
const SCAN_QUERY: &'static str = "SELECT id, name, value FROM items i
    WHERE profile_id = ?1 AND kind = ?2 AND category = ?3
    AND (expiry IS NULL OR expiry > datetime('now'))";
const TAG_QUERY: &'static str = "SELECT item_id, name, value, plaintext FROM items_tags";
const TAG_INSERT_QUERY: &'static str = "INSERT INTO items_tags (item_id, name, value, plaintext)
    VALUES(?1, ?2, ?3, ?4)";
const LOCK_INSERT_QUERY: &'static str = "INSERT INTO items_locks (id, expiry) VALUES (?1, ?2)
    ON CONFLICT (id) DO UPDATE SET expiry=excluded.expiry
    WHERE expiry <= datetime('now')";
const LOCK_DELETE_QUERY: &'static str = "DELETE FROM items_locks WHERE id=?1 AND expiry=?2";

struct TagRetriever {
    batch_size: usize,
    query: String,
}

impl TagRetriever {
    pub fn new(query: &str, batch_size: usize) -> Self {
        let mut query = query.to_owned();
        query.push_str(" WHERE item_id IN (");
        query.extend(std::iter::repeat("?").take(batch_size).intersperse(", "));
        query.push(')');
        Self { batch_size, query }
    }

    pub async fn fetch_row_tags<'e, E>(
        exec: E,
        query: &str,
        row_id: i64,
        key: AsyncEncryptor<StoreKey>,
    ) -> KvResult<Vec<EntryTag>>
    where
        E: Executor<'e, Database = Sqlite>,
    {
        let mut query = query.to_owned();
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
            .fetch_all(exec)
            .await?;
        key.decrypt_entry_tags(tags).await
    }

    pub async fn fetch_tags(
        &self,
        pool: &SqlitePool,
        key: &AsyncEncryptor<StoreKey>,
        ids: &[i32],
    ) -> KvResult<BTreeMap<i32, Vec<EntryTag>>> {
        let count = ids.len();
        if count > self.batch_size {
            return Err(err_msg!(
                Unexpected,
                "Number of item IDs exceeds batch size in tag retriever"
            ));
        }
        let mut enc_tags = BTreeMap::new();
        let mut stmt = sqlx::query(&self.query);
        for id in ids {
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
        let mut results = BTreeMap::new();
        for (id, tags) in enc_tags {
            results.insert(id, key.decrypt_entry_tags(tags).await?);
        }
        Ok(results)
    }

    pub async fn populate_tags(
        &self,
        pool: &SqlitePool,
        key: &AsyncEncryptor<StoreKey>,
        rows: &mut Vec<Entry>,
        ids: &[i32],
    ) -> KvResult<()> {
        let mut tags = self.fetch_tags(pool, key, ids).await?;
        for (idx, id) in ids.into_iter().enumerate() {
            if let Some(t) = tags.remove(id) {
                rows[idx].tags.replace(t);
            }
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
impl<'a> OpenStore for SqliteStoreOptions<'a> {
    type Store = Store<SqliteStore>;

    async fn open_store(self, pass_key: Option<&str>) -> KvResult<Self::Store> {
        let conn_opts = SqliteConnectOptions::from_str(self.path.as_ref())?;
        let conn_pool = self.options.connect_with(conn_opts).await?;

        let mut conn = conn_pool.acquire().await?;
        let mut ver_ok = false;
        let mut default_profile: Option<String> = None;
        let mut wrap_key_ref: Option<String> = None;

        let config = sqlx::query(
            r#"SELECT name, value FROM config
            WHERE name IN ("default_profile", "version", "wrap_key")"#,
        )
        .fetch_all(&mut conn)
        .await?;
        for row in config {
            match row.try_get(0)? {
                "default_profile" => {
                    default_profile.replace(row.try_get(1)?);
                }
                "version" => {
                    if row.try_get::<&str, _>(1)? != "1" {
                        return Err(err_msg!(Unsupported, "Unsupported store version"));
                    }
                    ver_ok = true;
                }
                "wrap_key" => {
                    wrap_key_ref.replace(row.try_get(1)?);
                }
                _ => (),
            }
        }
        if !ver_ok {
            return Err(err_msg!(Unsupported, "Store version not found"));
        }
        let default_profile = default_profile
            .ok_or_else(|| err_msg!(Unsupported, "Default store profile not found"))?;
        let wrap_key = if let Some(wrap_key_ref) = wrap_key_ref {
            WrapKeyReference::parse_uri(&wrap_key_ref)?
                .resolve(pass_key)
                .await?
        } else {
            return Err(err_msg!(Unsupported, "Store wrap key not found"));
        };
        let mut key_cache = KeyCache::new(wrap_key);

        let row = sqlx::query("SELECT id, store_key FROM profiles WHERE name = ?1")
            .bind(&default_profile)
            .fetch_one(&mut conn)
            .await?;
        let profile_id = row.try_get(0)?;
        let store_key = key_cache.load_key(row.try_get(1)?).await?;
        key_cache.add_profile(default_profile.clone(), profile_id, store_key);

        Ok(Store::new(SqliteStore::new(
            conn_pool,
            default_profile,
            key_cache,
        )))
    }
}

#[async_trait]
impl<'a> ProvisionStore for SqliteStoreOptions<'a> {
    async fn provision_store(self, spec: ProvisionStoreSpec) -> KvResult<Store<SqliteStore>> {
        let conn_opts = SqliteConnectOptions::from_str(self.path.as_ref())?.create_if_missing(true);
        let conn_pool = self.options.connect_with(conn_opts).await?;
        let mut conn = conn_pool.acquire().await?;

        sqlx::query(
            r#"
            BEGIN EXCLUSIVE TRANSACTION;

            CREATE TABLE config (
                name TEXT NOT NULL,
                value TEXT,
                PRIMARY KEY (name)
            );
            INSERT INTO config (name, value) VALUES
                ("default_profile", ?1),
                ("version", "1"),
                ("wrap_key", ?2);

            CREATE TABLE profiles (
                id INTEGER NOT NULL,
                name TEXT NOT NULL,
                reference TEXT NULL,
                store_key BLOB NULL,
                PRIMARY KEY(id)
            );
            CREATE UNIQUE INDEX ix_profile_name ON profiles (name);

            CREATE TABLE items (
                id INTEGER NOT NULL,
                profile_id INTEGER NOT NULL,
                kind INTEGER NOT NULL,
                category BLOB NOT NULL,
                name BLOB NOT NULL,
                value BLOB NOT NULL,
                expiry DATETIME NULL,
                PRIMARY KEY (id),
                FOREIGN KEY (profile_id) REFERENCES profiles (id)
                    ON DELETE CASCADE ON UPDATE CASCADE
            );
            CREATE UNIQUE INDEX ix_items_uniq ON items (profile_id, kind, category, name);

            CREATE TABLE items_tags (
                item_id INTEGER NOT NULL,
                name BLOB NOT NULL,
                value BLOB NOT NULL,
                plaintext BOOLEAN NOT NULL,
                PRIMARY KEY (name, plaintext, item_id),
                FOREIGN KEY (item_id) REFERENCES items (id)
                    ON DELETE CASCADE ON UPDATE CASCADE
            );
            CREATE INDEX ix_items_tags_item_id ON items_tags (item_id);
            CREATE INDEX ix_items_tags_value ON items_tags (plaintext, SUBSTR(value, 0, 12));

            CREATE TABLE items_locks (
                id INTEGER NOT NULL,
                expiry DATETIME NOT NULL,
                PRIMARY KEY (id)
            );

            INSERT INTO profiles (name, store_key) VALUES (?1, ?3);

            COMMIT;
        "#,
        )
        .persistent(false)
        .bind(&spec.profile_name)
        .bind(spec.wrap_key_ref)
        .bind(spec.enc_store_key)
        .execute(&mut conn)
        .await?;

        let mut key_cache = KeyCache::new(spec.wrap_key);

        let row = sqlx::query("SELECT id FROM profiles WHERE name = ?1")
            .persistent(false)
            .bind(&spec.profile_name)
            .fetch_one(&mut conn)
            .await?;
        key_cache.add_profile(spec.profile_name.clone(), row.try_get(0)?, spec.store_key);

        Ok(Store::new(SqliteStore::new(
            conn_pool,
            spec.profile_name,
            key_cache,
        )))
    }
}

pub struct SqliteStore {
    conn_pool: SqlitePool,
    default_profile: String,
    key_cache: KeyCache,
}

impl SqliteStore {
    pub(crate) fn new(conn_pool: SqlitePool, default_profile: String, key_cache: KeyCache) -> Self {
        Self {
            conn_pool,
            default_profile,
            key_cache,
        }
    }

    async fn get_profile_key(
        &self,
        name: Option<String>,
    ) -> KvResult<(ProfileId, AsyncEncryptor<StoreKey>)> {
        if let Some((pid, key)) = self.key_cache.get_profile(
            name.as_ref()
                .map(String::as_str)
                .unwrap_or(self.default_profile.as_str()),
        ) {
            Ok((pid, AsyncEncryptor(Some(key))))
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
impl RawStore for SqliteStore {
    async fn count(
        &self,
        profile: Option<String>,
        kind: EntryKind,
        category: String,
        tag_filter: Option<wql::Query>,
    ) -> KvResult<i64> {
        let (profile_id, key) = self.get_profile_key(profile).await?;
        let category = key.encrypt_entry_category(category).await?;
        let mut params = QueryParams::new();
        params.push(profile_id);
        params.push(kind as i32);
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
        profile: Option<String>,
        kind: EntryKind,
        category: String,
        name: String,
        options: EntryFetchOptions,
    ) -> KvResult<Option<Entry>> {
        let (profile_id, key) = self.get_profile_key(profile).await?;
        let raw_category = category.clone();
        let raw_name = name.clone();
        let (category, name) = key.encrypt_entry_category_name(category, name).await?;
        if let Some(row) = sqlx::query(FETCH_QUERY)
            .bind(profile_id)
            .bind(kind as i32)
            .bind(category)
            .bind(name)
            .fetch_optional(&self.conn_pool)
            .await?
        {
            let tags = if options.retrieve_tags {
                // FIXME use the same connection to fetch all tags
                Some(
                    TagRetriever::fetch_row_tags(
                        &self.conn_pool,
                        TAG_QUERY,
                        row.try_get(0)?,
                        key.clone(),
                    )
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
        profile: Option<String>,
        kind: EntryKind,
        category: String,
        options: EntryFetchOptions,
        tag_filter: Option<wql::Query>,
        offset: Option<i64>,
        max_rows: Option<i64>,
    ) -> KvResult<Scan<Entry>> {
        let (profile_id, key) = self.get_profile_key(profile).await?;
        let pool = self.conn_pool.clone();

        perform_scan(
            pool,
            profile_id,
            kind,
            key,
            category,
            tag_filter,
            offset,
            max_rows,
            options.retrieve_tags,
        )
        .await
    }

    async fn update(
        &self,
        profile: Option<String>,
        kind: EntryKind,
        entries: Vec<UpdateEntry>,
    ) -> KvResult<()> {
        if entries.is_empty() {
            debug!("Skip update: no entries");
            return Ok(());
        }
        let (profile_id, key) = self.get_profile_key(profile).await?;
        let updates = prepare_update(profile_id, kind, key, entries).await?;
        let mut txn = self.conn_pool.begin().await?; // deferred write txn
        txn = perform_update(txn, updates).await?;
        Ok(txn.commit().await?)
    }

    async fn create_lock(
        &self,
        profile: Option<String>,
        kind: EntryKind,
        lock_info: UpdateEntry,
        acquire_timeout_ms: Option<i64>,
    ) -> KvResult<(Entry, EntryLock)> {
        let (profile_id, key) = self.get_profile_key(profile).await?;
        let category = lock_info.category.clone();
        let name = lock_info.name.clone();
        let value = lock_info.value.clone();
        let tags = lock_info.tags.clone();
        let hash = hash_lock_info(profile_id, kind, category.as_str(), name.as_str());
        let update = prepare_single_update(profile_id, kind, key.clone(), lock_info).await?;

        let interval = 50;
        let expire = acquire_timeout_ms.map(|offs| {
            Instant::now() + Duration::from_millis(std::cmp::max(0, offs - interval) as u64)
        });
        let lock_expiry = loop {
            let lock_expiry = expiry_timestamp(LOCK_EXPIRY)?;
            let upserted = sqlx::query(LOCK_INSERT_QUERY)
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
                        sqlx::query(LOCK_DELETE_QUERY)
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

        let (entry, is_new) = match sqlx::query(FETCH_QUERY)
            .bind(profile_id)
            .bind(kind as i32)
            .bind(&update.enc_category)
            .bind(&update.enc_name)
            .fetch_optional(&mut txn)
            .await?
        {
            Some(row) => {
                let value = key.decrypt_entry_value(row.try_get(1)?).await?;
                let tags =
                    TagRetriever::fetch_row_tags(&mut txn, TAG_QUERY, row.try_get(0)?, key.clone())
                        .await?;
                (
                    Entry {
                        category,
                        name,
                        value,
                        tags: Some(tags),
                    },
                    false,
                )
            }
            None => {
                if update.enc_value.is_none() {
                    sqlx::query(LOCK_DELETE_QUERY)
                        .bind(lock_handle.hash)
                        .bind(lock_handle.expiry)
                        .execute(&mut txn)
                        .await?;
                    return Err(err_msg!(NotFound, "Record not found for lock"));
                }
                let expiry = update.expire_ms.map(expiry_timestamp).transpose()?;
                let row_id = sqlx::query(INSERT_QUERY)
                    .bind(profile_id)
                    .bind(kind as i32)
                    .bind(update.enc_category)
                    .bind(update.enc_name)
                    .bind(update.enc_value.unwrap())
                    .bind(expiry)
                    .execute(&mut txn)
                    .await?
                    .last_insert_rowid();
                if let Some(tags) = update.enc_tags {
                    for tag in tags {
                        sqlx::query(TAG_INSERT_QUERY)
                            .bind(row_id)
                            .bind(tag.name)
                            .bind(tag.value)
                            .bind(tag.plaintext as i32)
                            .execute(&mut txn)
                            .await?;
                    }
                }
                txn.commit().await?;
                (
                    Entry {
                        category,
                        name,
                        value: value.unwrap(),
                        tags,
                    },
                    true,
                )
            }
        };

        Ok((
            entry,
            EntryLock::new(is_new, move |entries| async move {
                if entries.is_empty() {
                    debug!("Skip update: no entries");
                    return Ok(());
                }
                let updates = prepare_update(profile_id, kind, key, entries).await?;
                let mut txn = lock_handle.pool.as_ref().unwrap().begin().await?; // deferred write txn
                txn = perform_update(txn, updates).await?;
                if sqlx::query(LOCK_DELETE_QUERY)
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

async fn perform_scan(
    pool: SqlitePool,
    profile_id: ProfileId,
    kind: EntryKind,
    key: AsyncEncryptor<StoreKey>,
    category: String,
    tag_filter: Option<wql::Query>,
    offset: Option<i64>,
    max_rows: Option<i64>,
    retrieve_tags: bool,
) -> KvResult<Scan<Entry>> {
    let raw_category = category.clone();
    let category = key.encrypt_entry_category(category).await?;

    let scan = try_stream! {
        let mut params = QueryParams::new();
        params.push(profile_id);
        params.push(kind as i32);
        params.push(category.clone());
        let tag_filter = encode_tag_filter::<SqliteStore>(tag_filter, key.0.clone(), params.len()).await?;
        let query = extend_query::<SqliteStore>(SCAN_QUERY, &mut params, tag_filter, offset, max_rows)?;
        let mut batch = Vec::<Entry>::with_capacity(PAGE_SIZE);
        let mut ids = Vec::<i32>::with_capacity(PAGE_SIZE);
        let mut tag_retriever = if retrieve_tags {
            Some(TagRetriever::new(TAG_QUERY, PAGE_SIZE))
        } else {
            None
        };

        let mut rows = sqlx::query_with(query.as_str(), params).fetch(&pool);
        while let Some(row) = rows.next().await {
            let row = row?;
            let row_id = row.try_get(0)?;
            let (name, value) = key.decrypt_entry_name_value(row.try_get(1)?, row.try_get(2)?).await?;
            batch.push(Entry {
                category: raw_category.clone(),
                name,
                value,
            tags: None});
            ids.push(row_id);

            if batch.len() == PAGE_SIZE {
                if let Some(retr) = tag_retriever.as_mut() {
                    retr.populate_tags(&pool, &key, &mut batch, ids.as_slice()).await?;
                }
                yield batch.split_off(0);
                ids.clear();
            }
        }
        drop(rows);

        if batch.len() > 0 {
            if let Some(retr) = tag_retriever.as_mut() {
                retr.populate_tags(&pool, &key, &mut batch, ids.as_slice()).await?;
            }
            yield batch;
        }
        drop(query);
    };
    Ok(Scan::new(scan, PAGE_SIZE))
}

async fn perform_update(
    mut txn: Transaction<'static, Sqlite>,
    updates: Vec<PreparedUpdate>,
) -> KvResult<Transaction<'static, Sqlite>> {
    for upd in updates {
        let PreparedUpdate {
            profile_id,
            kind,
            enc_category,
            enc_name,
            enc_value,
            enc_tags,
            expire_ms,
        } = upd;
        sqlx::query(DELETE_QUERY)
            .bind(profile_id)
            .bind(kind as i32)
            .bind(&enc_category)
            .bind(&enc_name)
            .execute(&mut txn)
            .await?;

        if let Some(enc_value) = enc_value {
            trace!("Insert entry");
            let row_id = sqlx::query(INSERT_QUERY)
                .bind(profile_id)
                .bind(kind as i32)
                .bind(enc_category)
                .bind(enc_name)
                .bind(enc_value)
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
                .fetch_one(&db.inner.conn_pool)
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
    fn sqlite_query_placeholders() {
        assert_eq!(
            &replace_arg_placeholders::<SqliteStore>("This $$ is $10 a $$ string!", 3),
            "This ?3 is ?12 a ?5 string!",
        );
        assert_eq!(
            &replace_arg_placeholders::<SqliteStore>("This $a is a string!", 1),
            "This $a is a string!",
        );
    }
}
