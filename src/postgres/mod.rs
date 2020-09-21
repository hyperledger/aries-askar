use std::borrow::Cow;
use std::time::Duration;

use async_stream::try_stream;
use async_trait::async_trait;

use futures_lite::stream::StreamExt;

use sqlx::{
    postgres::{PgPool, PgPoolOptions, PgRow, Postgres},
    Executor, Row, Transaction,
};

use super::db_utils::{
    encode_tag_filter, expiry_timestamp, extend_query, hash_lock_info, prepare_update,
    replace_arg_placeholders, PreparedUpdate, QueryParams, QueryPrepare, PAGE_SIZE,
};
use super::error::Result as KvResult;
use super::keys::{store_key::StoreKey, AsyncEncryptor};
use super::options::IntoOptions;
use super::store::{EntryLock, EntryScan, KeyCache, ProvisionStore, ProvisionStoreSpec, Store};
use super::types::{
    EncEntryTag, Entry, EntryFetchOptions, EntryTag, KeyId, ProfileId, UpdateEntry,
};
use super::wql;

const COUNT_QUERY: &'static str = "SELECT COUNT(*) FROM items i
    WHERE store_key_id = $1 AND category = $2
    AND (expiry IS NULL OR expiry > CURRENT_TIMESTAMP)";
const DELETE_QUERY: &'static str = "DELETE FROM items
    WHERE store_key_id = $1 AND category = $2 AND name = $3";
const FETCH_QUERY: &'static str = "SELECT id, value FROM items i
    WHERE store_key_id = $1 AND category = $2 AND name = $3
    AND (expiry IS NULL OR expiry > CURRENT_TIMESTAMP)";
const INSERT_QUERY: &'static str = "INSERT INTO items(store_key_id, category, name, value, expiry)
    VALUES($1, $2, $3, $4, $5) RETURNING id";
const SCAN_QUERY: &'static str = "SELECT id, name, value FROM items i WHERE store_key_id = $1
    AND category = $2 AND (expiry IS NULL OR expiry > CURRENT_TIMESTAMP)";
const TAG_QUERY: &'static str = "SELECT name, value, plaintext FROM items_tags WHERE item_id = $1";
const TAG_INSERT_QUERY: &'static str = "INSERT INTO items_tags(item_id, name, value, plaintext)
    VALUES($1, $2, $3, $4)";

#[derive(Debug)]
pub struct PostgresStoreOptions {
    uri: String,
    admin_uri: Option<String>,
}

impl PostgresStoreOptions {
    pub fn new<'a, O>(options: O) -> KvResult<Self>
    where
        O: IntoOptions<'a>,
    {
        let mut opts = options.into_options()?;
        let admin_user = opts.query.remove("admin_username");
        let admin_pass = opts.query.remove("admin_password");
        let uri = opts.clone().into_uri();
        let admin_uri = if admin_user.is_some() || admin_pass.is_some() {
            if let Some(admin_user) = admin_user {
                opts.user = Cow::Owned(admin_user);
            }
            if let Some(admin_pass) = admin_pass {
                opts.password = Cow::Owned(admin_pass);
            }
            Some(opts.into_uri())
        } else {
            None
        };
        Ok(Self { uri, admin_uri })
    }
}

#[async_trait]
impl ProvisionStore for PostgresStoreOptions {
    type Store = PostgresStore;

    async fn provision_store(self, spec: ProvisionStoreSpec) -> KvResult<Self::Store> {
        let mut conn_pool = PgPoolOptions::default()
            .connect_timeout(Duration::from_secs(10))
            .min_connections(1)
            .max_connections(10)
            .test_before_acquire(false)
            .connect(
                self.admin_uri
                    .as_ref()
                    .map(String::as_str)
                    .unwrap_or_else(|| self.uri.as_str()),
            )
            .await?;

        let (default_profile, key_cache) = PostgresStore::init_db(&conn_pool, spec, false).await?;

        if self.admin_uri.is_some() {
            conn_pool = PgPool::connect(self.uri.as_str()).await?;
        }

        Ok(PostgresStore::new(conn_pool, default_profile, key_cache))
    }
}

#[derive(Debug)]
struct Lock {
    txn: Transaction<'static, Postgres>,
}

#[cfg(feature = "pg_test")]
pub struct TestDB<'t> {
    inst: PostgresStore,
    #[allow(unused)]
    txn: Transaction<'t, Postgres>,
}

#[cfg(feature = "pg_test")]
impl std::ops::Deref for TestDB<'_> {
    type Target = PostgresStore;

    fn deref(&self) -> &Self::Target {
        &self.inst
    }
}

pub struct PostgresStore {
    conn_pool: PgPool,
    default_profile: ProfileId,
    key_cache: KeyCache,
}

impl QueryPrepare for PostgresStore {
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

impl PostgresStore {
    pub(crate) fn new(conn_pool: PgPool, default_profile: ProfileId, key_cache: KeyCache) -> Self {
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
            unimplemented!()
        }
    }

    #[cfg(feature = "pg_test")]
    pub async fn provision_test_db<'t>() -> KvResult<TestDB<'t>> {
        let path = match std::env::var("POSTGRES_URL") {
            Ok(p) if !p.is_empty() => p,
            _ => panic!("'POSTGRES_URL' must be defined"),
        };
        let conn_pool = PgPool::connect(path.as_str()).await?;

        // we hold a transaction open with a common advisory lock key.
        // this will block until any existing TestDB instance is dropped
        let mut txn = conn_pool.begin().await?;
        txn.execute("SELECT pg_advisory_xact_lock(99999);").await?;

        let spec = ProvisionStoreSpec::create_default().await?;
        let (default_profile, key_cache) = PostgresStore::init_db(&conn_pool, spec, true).await?;
        let inst = Self::new(conn_pool, default_profile, key_cache);

        Ok(TestDB { inst, txn })
    }

    pub(crate) async fn init_db(
        conn_pool: &PgPool,
        spec: ProvisionStoreSpec,
        reset: bool,
    ) -> KvResult<(ProfileId, KeyCache)> {
        if reset {
            conn_pool
                .execute(
                    "
                    DROP TABLE IF EXISTS
                      config, profiles,
                      store_keys, keys,
                      items, items_tags;
                    ",
                )
                .await?;
        }

        let mut txn = conn_pool.begin().await?;
        txn.execute(
            "
            CREATE TABLE config (
                name TEXT NOT NULL,
                value TEXT,
                PRIMARY KEY(name)
            );

            CREATE TABLE profiles (
                id BIGSERIAL,
                active_key_id BIGINT NULL,
                name TEXT NOT NULL,
                reference TEXT NULL,
                PRIMARY KEY(id)
            );
            CREATE UNIQUE INDEX ix_profile_name ON profiles(name);

            CREATE TABLE store_keys (
                id BIGSERIAL,
                profile_id BIGINT NOT NULL,
                value BYTEA NULL,
                PRIMARY KEY(id),
                FOREIGN KEY(profile_id) REFERENCES profiles(id)
                    ON DELETE CASCADE ON UPDATE CASCADE
            );

            ALTER TABLE profiles ADD FOREIGN KEY(active_key_id)
                REFERENCES store_keys(id) ON DELETE SET NULL ON UPDATE CASCADE;

            CREATE TABLE keys (
                id BIGSERIAL,
                store_key_id BIGINT NOT NULL,
                category BYTEA NOT NULL,
                name BYTEA NOT NULL,
                reference TEXT NULL,
                value BYTEA NULL,
                PRIMARY KEY(id),
                FOREIGN KEY(store_key_id) REFERENCES store_keys(id)
                    ON DELETE CASCADE ON UPDATE CASCADE
            );
            CREATE UNIQUE INDEX ix_keys_uniq ON keys(store_key_id, category, name);

            CREATE TABLE items (
                id BIGSERIAL,
                store_key_id BIGINT NOT NULL,
                category BYTEA NOT NULL,
                name BYTEA NOT NULL,
                value BYTEA NOT NULL,
                expiry TIMESTAMP NULL,
                PRIMARY KEY(id),
                FOREIGN KEY(store_key_id) REFERENCES store_keys(id)
                    ON DELETE CASCADE ON UPDATE CASCADE
            );
            CREATE UNIQUE INDEX ix_items_uniq ON items(store_key_id, category, name);

            CREATE TABLE items_tags (
                item_id BIGINT NOT NULL,
                name BYTEA NOT NULL,
                value BYTEA NOT NULL,
                plaintext SMALLINT NOT NULL,
                PRIMARY KEY(name, item_id, plaintext),
                FOREIGN KEY(item_id) REFERENCES items(id)
                    ON DELETE CASCADE ON UPDATE CASCADE
            );
            CREATE INDEX ix_items_tags_item_id ON items_tags(item_id);
            CREATE INDEX ix_items_tags_value ON items_tags(value) WHERE plaintext = 1;
        ",
        )
        .await?;

        sqlx::query(
            "INSERT INTO config (name, value) VALUES
                ('default_profile', $1),
                ('wrap_key', $2),
                ('version', '1');",
        )
        .persistent(false)
        .bind(&spec.profile_id)
        .bind(spec.wrap_key_ref)
        .execute(&mut txn)
        .await?;

        let ins_profile = sqlx::query(
            "WITH ins AS (INSERT INTO profiles (name) VALUES ($1) RETURNING id AS prof_id)
                INSERT INTO store_keys (profile_id, value) SELECT prof_id, $2 FROM ins
                RETURNING profile_id, id AS key_id",
        )
        .bind(&spec.profile_id)
        .bind(spec.enc_store_key)
        .fetch_one(&mut txn)
        .await?;

        let default_profile: i64 = ins_profile.try_get(0)?;
        let key_id: i64 = ins_profile.try_get(1)?;

        sqlx::query("UPDATE profiles SET active_key_id = $1 WHERE id = $2")
            .persistent(false)
            .bind(key_id)
            .bind(default_profile)
            .execute(&mut txn)
            .await?;

        txn.commit().await?;

        let mut key_cache = KeyCache::new(spec.wrap_key);
        key_cache.set_profile_key(default_profile, key_id, spec.store_key);

        Ok((default_profile, key_cache))
    }
}

async fn fetch_row_tags(
    pool: &PgPool,
    row_id: i64,
    key: AsyncEncryptor<StoreKey>,
) -> KvResult<Option<Vec<EntryTag>>> {
    let tags = sqlx::query(TAG_QUERY)
        .bind(row_id)
        .try_map(|row: PgRow| {
            let name = row.try_get(0)?;
            let value = row.try_get(1)?;
            let plaintext = row.try_get::<i16, _>(2)? != 0;
            Ok(EncEntryTag {
                name,
                value,
                plaintext,
            })
        })
        .fetch_all(pool)
        .await?;
    Ok(if tags.is_empty() {
        None
    } else {
        Some(key.decrypt_entry_tags(tags).await?)
    })
}

#[async_trait]
impl Store for PostgresStore {
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
                fetch_row_tags(&self.conn_pool, row.try_get(0)?, key.clone()).await?
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
        let pool = self.conn_pool.clone();
        let (key_id, key) = self.get_profile_key(profile_id).await?;
        let raw_category = category.clone();
        let category = key.encrypt_entry_category(category).await?;
        let scan = try_stream! {
            let mut params = QueryParams::new();
            params.push(key_id);
            params.push(category.clone());
            let tag_filter = encode_tag_filter::<Self>(tag_filter, key.0.clone(), params.len()).await?;
            let query = extend_query::<Self>(SCAN_QUERY, &mut params, tag_filter, offset, max_rows)?;
            let mut batch = Vec::with_capacity(PAGE_SIZE);
            let mut rows = sqlx::query_with(query.as_str(), params).fetch(&pool);
            while let Some(row) = rows.next().await {
                let row = row?;
                let tags = if options.retrieve_tags {
                    // FIXME - fetch tags in batches, or better as part of the SELECT statement
                    fetch_row_tags(&pool, row.try_get(0)?, key.clone()).await?
                } else {
                    None
                };
                let (name, value) = key.decrypt_entry_name_value(row.try_get(1)?, row.try_get(2)?).await?;
                let entry = Entry {
                    category: raw_category.clone(),
                    name,
                    value,
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
        let mut txn = self.conn_pool.begin().await?;
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

        let mut lock_txn = self.conn_pool.begin().await?;
        if let Some(timeout) = acquire_timeout_ms {
            if timeout > 0 {
                let set_timeout = format!("SET LOCAL lock_timeout = {}", timeout);
                lock_txn.execute(set_timeout.as_str()).await?;
            }
        }

        if let Err(_) = sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(hash)
            .execute(&mut lock_txn)
            .await
        {
            // assuming failure due to lock timeout
            return Err(err_msg!(Timeout, "Timed out waiting for lock"));
        }

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
                    tags: None, // FIXME optionally fetch tags
                }
            }
            None => {
                let row_id: i64 = sqlx::query_scalar(INSERT_QUERY)
                    .bind(&key_id)
                    .bind(enc_entry.category.as_ref())
                    .bind(enc_entry.name.as_ref())
                    .bind(enc_entry.value.as_ref())
                    .bind(expiry)
                    .fetch_one(&mut txn)
                    .await?;
                if let Some(tags) = enc_tags {
                    for tag in tags {
                        sqlx::query(TAG_INSERT_QUERY)
                            .bind(row_id)
                            .bind(&tag.name)
                            .bind(&tag.value)
                            .bind(tag.plaintext as i16)
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
                let txn = perform_update(lock_txn, updates).await?;
                txn.commit().await?;
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
    mut txn: Transaction<'static, Postgres>,
    updates: Vec<PreparedUpdate>,
) -> KvResult<Transaction<'static, Postgres>> {
    for upd in updates {
        let PreparedUpdate {
            key_id,
            enc_entry,
            enc_tags,
            expire_ms,
        } = upd;
        sqlx::query(DELETE_QUERY)
            .bind(key_id)
            .bind(enc_entry.category.as_ref())
            .bind(enc_entry.name.as_ref())
            .execute(&mut txn)
            .await?;

        if expire_ms != Some(0) {
            trace!("Insert entry");
            let row_id: i64 = sqlx::query_scalar(INSERT_QUERY)
                .bind(key_id)
                .bind(enc_entry.category.as_ref())
                .bind(enc_entry.name.as_ref())
                .bind(enc_entry.value.as_ref())
                .bind(expire_ms.map(expiry_timestamp).transpose()?)
                .fetch_one(&mut txn)
                .await?;
            if let Some(tags) = enc_tags {
                for tag in tags {
                    sqlx::query(TAG_INSERT_QUERY)
                        .bind(row_id)
                        .bind(&tag.name)
                        .bind(&tag.value)
                        .bind(tag.plaintext as i16)
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

    #[test]
    fn postgres_simple_and_convert_args_works() {
        assert_eq!(
            replace_arg_placeholders::<PostgresStore>("This $$ is $$ a $$ string!", 3),
            ("This $3 is $4 a $5 string!".to_string(), 6),
        );
        assert_eq!(
            replace_arg_placeholders::<PostgresStore>("This is a string!", 1),
            ("This is a string!".to_string(), 1),
        );
    }

    #[test]
    fn postgres_parse_uri() {
        let uri = "postgres://user:pass@host?admin_username=user2&admin_password=pass2&test=1";
        let opts = PostgresStoreOptions::new(uri).unwrap();
        assert_eq!(opts.uri, "postgres://user:pass@host?test=1");
        assert_eq!(
            opts.admin_uri,
            Some("postgres://user2:pass2@host?test=1".to_owned())
        );
    }
}
