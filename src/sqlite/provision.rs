use std::borrow::Cow;
use std::str::FromStr;

use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    Row,
};

use super::SqliteStore;
use crate::error::Result;
use crate::future::BoxFuture;
use crate::keys::wrap::WrapKeyReference;
use crate::options::IntoOptions;
use crate::store::{KeyCache, OpenStore, ProvisionStore, ProvisionStoreSpec, Store};

#[derive(Debug)]
pub struct SqliteStoreOptions<'a> {
    path: Cow<'a, str>,
    options: SqlitePoolOptions,
}

impl<'a> SqliteStoreOptions<'a> {
    pub fn new<O>(options: O) -> Result<Self>
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

    async fn provision(self, spec: ProvisionStoreSpec) -> Result<Store<SqliteStore>> {
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

    async fn open(self, pass_key: Option<&str>) -> Result<Store<SqliteStore>> {
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

    pub fn in_memory() -> Self {
        Self::new(":memory:").unwrap()
    }
}

impl<'a> OpenStore<'a> for SqliteStoreOptions<'a> {
    fn open_store(self, pass_key: Option<&'a str>) -> BoxFuture<'a, Result<Store<SqliteStore>>> {
        Box::pin(async move { self.open(pass_key).await })
    }
}

impl<'a> ProvisionStore<'a> for SqliteStoreOptions<'a> {
    type Store = Store<SqliteStore>;

    fn provision_store(
        self,
        spec: ProvisionStoreSpec,
    ) -> BoxFuture<'a, Result<Store<SqliteStore>>> {
        Box::pin(async move { self.provision(spec).await })
    }
}
