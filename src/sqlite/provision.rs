use std::borrow::Cow;
use std::fs::remove_file;
use std::io::ErrorKind as IoErrorKind;
use std::str::FromStr;

use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions},
    Row,
};

use super::SqliteStore;
use crate::db_utils::{init_keys, random_profile_name};
use crate::error::Result;
use crate::future::{unblock_scoped, BoxFuture};
use crate::keys::{
    wrap::{WrapKeyMethod, WrapKeyReference},
    KeyCache, PassKey,
};
use crate::options::IntoOptions;
use crate::store::{ManageBackend, Store};

#[derive(Debug)]
pub struct SqliteStoreOptions<'a> {
    pub(crate) in_memory: bool,
    pub(crate) path: Cow<'a, str>,
    pub(crate) options: SqlitePoolOptions,
}

impl<'a> SqliteStoreOptions<'a> {
    pub fn new<O>(options: O) -> Result<Self>
    where
        O: IntoOptions<'a>,
    {
        let opts = options.into_options()?;
        Ok(Self {
            in_memory: opts.host == ":memory:",
            path: opts.host,
            options: SqlitePoolOptions::default()
                // must maintain at least 1 connection to avoid dropping in-memory database
                .min_connections(1)
                .max_connections(10), // FIXME - default to num_cpus?
        })
    }

    pub async fn provision(
        self,
        method: WrapKeyMethod,
        pass_key: PassKey<'a>,
        profile: Option<&'a str>,
        recreate: bool,
    ) -> Result<Store<SqliteStore>> {
        if recreate && !self.in_memory {
            try_remove_file(self.path.as_ref()).await?;
        }

        let conn_opts = SqliteConnectOptions::from_str(self.path.as_ref())?.create_if_missing(true);
        let conn_pool = self.options.connect_with(conn_opts).await?;

        if !recreate {
            if sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='config'",
            )
            .fetch_one(&conn_pool)
            .await?
                == 1
            {
                return open_db(
                    conn_pool,
                    Some(method),
                    pass_key,
                    profile,
                    self.path.to_string(),
                )
                .await;
            }
            // no 'config' table, assume empty database
        }

        let default_profile = profile
            .map(str::to_string)
            .unwrap_or_else(random_profile_name);
        let key_cache = init_db(&conn_pool, &default_profile, method, pass_key).await?;

        Ok(Store::new(SqliteStore::new(
            conn_pool,
            default_profile,
            key_cache,
            self.path.to_string(),
        )))
    }

    pub async fn open(
        self,
        method: Option<WrapKeyMethod>,
        pass_key: PassKey<'_>,
        profile: Option<&'a str>,
    ) -> Result<Store<SqliteStore>> {
        let conn_opts = SqliteConnectOptions::from_str(self.path.as_ref())?;
        let conn_pool = self.options.connect_with(conn_opts).await?;
        Ok(open_db(conn_pool, method, pass_key, profile, self.path.to_string()).await?)
    }

    pub async fn remove(self) -> Result<bool> {
        if self.in_memory {
            Ok(true)
        } else {
            try_remove_file(self.path.as_ref()).await
        }
    }

    pub fn in_memory() -> Self {
        Self {
            in_memory: true,
            path: Cow::Borrowed(":memory:"),
            options: SqlitePoolOptions::default(),
        }
    }
}

impl<'a> ManageBackend<'a> for SqliteStoreOptions<'a> {
    type Store = Store<SqliteStore>;

    fn open_backend(
        self,
        method: Option<WrapKeyMethod>,
        pass_key: PassKey<'a>,
        profile: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Store<SqliteStore>>> {
        Box::pin(self.open(method, pass_key, profile))
    }

    fn provision_backend(
        self,
        method: WrapKeyMethod,
        pass_key: PassKey<'a>,
        profile: Option<&'a str>,
        recreate: bool,
    ) -> BoxFuture<'a, Result<Store<SqliteStore>>> {
        Box::pin(self.provision(method, pass_key, profile, recreate))
    }

    fn remove_backend(self) -> BoxFuture<'a, Result<bool>> {
        Box::pin(self.remove())
    }
}

async fn init_db(
    conn_pool: &SqlitePool,
    profile_name: &str,
    method: WrapKeyMethod,
    pass_key: PassKey<'_>,
) -> Result<KeyCache> {
    let (store_key, enc_store_key, wrap_key, wrap_key_ref) =
        unblock_scoped(|| init_keys(method, pass_key)).await?;

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
            id INTEGER NOT NULL,
            item_id INTEGER NOT NULL,
            name BLOB NOT NULL,
            value BLOB NOT NULL,
            plaintext BOOLEAN NOT NULL,
            PRIMARY KEY (id),
            FOREIGN KEY (item_id) REFERENCES items (id)
                ON DELETE CASCADE ON UPDATE CASCADE
        );
        CREATE INDEX ix_items_tags_item_id ON items_tags (item_id);
        CREATE INDEX ix_items_tags_value ON items_tags (plaintext, name, SUBSTR(value, 0, 12));

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
    .bind(profile_name)
    .bind(wrap_key_ref)
    .bind(enc_store_key)
    .execute(&mut conn)
    .await?;

    let mut key_cache = KeyCache::new(wrap_key);

    let row = sqlx::query("SELECT id FROM profiles WHERE name = ?1")
        .persistent(false)
        .bind(profile_name)
        .fetch_one(&mut conn)
        .await?;
    key_cache.add_profile_mut(profile_name.to_string(), row.try_get(0)?, store_key);

    Ok(key_cache)
}

async fn open_db(
    conn_pool: SqlitePool,
    method: Option<WrapKeyMethod>,
    pass_key: PassKey<'_>,
    profile: Option<&str>,
    path: String,
) -> Result<Store<SqliteStore>> {
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
    let profile = profile
        .map(str::to_string)
        .or(default_profile)
        .ok_or_else(|| err_msg!(Unsupported, "Default store profile not found"))?;
    let wrap_key = if let Some(wrap_key_ref) = wrap_key_ref {
        let wrap_ref = WrapKeyReference::parse_uri(&wrap_key_ref)?;
        if let Some(method) = method {
            if !wrap_ref.compare_method(&method) {
                return Err(err_msg!(Input, "Store key wrap method mismatch"));
            }
        }
        unblock_scoped(|| wrap_ref.resolve(pass_key)).await?
    } else {
        return Err(err_msg!(Unsupported, "Store wrap key not found"));
    };
    let mut key_cache = KeyCache::new(wrap_key);

    let row = sqlx::query("SELECT id, store_key FROM profiles WHERE name = ?1")
        .bind(&profile)
        .fetch_one(&mut conn)
        .await?;
    let profile_id = row.try_get(0)?;
    let store_key = key_cache.load_key(row.try_get(1)?).await?;
    key_cache.add_profile_mut(profile.clone(), profile_id, store_key);

    Ok(Store::new(SqliteStore::new(
        conn_pool, profile, key_cache, path,
    )))
}

async fn try_remove_file(path: &str) -> Result<bool> {
    unblock_scoped(|| match remove_file(path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == IoErrorKind::NotFound => Ok(false),
        Err(err) => Err(err_msg!(Backend, "Error removing file").with_cause(err)),
    })
    .await
}
