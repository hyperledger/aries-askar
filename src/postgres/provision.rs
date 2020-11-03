use std::borrow::Cow;
use std::time::Duration;

use sqlx::{
    postgres::{PgPool, PgPoolOptions},
    Executor, Row,
};

use crate::error::Result;
use crate::future::BoxFuture;
use crate::keys::wrap::WrapKeyReference;
use crate::options::IntoOptions;
use crate::store::{KeyCache, OpenStore, ProvisionStore, ProvisionStoreSpec, Store};

use super::PostgresStore;

#[derive(Debug)]
pub struct PostgresStoreOptions {
    uri: String,
    admin_uri: Option<String>,
}

impl PostgresStoreOptions {
    pub fn new<'a, O>(options: O) -> Result<Self>
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

    async fn provision(self, spec: ProvisionStoreSpec) -> Result<Store<PostgresStore>> {
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

        let (default_profile, key_cache) = init_db(&conn_pool, spec, false).await?;

        if self.admin_uri.is_some() {
            conn_pool = PgPool::connect(self.uri.as_str()).await?;
        }

        Ok(Store::new(PostgresStore::new(
            conn_pool,
            default_profile,
            key_cache,
        )))
    }

    async fn open(self, pass_key: Option<&str>) -> Result<Store<PostgresStore>> {
        let conn_pool = PgPoolOptions::default()
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

        let mut conn = conn_pool.acquire().await?;
        let mut ver_ok = false;
        let mut default_profile: Option<String> = None;
        let mut wrap_key_ref: Option<String> = None;

        let config = sqlx::query(
            r#"SELECT name, value FROM config
            WHERE name IN ('default_profile', 'version', 'wrap_key')"#,
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

        let row = sqlx::query("SELECT id, store_key FROM profiles WHERE name = $1")
            .bind(&default_profile)
            .fetch_one(&mut conn)
            .await?;
        let profile_id = row.try_get(0)?;
        let store_key = key_cache.load_key(row.try_get(1)?).await?;
        key_cache.add_profile(default_profile.clone(), profile_id, store_key);

        Ok(Store::new(PostgresStore::new(
            conn_pool,
            default_profile,
            key_cache,
        )))
    }
}

impl<'a> ProvisionStore<'a> for PostgresStoreOptions {
    type Store = Store<PostgresStore>;

    fn provision_store(
        self,
        spec: ProvisionStoreSpec,
    ) -> BoxFuture<'a, Result<Store<PostgresStore>>> {
        Box::pin(self.provision(spec))
    }
}

impl<'a> OpenStore<'a> for PostgresStoreOptions {
    fn open_store(self, pass_key: Option<&'a str>) -> BoxFuture<'a, Result<Store<PostgresStore>>> {
        Box::pin(self.open(pass_key))
    }
}

pub(crate) async fn init_db(
    conn_pool: &PgPool,
    spec: ProvisionStoreSpec,
    reset: bool,
) -> Result<(String, KeyCache)> {
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
            name TEXT NOT NULL,
            reference TEXT NULL,
            store_key BYTEA NULL,
            PRIMARY KEY(id)
        );
        CREATE UNIQUE INDEX ix_profile_name ON profiles(name);

        CREATE TABLE items (
            id BIGSERIAL,
            profile_id BIGINT NOT NULL,
            kind SMALLINT NOT NULL,
            category BYTEA NOT NULL,
            name BYTEA NOT NULL,
            value BYTEA NOT NULL,
            expiry TIMESTAMP NULL,
            PRIMARY KEY(id),
            FOREIGN KEY(profile_id) REFERENCES profiles(id)
                ON DELETE CASCADE ON UPDATE CASCADE
        );
        CREATE UNIQUE INDEX ix_items_uniq ON items(profile_id, kind, category, name);

        CREATE TABLE items_tags (
            item_id BIGINT NOT NULL,
            name BYTEA NOT NULL,
            value BYTEA NOT NULL,
            plaintext SMALLINT NOT NULL,
            PRIMARY KEY(name, plaintext, item_id),
            FOREIGN KEY(item_id) REFERENCES items(id)
                ON DELETE CASCADE ON UPDATE CASCADE
        );
        CREATE INDEX ix_items_tags_item_id ON items_tags(item_id);
        CREATE INDEX ix_items_tags_value ON items_tags(plaintext, SUBSTR(value, 0, 12));
    ",
    )
    .await?;

    sqlx::query(
        "INSERT INTO config (name, value) VALUES
            ('default_profile', $1),
            ('version', '1'),
            ('wrap_key', $2)",
    )
    .persistent(false)
    .bind(&spec.profile_name)
    .bind(spec.wrap_key_ref)
    .execute(&mut txn)
    .await?;

    let profile_id =
        sqlx::query_scalar("INSERT INTO profiles (name, store_key) VALUES ($1, $2) RETURNING id")
            .bind(&spec.profile_name)
            .bind(spec.enc_store_key)
            .fetch_one(&mut txn)
            .await?;

    txn.commit().await?;

    let mut key_cache = KeyCache::new(spec.wrap_key);
    key_cache.add_profile(spec.profile_name.clone(), profile_id, spec.store_key);

    Ok((spec.profile_name, key_cache))
}

#[cfg(test)]
mod tests {
    use super::*;

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
