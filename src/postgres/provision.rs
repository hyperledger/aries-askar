use std::borrow::Cow;
use std::time::Duration;

use sqlx::{
    postgres::{PgConnection, PgPool, PgPoolOptions, Postgres},
    Connection, Error as SqlxError, Executor, Row, Transaction,
};

use crate::db_utils::ProvisionStoreSpec;
use crate::error::Result;
use crate::future::BoxFuture;
use crate::keys::{
    wrap::{WrapKeyMethod, WrapKeyReference},
    KeyCache,
};
use crate::options::IntoOptions;
use crate::store::{ManageBackend, Store};

use super::PostgresStore;

const DEFAULT_CONNECT_TIMEOUT: u64 = 30;

#[derive(Debug)]
pub struct PostgresStoreOptions {
    pub(crate) connect_timeout: Duration,
    pub(crate) uri: String,
    pub(crate) admin_uri: String,
    pub(crate) host: String,
    pub(crate) name: String,
}

impl PostgresStoreOptions {
    pub fn new<'a, O>(options: O) -> Result<Self>
    where
        O: IntoOptions<'a>,
    {
        let mut opts = options.into_options()?;
        let admin_acct = opts.query.remove("admin_account");
        let admin_pass = opts.query.remove("admin_password");
        let uri = opts.clone().into_uri();
        if admin_acct.is_some() || admin_pass.is_some() {
            if let Some(admin_acct) = admin_acct {
                opts.user = Cow::Owned(admin_acct);
            }
            if let Some(admin_pass) = admin_pass {
                opts.password = Cow::Owned(admin_pass);
            }
        }
        let host = opts.host.to_string();
        let path = opts.path.as_ref();
        if path.len() < 2 {
            return Err(err_msg!("Missing database name"));
        }
        let name = (&path[1..]).to_string();
        if name.find(|c| c == '"' || c == '\0').is_some() {
            return Err(err_msg!(
                "Invalid character in database name: '\"' and '\\0' are disallowed"
            ));
        }
        // admin user selects no default database
        opts.path = Cow::Borrowed("");
        Ok(Self {
            connect_timeout: Duration::from_secs(DEFAULT_CONNECT_TIMEOUT),
            uri,
            admin_uri: opts.into_uri(),
            host,
            name,
        })
    }

    async fn pool(&self) -> std::result::Result<PgPool, SqlxError> {
        PgPoolOptions::default()
            .connect_timeout(self.connect_timeout)
            .min_connections(0)
            .max_connections(10)
            .test_before_acquire(false)
            .connect(self.uri.as_str())
            .await
    }

    pub(crate) async fn create_db_pool(&self) -> Result<PgPool> {
        // try connecting normally in case the database exists
        match self.pool().await {
            Ok(pool) => Ok(pool),
            Err(SqlxError::Database(db_err)) if db_err.code() == Some(Cow::Borrowed("3D000")) => {
                // error 3D000 is INVALID CATALOG NAME in postgres,
                // this indicates that the database does not exist
                let mut admin_conn = PgConnection::connect(self.admin_uri.as_ref()).await?;
                // any character except NUL is allowed in an identifier.
                // double quotes must be escaped, but we just disallow those
                let create_q = format!("CREATE DATABASE \"{}\"", self.name);
                match sqlx::query(&create_q)
                    .persistent(false)
                    .execute(&mut admin_conn)
                    .await
                {
                    Ok(_) => (),
                    Err(SqlxError::Database(db_err))
                        if db_err.code() == Some(Cow::Borrowed("42P04")) =>
                    {
                        // duplicate database error. assume another connection created the
                        // database before we could and continue
                    }
                    Err(err) => {
                        return Err(err_msg!(Backend, "Error creating database").with_cause(err))
                    }
                }
                Ok(self.pool().await?)
            }
            Err(err) => return Err(err_msg!(Backend, "Error opening database").with_cause(err)),
        }
    }

    pub async fn provision(
        self,
        method: WrapKeyMethod,
        pass_key: Option<&str>,
        recreate: bool,
    ) -> Result<Store<PostgresStore>> {
        let conn_pool = self.create_db_pool().await?;
        let mut txn = conn_pool.begin().await?;

        if recreate {
            // remove expected tables
            reset_db(&mut *txn).await?;
        } else {
            if sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM information_schema.tables
                WHERE table_schema='public' AND table_name='config'",
            )
            .fetch_one(&mut txn)
            .await?
                == 1
            {
                // proceed to open, will fail if the version doesn't match
                return open_db(conn_pool, Some(method), pass_key, self.host, self.name).await;
            }
            // no 'config' table, assume empty database
        }

        let spec = ProvisionStoreSpec::create(method, pass_key).await?;
        let (default_profile, key_cache) = init_db(txn, spec).await?;

        Ok(Store::new(PostgresStore::new(
            conn_pool,
            default_profile,
            key_cache,
            self.host,
            self.name,
        )))
    }

    pub async fn open(
        self,
        method: Option<WrapKeyMethod>,
        pass_key: Option<&str>,
    ) -> Result<Store<PostgresStore>> {
        let conn_pool = PgPoolOptions::default()
            .connect_timeout(Duration::from_secs(10))
            .min_connections(0)
            .max_connections(10)
            .test_before_acquire(false)
            .connect(self.uri.as_str())
            .await?;

        open_db(conn_pool, method, pass_key, self.host, self.name).await
    }

    pub async fn remove(self) -> Result<bool> {
        Ok(false)
    }
}

impl<'a> ManageBackend<'a> for PostgresStoreOptions {
    type Store = Store<PostgresStore>;

    fn open_backend(
        self,
        method: Option<WrapKeyMethod>,
        pass_key: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Store<PostgresStore>>> {
        Box::pin(self.open(method, pass_key))
    }

    fn provision_backend(
        self,
        method: WrapKeyMethod,
        pass_key: Option<&'a str>,
        recreate: bool,
    ) -> BoxFuture<'a, Result<Store<PostgresStore>>> {
        Box::pin(self.provision(method, pass_key, recreate))
    }

    fn remove_backend(self) -> BoxFuture<'a, Result<bool>> {
        Box::pin(self.remove())
    }
}

pub(crate) async fn init_db<'t>(
    mut txn: Transaction<'t, Postgres>,
    spec: ProvisionStoreSpec,
) -> Result<(String, KeyCache)> {
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
            id BIGSERIAL,
            item_id BIGINT NOT NULL,
            name BYTEA NOT NULL,
            value BYTEA NOT NULL,
            plaintext SMALLINT NOT NULL,
            PRIMARY KEY(id),
            FOREIGN KEY(item_id) REFERENCES items(id)
                ON DELETE CASCADE ON UPDATE CASCADE
        );
        CREATE INDEX ix_items_tags_item_id ON items_tags(item_id);
        CREATE INDEX ix_items_tags_name_value ON items_tags(plaintext, name, SUBSTR(value, 0, 12));
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

pub(crate) async fn reset_db(conn: &mut PgConnection) -> Result<()> {
    conn.execute(
        "
        DROP TABLE IF EXISTS
          config, profiles,
          store_keys, keys,
          items, items_tags;
        ",
    )
    .await?;
    Ok(())
}

pub(crate) async fn open_db(
    conn_pool: PgPool,
    method: Option<WrapKeyMethod>,
    pass_key: Option<&str>,
    host: String,
    name: String,
) -> Result<Store<PostgresStore>> {
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
    let default_profile =
        default_profile.ok_or_else(|| err_msg!(Unsupported, "Default store profile not found"))?;
    let wrap_key = if let Some(wrap_key_ref) = wrap_key_ref {
        let wrap_ref = WrapKeyReference::parse_uri(&wrap_key_ref)?;
        if let Some(method) = method {
            if !wrap_ref.compare_method(&method) {
                return Err(err_msg!("Store key wrap method mismatch"));
            }
        }
        wrap_ref.resolve(pass_key).await?
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
        host,
        name,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postgres_parse_uri() {
        let uri =
            "postgres://user:pass@host/db_name?admin_account=user2&admin_password=pass2&test=1";
        let opts = PostgresStoreOptions::new(uri).unwrap();
        assert_eq!(opts.uri, "postgres://user:pass@host/db_name?test=1");
        assert_eq!(opts.admin_uri, "postgres://user2:pass2@host?test=1");
    }
}
