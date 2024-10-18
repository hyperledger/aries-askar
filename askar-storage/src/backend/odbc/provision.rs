use std::time::Duration;
use std::fs;
use odbc_api::{Cursor, IntoParameter};

use crate::{
    backend::{
        db_utils::{init_keys, random_profile_name},
        ManageBackend,
    },
    error::Error,
    future::{unblock, BoxFuture},
    options::IntoOptions,
    protect::{KeyCache, PassKey, StoreKeyMethod, StoreKeyReference},
};

use super::OdbcBackend;
use crate::odbc::OdbcConnectionManager;

/// Allow the aries-askar error object to handle ODBC API errors.
impl From<odbc_api::Error> for Error {
    fn from(err: odbc_api::Error) -> Self {
        err_msg!(Backend, "Error returned from the database").with_cause(err)
    }
}

/// Allow the aries-askar error object to handle std::io errors.
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        err_msg!(Backend, "IO Error").with_cause(err)
    }
}

/// Defaults.
const DEFAULT_CONNECT_TIMEOUT: u64 = 30;
const DEFAULT_IDLE_TIMEOUT: u64 = 300;
const DEFAULT_MAX_LIFETIME: u64 = 300;
const DEFAULT_MIN_CONNECTIONS: u32 = 0;
const DEFAULT_MAX_CONNECTIONS: u32 = 10;

/// Configuration options for ODBC stores
#[derive(Debug)]
pub struct OdbcStoreOptions {
    pub(crate) connect_timeout: Duration,
    pub(crate) idle_timeout: Duration,
    pub(crate) max_lifetime: Duration,
    pub(crate) max_connections: u32,
    pub(crate) min_connections: u32,
    pub(crate) connection_string: String,
    pub(crate) schema_file: String,
}

impl OdbcStoreOptions {
    /// Initialize `OdbcStoreOptions` from a generic set of options
    pub fn new<'a, O>(options: O) -> Result<Self, Error>
    where
        O: IntoOptions<'a>,
    {
        let mut opts = options.into_options()?;
        let connect_timeout = if let Some(timeout) = opts.query.remove("connect_timeout") {
            timeout
                .parse()
                .map_err(err_map!(Input, "Error parsing 'connect_timeout' parameter"))?
        } else {
            DEFAULT_CONNECT_TIMEOUT
        };
        let idle_timeout = if let Some(timeout) = opts.query.remove("idle_timeout") {
            timeout
                .parse()
                .map_err(err_map!(Input, "Error parsing 'idle_timeout' parameter"))?
        } else {
            DEFAULT_IDLE_TIMEOUT
        };
        let max_lifetime = if let Some(timeout) = opts.query.remove("max_lifetime") {
            timeout
                .parse()
                .map_err(err_map!(Input, "Error parsing 'max_lifetime' parameter"))?
        } else {
            DEFAULT_MAX_LIFETIME
        };
        let max_connections = if let Some(max_conn) = opts.query.remove("max_connections") {
            max_conn
                .parse()
                .map_err(err_map!(Input, "Error parsing 'max_connections' parameter"))?
        } else {
            DEFAULT_MAX_CONNECTIONS
        };
        let min_connections = if let Some(min_conn) = opts.query.remove("min_connections") {
            min_conn
                .parse()
                .map_err(err_map!(Input, "Error parsing 'min_connections' parameter"))?
        } else {
            DEFAULT_MIN_CONNECTIONS
        };

        let schema_file = opts.query.remove("schema_file");
        if !schema_file.is_some() {
            return Err(err_msg!(Input, "Missing 'schema_file' parameter"));
        }

        let mut connection_string = opts.host.to_string();
        connection_string.push_str(&opts.path);

        Ok(Self {
            connect_timeout: Duration::from_secs(connect_timeout),
            idle_timeout: Duration::from_secs(idle_timeout),
            max_lifetime: Duration::from_secs(max_lifetime),
            max_connections,
            min_connections,
            connection_string,
            schema_file: schema_file.unwrap(),
        })
    }

    /// Provision an Odbc store from this set of configuration options
    pub async fn provision(
        self,
        method: StoreKeyMethod,
        pass_key: PassKey<'_>,
        profile: Option<String>,
        recreate: bool,
    ) -> Result<OdbcBackend, Error> {
        // Create the pool to the database server.
        let pool = self.open_pool().await;

        if self.config_exists(&pool) {
            if !recreate {
                // If the database has already been created we just open
                // it now.
                return Ok(self.open(Some(method), pass_key, profile).await?);
            } else {
                self.drop_tables(&pool)?;
            }
        }

        // If we get this far it means that the database has not yet been provisioned.
        // We need to provision the database now.  We do this by applying the database
        // schema which has been provided in the schema file.  We need to execute each
        // SQL statement one at a time as the ODBC API does not appear to support the
        // execution of multiple statements in a single API call.
        let schema: String = fs::read_to_string(self.schema_file)?;

        let statements = schema.split(";");
        for statement in statements {
            let trimmed_statement = statement.trim();

            if trimmed_statement.len() > 0 {
                pool.get().unwrap().raw().execute(trimmed_statement, ())?;
            }
        }

        // Initialise the key store.
        let (profile_key, enc_profile_key, store_key, store_key_ref) = unblock({
            let pass_key = pass_key.into_owned();
            move || init_keys(method, pass_key)
        })
        .await?;

        // Work out the profile.
        let default_profile = profile.unwrap_or_else(random_profile_name);

        // Save the configuration information.
        pool.get().unwrap().raw().execute("INSERT INTO config (name, value) VALUES
                ('default_profile', ?),
                ('key', ?),
                ('version', ?)",
            (&default_profile.clone().into_parameter(), &store_key_ref.into_parameter(), &"1".into_parameter()))?;

        pool.get().unwrap().raw().execute("INSERT INTO profiles (name, profile_key) VALUES (?, ?)",
            (&default_profile.clone().into_parameter(), &enc_profile_key.clone().into_parameter()))?;

        // Retrieve the profile ID from the table.
        let mut profile_id: i64 = 0;

        pool.get().unwrap().raw().execute(
                "SELECT id from profiles WHERE name=? and profile_key=?",
                (&default_profile.clone().into_parameter(), &enc_profile_key.clone().into_parameter()))
            .unwrap().unwrap()
            .next_row().unwrap().unwrap()
            .get_data(1, &mut profile_id)?;

        let mut key_cache = KeyCache::new(store_key);
        key_cache.add_profile_mut(default_profile.clone(), profile_id, profile_key);

        // Return a newly created backend for the database server.
        Ok(OdbcBackend::new(
            pool,
            default_profile,
            key_cache,
        ))
    }



    /// Open an existing Odbc store from this set of configuration options
    pub async fn open(
        self,
        method: Option<StoreKeyMethod>,
        pass_key: PassKey<'_>,
        profile: Option<String>,
    ) -> Result<OdbcBackend, Error> {
        // Create the pool to the database server.
        let pool = self.open_pool().await;

        // We need to retrieve the profile, key and version from the
        // config table.
        let mut ver_ok = false;
        let mut default_profile: Option<String> = None;
        let mut store_key_ref: Option<String> = None;

        match pool.get().unwrap().raw().execute(
                "SELECT name, value FROM config WHERE name IN ('default_profile', 'key', 'version')", ()) {
            Ok(cursor) => {
                let mut unwrapped = cursor.unwrap();

                while let Some(mut row) = unwrapped.next_row()? {
                    // Retrieve the name and value in the row.
                    let mut name_buf = Vec::new();
                    row.get_text(1, &mut name_buf)?;
                    let name = String::from_utf8(name_buf).unwrap();

                    let mut value_buf = Vec::new();
                    row.get_text(2, &mut value_buf)?;
                    let value = String::from_utf8(value_buf).unwrap();

                    // Check the name and process the value.
                    match name.as_str() {
                        "default_profile" => {
                            default_profile.replace(value);
                        }
                        "key" => {
                            store_key_ref.replace(value);
                        }
                        "version" => {
                            if value != "1" {
                                return Err(err_msg!(Unsupported, "Unsupported store version"));
                            }
                            ver_ok = true;
                        }
                        _ => (),
                    }
                }
            }
            Err(_error) => {
                return Err(err_msg!(Unsupported, "Configuration data not found"));
            }
        };

        if !ver_ok {
            return Err(err_msg!(Unsupported, "Store version not found"));
        }

        // Work out our profile and store key.
        let profile = profile
            .or(default_profile)
            .ok_or_else(|| err_msg!(Unsupported, "Default store profile not found"))?;

        let store_key = if let Some(store_key_ref) = store_key_ref {
            let wrap_ref = StoreKeyReference::parse_uri(&store_key_ref)?;
            if let Some(method) = method {
                if !wrap_ref.compare_method(&method) {
                    return Err(err_msg!(Input, "Store key method mismatch"));
                }
            }
            unblock({
                let pass_key = pass_key.into_owned();
                move || wrap_ref.resolve(pass_key)
            })
            .await?
        } else {
            return Err(err_msg!(Unsupported, "Store key not found"));
        };

        // Retrieve the key from the database.
        let mut profile_id: i64 = 0;
        let mut profile_key_buf = Vec::new();

        if let Ok(Some(mut cursor)) = pool.get().unwrap().raw().execute(
            "SELECT id, profile_key from profiles WHERE name=?",
            &profile.clone().into_parameter()) {
            let mut row = cursor.next_row().unwrap().unwrap();

            row.get_data(1, &mut profile_id)?;
            row.get_binary(2, &mut profile_key_buf).unwrap();
        }

        let mut key_cache = KeyCache::new(store_key);

        let profile_key = key_cache.load_key(profile_key_buf).await?;

        key_cache.add_profile_mut(profile.clone(), profile_id, profile_key);

        // Return a newly created backend for the database server.
        Ok(OdbcBackend::new(
            pool,
            profile,
            key_cache,
        ))
    }

    /// Remove an existing Odbc store defined by these configuration options
    pub async fn remove(self) -> Result<bool, Error> {
        // Create the pool to the database server.
        let pool = self.open_pool().await;

        // If the config table exists we attempt to drop all of the tables now.
        if self.config_exists(&pool) {
            self.drop_tables(&pool)?;
        }

        Ok(true)
    }

    /// Create a pool of connections to the database server.
    async fn open_pool(&self) -> r2d2::Pool<OdbcConnectionManager> {
        let manager = OdbcConnectionManager::new(self.connection_string.clone());
        r2d2::Pool::builder()
            .max_size(self.max_connections)
            .min_idle(Some(self.min_connections))
            .max_lifetime(Some(self.max_lifetime))
            .connection_timeout(self.connect_timeout)
            .idle_timeout(Some(self.idle_timeout))
            .build(manager)
            .unwrap()
    }

    // Drop all of our tables from the database server.
    fn drop_tables(&self, pool: &r2d2::Pool<OdbcConnectionManager>) -> Result<(), Error> {
        let table_names: [&str; 4] = ["items_tags", "items", "profiles", "config"];

        for table_name in &table_names {
            pool.get().unwrap().raw().execute(format!("DROP TABLE {}", table_name).as_str(), ());
        }

        Ok(())
    }

    // Check to see whether our config table exists or not.
    fn config_exists(&self, pool: &r2d2::Pool<OdbcConnectionManager>) -> bool {
        // Check to see if the config table currently exists.
        pool.get().unwrap().raw().execute("select count(name) from config", ()).is_ok()
    }

}

impl<'a> ManageBackend<'a> for OdbcStoreOptions {
    type Backend = OdbcBackend;

    /// Open a connection to the backend.
    fn open_backend(
        self,
        method: Option<StoreKeyMethod>,
        pass_key: PassKey<'a>,
        profile: Option<String>,
    ) -> BoxFuture<'a, Result<OdbcBackend, Error>> {
        let pass_key = pass_key.into_owned();
        Box::pin(self.open(method, pass_key, profile))
    }

    /// Provision the backend with our schema.
    fn provision_backend(
        self,
        method: StoreKeyMethod,
        pass_key: PassKey<'a>,
        profile: Option<String>,
        recreate: bool,
    ) -> BoxFuture<'a, Result<OdbcBackend, Error>> {
        let pass_key = pass_key.into_owned();
        Box::pin(self.provision(method, pass_key, profile, recreate))
    }

    /// Clean out the backend of our data/schema.
    fn remove_backend(self) -> BoxFuture<'a, Result<bool, Error>> {
        Box::pin(self.remove())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ensure that the ODBC URI is parsed correctly.
    #[test]
    fn odbc_parse_uri() {
        let uri = "odbc://test_connection_string\
            ?connect_timeout=10\
            &idle_timeout=11\
            &max_lifetime=12\
            &max_connections=13\
            &min_connections=14\
            &schema_file=test.sql";
        let opts = OdbcStoreOptions::new(uri).unwrap();

        assert_eq!(opts.connect_timeout, Duration::from_secs(10));
        assert_eq!(opts.idle_timeout, Duration::from_secs(11));
        assert_eq!(opts.max_lifetime, Duration::from_secs(12));
        assert_eq!(opts.max_connections, 13);
        assert_eq!(opts.min_connections, 14);
        assert_eq!(opts.connection_string, "test_connection_string");
        assert_eq!(opts.schema_file, "test.sql");
    }
}
