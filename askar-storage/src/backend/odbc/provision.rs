use std::borrow::Cow;
use std::time::Duration;
use odbc_api::Cursor;

use crate::{
    backend::ManageBackend,
    error::Error,
    future::BoxFuture,
    options::IntoOptions,
    protect::{PassKey, StoreKeyMethod}
};

use super::OdbcBackend;
use crate::odbc::OdbcConnectionManager;

fn connect(connection_string: &str) {
    println!("Using my connection pool...");
    let manager = OdbcConnectionManager::new(connection_string);
    let pool = r2d2::Pool::builder()
        .max_size(5)
        .build(manager)
        .unwrap();

    for i in 0..50 {
        println!("iteration: {i}.");
        let mut cursor = match pool.get().unwrap().raw().execute("SELECT * FROM profiles", ()) {
            Ok(cursor) => {
                let mut unwrapped = cursor.unwrap();

                while let Some(mut row) = unwrapped.next_row().expect("Failed to fetch next row.") {
                    let mut output_a: i64 = 0;
                    row.get_data(1, &mut output_a).unwrap();
                    println!("ID: {output_a}");
                }
            }
            Err(error) => {
                println!("An error occured: {error}");
            }
        };
    }
}

const DEFAULT_CONNECT_TIMEOUT: u64 = 30;
const DEFAULT_IDLE_TIMEOUT: u64 = 300;
const DEFAULT_MIN_CONNECTIONS: u32 = 0;
const DEFAULT_MAX_CONNECTIONS: u32 = 10;

/// Configuration options for ODBC stores
#[derive(Debug)]
pub struct OdbcStoreOptions {
    pub(crate) connect_timeout: Duration,
    pub(crate) idle_timeout: Duration,
    pub(crate) max_connections: u32,
    pub(crate) min_connections: u32,
    pub(crate) uri: String,
    pub(crate) admin_uri: String,
    pub(crate) host: String,
    pub(crate) name: String,
    pub(crate) username: String,
    pub(crate) schema: Option<String>,
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
        let schema = opts.query.remove("schema");
        let admin_acct = opts.query.remove("admin_account");
        let admin_pass = opts.query.remove("admin_password");
        let username = match opts.user.as_ref() {
            "" => "odbc".to_owned(),
            a => a.to_owned(),
        };
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
            return Err(err_msg!(Input, "Missing database name"));
        }
        let name = path[1..].to_string();
        if let Some(schema) = schema.as_ref() {
            _validate_ident(schema, "schema")?;
        }
        _validate_ident(&name, "database")?;
        _validate_ident(&username, "username")?;
        // admin user selects the default database
        opts.path = Cow::Borrowed("/odbc");
        Ok(Self {
            connect_timeout: Duration::from_secs(connect_timeout),
            idle_timeout: Duration::from_secs(idle_timeout),
            max_connections,
            min_connections,
            uri,
            admin_uri: opts.into_uri(),
            host,
            name,
            username,
            schema,
        })
    }

    /// Provision a Odbc store from this set of configuration options
    pub async fn provision(
        self,
        method: StoreKeyMethod,
        pass_key: PassKey<'_>,
        profile: Option<String>,
        recreate: bool,
    ) -> Result<OdbcBackend, Error> {
        Err(err_msg!(Unsupported, "provision::provision()"))
    }



    /// Open an existing Odbc store from this set of configuration options
    pub async fn open(
        self,
        method: Option<StoreKeyMethod>,
        pass_key: PassKey<'_>,
        profile: Option<String>,
    ) -> Result<OdbcBackend, Error> {
        let connection_string = "Driver=/tmp/clidriver/lib/libdb2o.so.1;Database=testdb;Hostname=10.10.10.200;Port=50000;Protocol=TCPIP;Uid=db2inst1;Pwd=passw0rd1;Security=;";

        connect(connection_string);

        Err(err_msg!(Unsupported, "provision::open() expected failure!"))
    }

    /// Remove an existing Odbc store defined by these configuration options
    pub async fn remove(self) -> Result<bool, Error> {
        Err(err_msg!(Unsupported, "provision::remove()"))
    }
}

impl<'a> ManageBackend<'a> for OdbcStoreOptions {
    type Backend = OdbcBackend;

    fn open_backend(
        self,
        method: Option<StoreKeyMethod>,
        pass_key: PassKey<'a>,
        profile: Option<String>,
    ) -> BoxFuture<'a, Result<OdbcBackend, Error>> {
        Box::pin(self.open(method, pass_key, profile))
    }

    fn provision_backend(
        self,
        method: StoreKeyMethod,
        pass_key: PassKey<'a>,
        profile: Option<String>,
        recreate: bool,
    ) -> BoxFuture<'a, Result<OdbcBackend, Error>> {
        Box::pin(self.provision(method, pass_key, profile, recreate))
    }

    fn remove_backend(self) -> BoxFuture<'a, Result<bool, Error>> {
        Box::pin(self.remove())
    }
}


/// Validate a ODBC identifier.
/// Any character except NUL is allowed in an identifier. Double quotes must be escaped,
/// but we just disallow those instead.
fn _validate_ident(ident: &str, name: &str) -> Result<(), Error> {
    if ident.is_empty() {
        Err(err_msg!(Input, "{name} identifier is empty"))
    } else if ident.find(|c| c == '"' || c == '\0').is_some() {
        Err(err_msg!(
            Input,
            "Invalid character in {name} identifier: '\"' and '\\0' are disallowed"
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn odbc_parse_uri() {
        /*
        let uri = "odbc://user:pass@host/db_name\
            ?admin_account=user2&admin_password=pass2\
            &connect_timeout=9&max_connections=23&min_connections=32\
            &idle_timeout=99\
            &test=1";
        let opts = OdbcStoreOptions::new(uri).unwrap();
        assert_eq!(opts.max_connections, 23);
        assert_eq!(opts.min_connections, 32);
        assert_eq!(opts.connect_timeout, Duration::from_secs(9));
        assert_eq!(opts.idle_timeout, Duration::from_secs(99));
        assert_eq!(opts.uri, "odbc://user:pass@host/db_name?test=1");
        assert_eq!(opts.admin_uri, "odbc://user2:pass2@host/postgres?test=1");
        */
    }
}
