// ODBC support for the `r2d2` connection pool.
use r2d2;
use std::fmt;
use std::error::Error;
use odbc_api::{
    Environment,
    ConnectionOptions
};

use lazy_static::lazy_static;

// We create a static ODBC environment reference so that
// it never goes out of scope.
lazy_static! {
    static ref ENV: Environment = Environment::new().unwrap();
}

/// Define the OdbcError type, which will handle mappings from
/// an odbc_api::Error.
///
#[derive(Debug)]
pub struct OdbcError(Box<dyn Error>);

impl Error for OdbcError {
    fn description(&self) -> &str {
        "Error connecting to the database via the ODBC driver"
    }
}

impl fmt::Display for OdbcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<odbc_api::Error> for OdbcError {
    fn from(err: odbc_api::Error) -> Self {
        OdbcError(Box::new(err))
    }
}

/// Define the connection, which simply wraps an
/// odbc_api::Connection object.
#[derive(Debug)]
pub struct OdbcConnection<'a>(odbc_api::Connection<'a>);

impl <'a> OdbcConnection<'a> {
    pub fn raw(&self) -> &odbc_api::Connection<'a> {
        &self.0
    }
}

/// Define the connection manager which manages the
/// pool of connections.  The r2d2::ManageConnection
/// object is used to actually manage the pool of
/// connections.
#[derive(Debug)]
pub struct OdbcConnectionManager {
    connection_string: String
}

impl OdbcConnectionManager {
    /// Creates a new `OdbcConnectionManager`.
    pub fn new<S: Into<String>>(connection_string: S) -> OdbcConnectionManager
    {
        OdbcConnectionManager {
            connection_string: connection_string.into()
        }
    }
}

impl r2d2::ManageConnection for OdbcConnectionManager {
    type Connection = OdbcConnection<'static>;
    type Error = OdbcError;

    /// Create a new connection to the server.
    fn connect(&self) -> std::result::Result<Self::Connection, Self::Error> {
        let env = &ENV;
        let conn = env.connect_with_connection_string(&self.connection_string, ConnectionOptions::default())?;
        Ok(OdbcConnection(conn))
    }

    /// Check to see whether the connection is still valid or not.  We use
    /// the ODBC is_dead function, which will return true if a request to the
    /// database server failed.
    fn is_valid(&self, _conn: &mut Self::Connection) -> std::result::Result<(), Self::Error> {
        if _conn.0.is_dead()? {
            Err(OdbcError("The connection to the database is no longer valid.".into()))
        } else {
            Ok(())
        }
    }

    fn has_broken(&self, _conn: &mut Self::Connection) -> bool {
        false
    }
}
