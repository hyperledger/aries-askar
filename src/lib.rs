#[macro_use]
mod error;
pub use self::error::{Error, ErrorKind, Result};

#[macro_use]
mod macros;

#[cfg(feature = "log")]
#[macro_use]
extern crate log;

pub(crate) mod db_utils;

pub mod indy_compat;

mod options;

#[cfg(feature = "ffi")]
#[macro_use]
extern crate serde;
#[cfg(feature = "ffi")]
#[macro_use]
extern crate serde_json;

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "postgres")]
pub mod postgres;

#[cfg(feature = "sqlite")]
pub mod sqlite;

mod keys;
pub use self::keys::wrap::{generate_raw_wrap_key, WrapKeyMethod};

mod store;
pub use self::store::{KvProvisionSpec, KvProvisionStore, KvStore};

mod types;
pub use self::types::{KvEntry, KvFetchOptions, KvTag, KvUpdateEntry};

pub mod wql;
