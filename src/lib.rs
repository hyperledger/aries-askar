#[macro_use]
mod error;
pub use self::error::{Error, ErrorKind, Result};

#[macro_use]
mod macros;

#[cfg(any(test, feature = "logger"))]
extern crate env_logger;
#[cfg(any(test, feature = "log"))]
#[macro_use]
extern crate log;

#[macro_use]
extern crate serde;

pub(crate) mod db_utils;

#[doc(hidden)]
pub mod future;

pub mod indy_compat;

mod options;

#[cfg(feature = "ffi")]
#[macro_use]
extern crate serde_json;

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(feature = "postgres")]
pub mod postgres;

#[macro_use]
pub(crate) mod serde_util;

#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "any")]
mod any;
#[cfg(feature = "any")]
pub use any::AnyStore;

mod keys;
pub use self::keys::{
    derive_verkey, verify_signature,
    wrap::{generate_raw_wrap_key, WrapKeyMethod},
    KeyAlg, KeyCategory, KeyEntry, KeyParams,
};

mod store;
pub use self::store::{Backend, ProvisionStore, ProvisionStoreSpec, QueryBackend, Session, Store};

mod types;
pub use self::types::{Entry, EntryTag, TagFilter};

mod wql;
