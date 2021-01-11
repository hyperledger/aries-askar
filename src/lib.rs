//! Secure storage designed for Hyperledger Aries agents

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, missing_debug_implementations, rust_2018_idioms)]

#[macro_use]
mod error;
pub use self::error::{Error, ErrorKind};

#[macro_use]
mod macros;

#[cfg(any(test, feature = "log"))]
#[macro_use]
extern crate log;

#[macro_use]
extern crate serde;

#[cfg(any(feature = "postgres", feature = "sqlite"))]
mod db_utils;

#[doc(hidden)]
pub mod future;

#[cfg(feature = "indy_compat")]
#[cfg_attr(docsrs, doc(cfg(feature = "indy_compat")))]
/// Indy wallet compatibility support
pub mod indy_compat;

mod options;

#[cfg(feature = "ffi")]
#[macro_use]
extern crate serde_json;

#[cfg(feature = "ffi")]
mod ffi;

#[cfg(feature = "postgres")]
#[cfg_attr(docsrs, doc(cfg(feature = "postgres")))]
/// Postgres database support
pub mod postgres;

#[macro_use]
pub(crate) mod serde_utils;

#[cfg(feature = "sqlite")]
#[cfg_attr(docsrs, doc(cfg(feature = "sqlite")))]
/// Sqlite database support
pub mod sqlite;

#[cfg(feature = "any")]
#[cfg_attr(docsrs, doc(cfg(feature = "any")))]
/// Generic backend (from URI) support
pub mod any;

mod keys;
pub use self::keys::{
    derive_verkey, verify_signature,
    wrap::{generate_raw_wrap_key, WrapKeyMethod},
    KeyAlg, KeyCategory, KeyEntry, KeyParams, PassKey,
};

mod store;
pub use self::store::{Backend, ManageBackend, QueryBackend, Scan, Session, Store};

mod types;
pub use self::types::{Entry, EntryOperation, EntryTag, SecretBytes, TagFilter};

mod wql;
