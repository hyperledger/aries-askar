//! Secure storage designed for Hyperledger Aries agents

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs, missing_debug_implementations, rust_2018_idioms)]

#[macro_use]
pub extern crate askar_crypto as crypto;

#[macro_use]
mod error;
pub use self::error::{Error, ErrorKind};

#[cfg(test)]
#[macro_use]
extern crate hex_literal;

#[macro_use]
mod macros;

#[cfg(any(test, feature = "log"))]
#[macro_use]
extern crate log;

#[macro_use]
extern crate serde;

pub mod backend;
pub use self::backend::{Backend, ManageBackend};

#[cfg(feature = "any")]
pub use self::backend::any;

#[cfg(feature = "postgres")]
pub use self::backend::postgres;

#[cfg(feature = "sqlite")]
pub use self::backend::sqlite;

#[doc(hidden)]
pub mod future;

#[cfg(feature = "ffi")]
#[macro_use]
extern crate serde_json;

#[cfg(feature = "ffi")]
mod ffi;

pub mod kms;

mod protect;
pub use protect::{generate_raw_store_key, PassKey, StoreKeyMethod};

mod storage;
pub use storage::{Entry, EntryTag, Scan, Store, TagFilter};
