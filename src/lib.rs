//! Secure storage designed for Hyperledger Aries agents

#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_docs, missing_debug_implementations, rust_2018_idioms)]

#[macro_use]
pub mod error;
pub use self::error::{Error, ErrorKind};

#[cfg(any(test, feature = "log"))]
#[macro_use]
extern crate log;

#[macro_use]
extern crate serde;

#[doc(hidden)]
pub use askar_crypto as crypto;
#[doc(hidden)]
pub use askar_storage as storage;
#[doc(hidden)]
pub use askar_storage::future;

#[cfg(feature = "ffi")]
pub mod ffi;

pub mod kms;

pub mod store;
pub use store::{entry, PassKey, Session, Store, StoreKeyMethod};
