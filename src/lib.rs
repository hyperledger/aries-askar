//! Secure storage designed for Hyperledger Aries agents

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, missing_debug_implementations, rust_2018_idioms)]

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

pub use askar_crypto as crypto;

#[doc(hidden)]
pub mod future;

#[cfg(feature = "indy_compat")]
#[cfg_attr(docsrs, doc(cfg(feature = "indy_compat")))]
/// Indy wallet compatibility support
pub mod indy_compat;

#[cfg(feature = "ffi")]
#[macro_use]
extern crate serde_json;

#[cfg(feature = "ffi")]
mod ffi;

mod protect;
pub use protect::{generate_raw_wrap_key, PassKey, WrapKeyMethod};

mod storage;
pub use storage::{
    entry::{Entry, EntryTag, TagFilter},
    key::KeyAlg,
    types::{Backend, ManageBackend, Store},
};
