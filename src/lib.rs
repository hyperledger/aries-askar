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

pub mod backends;

pub use askar_crypto as crypto;

#[doc(hidden)]
pub mod future;

#[cfg(feature = "indy_compat")]
#[cfg_attr(docsrs, doc(cfg(feature = "indy_compat")))]
/// Indy wallet compatibility support
pub mod indy_compat;

// #[cfg(feature = "ffi")]
// #[macro_use]
// extern crate serde_json;

// #[cfg(feature = "ffi")]
// mod ffi;

pub mod protect;

pub mod storage;

// #[macro_use]
// pub(crate) mod serde_utils;

// mod keys;
// pub use self::keys::{
//     derive_verkey, verify_signature,
//     wrap::{generate_raw_wrap_key, WrapKeyMethod},
//     KeyAlg, KeyCategory, KeyEntry, KeyParams, PassKey,
// };
