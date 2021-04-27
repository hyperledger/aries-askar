//! Cryptography primitives and operations for aries-askar.

#![no_std]
#![deny(missing_debug_implementations)]
// #![deny(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(any(test, feature = "std"))]
#[macro_use]
extern crate std;

#[cfg(test)]
#[macro_use]
extern crate hex_literal;

#[macro_use]
mod error;
pub use self::error::{Error, ErrorKind};

// re-export
pub use aead::generic_array;

pub mod alg;

pub mod buffer;

pub mod encrypt;
pub use self::encrypt::{KeyAeadInPlace, KeyAeadMeta};

pub mod jwk;

pub mod kdf;

pub mod random;

pub mod sign;
pub use self::sign::{KeySigVerify, KeySign, SignatureType};

pub mod repr;
pub use self::repr::{KeyGen, KeyMeta, KeyPublicBytes, KeySecretBytes, KeypairBytes, KeypairMeta};
