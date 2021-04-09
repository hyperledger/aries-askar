#![no_std]
// #![deny(missing_debug_implementations)]
// #![deny(missing_docs)]
// #![deny(unsafe_code)]

// #[cfg(feature="alloc")]
extern crate alloc;

#[cfg(test)]
#[macro_use]
extern crate std;

#[cfg(test)]
#[macro_use]
extern crate hex_literal;

#[macro_use]
mod error;

#[macro_use]
mod serde_utils;

// re-export
pub use aead::generic_array;

#[cfg(feature = "any")]
pub mod any;
#[cfg(feature = "any")]
pub use self::any::{AnyPrivateKey, AnyPublicKey};

pub mod alg;

mod buffer;
pub use self::buffer::{PassKey, SecretBytes};

pub mod caps;
pub use self::caps::{
    KeyAlg, /*KeyCapGetPublic,*/ KeyCapSign, KeyCapVerify, KeyCategory, SignatureFormat,
    SignatureType,
};

pub mod encrypt;

pub mod jwk;

pub mod kdf;

pub mod pack;

pub mod random;

// pub mod wrap;
