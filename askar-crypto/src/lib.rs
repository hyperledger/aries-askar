#![no_std]
// #![deny(missing_debug_implementations)]
// #![deny(missing_docs)]
// #![deny(unsafe_code)]

// #[cfg(feature="alloc")]
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

#[macro_use]
mod serde_utils;

// re-export
pub use aead::generic_array;

#[cfg(feature = "any")]
pub mod any;
#[cfg(feature = "any")]
pub use self::any::{AnyPrivateKey, AnyPublicKey};

pub mod alg;

pub mod buffer;

pub mod caps;
pub use self::caps::{KeyAlg, KeyCapSign, KeyCapVerify, SignatureFormat, SignatureType};

pub mod encrypt;

pub mod jwk;

pub mod kdf;

pub mod pack;

pub mod random;

pub mod repr;
pub use repr::{KeyGen, KeyGenInPlace, KeySecretBytes};
