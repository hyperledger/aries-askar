#![no_std]
// #![deny(missing_debug_implementations)]
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

#[cfg(feature = "any")]
pub mod any;
#[cfg(feature = "any")]
pub use self::any::{AnyPrivateKey, AnyPublicKey};

pub mod alg;
pub use self::alg::KeyAlg;

pub mod buffer;

pub mod encrypt;

pub mod jwk;

pub mod kdf;

pub mod random;

pub mod sign;
pub use self::sign::{KeySigVerify, KeySign, SignatureType};

pub mod repr;
pub use self::repr::{KeyGen, KeyGenInPlace, KeySecretBytes};
