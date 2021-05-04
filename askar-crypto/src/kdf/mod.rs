//! Key derivation function traits and implementations

#[cfg(feature = "alloc")]
use crate::buffer::SecretBytes;
use crate::{buffer::WriteBuffer, error::Error};

#[cfg(feature = "argon2")]
#[cfg_attr(docsrs, doc(cfg(feature = "argon2")))]
pub mod argon2;

pub mod concat;

pub mod ecdh_1pu;

pub mod ecdh_es;

/// Trait for keys supporting Diffie-Helman key exchange
pub trait KeyExchange<Rhs: ?Sized = Self> {
    /// Perform a key exchange, writing the result to the provided buffer.
    fn write_key_exchange(&self, other: &Rhs, out: &mut dyn WriteBuffer) -> Result<(), Error>;

    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    /// Perform a key exchange and return a new allocated buffer.
    fn key_exchange_bytes(&self, other: &Rhs) -> Result<SecretBytes, Error> {
        let mut buf = SecretBytes::with_capacity(128);
        self.write_key_exchange(other, &mut buf)?;
        Ok(buf)
    }
}

/// Trait for instantiation from a key exchange
pub trait FromKeyExchange<Lhs: ?Sized, Rhs: ?Sized>: Sized {
    /// Derive an instance of this key directly from a supported key exchange
    fn from_key_exchange(lhs: &Lhs, rhs: &Rhs) -> Result<Self, Error>;
}

/// Trait implemented by key derivation methods
pub trait KeyDerivation {
    /// Derive the raw bytes of a key from this KDF
    fn derive_key_bytes(&mut self, key_output: &mut [u8]) -> Result<(), Error>;
}

/// Trait for instantiation from a key derivation
pub trait FromKeyDerivation {
    /// Create a new instance of a key from a key derivation
    fn from_key_derivation<D: KeyDerivation>(derive: D) -> Result<Self, Error>
    where
        Self: Sized;
}
