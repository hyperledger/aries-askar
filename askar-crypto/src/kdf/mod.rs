#[cfg(feature = "alloc")]
use crate::buffer::SecretBytes;
use crate::{buffer::WriteBuffer, error::Error};

pub mod argon2;

pub mod concat;

pub mod ecdh_1pu;

pub mod ecdh_es;

pub trait KeyExchange<Rhs: ?Sized = Self> {
    fn key_exchange_buffer(&self, other: &Rhs, out: &mut dyn WriteBuffer) -> Result<(), Error>;

    #[cfg(feature = "alloc")]
    fn key_exchange_bytes(&self, other: &Rhs) -> Result<SecretBytes, Error> {
        let mut buf = SecretBytes::with_capacity(128);
        self.key_exchange_buffer(other, &mut buf)?;
        Ok(buf)
    }
}

pub trait FromKeyExchange<Lhs: ?Sized, Rhs: ?Sized>: Sized {
    fn from_key_exchange(lhs: &Lhs, rhs: &Rhs) -> Result<Self, Error>;
}

pub trait KeyDerivation {
    fn derive_key_bytes(&mut self, key_output: &mut [u8]) -> Result<(), Error>;
}

pub trait FromKeyDerivation {
    fn from_key_derivation<D: KeyDerivation>(derive: D) -> Result<Self, Error>
    where
        Self: Sized;
}
