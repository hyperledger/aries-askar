#[cfg(feature = "alloc")]
use crate::buffer::SecretBytes;
use crate::{buffer::WriteBuffer, error::Error};

pub mod argon2;

pub mod concat;

pub mod ecdh_1pu;

pub mod ecdh_es;

pub trait KeyExchange<Rhs = Self> {
    fn key_exchange_buffer<B: WriteBuffer>(&self, other: &Rhs, out: &mut B) -> Result<(), Error>;

    #[cfg(feature = "alloc")]
    fn key_exchange_bytes(&self, other: &Rhs) -> Result<SecretBytes, Error> {
        let mut buf = SecretBytes::with_capacity(128);
        self.key_exchange_buffer(other, &mut buf)?;
        Ok(buf)
    }
}

pub trait FromKeyExchange<Lhs, Rhs>: Sized {
    fn from_key_exchange(lhs: &Lhs, rhs: &Rhs) -> Result<Self, Error>;
}
