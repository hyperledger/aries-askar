//! Key derivation function traits and implementations

#[cfg(feature = "alloc")]
use crate::buffer::SecretBytes;
use crate::{alg::AnyKey, buffer::WriteBuffer, error::Error};

#[cfg(feature = "argon2")]
#[cfg_attr(docsrs, doc(cfg(feature = "argon2")))]
pub mod argon2;

pub mod concat;

pub mod ecdh_1pu;

pub mod ecdh_es;

/// Trait for keys supporting Diffie-Hellman key exchange
pub trait KeyExchange<Rhs: ?Sized = Self> {
    /// The length of the resulting key
    const EXCHANGE_KEY_LENGTH: usize;

    /// Access a temporary slice of the exchange key output
    fn with_key_exchange<O>(&self, public: &Rhs, f: impl FnOnce(&[u8]) -> O) -> Result<O, Error>;
}

/// Object-safe trait for keys supporting Diffie-Hellman key exchange
pub trait DynKeyExchange {
    /// The length of the resulting key
    fn exchange_key_length(&self, _public: &dyn AnyKey) -> Option<usize> {
        None
    }

    /// Perform a key exchange, writing the result to the provided buffer.
    fn write_key_exchange(
        &self,
        _public: &dyn AnyKey,
        _out: &mut dyn WriteBuffer,
    ) -> Result<(), Error> {
        Err(err_msg!(Unsupported))
    }

    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    /// Perform a key exchange and return a new allocated buffer.
    fn key_exchange_bytes(&self, public: &dyn AnyKey) -> Result<SecretBytes, Error> {
        let mut buf = SecretBytes::with_capacity(128);
        self.write_key_exchange(public, &mut buf)?;
        Ok(buf)
    }
}

impl<K: KeyExchange + 'static> DynKeyExchange for K {
    #[inline]
    fn exchange_key_length(&self, public: &dyn AnyKey) -> Option<usize> {
        if public.is::<K>() {
            Some(K::EXCHANGE_KEY_LENGTH)
        } else {
            None
        }
    }

    fn write_key_exchange(
        &self,
        public: &dyn AnyKey,
        out: &mut dyn WriteBuffer,
    ) -> Result<(), Error> {
        if let Some(public) = public.downcast_ref() {
            self.with_key_exchange(public, |buf| out.buffer_write(buf))?
        } else {
            Err(err_msg!(Unsupported))
        }
    }
}

/// Trait for instantiation from a key exchange
pub trait FromKeyExchange: Sized {
    /// Derive an instance of this key directly from a supported key exchange
    fn from_key_exchange(lhs: &dyn AnyKey, rhs: &dyn AnyKey) -> Result<Self, Error>;
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
