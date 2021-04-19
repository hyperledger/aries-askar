#[cfg(feature = "alloc")]
use crate::buffer::SecretBytes;
use crate::{buffer::WriteBuffer, error::Error, generic_array::ArrayLength};

/// Generate a new random key.
pub trait KeyGen: Sized {
    fn generate() -> Result<Self, Error>;
}

/// Allows a key to be created uninitialized and populated later,
/// for instance when nested inside another struct.
pub trait KeyGenInPlace {
    unsafe fn generate_in_place(this: *mut Self) -> Result<(), Error>;
}

/// Convert between key instance and key secret bytes.
pub trait KeySecretBytes {
    fn from_secret_bytes(key: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;

    fn with_secret_bytes<O>(&self, f: impl FnOnce(Option<&[u8]>) -> O) -> O;

    fn to_secret_bytes_buffer<B: WriteBuffer>(&self, out: &mut B) -> Result<(), Error> {
        self.with_secret_bytes(|buf| {
            if let Some(buf) = buf {
                out.buffer_write(buf)
            } else {
                Err(err_msg!(MissingSecretKey))
            }
        })
    }

    #[cfg(feature = "alloc")]
    fn to_secret_bytes(&self) -> Result<SecretBytes, Error> {
        let mut buf = SecretBytes::with_capacity(128);
        self.to_secret_bytes_buffer(&mut buf)?;
        Ok(buf)
    }
}

/// Convert between key instance and key public bytes.
pub trait KeyPublicBytes {
    fn from_public_bytes(key: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;

    fn with_public_bytes<O>(&self, f: impl FnOnce(&[u8]) -> O) -> O;

    fn to_public_bytes_buffer<B: WriteBuffer>(&self, out: &mut B) -> Result<(), Error> {
        self.with_public_bytes(|buf| out.buffer_write(buf))
    }

    #[cfg(feature = "alloc")]
    fn to_public_bytes(&self) -> Result<SecretBytes, Error> {
        let mut buf = SecretBytes::with_capacity(128);
        self.to_public_bytes_buffer(&mut buf)?;
        Ok(buf)
    }
}

/// Convert between keypair instance and keypair (secret and public) bytes.
pub trait KeypairBytes {
    fn from_keypair_bytes(key: &[u8]) -> Result<Self, Error>
    where
        Self: Sized;

    fn with_keypair_bytes<O>(&self, f: impl FnOnce(Option<&[u8]>) -> O) -> O;

    fn to_keypair_bytes_buffer<B: WriteBuffer>(&self, out: &mut B) -> Result<(), Error> {
        self.with_keypair_bytes(|buf| {
            if let Some(buf) = buf {
                out.buffer_write(buf)
            } else {
                Err(err_msg!(MissingSecretKey))
            }
        })
    }

    #[cfg(feature = "alloc")]
    fn to_keypair_bytes(&self) -> Result<SecretBytes, Error> {
        let mut buf = SecretBytes::with_capacity(128);
        self.to_keypair_bytes_buffer(&mut buf)?;
        Ok(buf)
    }
}

/// For concrete secret key types
pub trait KeyMeta {
    type KeySize: ArrayLength<u8>;
}

/// For concrete secret + public key types
pub trait KeypairMeta: KeyMeta {
    type PublicKeySize: ArrayLength<u8>;
    type KeypairSize: ArrayLength<u8>;
}
