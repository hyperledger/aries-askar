#[cfg(feature = "alloc")]
use alloc::{borrow::Cow, string::String, vec::Vec};

use crate::{buffer::WriteBuffer, error::Error};

#[cfg(feature = "alloc")]
mod borrow;
#[cfg(feature = "alloc")]
pub use self::borrow::Jwk;

mod encode;
pub use self::encode::{JwkEncoder, JwkEncoderMode};

mod ops;
pub use self::ops::{KeyOps, KeyOpsSet};

mod parts;
pub use self::parts::JwkParts;

pub trait ToJwk {
    fn to_jwk_buffer<B: WriteBuffer>(&self, buffer: &mut JwkEncoder<B>) -> Result<(), Error>;

    #[cfg(feature = "alloc")]
    fn to_jwk_public(&self) -> Result<Jwk<'static>, Error> {
        let mut v = Vec::with_capacity(128);
        let mut buf = JwkEncoder::new(&mut v, JwkEncoderMode::PublicKey)?;
        self.to_jwk_buffer(&mut buf)?;
        buf.finalize()?;
        Ok(Jwk::Encoded(Cow::Owned(String::from_utf8(v).unwrap())))
    }

    #[cfg(feature = "alloc")]
    fn to_jwk_secret(&self) -> Result<Jwk<'static>, Error> {
        let mut v = Vec::with_capacity(128);
        let mut buf = JwkEncoder::new(&mut v, JwkEncoderMode::SecretKey)?;
        self.to_jwk_buffer(&mut buf)?;
        buf.finalize()?;
        Ok(Jwk::Encoded(Cow::Owned(String::from_utf8(v).unwrap())))
    }
}

pub trait FromJwk: Sized {
    #[cfg(feature = "alloc")]
    fn from_jwk(jwk: Jwk<'_>) -> Result<Self, Error> {
        let parts = jwk.to_parts()?;
        Self::from_jwk_parts(parts)
    }

    fn from_jwk_parts(jwk: JwkParts<'_>) -> Result<Self, Error>;
}
