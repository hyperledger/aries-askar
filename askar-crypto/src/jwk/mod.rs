#[cfg(feature = "alloc")]
use alloc::{borrow::Cow, string::String, vec::Vec};

use sha2::Sha256;

use crate::{
    buffer::{HashBuffer, ResizeBuffer},
    error::Error,
};

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
    fn to_jwk_encoder(&self, enc: &mut JwkEncoder<'_>) -> Result<(), Error>;

    #[cfg(feature = "alloc")]
    fn to_jwk_thumbprint(&self) -> Result<String, Error> {
        let mut v = Vec::with_capacity(43);
        jwk_thumbprint_buffer(self, &mut v)?;
        Ok(String::from_utf8(v).unwrap())
    }

    #[cfg(feature = "alloc")]
    fn to_jwk_public(&self) -> Result<Jwk<'static>, Error> {
        let mut v = Vec::with_capacity(128);
        let mut buf = JwkEncoder::new(&mut v, JwkEncoderMode::PublicKey)?;
        self.to_jwk_encoder(&mut buf)?;
        buf.finalize()?;
        Ok(Jwk::Encoded(Cow::Owned(String::from_utf8(v).unwrap())))
    }

    #[cfg(feature = "alloc")]
    fn to_jwk_secret(&self) -> Result<Jwk<'static>, Error> {
        let mut v = Vec::with_capacity(128);
        let mut buf = JwkEncoder::new(&mut v, JwkEncoderMode::SecretKey)?;
        self.to_jwk_encoder(&mut buf)?;
        buf.finalize()?;
        Ok(Jwk::Encoded(Cow::Owned(String::from_utf8(v).unwrap())))
    }
}

pub fn jwk_thumbprint_buffer<K: ToJwk + ?Sized>(
    key: &K,
    output: &mut dyn ResizeBuffer,
) -> Result<(), Error> {
    let mut hasher = HashBuffer::<Sha256>::new();
    let mut buf = JwkEncoder::new(&mut hasher, JwkEncoderMode::Thumbprint)?;
    key.to_jwk_encoder(&mut buf)?;
    buf.finalize()?;
    let hash = hasher.finalize();
    base64::encode_config_slice(&hash, base64::URL_SAFE_NO_PAD, output.buffer_extend(43)?);
    Ok(())
}

pub trait FromJwk: Sized {
    fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let parts =
            serde_json::from_str(jwk).map_err(err_map!(InvalidData, "Error parsing JWK"))?;
        Self::from_jwk_parts(parts)
    }

    fn from_jwk_parts(jwk: JwkParts<'_>) -> Result<Self, Error>;
}
