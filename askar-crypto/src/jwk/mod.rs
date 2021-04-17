#[cfg(feature = "alloc")]
use alloc::{borrow::Cow, string::String, vec::Vec};

use sha2::Sha256;

use crate::{
    buffer::{HashBuffer, WriteBuffer},
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
    fn to_jwk_encoder<B: WriteBuffer>(&self, enc: &mut JwkEncoder<B>) -> Result<(), Error>;

    fn to_jwk_thumbprint_buffer<B: WriteBuffer>(&self, output: &mut B) -> Result<(), Error> {
        let mut hasher = HashBuffer::<Sha256>::new();
        let mut buf = JwkEncoder::new(&mut hasher, JwkEncoderMode::Thumbprint)?;
        self.to_jwk_encoder(&mut buf)?;
        buf.finalize()?;
        let hash = hasher.finalize();
        output.write_with(43, |buf| {
            Ok(base64::encode_config_slice(
                &hash,
                base64::URL_SAFE_NO_PAD,
                buf,
            ))
        })?;
        Ok(())
    }

    #[cfg(feature = "alloc")]
    fn to_jwk_thumbprint(&self) -> Result<String, Error> {
        let mut v = Vec::with_capacity(43);
        self.to_jwk_thumbprint_buffer(&mut v)?;
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

pub trait FromJwk: Sized {
    fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let parts =
            serde_json::from_str(jwk).map_err(err_map!(InvalidData, "Error parsing JWK"))?;
        Self::from_jwk_parts(parts)
    }

    fn from_jwk_parts(jwk: JwkParts<'_>) -> Result<Self, Error>;
}
