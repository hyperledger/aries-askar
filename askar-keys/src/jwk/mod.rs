use alloc::{borrow::Cow, string::String, vec::Vec};

use zeroize::Zeroize;

use crate::{buffer::WriteBuffer, error::Error};

mod ops;
pub use self::ops::{KeyOps, KeyOpsSet};

mod parse;
pub use self::parse::JwkParts;

#[derive(Clone, Debug)]
pub enum Jwk<'a> {
    Encoded(Cow<'a, str>),
    Parts(JwkParts<'a>),
}

impl Jwk<'_> {
    pub fn to_parts(&self) -> Result<Jwk<'_>, Error> {
        match self {
            Self::Encoded(s) => Ok(Jwk::Parts(
                serde_json::from_str(s.as_ref()).map_err(err_map!("Error deserializing JWK"))?,
            )),
            Self::Parts(p) => Ok(Jwk::Parts(*p)),
        }
    }
}

impl Zeroize for Jwk<'_> {
    fn zeroize(&mut self) {
        match self {
            Self::Encoded(Cow::Owned(s)) => s.zeroize(),
            Self::Encoded(_) => (),
            Self::Parts(..) => (),
        }
    }
}

struct JwkBuffer<'s, B>(&'s mut B);

impl<B: WriteBuffer> bs58::encode::EncodeTarget for JwkBuffer<'_, B> {
    fn encode_with(
        &mut self,
        max_len: usize,
        f: impl for<'a> FnOnce(&'a mut [u8]) -> Result<usize, bs58::encode::Error>,
    ) -> Result<usize, bs58::encode::Error> {
        if let Some(ext) = self.0.extend_buffer(max_len) {
            let len = f(ext)?;
            if len < max_len {
                self.0.truncate_by(max_len - len);
            }
            Ok(len)
        } else {
            Err(bs58::encode::Error::BufferTooSmall)
        }
    }
}

pub struct JwkEncoder<'b, B: WriteBuffer> {
    buffer: &'b mut B,
}

impl<'b, B: WriteBuffer> JwkEncoder<'b, B> {
    pub fn new(buffer: &'b mut B, kty: &str) -> Result<Self, Error> {
        buffer.extend_from_slice(b"{\"kty\":\"")?;
        buffer.extend_from_slice(kty.as_bytes())?;
        buffer.extend_from_slice(b"\"")?;
        Ok(Self { buffer })
    }

    pub fn add_str(&mut self, key: &str, value: &str) -> Result<(), Error> {
        let buffer = &mut *self.buffer;
        buffer.extend_from_slice(b",\"")?;
        buffer.extend_from_slice(key.as_bytes())?;
        buffer.extend_from_slice(b"\":\"")?;
        buffer.extend_from_slice(value.as_bytes())?;
        buffer.extend_from_slice(b"\"")?;
        Ok(())
    }

    pub fn add_as_base58(&mut self, key: &str, value: &[u8]) -> Result<(), Error> {
        let buffer = &mut *self.buffer;
        buffer.extend_from_slice(b",\"")?;
        buffer.extend_from_slice(key.as_bytes())?;
        buffer.extend_from_slice(b"\":\"")?;
        bs58::encode(value)
            .into(JwkBuffer(buffer))
            .map_err(|_| err_msg!("buffer too small"))?;
        buffer.extend_from_slice(b"\"")?;
        Ok(())
    }

    pub fn add_key_ops(&mut self, ops: impl Into<KeyOpsSet>) -> Result<(), Error> {
        let buffer = &mut *self.buffer;
        buffer.extend_from_slice(b",\"key_ops\":[")?;
        for (idx, op) in ops.into().into_iter().enumerate() {
            if idx > 0 {
                buffer.extend_from_slice(b",\"")?;
            } else {
                buffer.extend_from_slice(b"\"")?;
            }
            buffer.extend_from_slice(op.as_str().as_bytes())?;
            buffer.extend_from_slice(b"\"")?;
        }
        buffer.extend_from_slice(b"]")?;
        Ok(())
    }

    pub fn finalize(self) -> Result<(), Error> {
        self.buffer.extend_from_slice(b"}")?;
        Ok(())
    }
}

pub trait KeyToJwk {
    const KTY: &'static str;

    fn to_jwk(&self) -> Result<String, Error> {
        let mut v = Vec::with_capacity(128);
        let mut buf = JwkEncoder::new(&mut v, Self::KTY)?;
        self.to_jwk_buffer(&mut buf)?;
        Ok(String::from_utf8(v).unwrap())
    }

    fn to_jwk_buffer<B: WriteBuffer>(&self, buffer: &mut JwkEncoder<B>) -> Result<(), Error>;
}

pub trait KeyToJwkPrivate: KeyToJwk {
    fn to_jwk_private(&self) -> Result<String, Error> {
        let mut v = Vec::with_capacity(128);
        let mut buf = JwkEncoder::new(&mut v, Self::KTY)?;
        self.to_jwk_buffer_private(&mut buf)?;
        Ok(String::from_utf8(v).unwrap())
    }

    fn to_jwk_buffer_private<B: WriteBuffer>(
        &self,
        buffer: &mut JwkEncoder<B>,
    ) -> Result<(), Error>;
}

// pub trait JwkBuilder<'s> {
//     // key type
//     kty: &'a str,
//     // curve type
//     crv: Option<&'a str>,
//     // curve key public y coordinate
//     x: Option<&'a str>,
//     // curve key public y coordinate
//     y: Option<&'a str>,
//     // curve key private key bytes
//     d: Option<&'a str>,
//     // used by symmetric keys like AES
//     k: Option<&'a str>,
// }

// impl<'de> Serialize for JwkParts<'de> {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         let ret = serializer.serialize_map(None).unwrap();

//         let add_attr = |name: &str, val: &str| {
//             ret.serialize_key(name);
//             ret.serialize_value(val);
//         };

//         add_attr("kty", self.kty.as_ref());
//         if let Some(attr) = self.crv.as_ref() {
//             add_attr("crv", attr.as_ref());
//             if let Some(attr) = self.x.as_ref() {
//                 add_attr("x", attr.as_ref());
//             }
//             if let Some(attr) = self.y.as_ref() {
//                 add_attr("y", attr.as_ref());
//             }
//             if let Some(attr) = self.d.as_ref() {
//                 add_attr("d", attr.as_ref());
//             }
//         }
//         if let Some(attr) = self.k.as_ref() {
//             add_attr("k", attr.as_ref());
//         }
//         ret.end()
//     }
// }
