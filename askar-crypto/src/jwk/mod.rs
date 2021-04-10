use alloc::{borrow::Cow, string::String, vec::Vec};

use zeroize::Zeroize;

use crate::{buffer::WriteBuffer, error::Error};

mod encode;
pub use encode::JwkEncoder;

mod ops;
pub use self::ops::{KeyOps, KeyOpsSet};

mod parts;
pub use self::parts::JwkParts;

#[derive(Clone, Debug)]
pub enum Jwk<'a> {
    Encoded(Cow<'a, str>),
    Parts(JwkParts<'a>),
}

impl Jwk<'_> {
    pub fn to_parts(&self) -> Result<JwkParts<'_>, Error> {
        match self {
            Self::Encoded(s) => Ok(
                serde_json::from_str(s.as_ref()).map_err(err_map!("Error deserializing JWK"))?
            ),
            Self::Parts(p) => Ok(*p),
        }
    }

    pub fn as_opt_str(&self) -> Option<&str> {
        match self {
            Self::Encoded(s) => Some(s.as_ref()),
            Self::Parts(_) => None,
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

pub trait KeyToJwk {
    const KTY: &'static str;

    fn to_jwk(&self) -> Result<Jwk<'static>, Error> {
        let mut v = Vec::with_capacity(128);
        let mut buf = JwkEncoder::new(&mut v, Self::KTY)?;
        self.to_jwk_buffer(&mut buf)?;
        buf.finalize()?;
        Ok(Jwk::Encoded(Cow::Owned(String::from_utf8(v).unwrap())))
    }

    fn to_jwk_buffer<B: WriteBuffer>(&self, buffer: &mut JwkEncoder<B>) -> Result<(), Error>;
}

pub trait KeyToJwkPrivate: KeyToJwk {
    fn to_jwk_private(&self) -> Result<Jwk<'static>, Error> {
        let mut v = Vec::with_capacity(128);
        let mut buf = JwkEncoder::new(&mut v, Self::KTY)?;
        self.to_jwk_buffer_private(&mut buf)?;
        buf.finalize()?;
        Ok(Jwk::Encoded(Cow::Owned(String::from_utf8(v).unwrap())))
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
