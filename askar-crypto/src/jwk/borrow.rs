use alloc::{borrow::Cow, string::String};

use zeroize::Zeroize;

use super::parts::JwkParts;
use crate::error::Error;

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

impl<'a> From<Cow<'a, str>> for Jwk<'a> {
    fn from(jwk: Cow<'a, str>) -> Self {
        Jwk::Encoded(jwk)
    }
}

impl<'a> From<&'a str> for Jwk<'a> {
    fn from(jwk: &'a str) -> Self {
        Jwk::Encoded(Cow::Borrowed(jwk))
    }
}

impl<'a> From<String> for Jwk<'a> {
    fn from(jwk: String) -> Self {
        Jwk::Encoded(Cow::Owned(jwk))
    }
}

impl<'a> From<JwkParts<'a>> for Jwk<'a> {
    fn from(jwk: JwkParts<'a>) -> Self {
        Jwk::Parts(jwk)
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
