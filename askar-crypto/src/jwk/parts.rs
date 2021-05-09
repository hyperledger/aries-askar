use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};

#[cfg(feature = "arbitrary")]
use arbitrary::Arbitrary;
use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

use super::ops::{KeyOps, KeyOpsSet};
use crate::error::Error;

/// A parsed JWK
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
pub struct JwkParts<'a> {
    /// Key type
    pub kty: &'a str,
    /// Key ID
    pub kid: OptAttr<'a>,
    /// Curve type
    pub crv: OptAttr<'a>,
    /// Curve key public x coordinate
    pub x: OptAttr<'a>,
    /// Curve key public y coordinate
    pub y: OptAttr<'a>,
    /// Curve key private key bytes
    pub d: OptAttr<'a>,
    /// Used by symmetric keys like AES
    pub k: OptAttr<'a>,
    /// Recognized key operations
    pub key_ops: Option<KeyOpsSet>,
}

impl<'de> JwkParts<'de> {
    /// Parse a JWK from a string reference
    pub fn from_str(jwk: &'de str) -> Result<Self, Error> {
        let (parts, _read) =
            serde_json_core::from_str(jwk).map_err(err_map!(InvalidData, "Error parsing JWK"))?;
        Ok(parts)
    }

    /// Parse a JWK from a byte slice
    pub fn from_slice(jwk: &'de [u8]) -> Result<Self, Error> {
        let (parts, _read) =
            serde_json_core::from_slice(jwk).map_err(err_map!(InvalidData, "Error parsing JWK"))?;
        Ok(parts)
    }
}

#[derive(Copy, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(Arbitrary))]
#[repr(transparent)]
pub struct OptAttr<'a>(Option<&'a str>);

impl OptAttr<'_> {
    pub fn is_none(&self) -> bool {
        self.0.is_none()
    }

    pub fn is_some(&self) -> bool {
        self.0.is_some()
    }

    pub fn to_option(&self) -> Option<&str> {
        self.0
    }

    pub fn decode_base64(&self, output: &mut [u8]) -> Result<usize, Error> {
        if let Some(s) = self.0 {
            let max_input = (output.len() * 4 + 2) / 3; // ceil(4*n/3)
            if s.len() > max_input {
                Err(err_msg!(InvalidData, "Base64 length exceeds max"))
            } else {
                base64::decode_config_slice(s, base64::URL_SAFE_NO_PAD, output)
                    .map_err(|_| err_msg!(InvalidData, "Base64 decode error"))
            }
        } else {
            Err(err_msg!(InvalidData, "Empty attribute"))
        }
    }
}

impl Debug for OptAttr<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.0 {
            None => f.write_str("None"),
            Some(s) => f.write_fmt(format_args!("{:?}", s)),
        }
    }
}

impl AsRef<str> for OptAttr<'_> {
    fn as_ref(&self) -> &str {
        self.0.unwrap_or_default()
    }
}

impl<'o> From<&'o str> for OptAttr<'o> {
    fn from(s: &'o str) -> Self {
        Self(Some(s))
    }
}

impl<'o> From<Option<&'o str>> for OptAttr<'o> {
    fn from(s: Option<&'o str>) -> Self {
        Self(s)
    }
}

impl PartialEq<Option<&str>> for OptAttr<'_> {
    fn eq(&self, other: &Option<&str>) -> bool {
        self.0 == *other
    }
}

impl PartialEq<&str> for OptAttr<'_> {
    fn eq(&self, other: &&str) -> bool {
        match self.0 {
            None => false,
            Some(s) => (*other) == s,
        }
    }
}

struct JwkMapVisitor<'de>(PhantomData<&'de ()>);

impl<'de> Visitor<'de> for JwkMapVisitor<'de> {
    type Value = JwkParts<'de>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an object representing a JWK")
    }

    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut kty = None;
        let mut kid = None;
        let mut crv = None;
        let mut x = None;
        let mut y = None;
        let mut d = None;
        let mut k = None;
        let mut key_ops = None;

        while let Some(key) = access.next_key::<&str>()? {
            match key {
                "kty" => kty = Some(access.next_value()?),
                "kid" => kid = Some(access.next_value()?),
                "crv" => crv = Some(access.next_value()?),
                "x" => x = Some(access.next_value()?),
                "y" => y = Some(access.next_value()?),
                "d" => d = Some(access.next_value()?),
                "k" => k = Some(access.next_value()?),
                "use" => {
                    let ops = match access.next_value()? {
                        "enc" => {
                            KeyOps::Encrypt | KeyOps::Decrypt | KeyOps::WrapKey | KeyOps::UnwrapKey
                        }
                        "sig" => KeyOps::Sign | KeyOps::Verify,
                        _ => KeyOpsSet::new(),
                    };
                    if !ops.is_empty() {
                        key_ops = Some(key_ops.unwrap_or_default() | ops);
                    }
                }
                "key_ops" => key_ops = Some(access.next_value()?),
                _ => (),
            }
        }

        if let Some(kty) = kty {
            Ok(JwkParts {
                kty,
                kid: kid.into(),
                crv: crv.into(),
                x: x.into(),
                y: y.into(),
                d: d.into(),
                k: k.into(),
                key_ops,
            })
        } else {
            Err(serde::de::Error::missing_field("kty"))
        }
    }
}

impl<'de> Deserialize<'de> for JwkParts<'de> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(JwkMapVisitor(PhantomData))
    }
}

struct KeyOpsVisitor;

impl<'de> Visitor<'de> for KeyOpsVisitor {
    type Value = KeyOpsSet;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an array of key operations")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut ops = KeyOpsSet::new();
        while let Some(op) = seq.next_element()? {
            if let Some(op) = KeyOps::from_str(op) {
                if ops & op {
                    return Err(serde::de::Error::duplicate_field(op.as_str()));
                } else {
                    ops = ops | op;
                }
            }
        }
        Ok(ops)
    }
}

impl<'de> Deserialize<'de> for KeyOpsSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(KeyOpsVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sample_okp() {
        let jwk = r#"{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
            "key_ops": ["sign", "verify"],
            "kid": "FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ"
        }"#;
        let parts = JwkParts::from_str(jwk).unwrap();
        assert_eq!(parts.kty, "OKP");
        assert_eq!(
            parts.kid,
            Some("FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ")
        );
        assert_eq!(parts.crv, Some("Ed25519"));
        assert_eq!(parts.x, Some("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"));
        assert_eq!(parts.y, None);
        assert_eq!(parts.d, Some("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"));
        assert_eq!(parts.k, None);
        assert_eq!(parts.key_ops, Some(KeyOps::Sign | KeyOps::Verify));
    }
}
