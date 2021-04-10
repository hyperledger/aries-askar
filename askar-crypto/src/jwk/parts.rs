use core::{
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    ops::Deref,
};

use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

use super::ops::{KeyOps, KeyOpsSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JwkParts<'a> {
    // key type
    pub kty: &'a str,
    // key ID
    pub kid: OptStr<'a>,
    // curve type
    pub crv: OptStr<'a>,
    // curve key public y coordinate
    pub x: OptStr<'a>,
    // curve key public y coordinate
    pub y: OptStr<'a>,
    // curve key private key bytes
    pub d: OptStr<'a>,
    // used by symmetric keys like AES
    pub k: OptStr<'a>,
    // recognized key operations
    pub key_ops: Option<KeyOpsSet>,
}

#[derive(Copy, Clone, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct OptStr<'a>(Option<&'a str>);

impl OptStr<'_> {
    pub fn is_none(&self) -> bool {
        self.0.is_none()
    }

    pub fn to_option(&self) -> Option<&str> {
        self.0
    }
}

impl AsRef<[u8]> for OptStr<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.unwrap_or_default().as_bytes()
    }
}

impl Debug for OptStr<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.0 {
            None => f.write_str("None"),
            Some(s) => f.write_fmt(format_args!("{:?}", s)),
        }
    }
}

impl Deref for OptStr<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.unwrap_or_default()
    }
}

impl<'o> From<&'o str> for OptStr<'o> {
    fn from(s: &'o str) -> Self {
        Self(Some(s))
    }
}

impl<'o> From<Option<&'o str>> for OptStr<'o> {
    fn from(s: Option<&'o str>) -> Self {
        Self(s)
    }
}

impl PartialEq<Option<&str>> for OptStr<'_> {
    fn eq(&self, other: &Option<&str>) -> bool {
        self.0 == *other
    }
}

impl PartialEq<&str> for OptStr<'_> {
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

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
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
                kid: OptStr::from(kid),
                crv: OptStr::from(crv),
                x: OptStr::from(x),
                y: OptStr::from(y),
                d: OptStr::from(d),
                k: OptStr::from(k),
                key_ops,
            })
        } else {
            Err(serde::de::Error::custom("missing 'kty' property for JWK"))
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

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
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
                    return Err(serde::de::Error::custom(alloc::format!(
                        "duplicate key operation: {}",
                        op
                    )));
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
        let parts = serde_json::from_str::<JwkParts>(jwk).unwrap();
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
