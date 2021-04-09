use core::{fmt, marker::PhantomData};

use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

use super::ops::{KeyOps, KeyOpsSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JwkParts<'a> {
    // key type
    kty: &'a str,
    // key ID
    kid: Option<&'a str>,
    // curve type
    crv: Option<&'a str>,
    // curve key public y coordinate
    x: Option<&'a str>,
    // curve key public y coordinate
    y: Option<&'a str>,
    // curve key private key bytes
    d: Option<&'a str>,
    // used by symmetric keys like AES
    k: Option<&'a str>,
    // recognized key operations
    key_ops: Option<KeyOpsSet>,
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
                "key_ops" => key_ops = Some(access.next_value()?),
                _ => (),
            }
        }

        if let Some(kty) = kty {
            Ok(JwkParts {
                kty,
                kid,
                crv,
                x,
                y,
                d,
                k,
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
        assert_eq!(
            serde_json::from_str::<JwkParts>(jwk).unwrap(),
            JwkParts {
                kty: "OKP",
                kid: Some("FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ"),
                crv: Some("Ed25519"),
                x: Some("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"),
                y: None,
                d: Some("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"),
                k: None,
                key_ops: Some(KeyOps::Sign | KeyOps::Verify)
            }
        )
    }
}
