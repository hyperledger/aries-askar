use std::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use zeroize::Zeroize;

pub use crate::crypto::KeyAlg;

use super::entry::{sorted_tags, EntryTag};
use crate::{crypto::buffer::SecretBytes, error::Error};

/// Categories of keys supported by the default KMS
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
pub enum KeyCategory {
    /// A private key or keypair
    PrivateKey,
    /// A public key
    PublicKey,
}

impl KeyCategory {
    /// Get a reference to a string representing the `KeyCategory`
    pub fn as_str(&self) -> &str {
        match self {
            Self::PrivateKey => "private",
            Self::PublicKey => "public",
        }
    }

    /// Convert the `KeyCategory` into an owned string
    pub fn to_string(&self) -> String {
        self.as_str().to_string()
    }
}

// serde_as_str_impl!(KeyCategory);

impl AsRef<str> for KeyCategory {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for KeyCategory {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "private" => Self::PrivateKey,
            "public" => Self::PublicKey,
            _ => return Err(err_msg!("Unknown key category: {}", s)),
        })
    }
}

impl Display for KeyCategory {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parameters defining a stored key
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct KeyParams {
    /// Associated key metadata
    #[serde(default, rename = "meta", skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,

    /// An optional external reference for the key
    #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,

    /// The associated key data in JWK format
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<SecretBytes>,
}

impl KeyParams {
    pub(crate) fn to_bytes(&self) -> Result<SecretBytes, Error> {
        serde_cbor::to_vec(self)
            .map(SecretBytes::from)
            .map_err(|e| err_msg!(Unexpected, "Error serializing key params: {}", e))
    }

    pub(crate) fn from_slice(params: &[u8]) -> Result<KeyParams, Error> {
        let result = serde_cbor::from_slice(params)
            .map_err(|e| err_msg!(Unexpected, "Error deserializing key params: {}", e));
        result
    }
}

/// A stored key entry
#[derive(Clone, Debug, Eq)]
pub struct KeyEntry {
    /// The category of the key entry (public or private)
    pub category: KeyCategory,
    /// The key entry identifier
    pub ident: String,
    /// The parameters defining the key
    pub params: KeyParams,
    /// Tags associated with the key entry record
    pub tags: Option<Vec<EntryTag>>,
}

impl KeyEntry {
    /// Determine if a key entry refers to a local or external key
    pub fn is_local(&self) -> bool {
        self.params.reference.is_none()
    }

    /// Fetch the associated key data
    pub fn key_data(&self) -> Option<&[u8]> {
        self.params.data.as_ref().map(AsRef::as_ref)
    }

    pub(crate) fn sorted_tags(&self) -> Option<Vec<&EntryTag>> {
        self.tags.as_ref().and_then(sorted_tags)
    }
}

impl PartialEq for KeyEntry {
    fn eq(&self, rhs: &Self) -> bool {
        self.category == rhs.category
            && self.ident == rhs.ident
            && self.params == rhs.params
            && self.sorted_tags() == rhs.sorted_tags()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_params_roundtrip() {
        let params = KeyParams {
            metadata: Some("meta".to_string()),
            reference: None,
            data: Some(SecretBytes::from(vec![0, 0, 0, 0])),
        };
        let enc_params = params.to_bytes().unwrap();
        let p2 = KeyParams::from_slice(&enc_params).unwrap();
        assert_eq!(p2, params);
    }
}
