use std::borrow::Cow;
use std::convert::Infallible;
use std::fmt::{self, Debug, Display, Formatter};
use std::mem::ManuallyDrop;
use std::ops::Deref;
use std::ptr;
use std::str::FromStr;

use indy_utils::keys::{EncodedVerKey, KeyType as IndyKeyAlg, PrivateKey, VerKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::Error;
use crate::types::{sorted_tags, EntryTag, SecretBytes};

#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
pub enum KeyAlg {
    ED25519,
    Other(String),
}

serde_as_str_impl!(KeyAlg);

impl KeyAlg {
    pub fn as_str(&self) -> &str {
        match self {
            Self::ED25519 => "ed25519",
            Self::Other(other) => other.as_str(),
        }
    }
}

impl AsRef<str> for KeyAlg {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for KeyAlg {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "ed25519" => Self::ED25519,
            other => Self::Other(other.to_owned()),
        })
    }
}

impl Display for KeyAlg {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
pub enum KeyCategory {
    PublicKey,
    KeyPair,
    Other(String),
}

impl KeyCategory {
    pub fn as_str(&self) -> &str {
        match self {
            Self::PublicKey => "public",
            Self::KeyPair => "keypair",
            Self::Other(other) => other.as_str(),
        }
    }

    pub fn into_string(self) -> String {
        match self {
            Self::Other(other) => other,
            _ => self.as_str().to_owned(),
        }
    }
}

serde_as_str_impl!(KeyCategory);

impl AsRef<str> for KeyCategory {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for KeyCategory {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "public" => Self::PublicKey,
            "keypair" => Self::KeyPair,
            other => Self::Other(other.to_owned()),
        })
    }
}

impl Display for KeyCategory {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct KeyParams {
    pub alg: KeyAlg,
    #[serde(default, rename = "meta", skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,
    #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(
        default,
        rename = "pub",
        skip_serializing_if = "Option::is_none",
        with = "crate::serde_utils::as_base58"
    )]
    pub pub_key: Option<Vec<u8>>,
    #[serde(
        default,
        rename = "prv",
        skip_serializing_if = "Option::is_none",
        with = "crate::serde_utils::as_base58"
    )]
    pub prv_key: Option<SecretBytes>,
}

impl KeyParams {
    pub fn to_vec(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(self)
            .map_err(|e| err_msg!(Unexpected, "Error serializing key params: {}", e))
    }

    pub fn from_slice(params: &[u8]) -> Result<KeyParams, Error> {
        let result = serde_json::from_slice(params)
            .map_err(|e| err_msg!(Unexpected, "Error deserializing key params: {}", e));
        result
    }
}

impl Drop for KeyParams {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl Zeroize for KeyParams {
    fn zeroize(&mut self) {
        self.prv_key.zeroize();
    }
}

#[derive(Clone, Eq)]
pub struct KeyEntry {
    pub category: KeyCategory,
    pub ident: String,
    pub params: KeyParams,
    pub tags: Option<Vec<EntryTag>>,
}

impl KeyEntry {
    pub(crate) fn into_parts(self) -> (KeyCategory, String, KeyParams, Option<Vec<EntryTag>>) {
        let slf = ManuallyDrop::new(self);
        unsafe {
            (
                ptr::read(&slf.category),
                ptr::read(&slf.ident),
                ptr::read(&slf.params),
                ptr::read(&slf.tags),
            )
        }
    }

    pub fn is_local(&self) -> bool {
        self.params.reference.is_none()
    }

    pub fn encoded_verkey(&self) -> Result<EncodedVerKey, Error> {
        Ok(self
            .verkey()?
            .as_base58()
            .map_err(err_map!(Unexpected, "Error encoding verkey"))?)
    }

    pub fn verkey(&self) -> Result<VerKey, Error> {
        match (&self.params.alg, &self.params.pub_key) {
            (KeyAlg::ED25519, Some(pub_key)) => Ok(VerKey::new(pub_key, Some(IndyKeyAlg::ED25519))),
            (_, None) => Err(err_msg!(Input, "Undefined public key")),
            _ => Err(err_msg!(Unsupported, "Unsupported key algorithm")),
        }
    }

    pub fn private_key(&self) -> Result<PrivateKey, Error> {
        match (&self.params.alg, &self.params.prv_key) {
            (KeyAlg::ED25519, Some(prv_key)) => {
                Ok(PrivateKey::new(prv_key, Some(IndyKeyAlg::ED25519)))
            }
            (_, None) => Err(err_msg!(Input, "Undefined private key")),
            _ => Err(err_msg!(Unsupported, "Unsupported key algorithm")),
        }
    }

    pub fn sorted_tags(&self) -> Option<Vec<&EntryTag>> {
        self.tags.as_ref().and_then(sorted_tags)
    }
}

impl Debug for KeyEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyEntry")
            .field("category", &self.category)
            .field("ident", &self.ident)
            .field("params", &self.params)
            .field("tags", &self.tags)
            .finish()
    }
}

impl Drop for KeyEntry {
    fn drop(&mut self) {
        // currently nothing - KeyParams will zeroize itself on drop
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

#[derive(Clone)]
pub struct PassKey<'a>(Option<Cow<'a, str>>);

impl<'a> PassKey<'a> {
    pub fn as_ref(&self) -> PassKey<'_> {
        PassKey(Some(Cow::Borrowed(&**self)))
    }

    pub fn is_none(&self) -> bool {
        self.0.is_none()
    }

    pub fn into_owned(self) -> PassKey<'static> {
        let mut slf = ManuallyDrop::new(self);
        let val = slf.0.take();
        PassKey(match val {
            None => None,
            Some(Cow::Borrowed(s)) => Some(Cow::Owned(s.to_string())),
            Some(Cow::Owned(s)) => Some(Cow::Owned(s)),
        })
    }
}

impl<'a> Debug for PassKey<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if cfg!(test) {
            f.debug_tuple("PassKey").field(&*self).finish()
        } else {
            f.debug_tuple("PassKey").field(&"<hidden>").finish()
        }
    }
}

impl<'a> Default for PassKey<'a> {
    fn default() -> Self {
        Self(None)
    }
}

impl<'a> Deref for PassKey<'a> {
    type Target = str;

    fn deref(&self) -> &str {
        match self.0.as_ref() {
            None => "",
            Some(s) => s.as_ref(),
        }
    }
}

impl<'a> Drop for PassKey<'a> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<'a> From<&'a str> for PassKey<'a> {
    fn from(inner: &'a str) -> Self {
        Self(Some(Cow::Borrowed(inner)))
    }
}

impl<'a> From<String> for PassKey<'a> {
    fn from(inner: String) -> Self {
        Self(Some(Cow::Owned(inner)))
    }
}

impl<'a> From<Option<&'a str>> for PassKey<'a> {
    fn from(inner: Option<&'a str>) -> Self {
        Self(inner.map(Cow::Borrowed))
    }
}

impl<'a, 'b> PartialEq<PassKey<'b>> for PassKey<'a> {
    fn eq(&self, other: &PassKey<'b>) -> bool {
        &**self == &**other
    }
}

impl<'a> Eq for PassKey<'a> {}

impl<'a> Zeroize for PassKey<'a> {
    fn zeroize(&mut self) {
        match self.0.take() {
            Some(Cow::Owned(mut s)) => {
                s.zeroize();
            }
            _ => (),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_params_roundtrip() {
        let params = KeyParams {
            alg: KeyAlg::ED25519,
            metadata: Some("meta".to_string()),
            reference: None,
            pub_key: Some(vec![0, 0, 0, 0]),
            prv_key: Some(vec![1, 1, 1, 1].into()),
        };
        let enc_params = params.to_vec().unwrap();
        let p2 = KeyParams::from_slice(&enc_params).unwrap();
        assert_eq!(p2, params);
    }
}
