pub use crate::crypto::{
    alg::KeyAlg,
    buffer::{SecretBytes, WriteBuffer},
    kdf::{ecdh_1pu::Ecdh1PU, ecdh_es::EcdhEs, KeyDerivation, KeyExchange},
};
use crate::{
    crypto::{
        alg::{AnyKey, AnyKeyCreate},
        encrypt::KeyAeadInPlace,
        jwk::{FromJwk, ToJwk},
        random::fill_random,
        sign::{KeySigVerify, KeySign},
        Error as CryptoError,
    },
    error::Error,
    storage::entry::{Entry, EntryTag},
};

/// Parameters defining a stored key
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct KeyParams {
    /// Associated key metadata
    #[serde(default, rename = "meta", skip_serializing_if = "Option::is_none")]
    pub metadata: Option<String>,

    /// An optional external reference for the key
    #[serde(default, rename = "ref", skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,

    /// The associated key data (JWK)
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
#[derive(Debug)]
pub struct LocalKey {
    pub(crate) inner: Box<AnyKey>,
    pub(crate) ephemeral: bool,
}

impl LocalKey {
    /// Create a new random key or keypair
    pub fn generate(alg: KeyAlg, ephemeral: bool) -> Result<Self, Error> {
        let inner = Box::<AnyKey>::generate(alg)?;
        Ok(Self { inner, ephemeral })
    }

    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let inner = Box::<AnyKey>::from_jwk(jwk)?;
        Ok(Self {
            inner,
            ephemeral: false,
        })
    }

    pub fn from_public_bytes(alg: KeyAlg, public: &[u8]) -> Result<Self, Error> {
        let inner = Box::<AnyKey>::from_public_bytes(alg, public)?;
        Ok(Self {
            inner,
            ephemeral: false,
        })
    }

    pub fn from_secret_bytes(alg: KeyAlg, secret: &[u8]) -> Result<Self, Error> {
        let inner = Box::<AnyKey>::from_secret_bytes(alg, secret)?;
        Ok(Self {
            inner,
            ephemeral: false,
        })
    }

    pub fn from_key_derivation(alg: KeyAlg, derive: impl KeyDerivation) -> Result<Self, Error> {
        let inner = Box::<AnyKey>::from_key_derivation(alg, derive)?;
        Ok(Self {
            inner,
            ephemeral: false,
        })
    }

    pub(crate) fn encode(&self) -> Result<SecretBytes, Error> {
        Ok(self.inner.to_jwk_secret()?)
    }

    pub fn algorithm(&self) -> &str {
        self.inner.algorithm().as_str()
    }

    pub fn to_jwk_public(&self) -> Result<String, Error> {
        Ok(self.inner.to_jwk_public()?)
    }

    pub fn to_jwk_secret(&self) -> Result<SecretBytes, Error> {
        Ok(self.inner.to_jwk_secret()?)
    }

    pub fn to_jwk_thumbprint(&self) -> Result<String, Error> {
        // FIXME add special case for BLS G1+G2 (two prints)
        Ok(self.inner.to_jwk_thumbprint()?)
    }

    pub fn aead_random_nonce(&self) -> Result<Vec<u8>, Error> {
        let nonce_len = self.inner.aead_params().nonce_length;
        if nonce_len == 0 {
            return Err(err_msg!(
                Unsupported,
                "Key type does not support AEAD encryption"
            ));
        }
        let buf = SecretBytes::new_with(nonce_len, fill_random);
        Ok(buf.into_vec())
    }

    pub fn aead_encrypt(&self, message: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        let params = self.inner.aead_params();
        let enc_size = message.len() + params.nonce_length + params.tag_length;
        let mut buf = SecretBytes::with_capacity(enc_size);
        buf.extend_from_slice(message);
        self.inner.encrypt_in_place(&mut buf, nonce, aad)?;
        Ok(buf.into_vec())
    }

    pub fn aead_decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<SecretBytes, Error> {
        let mut buf = SecretBytes::from_slice(ciphertext);
        self.inner.decrypt_in_place(&mut buf, nonce, aad)?;
        Ok(buf)
    }

    pub fn sign_message(&self, message: &[u8], sig_type: Option<&str>) -> Result<Vec<u8>, Error> {
        let mut sig = Vec::new();
        self.inner.write_signature(message, None, &mut sig)?;
        Ok(sig)
    }

    pub fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        sig_type: Option<&str>,
    ) -> Result<bool, Error> {
        Ok(self.inner.verify_signature(message, signature, None)?)
    }
}

impl KeyExchange for LocalKey {
    fn key_exchange_buffer(
        &self,
        other: &LocalKey,
        out: &mut dyn WriteBuffer,
    ) -> Result<(), CryptoError> {
        self.inner.key_exchange_buffer(&other.inner, out)
    }
}

/// A stored key entry
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyEntry {
    /// The key entry identifier
    pub(crate) name: String,
    /// The parameters defining the key
    pub(crate) params: KeyParams,
    /// Key algorithm
    pub(crate) alg: Option<String>,
    /// Thumbprints for the key
    pub(crate) thumbprints: Vec<String>,
    /// Thumbprints for the key
    pub(crate) tags: Vec<EntryTag>,
}

impl KeyEntry {
    /// Accessor for the key identity
    pub fn algorithm(&self) -> Option<&str> {
        self.alg.as_ref().map(String::as_ref)
    }

    /// Accessor for the key identity
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Determine if a key entry refers to a local or external key
    pub fn is_local(&self) -> bool {
        self.params.reference.is_none()
    }

    pub(crate) fn from_entry(entry: Entry) -> Result<Self, Error> {
        let params = KeyParams::from_slice(&entry.value)?;
        let mut alg = None;
        let mut thumbprints = Vec::new();
        let mut tags = entry.tags;
        let mut idx = 0;
        while idx < tags.len() {
            let tag = &mut tags[idx];
            let name = tag.name();
            if name.starts_with("user:") {
                tag.update_name(|tag| tag.replace_range(0..5, ""));
                idx += 1;
            } else if name == "alg" {
                alg.replace(tags.remove(idx).into_value());
            } else if name == "thumb" {
                thumbprints.push(tags.remove(idx).into_value());
            } else {
                // unrecognized tag
                tags.remove(idx).into_value();
            }
        }
        // keep sorted for checking equality
        thumbprints.sort();
        tags.sort();
        Ok(Self {
            name: entry.name,
            params,
            alg,
            thumbprints,
            tags,
        })
    }

    fn load_key(&mut self) -> Result<LocalKey, Error> {
        if let Some(key_data) = self.params.data.as_ref() {
            let inner = Box::<AnyKey>::from_jwk_slice(key_data.as_ref())?;
            Ok(LocalKey {
                inner,
                ephemeral: false,
            })
        } else {
            Err(err_msg!("Missing key data"))
        }
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
