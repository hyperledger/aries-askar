use std::convert::TryFrom;

use super::alg::edwards::Ed25519KeyPair;
use super::caps::{
    KeyAlg, KeyCapGetPublic, KeyCapSign, KeyCategory, SignatureFormat, SignatureType,
};
use super::store::KeyEntry;
use crate::error::Error;
use crate::types::SecretBytes;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AnyPublicKey {
    pub alg: KeyAlg,
    pub data: Vec<u8>,
}

impl TryFrom<KeyEntry> for AnyPublicKey {
    type Error = Error;

    fn try_from(value: KeyEntry) -> Result<Self, Self::Error> {
        if value.category == KeyCategory::PublicKey {
            if let Some(data) = value.params.data {
                Ok(AnyPublicKey {
                    alg: value.params.alg,
                    data: data.into_vec(),
                })
            } else {
                Err(err_msg!(Unsupported, "Missing public key raw data"))
            }
        } else {
            Err(err_msg!(Unsupported, "Not a public key entry"))
        }
    }
}

#[derive(Debug)]
pub struct AnyPrivateKey {
    pub alg: KeyAlg,
    pub data: SecretBytes,
}

impl KeyCapGetPublic for AnyPrivateKey {
    fn key_get_public(&self, alg: Option<KeyAlg>) -> Result<AnyPublicKey, Error> {
        unimplemented!();
    }
}

impl KeyCapSign for AnyPrivateKey {
    fn key_sign(
        &self,
        data: &[u8],
        sig_type: Option<SignatureType>,
        sig_format: Option<SignatureFormat>,
    ) -> Result<Vec<u8>, Error> {
        match self.alg {
            KeyAlg::ED25519 => {
                Ed25519KeyPair::try_from(self).and_then(|k| k.key_sign(data, sig_type, sig_format))
            }
            _ => Err(err_msg!(
                Unsupported,
                "Signing not supported for this key type"
            )),
        }
    }
}

impl TryFrom<KeyEntry> for AnyPrivateKey {
    type Error = Error;

    fn try_from(value: KeyEntry) -> Result<Self, Self::Error> {
        if value.category == KeyCategory::PrivateKey {
            if let Some(data) = value.params.data {
                Ok(AnyPrivateKey {
                    alg: value.params.alg,
                    data,
                })
            } else {
                Err(err_msg!(Unsupported, "Missing private key raw data"))
            }
        } else {
            Err(err_msg!(Unsupported, "Not a private key entry"))
        }
    }
}
