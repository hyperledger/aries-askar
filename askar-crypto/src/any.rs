use std::convert::TryFrom;

use super::alg::ed25519::{Ed25519KeyPair, Ed25519PublicKey};
use super::alg::k256::{K256SigningKey, K256VerifyingKey};
use super::alg::p256::{P256SigningKey, P256VerifyingKey};
use super::caps::{
    EcCurves, KeyAlg, KeyCapGetPublic, KeyCapSign, KeyCapVerify, KeyCategory, SignatureFormat,
    SignatureType,
};
// use super::store::KeyEntry;
use crate::error::Error;
use crate::types::SecretBytes;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AnyPublicKey {
    pub(crate) alg: KeyAlg,
    pub(crate) data: Vec<u8>,
}

impl AnyPublicKey {
    pub fn key_alg(&self) -> KeyAlg {
        self.alg
    }

    pub fn key_data(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl KeyCapVerify for AnyPublicKey {
    fn key_verify(
        &self,
        data: &[u8],
        signature: &[u8],
        sig_type: Option<SignatureType>,
        sig_format: Option<SignatureFormat>,
    ) -> Result<bool, Error> {
        match self.alg {
            KeyAlg::Ed25519 => Ed25519PublicKey::try_from(self)
                .and_then(|k| k.key_verify(data, signature, sig_type, sig_format)),
            KeyAlg::Ecdsa(EcCurves::Secp256k1) => K256VerifyingKey::try_from(self)
                .and_then(|k| k.key_verify(data, signature, sig_type, sig_format)),
            KeyAlg::Ecdsa(EcCurves::Secp256r1) => P256VerifyingKey::try_from(self)
                .and_then(|k| k.key_verify(data, signature, sig_type, sig_format)),
            _ => Err(err_msg!(
                Unsupported,
                "Signature verification not supported for this key type"
            )),
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
    fn key_sign(&self, data: &[u8], sig_type: Option<SignatureType>) -> Result<Vec<u8>, Error> {
        match self.alg {
            KeyAlg::Ed25519 => {
                Ed25519KeyPair::try_from(self).and_then(|k| k.key_sign(data, sig_type, sig_format))
            }
            KeyAlg::Ecdsa(EcCurves::Secp256k1) => {
                K256SigningKey::try_from(self).and_then(|k| k.key_sign(data, sig_type, sig_format))
            }
            KeyAlg::Ecdsa(EcCurves::Secp256r1) => {
                P256SigningKey::try_from(self).and_then(|k| k.key_sign(data, sig_type, sig_format))
            }
            _ => Err(err_msg!(
                Unsupported,
                "Signing not supported for this key type"
            )),
        }
    }
}

impl KeyCapVerify for AnyPrivateKey {
    fn key_verify(
        &self,
        data: &[u8],
        signature: &[u8],
        sig_type: Option<SignatureType>,
        sig_format: Option<SignatureFormat>,
    ) -> Result<bool, Error> {
        match self.alg {
            KeyAlg::Ed25519 => Ed25519KeyPair::try_from(self)
                .and_then(|k| k.key_verify(data, signature, sig_type, sig_format)),
            KeyAlg::Ecdsa(EcCurves::Secp256k1) => K256SigningKey::try_from(self)
                .and_then(|k| k.key_verify(data, signature, sig_type, sig_format)),
            KeyAlg::Ecdsa(EcCurves::Secp256r1) => P256SigningKey::try_from(self)
                .and_then(|k| k.key_verify(data, signature, sig_type, sig_format)),
            _ => Err(err_msg!(
                Unsupported,
                "Signature verification not supported for this key type"
            )),
        }
    }
}
