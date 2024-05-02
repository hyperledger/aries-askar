//! Elliptic curve ECDH and ECDSA support on curve secp256r1 using the iOS Secure Enclave and
//! Android Strongbox
//!
//! This module reuses functionality from [`super::p256`]

use super::{
    p256::{P256KeyPair, ES256_SIGNATURE_LENGTH},
    EcCurves, HasKeyAlg, KeyAlg,
};
use crate::{
    buffer::WriteBuffer,
    error::{Error, ErrorKind},
    generic_array::typenum::{U32, U33, U65},
    jwk::ToJwk,
    repr::{KeyMeta, KeyPublicBytes, KeypairMeta},
    sign::{KeySigVerify, KeySign, SignatureType},
};
use secure_env::{
    error::SecureEnvError, Key as P256HardwareKeyReference, KeyOps, SecureEnvironment,
    SecureEnvironmentOps,
};

impl From<SecureEnvError> for Error {
    fn from(err: SecureEnvError) -> Self {
        let kind = match err {
            SecureEnvError::UnableToGenerateKey(_) => ErrorKind::Invalid,
            SecureEnvError::UnableToGetKeyPairById(_) => ErrorKind::Invalid,
            SecureEnvError::UnableToCreateSignature(_) => ErrorKind::Invalid,
            SecureEnvError::UnableToGetPublicKey(_) => ErrorKind::Invalid,
            SecureEnvError::HardwareBackedKeysAreNotSupported(_) => ErrorKind::Custom,
        };

        Self {
            kind,
            message: None,
            cause: None,
        }
    }
}

/// A P-256 (secp256r1) public key and reference to secret key stored in hardware
#[derive(Clone, Debug)]
pub struct P256HardwareKeyPair(P256HardwareKeyReference);

impl P256HardwareKeyPair {
    pub(crate) fn get_p256_keypair(&self) -> Result<P256KeyPair, Error> {
        let public_key = self.0.get_public_key()?;
        P256KeyPair::from_public_bytes(&public_key)
    }

    /// Sign a message with the secret key
    pub fn sign(&self, message: &[u8]) -> Option<[u8; ES256_SIGNATURE_LENGTH]> {
        self.0.sign(message).ok().and_then(|s| s.try_into().ok())
    }

    /// Verify a signature with the public key
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        if let Ok(keypair) = self.get_p256_keypair() {
            return keypair.verify_signature(message, signature);
        } else {
            false
        }
    }

    /// For this method the `rng` source is disregarded and the Secure Elements source will be
    /// used.
    pub fn generate(id: &str) -> Result<Self, Error> {
        Ok(Self(SecureEnvironment::generate_keypair(id)?))
    }

    /// Fetch the keypair from the Secure Element via the id
    pub fn from_id(id: &str) -> Result<Self, Error> {
        Ok(Self(SecureEnvironment::get_keypair_by_id(id)?))
    }
}

impl KeySigVerify for P256HardwareKeyPair {
    fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        sig_type: Option<SignatureType>,
    ) -> Result<bool, Error> {
        match sig_type {
            None | Some(SignatureType::ES256) => Ok(self.verify_signature(message, signature)),
            #[allow(unreachable_patterns)]
            _ => Err(err_msg!(Unsupported, "Unsupported signature type")),
        }
    }
}

impl KeySign for P256HardwareKeyPair {
    fn write_signature(
        &self,
        message: &[u8],
        sig_type: Option<SignatureType>,
        out: &mut dyn WriteBuffer,
    ) -> Result<(), Error> {
        match sig_type {
            None | Some(SignatureType::ES256) => {
                if let Some(sig) = self.sign(message) {
                    out.buffer_write(&sig[..])?;
                    Ok(())
                } else {
                    Err(err_msg!(Unsupported, "Undefined secret key"))
                }
            }
            #[allow(unreachable_patterns)]
            _ => Err(err_msg!(Unsupported, "Unsupported signature type")),
        }
    }
}

impl HasKeyAlg for P256HardwareKeyPair {
    fn algorithm(&self) -> KeyAlg {
        KeyAlg::EcCurve(EcCurves::Secp256r1)
    }
}

impl KeyMeta for P256HardwareKeyPair {
    type KeySize = U32;
}

impl KeypairMeta for P256HardwareKeyPair {
    type PublicKeySize = U33;
    type KeypairSize = U65;
}

impl ToJwk for P256HardwareKeyPair {
    fn encode_jwk(&self, enc: &mut dyn crate::jwk::JwkEncoder) -> Result<(), Error> {
        if enc.is_secret() {
            return Err(err_msg!(
                Unsupported,
                "Cannot create a JWK with secret attributes from a hardware bound key"
            ));
        }

        self.get_p256_keypair()?.encode_jwk(enc)
    }
}
