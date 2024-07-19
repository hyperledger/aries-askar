//! Elliptic curve ECDH and ECDSA support on curve secp256r1 using the iOS Secure Enclave and
//! Android Strongbox
//!
//! This module reuses functionality from [`super::p256`]

use super::{
    p256::{self, P256KeyPair, ES256_SIGNATURE_LENGTH},
    EcCurves, HasKeyAlg, HasKeyBackend, KeyAlg, KeyBackend,
};
use crate::{
    buffer::{SecretBytes, WriteBuffer},
    error::{Error, ErrorKind},
    generic_array::typenum::{U32, U33, U65},
    jwk::ToJwk,
    repr::{KeyMeta, KeyPublicBytes, KeypairMeta, ToPublicBytes},
    sign::{KeySigVerify, KeySign, SignatureType},
};
use secure_env::{
    error::SecureEnvError, Key as P256HardwareKeyReference, KeyOps, SecureEnvironment,
    SecureEnvironmentOps,
};

impl From<SecureEnvError> for Error {
    fn from(err: SecureEnvError) -> Self {
        let (kind, _msg) = match err {
            SecureEnvError::UnableToGenerateKey(s) => (ErrorKind::Invalid, s),
            SecureEnvError::UnableToGetKeyPairById(s) => (ErrorKind::Invalid, s),
            SecureEnvError::UnableToCreateSignature(s) => (ErrorKind::Invalid, s),
            SecureEnvError::UnableToGetPublicKey(s) => (ErrorKind::Invalid, s),

            #[cfg(target_os = "android")]
            SecureEnvError::HardwareBackedKeysAreNotSupported(s) => (ErrorKind::Custom, s),
            #[cfg(target_os = "android")]
            SecureEnvError::UnableToCreateJavaValue(s) => (ErrorKind::Custom, s),
            #[cfg(target_os = "android")]
            SecureEnvError::UnableToAttachJVMToThread(s) => (ErrorKind::Custom, s),
        };

        #[cfg(feature = "alloc")]
        return Self::from_msg(kind, alloc::boxed::Box::leak(_msg.into_boxed_str()));
        #[cfg(not(feature = "alloc"))]
        return Self {
            kind,
            message: None,
            #[cfg(feature = "std")]
            cause: None,
        };
    }
}

/// A P-256 (secp256r1) reference to a key pair stored in hardware
#[derive(Debug)]
pub struct P256HardwareKeyPair {
    pub(crate) inner: P256HardwareKeyReference,
    pub(crate) key_id: SecretBytes,
}

impl P256HardwareKeyPair {
    pub(crate) fn get_p256_keypair(&self) -> Result<P256KeyPair, Error> {
        let public_key = self.inner.get_public_key()?;
        P256KeyPair::from_public_bytes(&public_key)
    }

    /// Sign a message with the secret key
    pub fn sign(&self, message: &[u8]) -> Option<[u8; ES256_SIGNATURE_LENGTH]> {
        self.inner
            .sign(message)
            .ok()
            .and_then(|s| s.try_into().ok())
    }

    /// Verify a signature with the public key
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        if let Ok(keypair) = self.get_p256_keypair() {
            keypair.verify_signature(message, signature)
        } else {
            false
        }
    }

    /// For this method the `rng` source is disregarded and the Secure Elements source will be
    /// used.
    pub fn generate(id: &str) -> Result<Self, Error> {
        Ok(Self {
            inner: SecureEnvironment::generate_keypair(id)?,
            key_id: SecretBytes::from_slice(id.as_bytes()),
        })
    }

    /// Fetch the keypair from the Secure Element via the id
    pub fn from_id(id: &str) -> Result<Self, Error> {
        Ok(Self {
            inner: SecureEnvironment::get_keypair_by_id(id)?,
            key_id: SecretBytes::from_slice(id.as_bytes()),
        })
    }
}

impl ToPublicBytes for P256HardwareKeyPair {
    fn public_bytes_length(&self) -> Result<usize, Error> {
        Ok(p256::PUBLIC_KEY_LENGTH)
    }

    fn write_public_bytes(&self, out: &mut dyn WriteBuffer) -> Result<(), Error> {
        let public_key = self.inner.get_public_key()?;
        out.buffer_write(&public_key)
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

impl HasKeyBackend for P256HardwareKeyPair {
    fn key_backend(&self) -> KeyBackend {
        KeyBackend::SecureElement
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
