use std::str::FromStr;
use std::{borrow::Cow, panic::AssertUnwindSafe};

use super::enc::{Encrypted, ToDecrypt};
pub use crate::crypto::{
    alg::{AnyKey, KeyAlg},
    buffer::{SecretBytes, WriteBuffer},
    encrypt::KeyAeadParams,
};
use crate::{
    crypto::{
        alg::{bls::BlsKeyGen, AnyKeyCreate, BlsCurves},
        encrypt::KeyAeadInPlace,
        jwk::{FromJwk, ToJwk},
        kdf::KeyDerivation,
        random::{fill_random, RandomDet},
        repr::{DynPublicBytes, DynSecretBytes},
        sign::{KeySigVerify, KeySign, SignatureType},
    },
    error::Error,
};

/// A stored key entry
#[derive(Debug)]
pub struct LocalKey {
    pub(crate) inner: AssertUnwindSafe<Box<dyn AnyKey>>,
    pub(crate) ephemeral: bool,
}

impl LocalKey {
    #[inline]
    pub(crate) fn new(inner: Box<dyn AnyKey>, ephemeral: bool) -> Self {
        Self {
            inner: AssertUnwindSafe(inner),
            ephemeral,
        }
    }

    /// Create a new random key or keypair
    pub fn generate(alg: KeyAlg, ephemeral: bool) -> Result<Self, Error> {
        let inner = Box::<dyn AnyKey>::random(alg)?;
        Ok(Self::new(inner, ephemeral))
    }

    /// Create a new deterministic key or keypair
    pub fn from_seed(alg: KeyAlg, seed: &[u8], method: Option<&str>) -> Result<Self, Error> {
        let inner = match method {
            Some("bls_keygen") => Box::<dyn AnyKey>::generate(alg, BlsKeyGen::new(seed)?)?,
            None | Some("") => Box::<dyn AnyKey>::generate(alg, RandomDet::new(seed))?,
            _ => {
                return Err(err_msg!(
                    Unsupported,
                    "Unknown seed method for key generation"
                ))
            }
        };
        Ok(Self::new(inner, false))
    }

    /// Import a key or keypair from a JWK in binary format
    pub fn from_jwk_slice(jwk: &[u8]) -> Result<Self, Error> {
        let inner = Box::<dyn AnyKey>::from_jwk_slice(jwk)?;
        Ok(Self::new(inner, false))
    }

    /// Import a key or keypair from a JWK
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let inner = Box::<dyn AnyKey>::from_jwk(jwk)?;
        Ok(Self::new(inner, false))
    }

    /// Import a public key from its compact representation
    pub fn from_public_bytes(alg: KeyAlg, public: &[u8]) -> Result<Self, Error> {
        let inner = Box::<dyn AnyKey>::from_public_bytes(alg, public)?;
        Ok(Self::new(inner, false))
    }

    /// Export the raw bytes of the public key
    pub fn to_public_bytes(&self) -> Result<SecretBytes, Error> {
        Ok(self.inner.to_public_bytes()?)
    }

    /// Import a symmetric key or public-private keypair from its compact representation
    pub fn from_secret_bytes(alg: KeyAlg, secret: &[u8]) -> Result<Self, Error> {
        let inner = Box::<dyn AnyKey>::from_secret_bytes(alg, secret)?;
        Ok(Self::new(inner, false))
    }

    /// Export the raw bytes of the private key
    pub fn to_secret_bytes(&self) -> Result<SecretBytes, Error> {
        Ok(self.inner.to_secret_bytes()?)
    }

    /// Derive a new key from a Diffie-Hellman exchange between this keypair and a public key
    pub fn to_key_exchange(&self, alg: KeyAlg, pk: &LocalKey) -> Result<Self, Error> {
        let inner = Box::<dyn AnyKey>::from_key_exchange(alg, &**self.inner, &**pk.inner)?;
        Ok(Self::new(inner, self.ephemeral || pk.ephemeral))
    }

    pub(crate) fn from_key_derivation(
        alg: KeyAlg,
        derive: impl KeyDerivation,
    ) -> Result<Self, Error> {
        let inner = Box::<dyn AnyKey>::from_key_derivation(alg, derive)?;
        Ok(Self::new(inner, false))
    }

    pub(crate) fn encode(&self) -> Result<SecretBytes, Error> {
        Ok(self.inner.to_jwk_secret(None)?)
    }

    /// Accessor for the key algorithm
    pub fn algorithm(&self) -> KeyAlg {
        self.inner.algorithm()
    }

    /// Get the public JWK representation for this key or keypair
    pub fn to_jwk_public(&self, alg: Option<KeyAlg>) -> Result<String, Error> {
        Ok(self.inner.to_jwk_public(alg)?)
    }

    /// Get the JWK representation for this private key or keypair
    pub fn to_jwk_secret(&self) -> Result<SecretBytes, Error> {
        Ok(self.inner.to_jwk_secret(None)?)
    }

    /// Get the JWK thumbprint for this key or keypair
    pub fn to_jwk_thumbprint(&self, alg: Option<KeyAlg>) -> Result<String, Error> {
        Ok(self.inner.to_jwk_thumbprint(alg)?)
    }

    /// Get the set of indexed JWK thumbprints for this key or keypair
    pub fn to_jwk_thumbprints(&self) -> Result<Vec<String>, Error> {
        if self.inner.algorithm() == KeyAlg::Bls12_381(BlsCurves::G1G2) {
            return Ok(vec![
                self.inner
                    .to_jwk_thumbprint(Some(KeyAlg::Bls12_381(BlsCurves::G1)))?,
                self.inner
                    .to_jwk_thumbprint(Some(KeyAlg::Bls12_381(BlsCurves::G2)))?,
            ]);
        } else {
            Ok(vec![self.inner.to_jwk_thumbprint(None)?])
        }
    }

    /// Map this key or keypair to its equivalent for another key algorithm
    pub fn convert_key(&self, alg: KeyAlg) -> Result<Self, Error> {
        let inner = self.inner.convert_key(alg)?;
        Ok(Self::new(inner, self.ephemeral))
    }

    /// Fetch the AEAD parameter lengths
    pub fn aead_params(&self) -> Result<KeyAeadParams, Error> {
        let params = self.inner.aead_params();
        if params.tag_length == 0 {
            return Err(err_msg!(
                Unsupported,
                "AEAD is not supported for this key type"
            ));
        }
        Ok(params)
    }

    /// Calculate the padding required for a message
    pub fn aead_padding(&self, msg_len: usize) -> usize {
        self.inner.aead_padding(msg_len)
    }

    /// Create a new random nonce for AEAD message encryption
    pub fn aead_random_nonce(&self) -> Result<Vec<u8>, Error> {
        let nonce_len = self.inner.aead_params().nonce_length;
        if nonce_len == 0 {
            return Ok(Vec::new());
        }
        let mut buf = Vec::with_capacity(nonce_len);
        buf.resize(nonce_len, 0u8);
        fill_random(&mut buf);
        Ok(buf)
    }

    /// Perform AEAD message encryption with this encryption key
    pub fn aead_encrypt(
        &self,
        message: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<Encrypted, Error> {
        let params = self.inner.aead_params();
        let mut nonce = Cow::Borrowed(nonce);
        if nonce.is_empty() && params.nonce_length > 0 {
            nonce = Cow::Owned(self.aead_random_nonce()?);
        }
        let pad_len = self.inner.aead_padding(message.len());
        let mut buf =
            SecretBytes::from_slice_reserve(message, pad_len + params.tag_length + nonce.len());
        let tag_pos = self.inner.encrypt_in_place(&mut buf, nonce.as_ref(), aad)?;
        let nonce_pos = buf.len();
        if !nonce.is_empty() {
            buf.extend_from_slice(nonce.as_ref());
        }
        Ok(Encrypted::new(buf, tag_pos, nonce_pos))
    }

    /// Perform AEAD message decryption with this encryption key
    pub fn aead_decrypt<'d>(
        &'d self,
        ciphertext: impl Into<ToDecrypt<'d>>,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<SecretBytes, Error> {
        let mut buf = ciphertext.into().into_secret();
        self.inner.decrypt_in_place(&mut buf, nonce, aad)?;
        Ok(buf)
    }

    /// Sign a message with this private signing key
    pub fn sign_message(&self, message: &[u8], sig_type: Option<&str>) -> Result<Vec<u8>, Error> {
        let mut sig = Vec::new();
        self.inner.write_signature(
            message,
            sig_type.map(SignatureType::from_str).transpose()?,
            &mut sig,
        )?;
        Ok(sig)
    }

    /// Verify a message signature with this private signing key or public verification key
    pub fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        sig_type: Option<&str>,
    ) -> Result<bool, Error> {
        Ok(self.inner.verify_signature(
            message,
            signature,
            sig_type.map(SignatureType::from_str).transpose()?,
        )?)
    }

    /// Wrap another key using this key
    pub fn wrap_key(&self, key: &LocalKey, nonce: &[u8]) -> Result<Encrypted, Error> {
        let params = self.inner.aead_params();
        let mut buf = SecretBytes::with_capacity(
            key.inner.secret_bytes_length().unwrap_or_default()
                + params.tag_length
                + params.nonce_length,
        );
        key.inner.write_secret_bytes(&mut buf)?;
        let tag_pos = self.inner.encrypt_in_place(&mut buf, nonce, &[])?;
        let nonce_pos = buf.len();
        buf.extend_from_slice(nonce);
        Ok(Encrypted::new(buf, tag_pos, nonce_pos))
    }

    /// Unwrap a key using this key
    pub fn unwrap_key<'d>(
        &'d self,
        alg: KeyAlg,
        ciphertext: impl Into<ToDecrypt<'d>>,
        nonce: &[u8],
    ) -> Result<LocalKey, Error> {
        let mut buf = ciphertext.into().into_secret();
        self.inner.decrypt_in_place(&mut buf, nonce, &[])?;
        Self::from_secret_bytes(alg, buf.as_ref())
    }
}

impl AsRef<dyn AnyKey> for LocalKey {
    fn as_ref(&self) -> &dyn AnyKey {
        &**self.inner
    }
}

impl_anykey_as_ref!(LocalKey);
