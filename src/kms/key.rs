use std::str::FromStr;

pub use crate::crypto::{
    alg::KeyAlg,
    buffer::{SecretBytes, WriteBuffer},
    encrypt::KeyAeadParams,
};
use crate::{
    crypto::{
        alg::{AnyKey, AnyKeyCreate, BlsCurves},
        encrypt::KeyAeadInPlace,
        jwk::{FromJwk, ToJwk},
        kdf::{KeyDerivation, KeyExchange},
        random::fill_random,
        sign::{KeySigVerify, KeySign, SignatureType},
        Error as CryptoError,
    },
    error::Error,
};

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

    /// Import a key or keypair from a JWK
    pub fn from_jwk(jwk: &str) -> Result<Self, Error> {
        let inner = Box::<AnyKey>::from_jwk(jwk)?;
        Ok(Self {
            inner,
            ephemeral: false,
        })
    }

    /// Import a public key from its compact representation
    pub fn from_public_bytes(alg: KeyAlg, public: &[u8]) -> Result<Self, Error> {
        let inner = Box::<AnyKey>::from_public_bytes(alg, public)?;
        Ok(Self {
            inner,
            ephemeral: false,
        })
    }

    /// Export the raw bytes of the public key
    pub fn to_public_bytes(&self) -> Result<SecretBytes, Error> {
        Ok(self.inner.to_public_bytes()?)
    }

    /// Import a symmetric key or public-private keypair from its compact representation
    pub fn from_secret_bytes(alg: KeyAlg, secret: &[u8]) -> Result<Self, Error> {
        let inner = Box::<AnyKey>::from_secret_bytes(alg, secret)?;
        Ok(Self {
            inner,
            ephemeral: false,
        })
    }

    /// Export the raw bytes of the private key
    pub fn to_secret_bytes(&self) -> Result<SecretBytes, Error> {
        Ok(self.inner.to_secret_bytes()?)
    }

    /// Derive a new key from a Diffie-Hellman exchange between this keypair and a public key
    pub fn to_key_exchange(&self, alg: KeyAlg, pk: &LocalKey) -> Result<Self, Error> {
        let inner = Box::<AnyKey>::from_key_exchange(alg, &*self.inner, &*pk.inner)?;
        Ok(Self {
            inner,
            ephemeral: self.ephemeral || pk.ephemeral,
        })
    }

    pub(crate) fn from_key_derivation(
        alg: KeyAlg,
        derive: impl KeyDerivation,
    ) -> Result<Self, Error> {
        let inner = Box::<AnyKey>::from_key_derivation(alg, derive)?;
        Ok(Self {
            inner,
            ephemeral: false,
        })
    }

    pub(crate) fn encode(&self) -> Result<SecretBytes, Error> {
        Ok(self.inner.to_jwk_secret()?)
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
        Ok(self.inner.to_jwk_secret()?)
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
        Ok(Self {
            inner,
            ephemeral: self.ephemeral,
        })
    }

    /// Fetch the AEAD parameter lengths
    pub fn aead_params(&self) -> Result<KeyAeadParams, Error> {
        let params = self.inner.aead_params();
        if params.nonce_length == 0 {
            return Err(err_msg!(
                Unsupported,
                "AEAD is not supported for this key type"
            ));
        }
        Ok(params)
    }

    /// Create a new random nonce for AEAD message encryption
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

    /// Perform AEAD message encryption with this encryption key
    pub fn aead_encrypt(&self, message: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        let params = self.inner.aead_params();
        let mut buf =
            SecretBytes::from_slice_reserve(message, params.nonce_length + params.tag_length);
        self.inner.encrypt_in_place(&mut buf, nonce, aad)?;
        Ok(buf.into_vec())
    }

    /// Perform AEAD message decryption with this encryption key
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
}

impl KeyExchange for LocalKey {
    fn write_key_exchange(
        &self,
        other: &LocalKey,
        out: &mut dyn WriteBuffer,
    ) -> Result<(), CryptoError> {
        self.inner.write_key_exchange(&other.inner, out)
    }
}
