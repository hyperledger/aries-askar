use std::sync::Arc;
use crate::{
    crypto::alg::{KeyAlg, AesTypes, BlsCurves, Chacha20Types, EcCurves},
    kms::{LocalKey, Encrypted},
    uffi::error::ErrorCode,
};

#[derive(uniffi::Enum)]
pub enum AskarKeyAlg {
    A128Gcm,
    A256Gcm,
    A128CbcHs256,
    A256CbcHs512,
    A128Kw,
    A256Kw,
    Bls12_381G1,
    Bls12_381G2,
    Bls12_381G1g2,
    C20P,
    XC20P,
    Ed25519,
    X25519,
    K256,
    P256,
    P384,
}

impl Into<KeyAlg> for AskarKeyAlg {
    fn into(self) -> KeyAlg {
        match self {
            AskarKeyAlg::A128Gcm => KeyAlg::Aes(AesTypes::A128Gcm),
            AskarKeyAlg::A256Gcm => KeyAlg::Aes(AesTypes::A256Gcm),
            AskarKeyAlg::A128CbcHs256 => KeyAlg::Aes(AesTypes::A128CbcHs256),
            AskarKeyAlg::A256CbcHs512 => KeyAlg::Aes(AesTypes::A256CbcHs512),
            AskarKeyAlg::A128Kw => KeyAlg::Aes(AesTypes::A128Kw),
            AskarKeyAlg::A256Kw => KeyAlg::Aes(AesTypes::A256Kw),
            AskarKeyAlg::Bls12_381G1 => KeyAlg::Bls12_381(BlsCurves::G1),
            AskarKeyAlg::Bls12_381G2 => KeyAlg::Bls12_381(BlsCurves::G2),
            AskarKeyAlg::Bls12_381G1g2 => KeyAlg::Bls12_381(BlsCurves::G1G2),
            AskarKeyAlg::C20P => KeyAlg::Chacha20(Chacha20Types::C20P),
            AskarKeyAlg::XC20P => KeyAlg::Chacha20(Chacha20Types::XC20P),
            AskarKeyAlg::Ed25519 => KeyAlg::Ed25519,
            AskarKeyAlg::X25519 => KeyAlg::X25519,
            AskarKeyAlg::K256 => KeyAlg::EcCurve(EcCurves::Secp256k1),
            AskarKeyAlg::P256 => KeyAlg::EcCurve(EcCurves::Secp256r1),
            AskarKeyAlg::P384 => KeyAlg::EcCurve(EcCurves::Secp384r1),
        }
    }
}

impl From<KeyAlg> for AskarKeyAlg {
    fn from(key_alg: KeyAlg) -> Self {
        match key_alg {
            KeyAlg::Aes(AesTypes::A128Gcm) => AskarKeyAlg::A128Gcm,
            KeyAlg::Aes(AesTypes::A256Gcm) => AskarKeyAlg::A256Gcm,
            KeyAlg::Aes(AesTypes::A128CbcHs256) => AskarKeyAlg::A128CbcHs256,
            KeyAlg::Aes(AesTypes::A256CbcHs512) => AskarKeyAlg::A256CbcHs512,
            KeyAlg::Aes(AesTypes::A128Kw) => AskarKeyAlg::A128Kw,
            KeyAlg::Aes(AesTypes::A256Kw) => AskarKeyAlg::A256Kw,
            KeyAlg::Bls12_381(BlsCurves::G1) => AskarKeyAlg::Bls12_381G1,
            KeyAlg::Bls12_381(BlsCurves::G2) => AskarKeyAlg::Bls12_381G2,
            KeyAlg::Bls12_381(BlsCurves::G1G2) => AskarKeyAlg::Bls12_381G1g2,
            KeyAlg::Chacha20(Chacha20Types::C20P) => AskarKeyAlg::C20P,
            KeyAlg::Chacha20(Chacha20Types::XC20P) => AskarKeyAlg::XC20P,
            KeyAlg::Ed25519 => AskarKeyAlg::Ed25519,
            KeyAlg::X25519 => AskarKeyAlg::X25519,
            KeyAlg::EcCurve(EcCurves::Secp256k1) => AskarKeyAlg::K256,
            KeyAlg::EcCurve(EcCurves::Secp256r1) => AskarKeyAlg::P256,
            KeyAlg::EcCurve(EcCurves::Secp384r1) => AskarKeyAlg::P384,
        }
    }
}

#[derive(uniffi::Enum)]
pub enum SeedMethod {
    BlsKeyGen,
}

impl Into<&str> for SeedMethod {
    fn into(self) -> &'static str {
        match self {
            SeedMethod::BlsKeyGen => "bls_keygen",
        }
    }
}

#[derive(uniffi::Record)]
pub struct AeadParams {
    nonce_length: i32,
    tag_length: i32,
}

pub struct EncryptedBuffer {
    enc: Encrypted,
}

#[uniffi::export]
impl EncryptedBuffer {
    pub fn ciphertext(&self) -> Vec<u8> {
        self.enc.ciphertext().to_vec()
    }

    pub fn nonce(&self) -> Vec<u8> {
        self.enc.nonce().to_vec()
    }

    pub fn tag(&self) -> Vec<u8> {
        self.enc.tag().to_vec()
    }

    pub fn ciphertext_tag(&self) -> Vec<u8> {
        self.enc.buffer[0..(self.enc.nonce_pos)].to_vec()
    }
}

pub struct AskarLocalKey {
    pub key: LocalKey,
}

pub struct LocalKeyFactory {
}

impl LocalKeyFactory {
    pub fn new() -> Self {
        Self {}
    }
}

#[uniffi::export]
impl LocalKeyFactory {
    pub fn generate(&self, alg: AskarKeyAlg, ephemeral: bool) -> Result<Arc<AskarLocalKey>, ErrorCode> {
        let key = LocalKey::generate(alg.into(), ephemeral)?;
        Ok(Arc::new(AskarLocalKey { key }))
    }

    pub fn from_seed(&self, alg: AskarKeyAlg, seed: Vec<u8>, method: Option<SeedMethod>) -> Result<Arc<AskarLocalKey>, ErrorCode> {
        let key = LocalKey::from_seed(alg.into(), &seed, method.map(|m| m.into()))?;
        Ok(Arc::new(AskarLocalKey { key }))
    }

    pub fn from_jwk_slice(&self, jwk: Vec<u8>) -> Result<Arc<AskarLocalKey>, ErrorCode> {
        let key = LocalKey::from_jwk_slice(&jwk)?;
        Ok(Arc::new(AskarLocalKey { key }))
    }

    pub fn from_jwk(&self, jwk: String) -> Result<Arc<AskarLocalKey>, ErrorCode> {
        let key = LocalKey::from_jwk(&jwk)?;
        Ok(Arc::new(AskarLocalKey { key }))
    }

    pub fn from_public_bytes(&self, alg: AskarKeyAlg, bytes: Vec<u8>) -> Result<Arc<AskarLocalKey>, ErrorCode> {
        let key = LocalKey::from_public_bytes(alg.into(), &bytes)?;
        Ok(Arc::new(AskarLocalKey { key }))
    }

    pub fn from_secret_bytes(&self, alg: AskarKeyAlg, bytes: Vec<u8>) -> Result<Arc<AskarLocalKey>, ErrorCode> {
        let key = LocalKey::from_secret_bytes(alg.into(), &bytes)?;
        Ok(Arc::new(AskarLocalKey { key }))
    }
}

#[uniffi::export]
impl AskarLocalKey {
    pub fn to_public_bytes(&self) -> Result<Vec<u8>, ErrorCode> {
        Ok(self.key.to_public_bytes()?.into_vec())
    }

    pub fn to_secret_bytes(&self) -> Result<Vec<u8>, ErrorCode> {
        Ok(self.key.to_secret_bytes()?.into_vec())
    }

    pub fn to_key_exchange(&self, alg: AskarKeyAlg, pk: Arc<AskarLocalKey>) -> Result<Arc<AskarLocalKey>, ErrorCode> {
        let key = self.key.to_key_exchange(alg.into(), &pk.key)?;
        Ok(Arc::new(AskarLocalKey { key }))
    }

    pub fn algorithm(&self) -> AskarKeyAlg {
        self.key.algorithm().into()
    }

    pub fn to_jwk_public(&self, alg: Option<AskarKeyAlg>) -> Result<String, ErrorCode> {
        Ok(self.key.to_jwk_public(alg.map(|a| a.into()))?)
    }

    pub fn to_jwk_secret(&self) -> Result<Vec<u8>, ErrorCode> {
        Ok(self.key.to_jwk_secret()?.into_vec())
    }

    pub fn to_jwk_thumbprint(&self, alg: Option<AskarKeyAlg>) -> Result<String, ErrorCode> {
        Ok(self.key.to_jwk_thumbprint(alg.map(|a| a.into()))?)
    }

    pub fn to_jwk_thumbprints(&self) -> Result<Vec<String>, ErrorCode> {
        Ok(self.key.to_jwk_thumbprints()?)
    }

    pub fn convert_key(&self, alg: AskarKeyAlg) -> Result<Arc<AskarLocalKey>, ErrorCode> {
        let key = self.key.convert_key(alg.into())?;
        Ok(Arc::new(AskarLocalKey { key }))
    }

    pub fn aead_params(&self) -> Result<AeadParams, ErrorCode> {
        let params = self.key.aead_params()?;
        Ok(AeadParams {
            nonce_length: params.nonce_length as i32,
            tag_length: params.tag_length as i32,
        })
    }

    pub fn aead_padding(&self, msg_len: i32) -> i32 {
        self.key.aead_padding(msg_len as usize) as i32
    }

    pub fn aead_random_nonce(&self) -> Result<Vec<u8>, ErrorCode> {
        Ok(self.key.aead_random_nonce()?)
    }

    pub fn aead_encrypt(&self, message: Vec<u8>, nonce: Option<Vec<u8>>, aad: Option<Vec<u8>>) -> Result<Arc<EncryptedBuffer>, ErrorCode> {
        Ok(Arc::new(EncryptedBuffer {
            enc: self.key.aead_encrypt(&message, &nonce.unwrap_or_default(), &aad.unwrap_or_default())?,
        }))
    }

    pub fn aead_decrypt(&self, ciphertext: Vec<u8>, tag: Option<Vec<u8>>, nonce: Vec<u8>, aad: Option<Vec<u8>>) -> Result<Vec<u8>, ErrorCode> {
        Ok(self.key.aead_decrypt((ciphertext.as_slice(), tag.unwrap_or_default().as_slice()), &nonce, &aad.unwrap_or_default())?.to_vec())
    }

    pub fn sign_message(&self, message: Vec<u8>, sig_type: Option<String>) -> Result<Vec<u8>, ErrorCode> {
        Ok(self.key.sign_message(&message, sig_type.as_deref())?)
    }

    pub fn verify_signature(&self, message: Vec<u8>, signature: Vec<u8>, sig_type: Option<String>) -> Result<bool, ErrorCode> {
        Ok(self.key.verify_signature(&message, &signature, sig_type.as_deref())?)
    }

    pub fn wrap_key(&self, key: Arc<AskarLocalKey>, nonce: Option<Vec<u8>>) -> Result<Arc<EncryptedBuffer>, ErrorCode> {
        Ok(Arc::new(EncryptedBuffer {
            enc: self.key.wrap_key(&key.key, &nonce.unwrap_or_default())?,
        }))
    }

    pub fn unwrap_key(&self, alg: AskarKeyAlg, ciphertext: Vec<u8>, tag: Option<Vec<u8>>, nonce: Option<Vec<u8>>) -> Result<Arc<AskarLocalKey>, ErrorCode> {
        let key = self.key.unwrap_key(
            alg.into(),
            (ciphertext.as_slice(), tag.unwrap_or_default().as_slice()),
            &nonce.unwrap_or_default()
        )?;
        Ok(Arc::new(AskarLocalKey { key }))
    }
}
