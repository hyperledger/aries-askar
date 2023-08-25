use std::sync::Arc;
use crate::{
    kms::{
        crypto_box, crypto_box_open, crypto_box_random_nonce, crypto_box_seal, crypto_box_seal_open,
        derive_key_ecdh_1pu, derive_key_ecdh_es,
    },
    uffi::{
        error::ErrorCode,
        key::{AskarLocalKey, AskarKeyAlg, EncryptedBuffer},
    },
};

pub struct AskarCrypto {}

impl AskarCrypto {
    pub fn new() -> Self {
        Self {}
    }
}

#[uniffi::export]
impl AskarCrypto {
    pub fn random_nonce(&self) -> Result<Vec<u8>, ErrorCode> {
        Ok(crypto_box_random_nonce()?.to_vec())
    }

    pub fn crypto_box(
        &self,
        receiver_key: Arc<AskarLocalKey>,
        sender_key: Arc<AskarLocalKey>,
        message: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Result<Vec<u8>, ErrorCode> {
        Ok(crypto_box(&receiver_key.key, &sender_key.key, &message, &nonce)?)
    }

    pub fn box_open(
        &self,
        receiver_key: Arc<AskarLocalKey>,
        sender_key: Arc<AskarLocalKey>,
        message: Vec<u8>,
        nonce: Vec<u8>,
    ) -> Result<Vec<u8>, ErrorCode> {
        Ok(crypto_box_open(&receiver_key.key, &sender_key.key, &message, &nonce)?.to_vec())
    }

    pub fn box_seal(
        &self,
        receiver_key: Arc<AskarLocalKey>,
        message: Vec<u8>,
    ) -> Result<Vec<u8>, ErrorCode> {
        Ok(crypto_box_seal(&receiver_key.key, &message)?)
    }

    pub fn box_seal_open(
        &self,
        receiver_key: Arc<AskarLocalKey>,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, ErrorCode> {
        Ok(crypto_box_seal_open(&receiver_key.key, &ciphertext)?.to_vec())
    }
}

pub struct AskarEcdhEs {
    alg_id: Vec<u8>,
    apu: Vec<u8>,
    apv: Vec<u8>,
}

impl AskarEcdhEs {
    pub fn new(
        alg_id: String,
        apu: String,
        apv: String,
    ) -> Self {
        Self {
            alg_id: alg_id.into_bytes(),
            apu: apu.into_bytes(),
            apv: apv.into_bytes(),
        }
    }
}

#[uniffi::export]
impl AskarEcdhEs {
    pub fn derive_key(
        &self,
        enc_alg: AskarKeyAlg,
        ephemeral_key: Arc<AskarLocalKey>,
        receiver_key: Arc<AskarLocalKey>,
        receive: bool,
    ) -> Result<Arc<AskarLocalKey>, ErrorCode> {
        let key = derive_key_ecdh_es(
            enc_alg.into(),
            &ephemeral_key.key,
            &receiver_key.key,
            &self.alg_id,
            &self.apu,
            &self.apv,
            receive,
        )?;
        Ok(Arc::new(AskarLocalKey { key }))
    }

    pub fn encrypt_direct(
        &self,
        enc_alg: AskarKeyAlg,
        ephemeral_key: Arc<AskarLocalKey>,
        receiver_key: Arc<AskarLocalKey>,
        message: Vec<u8>,
        nonce: Option<Vec<u8>>,
        aad: Option<Vec<u8>>,
    ) -> Result<Arc<EncryptedBuffer>, ErrorCode> {
        let key = derive_key_ecdh_es(
            enc_alg.into(),
            &ephemeral_key.key,
            &receiver_key.key,
            &self.alg_id,
            &self.apu,
            &self.apv,
            false,
        )?;
        let derived = AskarLocalKey { key };
        Ok(derived.aead_encrypt(message, nonce, aad)?)
    }

    pub fn decrypt_direct(
        &self,
        enc_alg: AskarKeyAlg,
        ephemeral_key: Arc<AskarLocalKey>,
        receiver_key: Arc<AskarLocalKey>,
        ciphertext: Vec<u8>,
        tag: Option<Vec<u8>>,
        nonce: Vec<u8>,
        aad: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, ErrorCode> {
        let key = derive_key_ecdh_es(
            enc_alg.into(),
            &ephemeral_key.key,
            &receiver_key.key,
            &self.alg_id,
            &self.apu,
            &self.apv,
            true,
        )?;
        let derived = AskarLocalKey { key };
        Ok(derived.aead_decrypt(ciphertext, tag, nonce, aad)?)
    }

    pub fn sender_wrap_key(
        &self,
        wrap_alg: AskarKeyAlg,
        ephemeral_key: Arc<AskarLocalKey>,
        receiver_key: Arc<AskarLocalKey>,
        cek: Arc<AskarLocalKey>,
    ) -> Result<Arc<EncryptedBuffer>, ErrorCode> {
        let key = derive_key_ecdh_es(
            wrap_alg.into(),
            &ephemeral_key.key,
            &receiver_key.key,
            &self.alg_id,
            &self.apu,
            &self.apv,
            false,
        )?;
        let derived = AskarLocalKey { key };
        Ok(derived.wrap_key(cek, None)?)
    }

    pub fn receiver_unwrap_key(
        &self,
        wrap_alg: AskarKeyAlg,
        enc_alg: AskarKeyAlg,
        ephemeral_key: Arc<AskarLocalKey>,
        receiver_key: Arc<AskarLocalKey>,
        ciphertext: Vec<u8>,
        nonce: Option<Vec<u8>>,
        tag: Option<Vec<u8>>,
    ) -> Result<Arc<AskarLocalKey>, ErrorCode> {
        let key = derive_key_ecdh_es(
            wrap_alg.into(),
            &ephemeral_key.key,
            &receiver_key.key,
            &self.alg_id,
            &self.apu,
            &self.apv,
            true,
        )?;
        let derived = AskarLocalKey { key };
        Ok(derived.unwrap_key(enc_alg, ciphertext, tag, nonce)?)
    }
}

pub struct AskarEcdh1PU {
    alg_id: Vec<u8>,
    apu: Vec<u8>,
    apv: Vec<u8>,
}

impl AskarEcdh1PU {
    pub fn new(
        alg_id: String,
        apu: String,
        apv: String,
    ) -> Self {
        Self {
            alg_id: alg_id.into_bytes(),
            apu: apu.into_bytes(),
            apv: apv.into_bytes(),
        }
    }
}

#[uniffi::export]
impl AskarEcdh1PU {
    pub fn derive_key(
        &self,
        enc_alg: AskarKeyAlg,
        ephemeral_key: Arc<AskarLocalKey>,
        sender_key: Arc<AskarLocalKey>,
        receiver_key: Arc<AskarLocalKey>,
        cc_tag: Vec<u8>,
        receive: bool,
    ) -> Result<Arc<AskarLocalKey>, ErrorCode> {
        let key = derive_key_ecdh_1pu(
            enc_alg.into(),
            &ephemeral_key.key,
            &sender_key.key,
            &receiver_key.key,
            &self.alg_id,
            &self.apu,
            &self.apv,
            &cc_tag,
            receive,
        )?;
        Ok(Arc::new(AskarLocalKey { key }))
    }

    pub fn encrypt_direct(
        &self,
        enc_alg: AskarKeyAlg,
        ephemeral_key: Arc<AskarLocalKey>,
        sender_key: Arc<AskarLocalKey>,
        receiver_key: Arc<AskarLocalKey>,
        message: Vec<u8>,
        nonce: Option<Vec<u8>>,
        aad: Option<Vec<u8>>,
    ) -> Result<Arc<EncryptedBuffer>, ErrorCode> {
        let key = derive_key_ecdh_1pu(
            enc_alg.into(),
            &ephemeral_key.key,
            &sender_key.key,
            &receiver_key.key,
            &self.alg_id,
            &self.apu,
            &self.apv,
            &[],
            false,
        )?;
        let derived = AskarLocalKey { key };
        Ok(derived.aead_encrypt(message, nonce, aad)?)
    }

    pub fn decrypt_direct(
        &self,
        enc_alg: AskarKeyAlg,
        ephemeral_key: Arc<AskarLocalKey>,
        sender_key: Arc<AskarLocalKey>,
        receiver_key: Arc<AskarLocalKey>,
        ciphertext: Vec<u8>,
        tag: Option<Vec<u8>>,
        nonce: Vec<u8>,
        aad: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, ErrorCode> {
        let key = derive_key_ecdh_1pu(
            enc_alg.into(),
            &ephemeral_key.key,
            &sender_key.key,
            &receiver_key.key,
            &self.alg_id,
            &self.apu,
            &self.apv,
            &[],
            true,
        )?;
        let derived = AskarLocalKey { key };
        Ok(derived.aead_decrypt(ciphertext, tag, nonce, aad)?)
    }

    pub fn sender_wrap_key(
        &self,
        wrap_alg: AskarKeyAlg,
        ephemeral_key: Arc<AskarLocalKey>,
        sender_key: Arc<AskarLocalKey>,
        receiver_key: Arc<AskarLocalKey>,
        cek: Arc<AskarLocalKey>,
        cc_tag: Vec<u8>,
    ) -> Result<Arc<EncryptedBuffer>, ErrorCode> {
        let key = derive_key_ecdh_1pu(
            wrap_alg.into(),
            &ephemeral_key.key,
            &sender_key.key,
            &receiver_key.key,
            &self.alg_id,
            &self.apu,
            &self.apv,
            &cc_tag,
            false,
        )?;
        let derived = AskarLocalKey { key };
        Ok(derived.wrap_key(cek, None)?)
    }

    pub fn receiver_unwrap_key(
        &self,
        wrap_alg: AskarKeyAlg,
        enc_alg: AskarKeyAlg,
        ephemeral_key: Arc<AskarLocalKey>,
        sender_key: Arc<AskarLocalKey>,
        receiver_key: Arc<AskarLocalKey>,
        ciphertext: Vec<u8>,
        cc_tag: Vec<u8>,
        nonce: Option<Vec<u8>>,
        tag: Option<Vec<u8>>,
    ) -> Result<Arc<AskarLocalKey>, ErrorCode> {
        let key = derive_key_ecdh_1pu(
            enc_alg.into(),
            &ephemeral_key.key,
            &sender_key.key,
            &receiver_key.key,
            &self.alg_id,
            &self.apu,
            &self.apv,
            &cc_tag,
            true,
        )?;
        let derived = AskarLocalKey { key };
        Ok(derived.unwrap_key(wrap_alg, ciphertext, tag, nonce)?)
    }
}
