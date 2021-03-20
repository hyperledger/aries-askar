use std::collections::HashMap;
use std::sync::Arc;

use async_mutex::Mutex;
use zeroize::Zeroize;

use super::error::Result;
use super::future::unblock;
use super::types::{EncEntryTag, EntryTag, ProfileId, SecretBytes};

use self::store::StoreKey;
use self::wrap::WrapKey;

pub mod any;
pub use self::any::{AnyPrivateKey, AnyPublicKey};

pub mod alg;
use self::alg::edwards::{Ed25519KeyPair, Ed25519PublicKey};

pub mod caps;
pub use self::caps::{
    KeyAlg, KeyCapGetPublic, KeyCapSign, KeyCapVerify, KeyCategory, SignatureFormat, SignatureType,
};

pub mod encrypt;

pub mod kdf;

pub mod store;
pub use self::store::{KeyEntry, KeyParams};

mod types;
pub use self::types::PassKey;

pub mod wrap;

/// Derive the (public) verification key for a keypair
pub fn derive_verkey(alg: KeyAlg, seed: &[u8]) -> Result<String> {
    match alg {
        KeyAlg::Ed25519 => (),
        _ => return Err(err_msg!(Unsupported, "Unsupported key algorithm")),
    }
    let sk = Ed25519KeyPair::from_seed(seed)
        .map_err(err_map!(Unexpected, "Error generating keypair"))?;
    let pk = sk.public_key().to_string();
    Ok(pk)
}

/// Verify that a message signature is consistent with the signer's key
pub fn verify_signature(signer_vk: &str, data: &[u8], signature: &[u8]) -> Result<bool> {
    let vk = Ed25519PublicKey::from_str(&signer_vk).map_err(err_map!("Invalid verkey"))?;
    vk.key_verify(data, signature, None, None)
}

#[derive(Debug)]
pub struct KeyCache {
    profile_info: Mutex<HashMap<String, (ProfileId, Arc<StoreKey>)>>,
    pub(crate) wrap_key: Arc<WrapKey>,
}

impl KeyCache {
    pub fn new(wrap_key: impl Into<Arc<WrapKey>>) -> Self {
        Self {
            profile_info: Mutex::new(HashMap::new()),
            wrap_key: wrap_key.into(),
        }
    }

    pub async fn load_key(&self, ciphertext: Vec<u8>) -> Result<StoreKey> {
        let wrap_key = self.wrap_key.clone();
        unblock(move || {
            let mut data = wrap_key
                .unwrap_data(ciphertext)
                .map_err(err_map!(Encryption, "Error decrypting store key"))?;
            let key = StoreKey::from_slice(&data)?;
            data.zeroize();
            Ok(key)
        })
        .await
    }

    pub fn add_profile_mut(&mut self, ident: String, pid: ProfileId, key: StoreKey) {
        self.profile_info
            .get_mut()
            .insert(ident, (pid, Arc::new(key)));
    }

    pub async fn add_profile(&self, ident: String, pid: ProfileId, key: Arc<StoreKey>) {
        self.profile_info.lock().await.insert(ident, (pid, key));
    }

    pub async fn get_profile(&self, name: &str) -> Option<(ProfileId, Arc<StoreKey>)> {
        self.profile_info.lock().await.get(name).cloned()
    }
}

pub(crate) trait EntryEncryptor {
    fn prepare_input(input: &[u8]) -> SecretBytes {
        SecretBytes::from(input)
    }

    fn encrypt_entry_category(&self, category: SecretBytes) -> Result<Vec<u8>>;
    fn encrypt_entry_name(&self, name: SecretBytes) -> Result<Vec<u8>>;
    fn encrypt_entry_value(&self, value: SecretBytes) -> Result<Vec<u8>>;
    fn encrypt_entry_tags(&self, tags: Vec<EntryTag>) -> Result<Vec<EncEntryTag>>;

    fn decrypt_entry_category(&self, enc_category: Vec<u8>) -> Result<String>;
    fn decrypt_entry_name(&self, enc_name: Vec<u8>) -> Result<String>;
    fn decrypt_entry_value(&self, enc_value: Vec<u8>) -> Result<SecretBytes>;
    fn decrypt_entry_tags(&self, enc_tags: Vec<EncEntryTag>) -> Result<Vec<EntryTag>>;
}

pub struct NullEncryptor;

impl EntryEncryptor for NullEncryptor {
    fn encrypt_entry_category(&self, category: SecretBytes) -> Result<Vec<u8>> {
        Ok(category.into_vec())
    }
    fn encrypt_entry_name(&self, name: SecretBytes) -> Result<Vec<u8>> {
        Ok(name.into_vec())
    }
    fn encrypt_entry_value(&self, value: SecretBytes) -> Result<Vec<u8>> {
        Ok(value.into_vec())
    }
    fn encrypt_entry_tags(&self, tags: Vec<EntryTag>) -> Result<Vec<EncEntryTag>> {
        Ok(tags
            .into_iter()
            .map(|tag| match tag {
                EntryTag::Encrypted(name, value) => EncEntryTag {
                    name: name.into_bytes(),
                    value: value.into_bytes(),
                    plaintext: false,
                },
                EntryTag::Plaintext(name, value) => EncEntryTag {
                    name: name.into_bytes(),
                    value: value.into_bytes(),
                    plaintext: true,
                },
            })
            .collect())
    }

    fn decrypt_entry_category(&self, enc_category: Vec<u8>) -> Result<String> {
        Ok(String::from_utf8(enc_category).map_err(err_map!(Encryption))?)
    }
    fn decrypt_entry_name(&self, enc_name: Vec<u8>) -> Result<String> {
        Ok(String::from_utf8(enc_name).map_err(err_map!(Encryption))?)
    }
    fn decrypt_entry_value(&self, enc_value: Vec<u8>) -> Result<SecretBytes> {
        Ok(enc_value.into())
    }
    fn decrypt_entry_tags(&self, enc_tags: Vec<EncEntryTag>) -> Result<Vec<EntryTag>> {
        Ok(enc_tags.into_iter().try_fold(vec![], |mut acc, tag| {
            let name = String::from_utf8(tag.name).map_err(err_map!(Encryption))?;
            let value = String::from_utf8(tag.value).map_err(err_map!(Encryption))?;
            acc.push(if tag.plaintext {
                EntryTag::Plaintext(name, value)
            } else {
                EntryTag::Encrypted(name, value)
            });
            Result::Ok(acc)
        })?)
    }
}
