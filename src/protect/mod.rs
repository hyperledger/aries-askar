use std::{collections::HashMap, sync::Arc};

use async_mutex::Mutex;
use zeroize::Zeroize;

pub mod kdf;

mod hmac_key;

mod pass_key;
pub use self::pass_key::PassKey;

mod store_key;
pub use self::store_key::StoreKey;

mod wrap_key;
pub use self::wrap_key::{generate_raw_wrap_key, WrapKey, WrapKeyMethod};

use crate::{
    crypto::buffer::SecretBytes,
    error::Error,
    future::unblock,
    storage::{
        entry::{EncEntryTag, EntryTag},
        types::ProfileId,
    },
};

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

    pub async fn load_key(&self, ciphertext: SecretBytes) -> Result<StoreKey, Error> {
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
    fn prepare_input(input: &[u8]) -> Result<SecretBytes, Error> {
        Ok(SecretBytes::from(input))
    }

    fn encrypt_entry_category(&self, category: SecretBytes) -> Result<SecretBytes, Error>;
    fn encrypt_entry_name(&self, name: SecretBytes) -> Result<SecretBytes, Error>;
    fn encrypt_entry_value(&self, value: SecretBytes) -> Result<SecretBytes, Error>;
    fn encrypt_entry_tags(&self, tags: Vec<EntryTag>) -> Result<Vec<EncEntryTag>, Error>;

    fn decrypt_entry_category(&self, enc_category: SecretBytes) -> Result<String, Error>;
    fn decrypt_entry_name(&self, enc_name: SecretBytes) -> Result<String, Error>;
    fn decrypt_entry_value(&self, enc_value: SecretBytes) -> Result<SecretBytes, Error>;
    fn decrypt_entry_tags(&self, enc_tags: Vec<EncEntryTag>) -> Result<Vec<EntryTag>, Error>;
}

pub struct NullEncryptor;

impl EntryEncryptor for NullEncryptor {
    fn encrypt_entry_category(&self, category: SecretBytes) -> Result<SecretBytes, Error> {
        Ok(category)
    }
    fn encrypt_entry_name(&self, name: SecretBytes) -> Result<SecretBytes, Error> {
        Ok(name)
    }
    fn encrypt_entry_value(&self, value: SecretBytes) -> Result<SecretBytes, Error> {
        Ok(value)
    }
    fn encrypt_entry_tags(&self, tags: Vec<EntryTag>) -> Result<Vec<EncEntryTag>, Error> {
        Ok(tags
            .into_iter()
            .map(|tag| match tag {
                EntryTag::Encrypted(name, value) => EncEntryTag {
                    name: name.into_bytes().into(),
                    value: value.into_bytes().into(),
                    plaintext: false,
                },
                EntryTag::Plaintext(name, value) => EncEntryTag {
                    name: name.into_bytes().into(),
                    value: value.into_bytes().into(),
                    plaintext: true,
                },
            })
            .collect())
    }

    fn decrypt_entry_category(&self, enc_category: SecretBytes) -> Result<String, Error> {
        Ok(String::from_utf8(enc_category.into_vec()).map_err(err_map!(Encryption))?)
    }
    fn decrypt_entry_name(&self, enc_name: SecretBytes) -> Result<String, Error> {
        Ok(String::from_utf8(enc_name.into_vec()).map_err(err_map!(Encryption))?)
    }
    fn decrypt_entry_value(&self, enc_value: SecretBytes) -> Result<SecretBytes, Error> {
        Ok(enc_value.into())
    }
    fn decrypt_entry_tags(&self, enc_tags: Vec<EncEntryTag>) -> Result<Vec<EntryTag>, Error> {
        Ok(enc_tags.into_iter().try_fold(vec![], |mut acc, tag| {
            let name = String::from_utf8(tag.name.into_vec()).map_err(err_map!(Encryption))?;
            let value = String::from_utf8(tag.value.into_vec()).map_err(err_map!(Encryption))?;
            acc.push(if tag.plaintext {
                EntryTag::Plaintext(name, value)
            } else {
                EntryTag::Encrypted(name, value)
            });
            Result::<_, Error>::Ok(acc)
        })?)
    }
}
