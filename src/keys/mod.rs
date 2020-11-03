use std::borrow::Cow;
use std::sync::Arc;

use super::error::Result;
use super::future::blocking;
use super::types::{EncEntry, EncEntryTag, Entry, EntryTag};

pub mod kdf;

pub mod store;

mod types;
pub use self::types::{KeyAlg, KeyCategory, KeyEntry, KeyParams};

pub mod wrap;

use indy_utils::keys::{EncodedVerKey, PrivateKey};

// #[cfg(target_os = "macos")]
// mod keychain;

pub fn derive_verkey(alg: KeyAlg, seed: &[u8]) -> Result<String> {
    match alg {
        KeyAlg::ED25519 => (),
        _ => return Err(err_msg!("Unsupported key algorithm")),
    }

    let sk =
        PrivateKey::from_seed(seed).map_err(err_map!(Unexpected, "Error generating keypair"))?;
    let pk = sk
        .public_key()
        .map_err(err_map!(Unexpected, "Error generating public key"))?
        .as_base58()
        .map_err(err_map!(Unexpected, "Error encoding public key"))?
        .long_form();
    Ok(pk)
}

pub async fn verify_signature(signer_vk: &str, data: &[u8], signature: &[u8]) -> Result<bool> {
    let vk = EncodedVerKey::from_str(&signer_vk).map_err(err_map!("Invalid verkey"))?;
    Ok(vk
        .decode()
        .map_err(err_map!("Unsupported verkey"))?
        .verify_signature(&data, &signature)
        .unwrap_or(false))
}

pub trait EntryEncryptor {
    fn encrypt_entry_category(&self, category: &str) -> Result<Vec<u8>>;
    fn encrypt_entry_name(&self, name: &str) -> Result<Vec<u8>>;
    fn encrypt_entry_value(&self, value: &[u8]) -> Result<Vec<u8>>;
    fn encrypt_entry_tags(&self, tags: &[EntryTag]) -> Result<Vec<EncEntryTag>>;

    fn decrypt_entry_category(&self, enc_category: &[u8]) -> Result<String>;
    fn decrypt_entry_name(&self, enc_name: &[u8]) -> Result<String>;
    fn decrypt_entry_value(&self, enc_value: &[u8]) -> Result<Vec<u8>>;
    fn decrypt_entry_tags(&self, enc_tags: &[EncEntryTag]) -> Result<Vec<EntryTag>>;

    fn encrypt_entry(
        &self,
        entry: &Entry,
    ) -> Result<(EncEntry<'static>, Option<Vec<EncEntryTag>>)> {
        let enc_entry = EncEntry {
            category: Cow::Owned(self.encrypt_entry_category(&entry.category)?),
            name: Cow::Owned(self.encrypt_entry_name(&entry.name)?),
            value: Cow::Owned(self.encrypt_entry_value(&entry.value)?),
        };
        let enc_tags = entry
            .tags
            .as_ref()
            .map(|t| self.encrypt_entry_tags(t))
            .transpose()?;
        Ok((enc_entry, enc_tags))
    }

    fn decrypt_entry(
        &self,
        enc_entry: &EncEntry,
        enc_tags: Option<&Vec<EncEntryTag>>,
    ) -> Result<Entry> {
        let tags = enc_tags.map(|t| self.decrypt_entry_tags(t)).transpose()?;
        Ok(Entry {
            category: self.decrypt_entry_category(&enc_entry.category)?,
            name: self.decrypt_entry_name(&enc_entry.name)?,
            value: self.decrypt_entry_value(&enc_entry.value)?,
            tags,
        })
    }
}

pub struct NullEncryptor;

impl EntryEncryptor for NullEncryptor {
    fn encrypt_entry_category(&self, category: &str) -> Result<Vec<u8>> {
        Ok(category.as_bytes().to_vec())
    }
    fn encrypt_entry_name(&self, name: &str) -> Result<Vec<u8>> {
        Ok(name.as_bytes().to_vec())
    }
    fn encrypt_entry_value(&self, value: &[u8]) -> Result<Vec<u8>> {
        Ok(value.to_vec())
    }
    fn encrypt_entry_tags(&self, tags: &[EntryTag]) -> Result<Vec<EncEntryTag>> {
        Ok(tags
            .into_iter()
            .map(|tag| match tag {
                EntryTag::Encrypted(name, value) => EncEntryTag {
                    name: name.as_bytes().to_vec(),
                    value: value.as_bytes().to_vec(),
                    plaintext: false,
                },
                EntryTag::Plaintext(name, value) => EncEntryTag {
                    name: name.as_bytes().to_vec(),
                    value: value.as_bytes().to_vec(),
                    plaintext: true,
                },
            })
            .collect())
    }

    fn decrypt_entry_category(&self, enc_category: &[u8]) -> Result<String> {
        Ok(String::from_utf8(enc_category.to_vec()).map_err(err_map!(Encryption))?)
    }
    fn decrypt_entry_name(&self, enc_name: &[u8]) -> Result<String> {
        Ok(String::from_utf8(enc_name.to_vec()).map_err(err_map!(Encryption))?)
    }
    fn decrypt_entry_value(&self, enc_value: &[u8]) -> Result<Vec<u8>> {
        Ok(enc_value.to_vec())
    }
    fn decrypt_entry_tags(&self, enc_tags: &[EncEntryTag]) -> Result<Vec<EntryTag>> {
        Ok(enc_tags.into_iter().try_fold(vec![], |mut acc, tag| {
            let name = String::from_utf8(tag.name.to_vec()).map_err(err_map!(Encryption))?;
            let value = String::from_utf8(tag.value.to_vec()).map_err(err_map!(Encryption))?;
            acc.push(if tag.plaintext {
                EntryTag::Plaintext(name, value)
            } else {
                EntryTag::Encrypted(name, value)
            });
            Result::Ok(acc)
        })?)
    }
}

#[derive(Clone)]
pub struct AsyncEncryptor<T>(pub Option<Arc<T>>);

impl<T: EntryEncryptor + Send + Sync + 'static> AsyncEncryptor<T> {
    pub async fn encrypt_entry_category(&self, category: String) -> Result<Vec<u8>> {
        if let Some(key) = self.0.clone() {
            blocking(move || key.encrypt_entry_category(category.as_str())).await
        } else {
            Ok(category.into_bytes())
        }
    }

    pub async fn encrypt_entry_category_name(
        &self,
        category: String,
        name: String,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        if let Some(key) = self.0.clone() {
            blocking(move || {
                Ok((
                    key.encrypt_entry_category(category.as_str())?,
                    key.encrypt_entry_name(name.as_str())?,
                ))
            })
            .await
        } else {
            Ok((category.into_bytes(), name.into_bytes()))
        }
    }

    pub async fn encrypt_entry(
        &self,
        entry: Entry,
    ) -> Result<(EncEntry<'static>, Option<Vec<EncEntryTag>>)> {
        if let Some(key) = self.0.clone() {
            blocking(move || key.encrypt_entry(&entry)).await
        } else {
            NullEncryptor {}.encrypt_entry(&entry)
        }
    }

    pub async fn encrypt_entry_value_tags(
        &self,
        value: Vec<u8>,
        tags: Option<Vec<EntryTag>>,
    ) -> Result<(Vec<u8>, Option<Vec<EncEntryTag>>)> {
        if let Some(key) = self.0.clone() {
            blocking(move || {
                let value = key.encrypt_entry_value(&value)?;
                let tags = if let Some(tags) = tags {
                    Some(key.encrypt_entry_tags(&tags)?)
                } else {
                    None
                };
                Ok((value, tags))
            })
            .await
        } else {
            Ok((
                NullEncryptor {}.encrypt_entry_value(&value)?,
                tags.map(|tags| NullEncryptor {}.encrypt_entry_tags(&tags))
                    .transpose()?,
            ))
        }
    }

    // pub async fn encrypt_entry_tags(&self, tags: Vec<EntryTag>) -> Result<Vec<EncEntryTag>> {
    //     if tags.is_empty() {
    //         return Ok(vec![]);
    //     }
    //     if let Some(key) = self.0.clone() {
    //         blocking(move || key.encrypt_entry_tags(&tags)).await
    //     } else {
    //         NullEncryptor {}.encrypt_entry_tags(&tags)
    //     }
    // }

    pub async fn decrypt_entry_value(&self, enc_value: Vec<u8>) -> Result<Vec<u8>> {
        if let Some(key) = self.0.clone() {
            blocking(move || key.decrypt_entry_value(&enc_value)).await
        } else {
            Ok(enc_value)
        }
    }

    pub async fn decrypt_entry_name_value(
        &self,
        name: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<(String, Vec<u8>)> {
        if let Some(key) = self.0.clone() {
            blocking(move || {
                Ok((
                    key.decrypt_entry_name(&name)?,
                    key.decrypt_entry_value(&value)?,
                ))
            })
            .await
        } else {
            Ok((
                String::from_utf8(name).map_err(err_map!(Encryption))?,
                value,
            ))
        }
    }

    pub async fn decrypt_entry_tags(&self, enc_tags: Vec<EncEntryTag>) -> Result<Vec<EntryTag>> {
        if enc_tags.is_empty() {
            return Ok(vec![]);
        }
        if let Some(key) = self.0.clone() {
            blocking(move || key.decrypt_entry_tags(&enc_tags)).await
        } else {
            NullEncryptor {}.decrypt_entry_tags(&enc_tags)
        }
    }
}
