use std::borrow::Cow;
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use zeroize::Zeroize;

use super::error::Result;

pub type ProfileId = i64;

pub type KeyId = i64;

pub type Expiry = chrono::DateTime<chrono::Utc>;

#[derive(Clone, Eq, Zeroize)]
pub struct KvEntry {
    pub category: String,
    pub name: String,
    pub value: Vec<u8>,
    pub tags: Option<Vec<KvTag>>,
}

impl KvEntry {
    pub fn sorted_tags(&self) -> Option<Vec<&KvTag>> {
        if self.tags.is_some() {
            let tags = self.tags.as_ref().unwrap();
            if tags.len() > 0 {
                let mut tags = tags.iter().collect::<Vec<&KvTag>>();
                tags.sort();
                Some(tags)
            } else {
                None
            }
        } else {
            None
        }
    }
}

impl Debug for KvEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("KvEntry")
            .field("category", &self.category)
            .field("name", &self.name)
            .field("value", &MaybeStr(&self.value))
            .field("tags", &self.tags)
            .finish()
    }
}

impl Drop for KvEntry {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl PartialEq for KvEntry {
    fn eq(&self, rhs: &Self) -> bool {
        self.category == rhs.category
            && self.name == rhs.name
            && self.value == rhs.value
            && self.sorted_tags() == rhs.sorted_tags()
    }
}

pub struct KvEncEntry<'a> {
    pub category: Cow<'a, [u8]>,
    pub name: Cow<'a, [u8]>,
    pub value: Cow<'a, [u8]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KvUpdateEntry {
    pub entry: KvEntry,
    pub expire_ms: Option<i64>,
    pub profile_id: Option<ProfileId>,
}

impl Drop for KvUpdateEntry {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for KvUpdateEntry {
    fn zeroize(&mut self) {
        self.entry.zeroize();
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Zeroize)]
pub enum KvTag {
    Encrypted(String, String),
    Plaintext(String, String),
}

impl Debug for KvTag {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encrypted(name, value) => f
                .debug_tuple("Encrypted")
                .field(&name)
                .field(&value)
                .finish(),
            Self::Plaintext(name, value) => f
                .debug_tuple("Plaintext")
                .field(&name)
                .field(&value)
                .finish(),
        }
    }
}

pub struct KvEncTag {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    pub plaintext: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KvFetchOptions {
    pub retrieve_tags: bool,
    pub retrieve_value: bool,
}

impl KvFetchOptions {
    pub fn new(retrieve_tags: bool, retrieve_value: bool) -> Self {
        Self {
            retrieve_tags,
            retrieve_value,
        }
    }
}

impl Default for KvFetchOptions {
    fn default() -> Self {
        return Self {
            retrieve_tags: true,
            retrieve_value: true,
        };
    }
}

struct MaybeStr<'a>(&'a [u8]);

impl Debug for MaybeStr<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Ok(sval) = std::str::from_utf8(self.0) {
            write!(f, "{:?}", sval)
        } else {
            write!(f, "_\"{}\"", hex::encode(self.0))
        }
    }
}

// temporary types

pub trait EntryEncryptor {
    fn encrypt_entry_category(&self, category: &str) -> Result<Vec<u8>>;
    fn encrypt_entry_name(&self, name: &str) -> Result<Vec<u8>>;
    fn encrypt_entry_value(&self, value: &[u8]) -> Result<Vec<u8>>;
    fn encrypt_entry_tags(&self, tags: &Vec<KvTag>) -> Result<Vec<KvEncTag>>;

    fn decrypt_entry_category(&self, enc_category: &[u8]) -> Result<String>;
    fn decrypt_entry_name(&self, enc_name: &[u8]) -> Result<String>;
    fn decrypt_entry_value(&self, enc_value: &[u8]) -> Result<Vec<u8>>;
    fn decrypt_entry_tags(&self, enc_tags: &Vec<KvEncTag>) -> Result<Vec<KvTag>>;

    fn encrypt_entry(
        &self,
        entry: &KvEntry,
    ) -> Result<(KvEncEntry<'static>, Option<Vec<KvEncTag>>)> {
        let enc_entry = KvEncEntry {
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
        enc_entry: &KvEncEntry,
        enc_tags: Option<&Vec<KvEncTag>>,
    ) -> Result<KvEntry> {
        let tags = enc_tags.map(|t| self.decrypt_entry_tags(t)).transpose()?;
        Ok(KvEntry {
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
    fn encrypt_entry_tags(&self, tags: &Vec<KvTag>) -> Result<Vec<KvEncTag>> {
        Ok(tags
            .into_iter()
            .map(|tag| match tag {
                KvTag::Encrypted(name, value) => KvEncTag {
                    name: name.as_bytes().to_vec(),
                    value: value.as_bytes().to_vec(),
                    plaintext: false,
                },
                KvTag::Plaintext(name, value) => KvEncTag {
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
    fn decrypt_entry_tags(&self, enc_tags: &Vec<KvEncTag>) -> Result<Vec<KvTag>> {
        Ok(enc_tags.into_iter().try_fold(vec![], |mut acc, tag| {
            let name = String::from_utf8(tag.name.to_vec()).map_err(err_map!(Encryption))?;
            let value = String::from_utf8(tag.value.to_vec()).map_err(err_map!(Encryption))?;
            acc.push(if tag.plaintext {
                KvTag::Plaintext(name, value)
            } else {
                KvTag::Encrypted(name, value)
            });
            Result::Ok(acc)
        })?)
    }
}

impl<T> EntryEncryptor for Option<Arc<T>>
where
    T: EntryEncryptor,
{
    fn encrypt_entry_category(&self, category: &str) -> Result<Vec<u8>> {
        if let Some(key) = self {
            key.encrypt_entry_category(category)
        } else {
            Ok(category.as_bytes().to_vec())
        }
    }
    fn encrypt_entry_name(&self, name: &str) -> Result<Vec<u8>> {
        if let Some(key) = self {
            key.encrypt_entry_name(name)
        } else {
            Ok(name.as_bytes().to_vec())
        }
    }
    fn encrypt_entry_value(&self, value: &[u8]) -> Result<Vec<u8>> {
        if let Some(key) = self {
            key.encrypt_entry_value(value)
        } else {
            Ok(value.to_vec())
        }
    }
    fn encrypt_entry_tags(&self, tags: &Vec<KvTag>) -> Result<Vec<KvEncTag>> {
        if let Some(key) = self {
            key.encrypt_entry_tags(tags)
        } else {
            NullEncryptor {}.encrypt_entry_tags(tags)
        }
    }

    fn decrypt_entry_category(&self, enc_category: &[u8]) -> Result<String> {
        if let Some(key) = self {
            key.decrypt_entry_category(enc_category)
        } else {
            NullEncryptor {}.decrypt_entry_category(enc_category)
        }
    }
    fn decrypt_entry_name(&self, enc_name: &[u8]) -> Result<String> {
        if let Some(key) = self {
            key.decrypt_entry_name(enc_name)
        } else {
            NullEncryptor {}.decrypt_entry_name(enc_name)
        }
    }
    fn decrypt_entry_value(&self, enc_value: &[u8]) -> Result<Vec<u8>> {
        if let Some(key) = self {
            key.decrypt_entry_value(enc_value)
        } else {
            NullEncryptor {}.decrypt_entry_value(enc_value)
        }
    }
    fn decrypt_entry_tags(&self, enc_tags: &Vec<KvEncTag>) -> Result<Vec<KvTag>> {
        if let Some(key) = self {
            key.decrypt_entry_tags(enc_tags)
        } else {
            NullEncryptor {}.decrypt_entry_tags(enc_tags)
        }
    }
}
