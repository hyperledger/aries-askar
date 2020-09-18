use std::borrow::Cow;
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use zeroize::Zeroize;

use super::error::Result;

pub type ProfileId = i64;

pub type KeyId = i64;

pub type Expiry = chrono::DateTime<chrono::Utc>;

#[derive(Clone, Eq, Zeroize)]
pub struct Entry {
    pub category: String,
    pub name: String,
    pub value: Vec<u8>,
    pub tags: Option<Vec<EntryTag>>,
}

impl Entry {
    pub fn sorted_tags(&self) -> Option<Vec<&EntryTag>> {
        if self.tags.is_some() {
            let tags = self.tags.as_ref().unwrap();
            if tags.len() > 0 {
                let mut tags = tags.iter().collect::<Vec<&EntryTag>>();
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

impl Debug for Entry {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("category", &self.category)
            .field("name", &self.name)
            .field("value", &MaybeStr(&self.value))
            .field("tags", &self.tags)
            .finish()
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl PartialEq for Entry {
    fn eq(&self, rhs: &Self) -> bool {
        self.category == rhs.category
            && self.name == rhs.name
            && self.value == rhs.value
            && self.sorted_tags() == rhs.sorted_tags()
    }
}

pub struct EncEntry<'a> {
    pub category: Cow<'a, [u8]>,
    pub name: Cow<'a, [u8]>,
    pub value: Cow<'a, [u8]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateEntry {
    pub entry: Entry,
    pub expire_ms: Option<i64>,
    pub profile_id: Option<ProfileId>,
}

impl Drop for UpdateEntry {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for UpdateEntry {
    fn zeroize(&mut self) {
        self.entry.zeroize();
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Zeroize)]
pub enum EntryTag {
    Encrypted(String, String),
    Plaintext(String, String),
}

impl Debug for EntryTag {
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

pub struct EncEntryTag {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    pub plaintext: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryFetchOptions {
    pub retrieve_tags: bool,
}

impl EntryFetchOptions {
    pub fn new(retrieve_tags: bool) -> Self {
        Self { retrieve_tags }
    }
}

impl Default for EntryFetchOptions {
    fn default() -> Self {
        return Self {
            retrieve_tags: true,
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
    fn encrypt_entry_tags(&self, tags: &Vec<EntryTag>) -> Result<Vec<EncEntryTag>>;

    fn decrypt_entry_category(&self, enc_category: &[u8]) -> Result<String>;
    fn decrypt_entry_name(&self, enc_name: &[u8]) -> Result<String>;
    fn decrypt_entry_value(&self, enc_value: &[u8]) -> Result<Vec<u8>>;
    fn decrypt_entry_tags(&self, enc_tags: &Vec<EncEntryTag>) -> Result<Vec<EntryTag>>;

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
    fn encrypt_entry_tags(&self, tags: &Vec<EntryTag>) -> Result<Vec<EncEntryTag>> {
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
    fn decrypt_entry_tags(&self, enc_tags: &Vec<EncEntryTag>) -> Result<Vec<EntryTag>> {
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
    fn encrypt_entry_tags(&self, tags: &Vec<EntryTag>) -> Result<Vec<EncEntryTag>> {
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
    fn decrypt_entry_tags(&self, enc_tags: &Vec<EncEntryTag>) -> Result<Vec<EntryTag>> {
        if let Some(key) = self {
            key.decrypt_entry_tags(enc_tags)
        } else {
            NullEncryptor {}.decrypt_entry_tags(enc_tags)
        }
    }
}
