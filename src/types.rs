use std::fmt::{self, Debug, Formatter};

use zeroize::Zeroize;

use super::error::KvResult;

pub type ProfileId = i64;

pub type KeyId = i64;

pub type Expiry = chrono::DateTime<chrono::Utc>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KvLockOperation<T> {
    Verify(T),
    Release(T),
}

#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
pub enum KvKeySelect {
    ForProfile(ProfileId),
    ForProfileKey(ProfileId, KeyId),
}

#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
pub enum KvLockStatus {
    Locked,
    Unlocked,
}

#[derive(Clone, Eq, Zeroize)]
pub struct KvEntry {
    pub key_id: KeyId,
    pub category: Vec<u8>,
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    pub tags: Option<Vec<KvTag>>,
    pub locked: Option<KvLockStatus>,
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

    pub fn is_locked(&self) -> bool {
        return self.locked == Some(KvLockStatus::Locked);
    }
}

impl Debug for KvEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("KvEntry")
            .field("key_id", &self.key_id)
            .field("category", &MaybeStr(&self.category))
            .field("name", &MaybeStr(&self.name))
            .field("value", &MaybeStr(&self.value))
            .field("tags", &self.tags)
            .field("locked", &self.locked)
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
        self.key_id == rhs.key_id
            && self.category == rhs.category
            && self.name == rhs.name
            && self.value == rhs.value
            && self.sorted_tags() == rhs.sorted_tags()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KvUpdateEntry {
    pub profile_key: KvKeySelect,
    pub category: Vec<u8>,
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    pub tags: Option<Vec<KvTag>>,
    pub expire_ms: Option<i64>,
}

impl Drop for KvUpdateEntry {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Zeroize for KvUpdateEntry {
    fn zeroize(&mut self) {
        self.category.zeroize();
        self.name.zeroize();
        self.value.zeroize();
        self.tags.zeroize();
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Zeroize)]
pub enum KvTag {
    Encrypted(Vec<u8>, Vec<u8>),
    Plaintext(Vec<u8>, Vec<u8>),
}

impl Debug for KvTag {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encrypted(name, value) => f
                .debug_tuple("Encrypted")
                .field(&MaybeStr(name))
                .field(&MaybeStr(value))
                .finish(),
            Self::Plaintext(name, value) => f
                .debug_tuple("Plaintext")
                .field(&MaybeStr(name))
                .field(&MaybeStr(value))
                .finish(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KvFetchOptions {
    pub retrieve_tags: bool,
    pub retrieve_value: bool,
    pub check_lock: bool,
}

impl KvFetchOptions {
    pub fn new(retrieve_tags: bool, retrieve_value: bool, check_lock: bool) -> Self {
        Self {
            retrieve_tags,
            retrieve_value,
            check_lock,
        }
    }
}

impl Default for KvFetchOptions {
    fn default() -> Self {
        return Self {
            retrieve_tags: true,
            retrieve_value: true,
            check_lock: false,
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
    fn encrypt_category(&self, category: &[u8]) -> KvResult<Vec<u8>>;
    fn encrypt_name(&self, name: &[u8]) -> KvResult<Vec<u8>>;
    fn encrypt_value(&self, value: &[u8]) -> KvResult<Vec<u8>>;
    fn encrypt_tags(&self, tags: Vec<KvTag>) -> KvResult<Vec<KvTag>>;

    fn decrypt_category(&self, enc_category: &[u8]) -> KvResult<Vec<u8>>;
    fn decrypt_name(&self, enc_name: &[u8]) -> KvResult<Vec<u8>>;
    fn decrypt_value(&self, enc_value: &[u8]) -> KvResult<Vec<u8>>;
    fn decrypt_tags(&self, enc_tags: Vec<KvTag>) -> KvResult<Vec<KvTag>>;

    fn encrypt_entry(&self, mut entry: KvEntry) -> KvResult<KvEntry> {
        entry.category = self.encrypt_category(&entry.category)?;
        entry.name = self.encrypt_name(&entry.name)?;
        entry.value = self.encrypt_value(&entry.value)?;
        entry.tags = entry
            .tags
            .take()
            .map(|t| self.encrypt_tags(t))
            .transpose()?;
        Ok(entry)
    }

    fn decrypt_entry(&self, mut enc_entry: KvEntry) -> KvResult<KvEntry> {
        enc_entry.category = self.decrypt_category(&enc_entry.category)?;
        enc_entry.name = self.decrypt_name(&enc_entry.name)?;
        enc_entry.value = self.decrypt_value(&enc_entry.value)?;
        enc_entry.tags = enc_entry
            .tags
            .take()
            .map(|t| self.decrypt_tags(t))
            .transpose()?;
        Ok(enc_entry)
    }
}

pub struct NullEncryptor;

impl EntryEncryptor for NullEncryptor {
    fn encrypt_category(&self, category: &[u8]) -> KvResult<Vec<u8>> {
        Ok(category.to_vec())
    }
    fn encrypt_name(&self, name: &[u8]) -> KvResult<Vec<u8>> {
        Ok(name.to_vec())
    }
    fn encrypt_value(&self, value: &[u8]) -> KvResult<Vec<u8>> {
        Ok(value.to_vec())
    }
    fn encrypt_tags(&self, tags: Vec<KvTag>) -> KvResult<Vec<KvTag>> {
        Ok(tags)
    }
    fn encrypt_entry(&self, entry: KvEntry) -> KvResult<KvEntry> {
        Ok(entry)
    }

    fn decrypt_category(&self, enc_category: &[u8]) -> KvResult<Vec<u8>> {
        Ok(enc_category.to_vec())
    }
    fn decrypt_name(&self, enc_name: &[u8]) -> KvResult<Vec<u8>> {
        Ok(enc_name.to_vec())
    }
    fn decrypt_value(&self, enc_value: &[u8]) -> KvResult<Vec<u8>> {
        Ok(enc_value.to_vec())
    }
    fn decrypt_tags(&self, enc_tags: Vec<KvTag>) -> KvResult<Vec<KvTag>> {
        Ok(enc_tags)
    }
    fn decrypt_entry(&self, enc_entry: KvEntry) -> KvResult<KvEntry> {
        Ok(enc_entry)
    }
}
