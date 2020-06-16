use super::error::KvResult;

pub type ClientId = Vec<u8>;

pub type KeyId = Vec<u8>;

pub trait KvLockToken: Send {}

pub trait KvScanToken: Send {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KvLockOperation<T: KvLockToken> {
    Verify(T),
    Release(T),
}

#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
pub enum KvKeySelect {
    ForClient(ClientId),
    ForClientKey(ClientId, KeyId),
}

#[derive(Clone, Debug, Eq, Zeroize)]
pub struct KvEntry {
    pub key_id: KeyId,
    pub category: Vec<u8>,
    pub name: Vec<u8>,
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

impl PartialEq for KvEntry {
    fn eq(&self, rhs: &Self) -> bool {
        self.key_id == rhs.key_id
            && self.category == rhs.category
            && self.name == rhs.name
            && self.value == rhs.value
            && self.sorted_tags() == rhs.sorted_tags()
    }
}

#[derive(Debug, PartialEq, Eq, Zeroize)]
pub struct KvUpdateEntry {
    pub client_key: KvKeySelect,
    pub category: Vec<u8>,
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    pub tags: Option<Vec<KvTag>>,
    pub expiry: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Zeroize)]
pub enum KvTag {
    Encrypted(Vec<u8>, Vec<u8>),
    Plaintext(Vec<u8>, Vec<u8>),
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

// temporary types

pub trait EntryEncryptor {
    fn encrypt_category(&self, category: Vec<u8>) -> KvResult<Vec<u8>>;
    fn encrypt_name(&self, name: Vec<u8>) -> KvResult<Vec<u8>>;
    fn encrypt_value(&self, value: Vec<u8>) -> KvResult<Vec<u8>>;
    fn encrypt_tags(&self, tags: Vec<KvTag>) -> KvResult<Vec<KvTag>>;

    fn decrypt_category(&self, enc_category: Vec<u8>) -> KvResult<Vec<u8>>;
    fn decrypt_name(&self, enc_name: Vec<u8>) -> KvResult<Vec<u8>>;
    fn decrypt_value(&self, enc_value: Vec<u8>) -> KvResult<Vec<u8>>;
    fn decrypt_tags(&self, enc_tags: Vec<KvTag>) -> KvResult<Vec<KvTag>>;

    fn encrypt_entry(&self, entry: KvEntry) -> KvResult<KvEntry> {
        Ok(KvEntry {
            key_id: entry.key_id,
            category: self.encrypt_category(entry.category)?,
            name: self.encrypt_name(entry.name)?,
            value: self.encrypt_value(entry.value)?,
            tags: entry.tags.map(|t| self.encrypt_tags(t)).transpose()?,
        })
    }

    fn decrypt_entry(&self, enc_entry: KvEntry) -> KvResult<KvEntry> {
        Ok(KvEntry {
            key_id: enc_entry.key_id,
            category: self.decrypt_category(enc_entry.category)?,
            name: self.decrypt_name(enc_entry.name)?,
            value: self.decrypt_value(enc_entry.value)?,
            tags: enc_entry.tags.map(|t| self.decrypt_tags(t)).transpose()?,
        })
    }
}

pub struct NullEncryptor;

impl EntryEncryptor for NullEncryptor {
    fn encrypt_category(&self, category: Vec<u8>) -> KvResult<Vec<u8>> {
        Ok(category)
    }
    fn encrypt_name(&self, name: Vec<u8>) -> KvResult<Vec<u8>> {
        Ok(name)
    }
    fn encrypt_value(&self, value: Vec<u8>) -> KvResult<Vec<u8>> {
        Ok(value)
    }
    fn encrypt_tags(&self, tags: Vec<KvTag>) -> KvResult<Vec<KvTag>> {
        Ok(tags)
    }
    fn encrypt_entry(&self, entry: KvEntry) -> KvResult<KvEntry> {
        Ok(entry)
    }

    fn decrypt_category(&self, enc_category: Vec<u8>) -> KvResult<Vec<u8>> {
        Ok(enc_category)
    }
    fn decrypt_name(&self, enc_name: Vec<u8>) -> KvResult<Vec<u8>> {
        Ok(enc_name)
    }
    fn decrypt_value(&self, enc_value: Vec<u8>) -> KvResult<Vec<u8>> {
        Ok(enc_value)
    }
    fn decrypt_tags(&self, enc_tags: Vec<KvTag>) -> KvResult<Vec<KvTag>> {
        Ok(enc_tags)
    }
    fn decrypt_entry(&self, enc_entry: KvEntry) -> KvResult<KvEntry> {
        Ok(enc_entry)
    }
}
