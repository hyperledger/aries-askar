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

pub struct EnclaveHandle();

pub trait Enclave {
    fn encrypt_category(category: Vec<u8>) -> Vec<u8>;
    fn encrypt_name(name: Vec<u8>) -> Vec<u8>;
    fn encrypt_value(value: Vec<u8>) -> Vec<u8>;
}

impl Enclave for EnclaveHandle {
    fn encrypt_category(category: Vec<u8>) -> Vec<u8> {
        category
    }
    fn encrypt_name(name: Vec<u8>) -> Vec<u8> {
        name
    }
    fn encrypt_value(value: Vec<u8>) -> Vec<u8> {
        value
    }
}
