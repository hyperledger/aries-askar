pub type ClientId = Vec<u8>;

pub type KeyId = Vec<u8>;

pub trait KvLockToken: Clone + std::fmt::Debug + Send {}

pub trait KvScanToken: Clone + std::fmt::Debug + Send {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KvLockOperation<T: KvLockToken> {
    Verify(T),
    Release(T),
    Ignore,
}

#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
pub enum KvKeySelect {
    ForClient(ClientId),
    ForClientKey(ClientId, KeyId),
}

#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
pub struct KvRecord {
    pub category: Vec<u8>,
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    pub tags: Option<Vec<KvTag>>,
}

#[derive(Debug, PartialEq, Eq, Zeroize)]
pub struct KvUpdateRecord {
    pub client_key: KvKeySelect,
    pub category: Vec<u8>,
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    pub tags: Option<Vec<KvTag>>,
    pub expiry: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
pub enum KvTag {
    Encrypted(Vec<u8>, Vec<u8>),
    Plaintext(Vec<u8>, Vec<u8>),
}

pub struct KvFetchOptions {
    pub retrieve_tags: bool,
    pub retrieve_value: bool,
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
