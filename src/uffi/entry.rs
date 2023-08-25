use std::collections::HashMap;
use std::sync::Arc;
use crate::{
    kms::KeyEntry,
    storage::entry::Entry,
    uffi::{error::ErrorCode, key::AskarLocalKey},
};

pub struct AskarEntry {
    entry: Entry,
}

impl AskarEntry {
    pub fn new(entry: Entry) -> Self {
        Self { entry }
    }
}

#[uniffi::export]
impl AskarEntry {
    pub fn category(&self) -> String {
        self.entry.category.clone()
    }

    pub fn name(&self) -> String {
        self.entry.name.clone()
    }

    pub fn tags(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for tag in &self.entry.tags {
            map.insert(tag.name().to_string(), tag.value().to_string());
        }
        map
    }

    pub fn value(&self) -> Vec<u8> {
        self.entry.value.to_vec()
    }
}

pub struct AskarKeyEntry {
    entry: KeyEntry,
}

impl AskarKeyEntry {
    pub fn new(entry: KeyEntry) -> Self {
        Self { entry }
    }
}

#[uniffi::export]
impl AskarKeyEntry {
    pub fn algorithm(&self) -> Option<String> {
        self.entry.algorithm().map(String::from)
    }

    pub fn metadata(&self) -> Option<String> {
        self.entry.metadata().map(String::from)
    }

    pub fn name(&self) -> String {
        self.entry.name().to_string()
    }

    pub fn is_local(&self) -> bool {
        self.entry.is_local()
    }

    pub fn tags(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for tag in &self.entry.tags {
            map.insert(tag.name().to_string(), tag.value().to_string());
        }
        map
    }

    pub fn load_local_key(&self) -> Result<Arc<AskarLocalKey>, ErrorCode> {
        let key = self.entry.load_local_key()?;
        Ok(Arc::new(AskarLocalKey { key }))
    }
}
