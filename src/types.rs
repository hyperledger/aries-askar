use std::borrow::Cow;
use std::fmt::{self, Debug, Formatter};

use zeroize::Zeroize;

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
