use std::fmt::{self, Debug, Formatter};
use std::mem;
use std::ops::Deref;
use std::str::FromStr;

use aead::Buffer;
use serde::{
    de::{Error as SerdeError, MapAccess, SeqAccess, Visitor},
    ser::SerializeMap,
    Deserialize, Deserializer, Serialize, Serializer,
};
use zeroize::Zeroize;

use super::error::Error;
use super::wql;

pub type ProfileId = i64;

pub type Expiry = chrono::DateTime<chrono::Utc>;

pub(crate) fn sorted_tags(tags: &Vec<EntryTag>) -> Option<Vec<&EntryTag>> {
    if tags.len() > 0 {
        let mut tags = tags.iter().collect::<Vec<&EntryTag>>();
        tags.sort();
        Some(tags)
    } else {
        None
    }
}

/// A record in the store
#[derive(Clone, Debug, Eq)]
pub struct Entry {
    pub category: String,
    pub name: String,
    pub value: SecretBytes,
    pub tags: Option<Vec<EntryTag>>,
}

impl Entry {
    #[inline]
    pub fn new<C: Into<String>, N: Into<String>, V: Into<SecretBytes>>(
        category: C,
        name: N,
        value: V,
        tags: Option<Vec<EntryTag>>,
    ) -> Self {
        Self {
            category: category.into(),
            name: name.into(),
            value: value.into(),
            tags,
        }
    }

    pub fn sorted_tags(&self) -> Option<Vec<&EntryTag>> {
        self.tags.as_ref().and_then(sorted_tags)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryKind {
    Key = 1,
    Item = 2,
}

/// Supported operations for entries in the store
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryOperation {
    Insert,
    Replace,
    Remove,
}

/// A tag on a record in the store
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Zeroize)]
pub enum EntryTag {
    Encrypted(String, String),
    Plaintext(String, String),
}

impl EntryTag {
    pub fn name(&self) -> &str {
        match self {
            Self::Encrypted(name, _) | Self::Plaintext(name, _) => name,
        }
    }

    pub fn value(&self) -> &str {
        match self {
            Self::Encrypted(_, val) | Self::Plaintext(_, val) => val,
        }
    }
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct EntryTagSet(Vec<EntryTag>);

impl EntryTagSet {
    #[inline]
    pub fn new(tags: Vec<EntryTag>) -> Self {
        Self(tags)
    }

    #[inline]
    pub fn into_inner(self) -> Vec<EntryTag> {
        self.0
    }
}

impl<'de> Deserialize<'de> for EntryTagSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TagSetVisitor;

        impl<'d> Visitor<'d> for TagSetVisitor {
            type Value = EntryTagSet;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an object containing zero or more entry tags")
            }

            fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'d>,
            {
                let mut v = Vec::with_capacity(access.size_hint().unwrap_or_default());

                while let Some((key, values)) = access.next_entry::<&str, EntryTagValues>()? {
                    let (tag, enc) = match key.chars().next() {
                        Some('~') => (key[1..].to_owned(), false),
                        None => return Err(M::Error::custom("invalid tag name: empty string")),
                        _ => (key.to_owned(), true),
                    };
                    match (values, enc) {
                        (EntryTagValues::Single(value), true) => {
                            v.push(EntryTag::Encrypted(tag, value))
                        }
                        (EntryTagValues::Single(value), false) => {
                            v.push(EntryTag::Plaintext(tag, value))
                        }
                        (EntryTagValues::Multiple(values), true) => {
                            for value in values {
                                v.push(EntryTag::Encrypted(tag.clone(), value))
                            }
                        }
                        (EntryTagValues::Multiple(values), false) => {
                            for value in values {
                                v.push(EntryTag::Plaintext(tag.clone(), value))
                            }
                        }
                    }
                }

                Ok(EntryTagSet(v))
            }
        }

        deserializer.deserialize_map(TagSetVisitor)
    }
}

enum EntryTagValues {
    Single(String),
    Multiple(Vec<String>),
}

impl<'de> Deserialize<'de> for EntryTagValues {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TagValuesVisitor;

        impl<'d> Visitor<'d> for TagValuesVisitor {
            type Value = EntryTagValues;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string or list of strings")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: SerdeError,
            {
                Ok(EntryTagValues::Single(value.to_owned()))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: SerdeError,
            {
                Ok(EntryTagValues::Single(value))
            }

            fn visit_seq<S>(self, mut access: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'d>,
            {
                let mut v = Vec::with_capacity(access.size_hint().unwrap_or_default());
                while let Some(value) = access.next_element()? {
                    v.push(value)
                }
                Ok(EntryTagValues::Multiple(v))
            }
        }

        deserializer.deserialize_any(TagValuesVisitor)
    }
}

impl Serialize for EntryTagSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use std::collections::BTreeMap;

        #[derive(PartialOrd, Ord)]
        struct TagName<'a>(&'a str, bool);

        impl<'a> PartialEq for TagName<'a> {
            fn eq(&self, other: &Self) -> bool {
                self.1 == other.1 && self.0 == other.0
            }
        }

        impl<'a> Eq for TagName<'a> {}

        impl Serialize for TagName<'_> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                if self.1 {
                    serializer.serialize_str(&self.0)
                } else {
                    serializer.collect_str(&format_args!("~{}", self.0))
                }
            }
        }

        let mut tags = BTreeMap::new();
        for tag in self.0.iter() {
            let (name, value) = match tag {
                EntryTag::Encrypted(name, val) => (TagName(name.as_str(), true), val.as_str()),
                EntryTag::Plaintext(name, val) => (TagName(name.as_str(), false), val.as_str()),
            };
            tags.entry(name).or_insert_with(|| vec![]).push(value);
        }

        let mut map = serializer.serialize_map(Some(tags.len()))?;
        for (tag_name, values) in tags.into_iter() {
            if values.len() > 1 {
                map.serialize_entry(&tag_name, &values)?;
            } else {
                map.serialize_entry(&tag_name, &values[0])?;
            }
        }
        map.end()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EncEntryTag {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    pub plaintext: bool,
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

/// A protected byte buffer
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Zeroize)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub(crate) fn as_buffer(&mut self) -> SecretBytesMut<'_> {
        SecretBytesMut(&mut self.0)
    }

    pub(crate) fn into_vec(mut self) -> Vec<u8> {
        let mut v = vec![]; // note: no heap allocation for empty vec
        mem::swap(&mut v, &mut self.0);
        mem::forget(self);
        v
    }
}

impl Debug for SecretBytes {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if cfg!(test) {
            f.debug_tuple("Secret")
                .field(&MaybeStr(self.0.as_slice()))
                .finish()
        } else {
            f.write_str("<secret>")
        }
    }
}

impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Deref for SecretBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl From<&[u8]> for SecretBytes {
    fn from(inner: &[u8]) -> Self {
        Self(inner.to_vec())
    }
}

impl From<&str> for SecretBytes {
    fn from(inner: &str) -> Self {
        Self(inner.as_bytes().to_vec())
    }
}

impl From<String> for SecretBytes {
    fn from(inner: String) -> Self {
        Self(inner.into_bytes())
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(inner: Vec<u8>) -> Self {
        Self(inner)
    }
}

impl PartialEq<&[u8]> for SecretBytes {
    fn eq(&self, other: &&[u8]) -> bool {
        self.0.eq(other)
    }
}

impl PartialEq<Vec<u8>> for SecretBytes {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.0.eq(other)
    }
}

pub(crate) struct SecretBytesMut<'m>(&'m mut Vec<u8>);

impl SecretBytesMut<'_> {
    /// Obtain a large-enough SecretBytes without creating unsafe copies of
    /// the contained data
    pub fn reserve_extra(&mut self, extra: usize) {
        let len = self.0.len();
        if extra + len > self.0.capacity() {
            // allocate a new buffer and copy the secure data over
            let mut buf = Vec::with_capacity(extra + len);
            buf.extend_from_slice(&self.0[..]);
            mem::swap(&mut buf, &mut self.0);
            buf.zeroize()
        }
    }
}

impl Buffer for SecretBytesMut<'_> {
    fn extend_from_slice(&mut self, other: &[u8]) -> Result<(), aead::Error> {
        self.reserve_extra(other.len());
        self.0.extend_from_slice(other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len);
    }
}

impl AsRef<[u8]> for SecretBytesMut<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl AsMut<[u8]> for SecretBytesMut<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

/// A WQL filter used to restrict record queries
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct TagFilter {
    pub(crate) query: wql::Query,
}

impl TagFilter {
    #[inline]
    pub fn all_of(each: Vec<TagFilter>) -> Self {
        Self {
            query: wql::Query::And(unsafe { std::mem::transmute(each) }),
        }
    }

    #[inline]
    pub fn any_of(each: Vec<TagFilter>) -> Self {
        Self {
            query: wql::Query::Or(unsafe { std::mem::transmute(each) }),
        }
    }

    #[inline]
    pub fn not(filter: TagFilter) -> Self {
        Self {
            query: wql::Query::Not(Box::new(filter.query)),
        }
    }

    #[inline]
    pub fn is_eq(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            query: wql::Query::Eq(name.into(), value.into()),
        }
    }

    #[inline]
    pub fn is_not_eq(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            query: wql::Query::Neq(name.into(), value.into()),
        }
    }

    #[inline]
    pub fn is_gt(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            query: wql::Query::Gt(name.into(), value.into()),
        }
    }

    #[inline]
    pub fn is_gte(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            query: wql::Query::Gte(name.into(), value.into()),
        }
    }

    #[inline]
    pub fn is_lt(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            query: wql::Query::Lt(name.into(), value.into()),
        }
    }

    #[inline]
    pub fn is_lte(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            query: wql::Query::Lte(name.into(), value.into()),
        }
    }

    #[inline]
    pub fn is_like(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            query: wql::Query::Like(name.into(), value.into()),
        }
    }

    #[inline]
    pub fn is_in(name: impl Into<String>, value: Vec<String>) -> Self {
        Self {
            query: wql::Query::In(name.into(), value),
        }
    }

    #[inline]
    pub fn exist(names: Vec<String>) -> Self {
        Self {
            query: wql::Query::Exist(names),
        }
    }

    pub fn to_string(&self) -> Result<String, Error> {
        serde_json::to_string(&self.query).map_err(err_map!("Error encoding tag filter"))
    }
}

impl FromStr for TagFilter {
    type Err = Error;

    fn from_str(query: &str) -> Result<Self, Error> {
        let query = serde_json::from_str(query).map_err(err_map!("Error parsing tag query"))?;
        Ok(Self { query })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_tags() {
        let tags = EntryTagSet(vec![
            EntryTag::Encrypted("a".to_owned(), "aval".to_owned()),
            EntryTag::Plaintext("b".to_owned(), "bval".to_owned()),
            EntryTag::Plaintext("b".to_owned(), "bval-2".to_owned()),
        ]);
        let ser = serde_json::to_string(&tags).unwrap();
        assert_eq!(ser, r#"{"a":"aval","~b":["bval","bval-2"]}"#);
        let tags2 = serde_json::from_str(&ser).unwrap();
        assert_eq!(tags, tags2);
    }
}
