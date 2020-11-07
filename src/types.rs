use std::fmt::{self, Debug, Formatter};
use std::mem::ManuallyDrop;
use std::ptr;
use std::str::FromStr;

use serde::{
    de::{Error as SerdeError, MapAccess, Visitor},
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

#[derive(Clone, Eq)]
pub struct Entry {
    pub category: String,
    pub name: String,
    pub value: Vec<u8>,
    pub tags: Option<Vec<EntryTag>>,
}

impl Entry {
    pub(crate) fn into_parts(self) -> (String, String, Vec<u8>, Option<Vec<EntryTag>>) {
        let slf = ManuallyDrop::new(self);
        unsafe {
            (
                ptr::read(&slf.category),
                ptr::read(&slf.name),
                ptr::read(&slf.value),
                ptr::read(&slf.tags),
            )
        }
    }

    pub fn sorted_tags(&self) -> Option<Vec<&EntryTag>> {
        self.tags.as_ref().and_then(sorted_tags)
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

impl Zeroize for Entry {
    fn zeroize(&mut self) {
        self.value.zeroize()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryKind {
    Key = 1,
    Item = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryOperation {
    Insert,
    Replace,
    Remove,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Zeroize)]
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

                while let Some((key, value)) = access.next_entry::<&str, String>()? {
                    let tag = match key.chars().next() {
                        Some('~') => EntryTag::Plaintext(key[1..].to_owned(), value),
                        None => return Err(M::Error::custom("invalid tag name: empty string")),
                        _ => EntryTag::Encrypted(key.to_owned(), value),
                    };
                    v.push(tag)
                }

                Ok(EntryTagSet(v))
            }
        }

        deserializer.deserialize_map(TagSetVisitor)
    }
}

impl Serialize for EntryTagSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        struct TagName<'a>(&'a str, bool);

        impl Serialize for TagName<'_> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                if self.1 {
                    serializer.serialize_str(self.0)
                } else {
                    serializer.collect_str(&format_args!("~{}", self.0))
                }
            }
        }

        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for tag in self.0.iter() {
            let (name, value, enc) = match tag {
                EntryTag::Encrypted(name, val) => (name.as_str(), val.as_str(), true),
                EntryTag::Plaintext(name, val) => (name.as_str(), val.as_str(), false),
            };
            map.serialize_entry(&TagName(name, enc), value)?;
        }
        map.end()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncEntryTag {
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
        ]);
        let ser = serde_json::to_string(&tags).unwrap();
        assert_eq!(ser, r#"{"a":"aval","~b":"bval"}"#);
        let tags2 = serde_json::from_str(&ser).unwrap();
        assert_eq!(tags, tags2);
    }
}
