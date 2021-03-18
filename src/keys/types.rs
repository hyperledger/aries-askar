use std::borrow::Cow;
use std::cmp::Ordering;
use std::fmt::{self, Debug, Formatter};
use std::mem::ManuallyDrop;
use std::ops::Deref;

use aead::generic_array::{ArrayLength, GenericArray};
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

use crate::random::random_array;

/// A secure key representation for fixed-length keys
#[derive(Clone, Debug, Hash, Zeroize)]
pub struct ArrayKey<L: ArrayLength<u8>>(GenericArray<u8, L>);

impl<L: ArrayLength<u8>> ArrayKey<L> {
    pub const SIZE: usize = L::USIZE;

    #[inline]
    pub fn from_slice<D: AsRef<[u8]>>(data: D) -> Self {
        Self(GenericArray::clone_from_slice(data.as_ref()))
    }

    #[inline]
    pub fn extract(self) -> GenericArray<u8, L> {
        self.0
    }

    #[inline]
    pub fn random() -> Self {
        Self(random_array())
    }
}

impl<L: ArrayLength<u8>> Default for ArrayKey<L> {
    #[inline]
    fn default() -> Self {
        Self(GenericArray::default())
    }
}

impl<L: ArrayLength<u8>> From<GenericArray<u8, L>> for ArrayKey<L> {
    fn from(key: GenericArray<u8, L>) -> Self {
        Self(key)
    }
}

impl<L: ArrayLength<u8>> std::ops::Deref for ArrayKey<L> {
    type Target = GenericArray<u8, L>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<L: ArrayLength<u8>> std::ops::DerefMut for ArrayKey<L> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<L: ArrayLength<u8>> PartialEq for ArrayKey<L> {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}
impl<L: ArrayLength<u8>> Eq for ArrayKey<L> {}

impl<L: ArrayLength<u8>> PartialOrd for ArrayKey<L> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.partial_cmp(&*other)
    }
}
impl<L: ArrayLength<u8>> Ord for ArrayKey<L> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&*other)
    }
}

impl<L: ArrayLength<u8>> Serialize for ArrayKey<L> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(hex::encode(&self.0.as_slice()).as_str())
    }
}

impl<'a, L: ArrayLength<u8>> Deserialize<'a> for ArrayKey<L> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        deserializer.deserialize_str(KeyVisitor {
            _pd: std::marker::PhantomData,
        })
    }
}

struct KeyVisitor<L: ArrayLength<u8>> {
    _pd: std::marker::PhantomData<L>,
}

impl<'a, L: ArrayLength<u8>> Visitor<'a> for KeyVisitor<L> {
    type Value = ArrayKey<L>;

    fn expecting(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        formatter.write_str(stringify!($name))
    }

    fn visit_str<E>(self, value: &str) -> Result<ArrayKey<L>, E>
    where
        E: serde::de::Error,
    {
        let key = hex::decode(value).map_err(E::custom)?;
        Ok(ArrayKey(GenericArray::clone_from_slice(key.as_slice())))
    }
}

/// A possibly-empty password or key used to derive a store wrap key
#[derive(Clone)]
pub struct PassKey<'a>(Option<Cow<'a, str>>);

impl PassKey<'_> {
    /// Create a scoped reference to the passkey
    pub fn as_ref(&self) -> PassKey<'_> {
        PassKey(Some(Cow::Borrowed(&**self)))
    }

    pub(crate) fn is_none(&self) -> bool {
        self.0.is_none()
    }

    pub(crate) fn into_owned(self) -> PassKey<'static> {
        let mut slf = ManuallyDrop::new(self);
        let val = slf.0.take();
        PassKey(match val {
            None => None,
            Some(Cow::Borrowed(s)) => Some(Cow::Owned(s.to_string())),
            Some(Cow::Owned(s)) => Some(Cow::Owned(s)),
        })
    }
}

impl Debug for PassKey<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if cfg!(test) {
            f.debug_tuple("PassKey").field(&*self).finish()
        } else {
            f.debug_tuple("PassKey").field(&"<secret>").finish()
        }
    }
}

impl Default for PassKey<'_> {
    fn default() -> Self {
        Self(None)
    }
}

impl Deref for PassKey<'_> {
    type Target = str;

    fn deref(&self) -> &str {
        match self.0.as_ref() {
            None => "",
            Some(s) => s.as_ref(),
        }
    }
}

impl Drop for PassKey<'_> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<'a> From<&'a str> for PassKey<'a> {
    fn from(inner: &'a str) -> Self {
        Self(Some(Cow::Borrowed(inner)))
    }
}

impl From<String> for PassKey<'_> {
    fn from(inner: String) -> Self {
        Self(Some(Cow::Owned(inner)))
    }
}

impl<'a> From<Option<&'a str>> for PassKey<'a> {
    fn from(inner: Option<&'a str>) -> Self {
        Self(inner.map(Cow::Borrowed))
    }
}

impl<'a, 'b> PartialEq<PassKey<'b>> for PassKey<'a> {
    fn eq(&self, other: &PassKey<'b>) -> bool {
        &**self == &**other
    }
}
impl Eq for PassKey<'_> {}

impl Zeroize for PassKey<'_> {
    fn zeroize(&mut self) {
        match self.0.take() {
            Some(Cow::Owned(mut s)) => {
                s.zeroize();
            }
            _ => (),
        }
    }
}
