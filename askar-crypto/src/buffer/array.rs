use core::{
    cmp::Ordering,
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
};

use crate::generic_array::{ArrayLength, GenericArray};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

use crate::random::fill_random;

/// A secure representation for fixed-length keys
#[derive(Clone, Hash)]
pub struct ArrayKey<L: ArrayLength<u8>>(GenericArray<u8, L>);

impl<L: ArrayLength<u8>> ArrayKey<L> {
    pub const SIZE: usize = L::USIZE;

    #[inline]
    pub fn copy_from_slice<D: AsRef<[u8]>>(&mut self, data: D) {
        self.0[..].copy_from_slice(data.as_ref());
    }

    #[inline]
    pub fn extract(self) -> GenericArray<u8, L> {
        self.0.clone()
    }

    #[inline]
    pub fn from_slice(data: &[u8]) -> Self {
        // like <&GenericArray>::from_slice, panics if the length is incorrect
        Self(GenericArray::from_slice(data).clone())
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn random() -> Self {
        let mut slf = GenericArray::default();
        fill_random(&mut slf);
        Self(slf)
    }
}

impl<L: ArrayLength<u8>> AsRef<GenericArray<u8, L>> for ArrayKey<L> {
    fn as_ref(&self) -> &GenericArray<u8, L> {
        &self.0
    }
}

impl<L: ArrayLength<u8>> AsMut<GenericArray<u8, L>> for ArrayKey<L> {
    fn as_mut(&mut self) -> &mut GenericArray<u8, L> {
        &mut self.0
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

impl<L: ArrayLength<u8>> Debug for ArrayKey<L> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if cfg!(test) {
            f.debug_tuple("ArrayKey").field(&*self).finish()
        } else {
            f.debug_tuple("ArrayKey").field(&"<secret>").finish()
        }
    }
}

impl<L: ArrayLength<u8>> PartialEq for ArrayKey<L> {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}
impl<L: ArrayLength<u8>> Eq for ArrayKey<L> {}

impl<L: ArrayLength<u8>> PartialOrd for ArrayKey<L> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.partial_cmp(other.as_ref())
    }
}
impl<L: ArrayLength<u8>> Ord for ArrayKey<L> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(other.as_ref())
    }
}

impl<L: ArrayLength<u8>> Serialize for ArrayKey<L> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

impl<'de, L: ArrayLength<u8>> Deserialize<'de> for ArrayKey<L> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(KeyVisitor { _pd: PhantomData })
    }
}

impl<L: ArrayLength<u8>> Zeroize for ArrayKey<L> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<L: ArrayLength<u8>> Drop for ArrayKey<L> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

struct KeyVisitor<L: ArrayLength<u8>> {
    _pd: PhantomData<L>,
}

impl<'de, L: ArrayLength<u8>> de::Visitor<'de> for KeyVisitor<L> {
    type Value = ArrayKey<L>;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("ArrayKey")
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.len() != L::USIZE {
            return Err(E::invalid_length(value.len(), &self));
        }
        let mut arr = ArrayKey::default();
        arr.as_mut().copy_from_slice(value);
        Ok(arr)
    }
}
