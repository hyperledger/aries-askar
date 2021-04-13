use alloc::{string::String, vec::Vec};
use core::{
    cmp::Ordering,
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    mem,
    ops::Deref,
};

use crate::generic_array::{ArrayLength, GenericArray};
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

use crate::{error::Error, random::fill_random};

mod string;
pub(crate) use self::string::{HexRepr, MaybeStr};

mod writer;
pub use self::writer::Writer;

/// A secure key representation for fixed-length keys
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
        serializer.collect_str(&HexRepr(&self.0))
    }
}

impl<'a, L: ArrayLength<u8>> Deserialize<'a> for ArrayKey<L> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        deserializer.deserialize_str(KeyVisitor { _pd: PhantomData })
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

impl<'a, L: ArrayLength<u8>> Visitor<'a> for KeyVisitor<L> {
    type Value = ArrayKey<L>;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(stringify!($name))
    }

    fn visit_str<E>(self, value: &str) -> Result<ArrayKey<L>, E>
    where
        E: serde::de::Error,
    {
        let mut arr = GenericArray::default();
        hex::decode_to_slice(value, &mut arr[..]).map_err(E::custom)?;
        Ok(ArrayKey(arr))
    }
}

/// A heap-allocated, zeroized byte buffer
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Zeroize)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new_with(len: usize, f: impl FnOnce(&mut [u8])) -> Self {
        let mut slf = Self::with_capacity(len);
        slf.0.resize(len, 0u8);
        f(slf.0.as_mut());
        slf
    }

    pub fn with_capacity(max_len: usize) -> Self {
        Self(Vec::with_capacity(max_len))
    }

    pub fn from_slice(data: &[u8]) -> Self {
        let mut v = Vec::with_capacity(data.len());
        v.extend_from_slice(data);
        Self(v)
    }

    /// Try to convert the buffer value to a string reference
    pub fn as_opt_str(&self) -> Option<&str> {
        core::str::from_utf8(self.0.as_slice()).ok()
    }

    pub fn into_vec(mut self) -> Vec<u8> {
        // FIXME zeroize extra capacity?
        let mut v = Vec::new(); // note: no heap allocation for empty vec
        mem::swap(&mut v, &mut self.0);
        mem::forget(self);
        v
    }

    pub(crate) fn as_vec_mut(&mut self) -> &mut Vec<u8> {
        &mut self.0
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

impl AsMut<[u8]> for SecretBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
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

pub trait WriteBuffer {
    fn write_slice(&mut self, data: &[u8]) -> Result<(), Error> {
        let len = data.len();
        self.write_with(len, |ext| {
            ext.copy_from_slice(data);
            Ok(len)
        })?;
        Ok(())
    }

    fn write_with(
        &mut self,
        max_len: usize,
        f: impl FnOnce(&mut [u8]) -> Result<usize, Error>,
    ) -> Result<usize, Error>;
}

pub trait ResizeBuffer: WriteBuffer + AsRef<[u8]> + AsMut<[u8]> {
    fn buffer_resize(&mut self, len: usize) -> Result<(), Error>;
}

impl WriteBuffer for Vec<u8> {
    fn write_with(
        &mut self,
        max_len: usize,
        f: impl FnOnce(&mut [u8]) -> Result<usize, Error>,
    ) -> Result<usize, Error> {
        let len = self.len();
        self.resize(len + max_len, 0u8);
        let written = f(&mut self[len..(len + max_len)])?;
        if written < max_len {
            self.truncate(len + written);
        }
        Ok(written)
    }
}

impl ResizeBuffer for Vec<u8> {
    fn buffer_resize(&mut self, len: usize) -> Result<(), Error> {
        self.resize(len, 0u8);
        Ok(())
    }
}

impl WriteBuffer for SecretBytes {
    fn write_with(
        &mut self,
        max_len: usize,
        f: impl FnOnce(&mut [u8]) -> Result<usize, Error>,
    ) -> Result<usize, Error> {
        let len = self.0.len();
        let new_len = len + max_len;
        self.buffer_resize(new_len)?;
        let written = f(&mut self.0[len..new_len])?;
        if written < max_len {
            self.0.truncate(len + written);
        }
        Ok(written)
    }
}

impl ResizeBuffer for SecretBytes {
    fn buffer_resize(&mut self, len: usize) -> Result<(), Error> {
        let cap = self.0.capacity();
        if cap > 0 && len >= cap {
            // allocate a new buffer and copy the secure data over
            let new_cap = len.max(cap * 2).max(32);
            let mut buf = SecretBytes::with_capacity(new_cap);
            buf.0.extend_from_slice(&self.0[..]);
            mem::swap(&mut buf, self);
            // old buf zeroized on drop
        }
        self.0.resize(len, 0u8);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_buffer_vec() {
        let mut w = Vec::new();
        w.write_with(5, |buf| {
            buf.copy_from_slice(b"hello");
            Ok(2)
        })
        .unwrap();
        w.write_slice(b"y").unwrap();
        assert_eq!(&w[..], b"hey");
    }

    #[test]
    fn write_buffer_secret() {
        let mut w = SecretBytes::with_capacity(10);
        w.write_with(5, |buf| {
            buf.copy_from_slice(b"hello");
            Ok(2)
        })
        .unwrap();
        w.write_slice(b"y").unwrap();
        assert_eq!(&w[..], b"hey");
    }
}
