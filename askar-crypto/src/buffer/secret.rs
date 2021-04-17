use alloc::{string::String, vec::Vec};
use core::{
    fmt::{self, Debug, Formatter},
    mem,
    ops::{Deref, Range},
};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

use super::{string::MaybeStr, ResizeBuffer, WriteBuffer};
use crate::error::Error;

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

    #[inline]
    pub fn with_capacity(max_len: usize) -> Self {
        Self(Vec::with_capacity(max_len))
    }

    #[inline]
    pub fn from_slice(data: &[u8]) -> Self {
        let mut v = Vec::with_capacity(data.len());
        v.extend_from_slice(data);
        Self(v)
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Try to convert the buffer value to a string reference
    pub fn as_opt_str(&self) -> Option<&str> {
        core::str::from_utf8(self.0.as_slice()).ok()
    }

    pub fn ensure_capacity(&mut self, min_cap: usize) {
        let cap = self.0.capacity();
        if cap == 0 {
            self.0.reserve(min_cap);
        } else if cap > 0 && min_cap >= cap {
            // allocate a new buffer and copy the secure data over
            let new_cap = min_cap.max(cap * 2).max(32);
            let mut buf = SecretBytes::with_capacity(new_cap);
            buf.0.extend_from_slice(&self.0[..]);
            mem::swap(&mut buf, self);
            // old buf zeroized on drop
        }
    }

    #[inline]
    pub fn reserve(&mut self, extra: usize) {
        self.ensure_capacity(self.len() + extra)
    }

    #[inline]
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

    pub(crate) fn splice(
        &mut self,
        range: Range<usize>,
        iter: impl Iterator<Item = u8> + ExactSizeIterator,
    ) -> Result<(), Error> {
        assert!(range.end >= range.start);
        let rem_len = range.len();
        let ins_len = iter.len();
        if ins_len > rem_len {
            self.reserve(ins_len - rem_len);
        }
        self.0.splice(range, iter);
        Ok(())
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

impl WriteBuffer for SecretBytes {
    fn buffer_write(&mut self, data: &[u8]) -> Result<(), Error> {
        let pos = self.0.len();
        let new_len = pos + data.len();
        self.buffer_resize(new_len)?;
        self.0[pos..new_len].copy_from_slice(data);
        Ok(())
    }
}

impl ResizeBuffer for SecretBytes {
    fn buffer_insert(&mut self, pos: usize, data: &[u8]) -> Result<(), Error> {
        self.splice(pos..pos, data.into_iter().cloned())
    }

    fn buffer_remove(&mut self, range: Range<usize>) -> Result<(), Error> {
        self.0.drain(range);
        Ok(())
    }

    fn buffer_resize(&mut self, len: usize) -> Result<(), Error> {
        self.ensure_capacity(len);
        self.0.resize(len, 0u8);
        Ok(())
    }
}

impl Serialize for SecretBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_ref())
    }
}

impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(SecVisitor)
    }
}

struct SecVisitor;

impl<'de> de::Visitor<'de> for SecVisitor {
    type Value = SecretBytes;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("bytes")
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(SecretBytes::from_slice(value))
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{test_resize_buffer, test_write_buffer};
    use super::*;

    #[test]
    fn write_buffer_secret() {
        test_write_buffer(SecretBytes::with_capacity(10));
    }

    #[test]
    fn resize_buffer_secret() {
        test_resize_buffer(SecretBytes::with_capacity(10));
    }
}
