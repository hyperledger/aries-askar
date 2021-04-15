use alloc::{string::String, vec::Vec};
use core::{
    fmt::{self, Debug, Formatter},
    iter, mem,
    ops::{Deref, Range},
};

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

    pub fn reserve(&mut self, extra: usize) {
        self.ensure_capacity(self.len() + extra)
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
        self.ensure_capacity(len);
        self.0.resize(len, 0u8);
        Ok(())
    }

    fn buffer_splice_with(
        &mut self,
        range: Range<usize>,
        len: usize,
        f: impl FnOnce(&mut [u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let rem_len = range.len();
        if len > rem_len {
            self.reserve(len - rem_len);
        }
        let start = range.start;
        self.0.splice(range, iter::repeat(0u8).take(len));
        f(&mut self.0[start..(start + len)])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn test_write_buffer<B: WriteBuffer + AsRef<[u8]>>(mut w: B) {
        w.write_with(5, |buf| {
            buf.copy_from_slice(b"hello");
            Ok(2)
        })
        .unwrap();
        w.write_slice(b"y").unwrap();
        assert_eq!(&w.as_ref()[..], b"hey");
    }

    pub(crate) fn test_resize_buffer<B: ResizeBuffer>(mut w: B) {
        w.write_slice(b"hello").unwrap();
        w.buffer_splice_with(1..3, 5, |ext| {
            ext.copy_from_slice(b"sugar");
            Ok(())
        })
        .unwrap();
        assert_eq!(&w.as_ref()[..], b"hsugarlo");
        w.buffer_splice_with(1..6, 2, |ext| {
            ext.copy_from_slice(b"el");
            Ok(())
        })
        .unwrap();
        assert_eq!(&w.as_ref()[..], b"hello");
        w.buffer_resize(7).unwrap();
        assert_eq!(&w.as_ref()[..], b"hello\0\0");
        w.buffer_resize(5).unwrap();
        assert_eq!(&w.as_ref()[..], b"hello");
    }

    #[test]
    fn write_buffer_vec() {
        test_write_buffer(Vec::new());
    }

    #[test]
    fn resize_buffer_vec() {
        test_resize_buffer(Vec::new());
    }

    #[test]
    fn write_buffer_secret() {
        test_write_buffer(SecretBytes::with_capacity(10));
    }

    #[test]
    fn resize_buffer_secret() {
        test_resize_buffer(SecretBytes::with_capacity(10));
    }
}
