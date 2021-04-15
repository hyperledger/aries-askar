use alloc::vec::Vec;
use core::ops::Range;

use super::{ResizeBuffer, WriteBuffer};
use crate::error::Error;

pub struct Writer<'w, B: ?Sized> {
    inner: &'w mut B,
    pos: usize,
}

impl<B: ?Sized> Writer<'_, B> {
    pub fn position(&self) -> usize {
        self.pos
    }
}

impl<'w> Writer<'w, [u8]> {
    #[inline]
    pub fn from_slice(slice: &'w mut [u8]) -> Self {
        Writer {
            inner: slice,
            pos: 0,
        }
    }

    #[inline]
    pub fn from_slice_position(slice: &'w mut [u8], pos: usize) -> Self {
        Writer { inner: slice, pos }
    }
}

impl AsRef<[u8]> for Writer<'_, [u8]> {
    fn as_ref(&self) -> &[u8] {
        &self.inner[..self.pos]
    }
}

impl AsMut<[u8]> for Writer<'_, [u8]> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.inner[..self.pos]
    }
}

impl WriteBuffer for Writer<'_, [u8]> {
    fn write_with(
        &mut self,
        max_len: usize,
        f: impl FnOnce(&mut [u8]) -> Result<usize, Error>,
    ) -> Result<usize, Error> {
        let total = self.inner.len();
        let end = max_len + self.pos;
        if end > total {
            return Err(err_msg!(ExceededBuffer));
        }
        let written = f(&mut self.inner[self.pos..end])?;
        self.pos += written;
        Ok(written)
    }
}

impl ResizeBuffer for Writer<'_, [u8]> {
    fn buffer_resize(&mut self, len: usize) -> Result<(), Error> {
        let len = self.pos + len;
        if len > self.inner.len() {
            return Err(err_msg!(ExceededBuffer));
        }
        self.pos = len;
        Ok(())
    }

    fn buffer_splice_with(
        &mut self,
        range: Range<usize>,
        len: usize,
        f: impl FnOnce(&mut [u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let rem_len = range.len();
        if rem_len < len {
            if self.pos + len - rem_len > self.inner.len() {
                return Err(err_msg!(ExceededBuffer));
            }
            let diff = len - rem_len;
            self.pos += diff;
            for p in (self.pos - 1)..=range.end {
                self.inner[p] = self.inner[p - diff];
            }
        } else if rem_len != len {
            let diff = rem_len - len;
            for p in range.end..self.pos {
                self.inner[p] = self.inner[p + diff];
            }
            self.pos -= diff;
        }
        let end = range.start + len;
        let mslice = &mut self.inner[range.start..end];
        for p in 0..len {
            mslice[p] = 0u8;
        }
        f(mslice)?;
        Ok(())
    }
}

impl<'w> Writer<'w, Vec<u8>> {
    #[inline]
    pub fn from_vec(vec: &'w mut Vec<u8>) -> Self {
        Writer { inner: vec, pos: 0 }
    }

    #[inline]
    pub fn from_vec_skip(vec: &'w mut Vec<u8>, pos: usize) -> Self {
        Writer { inner: vec, pos }
    }
}

impl<B: WriteBuffer> WriteBuffer for Writer<'_, B> {
    fn write_with(
        &mut self,
        max_len: usize,
        f: impl FnOnce(&mut [u8]) -> Result<usize, Error>,
    ) -> Result<usize, Error> {
        self.inner.write_with(max_len, f)
    }
}

impl<B: ResizeBuffer> AsRef<[u8]> for Writer<'_, B> {
    fn as_ref(&self) -> &[u8] {
        &self.inner.as_ref()[self.pos..]
    }
}

impl<B: ResizeBuffer> AsMut<[u8]> for Writer<'_, B> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.inner.as_mut()[self.pos..]
    }
}

impl<B: ResizeBuffer> ResizeBuffer for Writer<'_, B> {
    fn buffer_resize(&mut self, len: usize) -> Result<(), Error> {
        self.inner.buffer_resize(self.pos + len)
    }

    fn buffer_splice_with(
        &mut self,
        range: Range<usize>,
        len: usize,
        f: impl FnOnce(&mut [u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.inner.buffer_splice_with(range, len, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_buffer_slice() {
        let mut buf = [0u8; 10];
        let mut w = Writer::from_slice(&mut buf);
        w.write_with(5, |buf| {
            buf.copy_from_slice(b"hello");
            Ok(2)
        })
        .unwrap();
        w.write_slice(b"y").unwrap();
        assert_eq!(w.position(), 3);
        assert_eq!(&buf[..3], b"hey");
    }
}
