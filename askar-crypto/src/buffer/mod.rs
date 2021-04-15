use alloc::vec::Vec;
use core::{iter, ops::Range};

use crate::error::Error;

mod array;
pub use self::array::ArrayKey;

mod secret;
pub use self::secret::SecretBytes;

mod string;
pub use self::string::HexRepr;

mod writer;
pub use self::writer::Writer;

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
    fn buffer_insert_slice(&mut self, pos: usize, data: &[u8]) -> Result<(), Error> {
        self.buffer_splice_with(pos..pos, data.len(), |ext| {
            ext.copy_from_slice(data);
            Ok(())
        })
    }

    fn buffer_remove(&mut self, range: Range<usize>) -> Result<(), Error> {
        self.buffer_splice_with(range, 0, |_| Ok(()))
    }

    fn buffer_resize(&mut self, len: usize) -> Result<(), Error>;

    fn buffer_splice_with(
        &mut self,
        range: Range<usize>,
        len: usize,
        f: impl FnOnce(&mut [u8]) -> Result<(), Error>,
    ) -> Result<(), Error>;
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

    fn buffer_splice_with(
        &mut self,
        range: Range<usize>,
        len: usize,
        f: impl FnOnce(&mut [u8]) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let start = range.start;
        self.splice(range, iter::repeat(0u8).take(len));
        f(&mut self[start..(start + len)])?;
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
}
