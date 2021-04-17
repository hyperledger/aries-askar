#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::ops::Range;

use crate::error::Error;

mod array;
pub use self::array::ArrayKey;

mod hash;
pub use self::hash::HashBuffer;

#[cfg(feature = "alloc")]
mod secret;
#[cfg(feature = "alloc")]
pub use self::secret::SecretBytes;

mod string;
pub use self::string::HexRepr;

mod writer;
pub use self::writer::Writer;

pub trait WriteBuffer {
    fn buffer_write(&mut self, data: &[u8]) -> Result<(), Error>;
}

pub trait ResizeBuffer: WriteBuffer + AsRef<[u8]> + AsMut<[u8]> {
    fn buffer_insert(&mut self, pos: usize, data: &[u8]) -> Result<(), Error>;

    fn buffer_remove(&mut self, range: Range<usize>) -> Result<(), Error>;

    fn buffer_resize(&mut self, len: usize) -> Result<(), Error>;

    fn buffer_extend(&mut self, len: usize) -> Result<&mut [u8], Error> {
        let pos = self.as_ref().len();
        let end = pos + len;
        self.buffer_resize(end)?;
        Ok(&mut self.as_mut()[pos..end])
    }
}

#[cfg(feature = "alloc")]
impl WriteBuffer for Vec<u8> {
    fn buffer_write(&mut self, data: &[u8]) -> Result<(), Error> {
        self.extend_from_slice(data);
        Ok(())
    }
}

#[cfg(feature = "alloc")]
impl ResizeBuffer for Vec<u8> {
    fn buffer_insert(&mut self, pos: usize, data: &[u8]) -> Result<(), Error> {
        self.splice(pos..pos, data.into_iter().cloned());
        Ok(())
    }

    fn buffer_remove(&mut self, range: Range<usize>) -> Result<(), Error> {
        self.drain(range);
        Ok(())
    }

    fn buffer_resize(&mut self, len: usize) -> Result<(), Error> {
        self.resize(len, 0u8);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn test_write_buffer<B: WriteBuffer + AsRef<[u8]>>(mut w: B) {
        w.buffer_write(b"he").unwrap();
        w.buffer_write(b"y").unwrap();
        assert_eq!(&w.as_ref()[..], b"hey");
    }

    pub(crate) fn test_resize_buffer<B: ResizeBuffer>(mut w: B) {
        w.buffer_write(b"hello").unwrap();
        w.buffer_insert(1, b"world").unwrap();
        assert_eq!(&w.as_ref()[..], b"hworldello");
        w.buffer_resize(12).unwrap();
        assert_eq!(&w.as_ref()[..], b"hworldello\0\0");
        w.buffer_resize(6).unwrap();
        assert_eq!(&w.as_ref()[..], b"hworld");
        w.buffer_insert(1, b"ello").unwrap();
        assert_eq!(&w.as_ref()[..], b"helloworld");
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
