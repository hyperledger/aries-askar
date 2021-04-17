use digest::Digest;

use crate::generic_array::GenericArray;

use crate::{buffer::WriteBuffer, error::Error};

const BUFFER_SIZE: usize = 256;

pub struct HashBuffer<D: Digest>(D);

impl<D: Digest> HashBuffer<D> {
    pub fn new() -> Self {
        Self(D::new())
    }

    pub fn finalize(self) -> GenericArray<u8, D::OutputSize> {
        self.0.finalize()
    }
}

impl<D: Digest> WriteBuffer for HashBuffer<D> {
    fn write_slice(&mut self, data: &[u8]) -> Result<(), Error> {
        self.0.update(data);
        Ok(())
    }

    fn write_with(
        &mut self,
        max_len: usize,
        f: impl FnOnce(&mut [u8]) -> Result<usize, Error>,
    ) -> Result<usize, Error> {
        // This could use a Vec to support larger inputs
        // but for current purposes a small fixed buffer is fine.
        // Could also accept the buffer (ResizeBuffer) as an argument
        // when creating the hasher.
        if max_len > BUFFER_SIZE {
            return Err(err_msg!(Usage, "Exceeded hash buffer size"));
        }
        let mut buf = [0u8; BUFFER_SIZE];
        let written = f(&mut buf[..max_len])?;
        self.write_slice(&buf[..written])?;
        Ok(written)
    }
}
