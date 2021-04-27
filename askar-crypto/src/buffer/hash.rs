use core::fmt::Debug;

use digest::Digest;

use crate::generic_array::GenericArray;

use crate::{buffer::WriteBuffer, error::Error};

#[derive(Debug)]
pub struct HashBuffer<D: Digest>(D);

impl<D: Digest> HashBuffer<D> {
    pub fn new() -> Self {
        Self(D::new())
    }

    pub fn finalize(self) -> GenericArray<u8, D::OutputSize> {
        self.0.finalize()
    }
}

impl<D: Debug + Digest> WriteBuffer for HashBuffer<D> {
    fn buffer_write(&mut self, data: &[u8]) -> Result<(), Error> {
        self.0.update(data);
        Ok(())
    }
}
