use core::fmt::Debug;

use digest::{Digest, Update};

use crate::generic_array::GenericArray;

use crate::{buffer::WriteBuffer, error::Error};

/// A `WriteBuffer` implementation which hashes its input
#[derive(Debug)]
pub struct HashBuffer<D: Digest>(D);

impl<D: Digest> HashBuffer<D> {
    /// Create a new instance
    pub fn new() -> Self {
        Self(D::new())
    }

    /// Finalize the hasher and extract the result
    pub fn finalize(self) -> GenericArray<u8, D::OutputSize> {
        self.0.finalize()
    }
}

impl<D: Digest> Default for HashBuffer<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: Debug + Digest> WriteBuffer for HashBuffer<D> {
    fn buffer_write(&mut self, data: &[u8]) -> Result<(), Error> {
        self.0.update(data);
        Ok(())
    }
}

impl<D: Debug + Digest> Update for HashBuffer<D> {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

pub trait Hashable {
    fn hash_into(&self, hasher: &mut impl Update) -> Result<(), Error>;
}

impl Hashable for &[u8] {
    fn hash_into(&self, hasher: &mut impl Update) -> Result<(), Error> {
        hasher.update(self);
        Ok(())
    }
}

impl<T: Hashable> Hashable for &[T] {
    fn hash_into(&self, hasher: &mut impl Update) -> Result<(), Error> {
        for item in self.iter() {
            item.hash_into(hasher)?;
        }
        Ok(())
    }
}

#[cfg(feature = "alloc")]
impl Hashable for alloc::vec::Vec<u8> {
    fn hash_into(&self, hasher: &mut impl Update) -> Result<(), Error> {
        hasher.update(&*self);
        Ok(())
    }
}

#[cfg(feature = "alloc")]
impl<T: Hashable> Hashable for alloc::vec::Vec<T> {
    fn hash_into(&self, hasher: &mut impl Update) -> Result<(), Error> {
        for item in self {
            item.hash_into(hasher)?;
        }
        Ok(())
    }
}
