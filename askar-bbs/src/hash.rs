//! Support for hashing inputs into scalar values

use core::fmt::{self, Debug, Formatter};

use askar_crypto::buffer::WriteBuffer;
use bls12_381::Scalar;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Sha3XofReader, Shake256,
};
use subtle::ConstantTimeEq;

use crate::Error;

#[derive(Clone, Debug)]
/// Derive Scalar values by hashing an arbitrary length input using Shake256
pub struct HashScalar<'d> {
    hasher: Shake256,
    dst: Option<&'d [u8]>,
}

impl<'d> HashScalar<'d> {
    /// Create a new HashScalar instance
    pub fn new(dst: Option<&'d [u8]>) -> Self {
        Self {
            hasher: Shake256::default(),
            dst,
        }
    }

    /// Create a new HashScalar instance with initial input to the hasher
    pub fn new_with_input(input: &[u8], dst: Option<&'d [u8]>) -> Self {
        let mut slf = Self::new(dst);
        slf.update(input);
        slf
    }
}

impl HashScalar<'_> {
    #[inline]
    /// Utility method to hash the input and return a single Scalar
    pub fn digest(input: impl AsRef<[u8]>, dst: Option<&[u8]>) -> Scalar {
        let mut state = HashScalar::new(dst);
        state.update(input.as_ref());
        state.finalize().next()
    }

    #[inline]
    /// Add more input to the hash state
    pub fn update(&mut self, input: impl AsRef<[u8]>) {
        self.hasher.update(input.as_ref());
    }

    /// Finalize the hasher and return a factory for Scalar values
    pub fn finalize(mut self) -> HashScalarRead {
        if let Some(dst) = self.dst {
            self.hasher.update(dst);
        }
        HashScalarRead(self.hasher.finalize_xof())
    }
}

impl WriteBuffer for HashScalar<'_> {
    fn buffer_write(&mut self, data: &[u8]) -> Result<(), Error> {
        self.update(data);
        Ok(())
    }
}

/// The output of a HashScalar, allowing for multiple Scalar values to be read
pub struct HashScalarRead(Sha3XofReader);

impl HashScalarRead {
    /// Read the next non-zero Scalar value from the extensible hash output
    pub fn next(&mut self) -> Scalar {
        let mut buf = [0u8; 64];
        let mut s;
        loop {
            self.0.read(&mut buf);
            s = Scalar::from_bytes_wide(&buf);
            if !bool::from(s.ct_eq(&Scalar::zero())) {
                break s;
            }
        }
    }
}

impl Debug for HashScalarRead {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("HashScalarRead").finish()
    }
}
