//! Support for reading and writing structures as bytes

use core::{
    array::TryFromSliceError,
    convert::{TryFrom, TryInto},
    fmt::Debug,
};

use askar_crypto::buffer::WriteBuffer;
use bls12_381::{G1Affine, Scalar};

use crate::Error;

/// Convert to and from a fixed-length byte array
pub trait FixedLengthBytes: Sized {
    /// The length of the byte array
    const LENGTH: usize;

    /// The type of the byte array
    type Buffer: AsRef<[u8]> + Clone + Copy + Debug;

    /// Work with a reference to the byte array
    fn with_bytes<R>(&self, f: impl FnOnce(&Self::Buffer) -> R) -> R;

    /// Convert from a byte array
    fn from_bytes(buf: &Self::Buffer) -> Result<Self, Error>;

    /// Read an instance from a cursor
    fn read_bytes(cur: &mut Cursor<'_>) -> Result<Self, Error>
    where
        for<'a> &'a Self::Buffer: TryFrom<&'a [u8], Error = TryFromSliceError>,
    {
        let buf = cur.read(Self::LENGTH)?.try_into().unwrap();
        Self::from_bytes(buf)
    }

    /// Write the byte array to a target
    fn write_bytes(&self, buf: &mut dyn WriteBuffer) -> Result<(), Error> {
        self.with_bytes(|b| buf.buffer_write(b.as_ref()))
    }
}

impl FixedLengthBytes for Scalar {
    const LENGTH: usize = 32;

    type Buffer = [u8; 32];

    fn from_bytes(buf: &Self::Buffer) -> Result<Self, Error> {
        let mut b = *buf;
        b.reverse(); // into little-endian
        if let Some(s) = bls12_381::Scalar::from_bytes(&b).into() {
            Ok(s)
        } else {
            Err(err_msg!(Usage, "Scalar bytes not in canonical format"))
        }
    }

    fn with_bytes<R>(&self, f: impl FnOnce(&Self::Buffer) -> R) -> R {
        let mut b = self.to_bytes();
        b.reverse(); // into big-endian
        f(&b)
    }
}

#[derive(Clone, Debug)]
/// A cursor for incrementally parsing a byte slice
pub struct Cursor<'r>(&'r [u8]);

impl<'r> Cursor<'r> {
    /// Create a new cursor instance
    pub fn new(buf: &'r [u8]) -> Self {
        Self(buf)
    }
}

impl Cursor<'_> {
    /// The remaining length of the slice
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Read a number of bytes from the slice
    pub fn read(&mut self, len: usize) -> Result<&[u8], Error> {
        if self.0.len() < len {
            Err(err_msg!(ExceededBuffer))
        } else {
            let (pfx, rest) = self.0.split_at(len);
            self.0 = rest;
            Ok(pfx)
        }
    }

    /// Read a type-safe number of bytes from the slice
    pub fn read_fixed<const L: usize>(&mut self) -> Result<&[u8; L], Error> {
        if self.0.len() < L {
            Err(err_msg!(ExceededBuffer))
        } else {
            let (pfx, rest) = self.0.split_at(L);
            self.0 = rest;
            Ok(pfx.try_into().unwrap())
        }
    }
}

pub(crate) trait CompressedBytes: Sized {
    fn read_compressed(cur: &mut Cursor<'_>) -> Result<Self, Error>;

    fn write_compressed(&self, buf: &mut dyn WriteBuffer) -> Result<(), Error>;
}

impl CompressedBytes for G1Affine {
    fn read_compressed(cur: &mut Cursor<'_>) -> Result<Self, Error> {
        if let Some(pt) = G1Affine::from_compressed(cur.read_fixed()?).into() {
            Ok(pt)
        } else {
            Err(err_msg!(Invalid, "Invalid G1 element"))
        }
    }

    fn write_compressed(&self, buf: &mut dyn WriteBuffer) -> Result<(), Error> {
        buf.buffer_write(&self.to_compressed())
    }
}
