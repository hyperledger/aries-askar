//! Support for reading and writing structures as bytes

use core::fmt::Debug;

use askar_crypto::buffer::WriteBuffer;

use crate::error::Error;

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

    /// Write the byte array to a target
    fn write_bytes(&self, buf: &mut dyn WriteBuffer) -> Result<(), askar_crypto::Error> {
        self.with_bytes(|b| buf.buffer_write(b.as_ref()))
    }
}
