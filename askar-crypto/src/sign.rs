//! Signature traits and parameters

#[cfg(feature = "alloc")]
use crate::buffer::SecretBytes;
use crate::{buffer::WriteBuffer, error::Error};

/// Signature creation operations
pub trait KeySign: KeySigVerify {
    /// Create a signature of the requested type and write it to the
    /// provided buffer.
    fn write_signature(
        &self,
        message: &[u8],
        sig_type: Option<SignatureType>,
        out: &mut dyn WriteBuffer,
    ) -> Result<(), Error>;

    #[cfg(feature = "alloc")]
    /// Create a signature of the requested type and return an allocated
    /// buffer.
    fn create_signature(
        &self,
        message: &[u8],
        sig_type: Option<SignatureType>,
    ) -> Result<SecretBytes, Error> {
        let mut buf = SecretBytes::with_capacity(128);
        self.write_signature(message, sig_type, &mut buf)?;
        Ok(buf)
    }
}

/// Signature verification operations
pub trait KeySigVerify {
    /// Check the validity of signature over a message with the
    /// specified signature type.
    fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        sig_type: Option<SignatureType>,
    ) -> Result<bool, Error>;
}

/// Supported signature types
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignatureType {
    // Bls12_1381(BlsGroups),
    /// Standard signature output for ed25519
    EdDSA,
    /// Elliptic curve DSA using P-256 and SHA-256
    ES256,
    /// Elliptic curve DSA using K-256 and SHA-256
    ES256K,
}

impl SignatureType {
    /// Get the length of the signature output.
    pub const fn signature_length(&self) -> usize {
        match self {
            // Self::Bls12_1381(BlsGroups::G1) => 48,
            // Self::Bls12_1381(BlsGroups::G2) => 96,
            Self::EdDSA => 64,
            Self::ES256 => 64,
            Self::ES256K => 64,
        }
    }
}
