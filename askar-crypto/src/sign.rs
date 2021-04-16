#[cfg(feature = "alloc")]
use crate::buffer::SecretBytes;
use crate::{alg::BlsGroups, buffer::WriteBuffer, error::Error};

pub trait KeySign: KeySigVerify {
    fn key_sign_buffer<B: WriteBuffer>(
        &self,
        data: &[u8],
        sig_type: Option<SignatureType>,
        out: &mut B,
    ) -> Result<(), Error>;

    #[cfg(feature = "alloc")]
    fn key_sign(&self, data: &[u8], sig_type: Option<SignatureType>) -> Result<SecretBytes, Error> {
        let mut buf = SecretBytes::with_capacity(128);
        self.key_sign_buffer(data, sig_type, &mut buf)?;
        Ok(buf)
    }
}

pub trait KeySigVerify {
    fn key_verify(
        &self,
        data: &[u8],
        signature: &[u8],
        sig_type: Option<SignatureType>,
    ) -> Result<bool, Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignatureType {
    Bls12_1381(BlsGroups),
    /// Standard signature output for ed25519
    EdDSA,
    // Elliptic curve DSA using P-256 and SHA-256
    ES256,
    // Elliptic curve DSA using K-256 and SHA-256
    ES256K,
}

impl SignatureType {
    pub const fn signature_size(&self) -> usize {
        match self {
            Self::Bls12_1381(BlsGroups::G1) => 48,
            Self::Bls12_1381(BlsGroups::G2) => 96,
            Self::EdDSA => 64,
            Self::ES256 => 64,
            Self::ES256K => 64,
        }
    }
}
