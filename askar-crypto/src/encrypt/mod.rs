use crate::generic_array::ArrayLength;

use crate::{buffer::ResizeBuffer, error::Error};

pub mod nacl_box;

/// Trait for key types which perform AEAD encryption
pub trait KeyAeadInPlace {
    /// Encrypt a secret value in place, appending the verification tag
    fn encrypt_in_place<B: ResizeBuffer>(
        &self,
        buffer: &mut B,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(), Error>;

    /// Decrypt an encrypted (verification tag appended) value in place
    fn decrypt_in_place<B: ResizeBuffer>(
        &self,
        buffer: &mut B,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(), Error>;

    /// Get the required nonce length for encryption
    fn nonce_length() -> usize;

    /// Get the length of the verification tag
    fn tag_length() -> usize;
}

/// For concrete key types with fixed nonce and tag sizes
pub trait KeyAeadMeta {
    type NonceSize: ArrayLength<u8>;
    type TagSize: ArrayLength<u8>;
}
