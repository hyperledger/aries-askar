use crate::{buffer::ResizeBuffer, error::Error};

pub mod nacl_box;

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

    /// Get the required nonce size for encryption
    fn nonce_size() -> usize;

    /// Get the size of the verification tag
    fn tag_size() -> usize;
}
