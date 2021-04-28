//! AEAD encryption traits and parameters

use crate::{
    buffer::ResizeBuffer,
    error::Error,
    generic_array::{ArrayLength, GenericArray},
    random::fill_random,
};

#[cfg(feature = "alloc")] // FIXME - support non-alloc?
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub mod crypto_box;

/// Trait for key types which perform AEAD encryption
pub trait KeyAeadInPlace {
    /// Encrypt a secret value in place, appending the verification tag
    fn encrypt_in_place(
        &self,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(), Error>;

    /// Decrypt an encrypted (verification tag appended) value in place
    fn decrypt_in_place(
        &self,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(), Error>;

    /// Get the nonce and tag length for encryption
    fn aead_params(&self) -> KeyAeadParams;
}

/// For concrete key types with fixed nonce and tag sizes
pub trait KeyAeadMeta {
    type NonceSize: ArrayLength<u8>;
    type TagSize: ArrayLength<u8>;

    fn random_nonce() -> GenericArray<u8, Self::NonceSize> {
        let mut nonce = GenericArray::default();
        fill_random(nonce.as_mut_slice());
        nonce
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyAeadParams {
    pub nonce_length: usize,
    pub tag_length: usize,
}
