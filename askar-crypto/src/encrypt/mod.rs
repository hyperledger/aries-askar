//! AEAD encryption traits and parameters

use crate::{buffer::ResizeBuffer, error::Error, generic_array::ArrayLength};

#[cfg(feature = "getrandom")]
use crate::generic_array::GenericArray;

#[cfg(feature = "crypto_box")]
#[cfg_attr(docsrs, doc(cfg(feature = "crypto_box")))]
pub mod crypto_box;

/// Object-safe trait for key types which perform AEAD encryption
pub trait KeyAeadInPlace {
    /// Encrypt a secret value in place, appending the verification tag and
    /// returning the length of the ciphertext
    fn encrypt_in_place(
        &self,
        _buffer: &mut dyn ResizeBuffer,
        _nonce: &[u8],
        _aad: &[u8],
    ) -> Result<usize, Error> {
        Err(err_msg!(Unsupported))
    }

    /// Decrypt an encrypted (verification tag appended) value in place
    fn decrypt_in_place(
        &self,
        _buffer: &mut dyn ResizeBuffer,
        _nonce: &[u8],
        _aad: &[u8],
    ) -> Result<(), Error> {
        Err(err_msg!(Unsupported))
    }

    /// Get the nonce and tag length for encryption
    fn aead_params(&self) -> KeyAeadParams {
        KeyAeadParams::default()
    }

    /// Get the ciphertext padding required
    fn aead_padding(&self, _msg_len: usize) -> usize {
        0
    }
}

/// For concrete key types with fixed nonce and tag sizes
pub trait KeyAeadMeta {
    /// The size of the AEAD nonce
    type NonceSize: ArrayLength<u8>;
    /// The size of the AEAD tag
    type TagSize: ArrayLength<u8>;

    /// Generate a new random nonce
    #[cfg(feature = "getrandom")]
    fn random_nonce() -> GenericArray<u8, Self::NonceSize> {
        let mut nonce = GenericArray::default();
        crate::random::fill_random(nonce.as_mut_slice());
        nonce
    }
}

/// A structure combining the AEAD parameters
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyAeadParams {
    /// The length of the nonce
    pub nonce_length: usize,
    /// The length of the tag
    pub tag_length: usize,
}
