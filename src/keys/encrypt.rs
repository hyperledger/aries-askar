use aead::generic_array::ArrayLength;
use indy_utils::keys::ArrayKey;

use crate::error::Result;
use crate::types::SecretBytes;

pub trait SymEncrypt {
    type KeySize: ArrayLength<u8>;
    type NonceSize: ArrayLength<u8>;
    type TagSize: ArrayLength<u8>;

    /// Convert a referenced secret value to a secure buffer with sufficient
    /// memory for in-place encryption, reusing the same buffer if possible
    fn prepare_input(input: &[u8]) -> SecretBytes;

    /// Encrypt a secret value and optional random nonce, producing a Vec containing the
    /// nonce, ciphertext and tag
    fn encrypt(
        input: SecretBytes,
        enc_key: &ArrayKey<Self::KeySize>,
        nonce: Option<ArrayKey<Self::NonceSize>>,
    ) -> Result<Vec<u8>>;

    /// Decrypt a combined encrypted value
    fn decrypt(enc: Vec<u8>, enc_key: &ArrayKey<Self::KeySize>) -> Result<SecretBytes>;
}

pub(crate) mod chacha {
    use std::ptr;

    use chacha20poly1305::{
        aead::{generic_array::typenum::Unsigned, AeadInPlace, NewAead},
        ChaCha20Poly1305, Key as ChaChaKey,
    };
    use indy_utils::keys::ArrayKey;

    use super::{Result, SecretBytes, SymEncrypt};

    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct ChaChaEncrypt;

    impl ChaChaEncrypt {
        const NONCE_SIZE: usize = <ChaCha20Poly1305 as AeadInPlace>::NonceSize::USIZE;
        const TAG_SIZE: usize = <ChaCha20Poly1305 as AeadInPlace>::TagSize::USIZE;
    }

    impl SymEncrypt for ChaChaEncrypt {
        type KeySize = <ChaCha20Poly1305 as NewAead>::KeySize;
        type NonceSize = <ChaCha20Poly1305 as AeadInPlace>::NonceSize;
        type TagSize = <ChaCha20Poly1305 as AeadInPlace>::TagSize;

        fn prepare_input(input: &[u8]) -> SecretBytes {
            let size = input.len() + Self::NONCE_SIZE + Self::TAG_SIZE;
            let mut buf = Vec::with_capacity(size);
            buf.extend_from_slice(input);
            SecretBytes::from(buf)
        }

        fn encrypt(
            mut input: SecretBytes,
            enc_key: &ArrayKey<Self::KeySize>,
            nonce: Option<ArrayKey<Self::NonceSize>>,
        ) -> Result<Vec<u8>> {
            let nonce = nonce.unwrap_or_else(|| ArrayKey::<Self::NonceSize>::random());
            let chacha = ChaCha20Poly1305::new(ChaChaKey::from_slice(enc_key));
            let mut buf = input.as_buffer();
            buf.reserve_extra(Self::NONCE_SIZE + Self::TAG_SIZE);
            chacha
                .encrypt_in_place(&nonce, &[], &mut buf)
                .map_err(|e| err_msg!(Encryption, "{}", e))?;
            let mut buf = input.into_vec();
            let cipher_tag = buf.len();
            unsafe {
                // prepend the nonce to the current (ciphertext + tag) vec contents.
                // extra capacity has previously been reserved for this
                ptr::copy(
                    buf.as_mut_ptr(),
                    buf.as_mut_ptr().add(Self::NONCE_SIZE),
                    cipher_tag,
                );
                ptr::copy(nonce.as_ptr(), buf.as_mut_ptr(), Self::NONCE_SIZE);
                buf.set_len(Self::NONCE_SIZE + cipher_tag);
            }
            Ok(buf)
        }

        fn decrypt(mut enc: Vec<u8>, enc_key: &ArrayKey<Self::KeySize>) -> Result<SecretBytes> {
            if enc.len() < Self::NONCE_SIZE + Self::TAG_SIZE {
                return Err(err_msg!(
                    Encryption,
                    "Buffer is too short to represent an encrypted value"
                ));
            }
            let nonce = ArrayKey::<Self::NonceSize>::from_slice(&enc[0..Self::NONCE_SIZE]);
            let chacha = ChaCha20Poly1305::new(ChaChaKey::from_slice(enc_key));
            unsafe {
                let cipher_len = enc.len() - Self::NONCE_SIZE;
                ptr::copy(
                    enc.as_mut_ptr().add(Self::NONCE_SIZE),
                    enc.as_mut_ptr(),
                    cipher_len,
                );
                enc.set_len(cipher_len);
            }
            let mut result = SecretBytes::from(enc);
            chacha
                .decrypt_in_place(&nonce, &[], &mut result.as_buffer())
                .map_err(|e| err_msg!(Encryption, "Error decrypting record: {}", e))?;
            Ok(result)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn chacha_key_round_trip() {
            let input = b"hello";
            let key = ArrayKey::random();
            let enc = ChaChaEncrypt::encrypt(SecretBytes::from(&input[..]), &key, None).unwrap();
            assert_eq!(
                enc.len(),
                input.len()
                    + <ChaChaEncrypt as SymEncrypt>::NonceSize::USIZE
                    + <ChaChaEncrypt as SymEncrypt>::TagSize::USIZE
            );
            let dec = ChaChaEncrypt::decrypt(enc, &key).unwrap();
            assert_eq!(dec, &input[..]);
        }
    }
}
