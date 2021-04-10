use alloc::vec::Vec;
use core::fmt::Debug;

use serde::{Deserialize, Serialize};

use crate::buffer::SecretBytes;
use crate::error::Error;

pub trait SymEncryptKey:
    Clone + Debug + Eq + Sized + Serialize + for<'de> Deserialize<'de>
{
    const SIZE: usize;

    fn as_bytes(&self) -> &[u8];

    fn from_slice(bytes: &[u8]) -> Self;

    fn from_seed(seed: &[u8]) -> Result<Self, Error>;

    fn random_key() -> Self;
}

pub trait SymEncryptHashKey:
    Clone + Debug + Eq + Sized + Serialize + for<'de> Deserialize<'de>
{
    const SIZE: usize;

    fn random_hash_key() -> Self;
}

pub trait SymEncrypt: Debug {
    type Key: SymEncryptKey;
    type HashKey: SymEncryptHashKey;
    type Nonce;

    /// Convert a referenced secret value to a secure buffer with sufficient
    /// memory for in-place encryption, reusing the same buffer if possible
    fn prepare_input(input: &[u8]) -> SecretBytes;

    /// Create a predictable nonce for an input, to allow searching
    fn hashed_nonce(input: &SecretBytes, key: &Self::HashKey) -> Result<Self::Nonce, Error>;

    /// Encrypt a secret value and optional random nonce, producing a Vec containing the
    /// nonce, ciphertext and tag
    fn encrypt(
        input: SecretBytes,
        enc_key: &Self::Key,
        nonce: Option<Self::Nonce>,
    ) -> Result<Vec<u8>, Error>;

    /// Get the expected size of an input value after encryption
    fn encrypted_size(input_size: usize) -> usize;

    /// Decrypt a combined encrypted value
    fn decrypt(enc: Vec<u8>, enc_key: &Self::Key) -> Result<SecretBytes, Error>;
}

pub(crate) mod aead {
    use alloc::vec::Vec;
    use core::{
        fmt::{self, Debug, Formatter},
        marker::PhantomData,
        ptr,
    };

    use chacha20poly1305::{
        aead::{
            generic_array::{
                typenum::{Unsigned, U32},
                ArrayLength,
            },
            AeadInPlace, NewAead,
        },
        ChaCha20Poly1305,
    };
    use hmac::{Hmac, Mac, NewMac};
    use sha2::Sha256;

    use super::{SymEncrypt, SymEncryptHashKey, SymEncryptKey};
    use crate::{
        buffer::{ArrayKey, SecretBytes},
        error::Error,
        random::random_deterministic,
    };

    pub type ChaChaEncrypt = AeadEncrypt<ChaCha20Poly1305>;

    const SEED_LENGTH: usize = 32;

    impl<L: ArrayLength<u8> + Debug> SymEncryptKey for ArrayKey<L> {
        const SIZE: usize = L::USIZE;

        fn as_bytes(&self) -> &[u8] {
            &**self
        }

        fn from_slice(bytes: &[u8]) -> Self {
            ArrayKey::from_slice(bytes)
        }

        fn from_seed(seed: &[u8]) -> Result<Self, Error> {
            if seed.len() != SEED_LENGTH {
                return Err(err_msg!(Encryption, "Invalid length for seed"));
            }
            let input = ArrayKey::from_slice(seed);
            let raw_key = SecretBytes::from(random_deterministic(&input, L::USIZE));
            Ok(ArrayKey::from_slice(&raw_key))
        }

        fn random_key() -> Self {
            ArrayKey::random()
        }
    }

    impl<L: ArrayLength<u8> + Debug> SymEncryptHashKey for ArrayKey<L> {
        const SIZE: usize = L::USIZE;

        fn random_hash_key() -> Self {
            ArrayKey::random()
        }
    }

    #[derive(PartialEq, Eq, PartialOrd, Ord)]
    pub struct AeadEncrypt<E>(PhantomData<E>);

    impl<E: AeadInPlace> AeadEncrypt<E> {
        const NONCE_SIZE: usize = E::NonceSize::USIZE;
        const TAG_SIZE: usize = E::TagSize::USIZE;
    }

    impl<E> Debug for AeadEncrypt<E> {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.debug_struct("AeadEncrypt").finish()
        }
    }

    impl<E> SymEncrypt for AeadEncrypt<E>
    where
        E: NewAead + AeadInPlace,
        E::KeySize: Debug,
    {
        type Key = ArrayKey<E::KeySize>;
        type HashKey = ArrayKey<U32>;
        type Nonce = ArrayKey<E::NonceSize>;

        fn prepare_input(input: &[u8]) -> SecretBytes {
            // if we must perform a heap allocation, try to make sure that the
            // allocation is large enough to avoid reallocating later (for performance)
            let size = input.len() + Self::NONCE_SIZE + Self::TAG_SIZE;
            let mut buf = Vec::with_capacity(size);
            buf.extend_from_slice(input);
            SecretBytes::from(buf)
        }

        fn hashed_nonce(input: &SecretBytes, key: &Self::HashKey) -> Result<Self::Nonce, Error> {
            let mut nonce_hmac =
                Hmac::<Sha256>::new_varkey(&**key).map_err(|e| err_msg!(Encryption, "{}", e))?;
            nonce_hmac.update(&*input);
            let nonce_long = nonce_hmac.finalize().into_bytes();
            Ok(ArrayKey::<E::NonceSize>::from_slice(
                &nonce_long[0..E::NonceSize::USIZE],
            ))
        }

        fn encrypt(
            mut input: SecretBytes,
            enc_key: &Self::Key,
            nonce: Option<Self::Nonce>,
        ) -> Result<Vec<u8>, Error> {
            let nonce = nonce.unwrap_or_else(|| Self::Nonce::random());
            let chacha = E::new(&enc_key);
            let mut buf = input.as_buffer();
            // should be trivial if prepare_input was used
            buf.reserve(Self::NONCE_SIZE + Self::TAG_SIZE);
            // replace the input data with the ciphertext and tag
            chacha
                .encrypt_in_place(&*nonce, &[], &mut buf)
                .map_err(|e| err_msg!(Encryption, "{}", e))?;
            let mut buf = input.into_vec();
            // prepend the nonce to the current (ciphertext + tag) Vec contents.
            // extra capacity has previously been reserved for this in order to avoid
            // reallocation of the Vec buffer
            buf.splice(0..0, nonce.as_slice().into_iter().cloned());
            Ok(buf)
        }

        #[inline]
        fn encrypted_size(input_size: usize) -> usize {
            Self::NONCE_SIZE + Self::TAG_SIZE + input_size
        }

        fn decrypt(mut enc: Vec<u8>, enc_key: &Self::Key) -> Result<SecretBytes, Error> {
            if enc.len() < Self::NONCE_SIZE + Self::TAG_SIZE {
                return Err(err_msg!(
                    Encryption,
                    "Buffer is too short to represent an encrypted value"
                ));
            }
            let nonce = Self::Nonce::from_slice(&enc[0..Self::NONCE_SIZE]);
            let chacha = E::new(&enc_key);
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
                input.len() + ChaChaEncrypt::NONCE_SIZE + ChaChaEncrypt::TAG_SIZE
            );
            let dec = ChaChaEncrypt::decrypt(enc, &key).unwrap();
            assert_eq!(dec, &input[..]);
        }

        #[test]
        fn chacha_encrypt_avoid_realloc() {
            let input = ChaChaEncrypt::prepare_input(b"hello");
            let buffer_ptr = input.as_ptr() as usize;
            let key = ArrayKey::random();
            let enc = ChaChaEncrypt::encrypt(input, &key, None).unwrap();
            assert_eq!(
                enc.as_ptr() as usize,
                buffer_ptr,
                "Same buffer should be used"
            );
        }
    }
}
