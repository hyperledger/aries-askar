//! AES key representations with AEAD support

use core::fmt::{self, Debug, Formatter};

use aead::{generic_array::ArrayLength, AeadCore, AeadInPlace, NewAead};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::{AesTypes, AnyKey, KeyAlg};
use crate::{
    buffer::{ArrayKey, Fill, ResizeBuffer},
    encrypt::{KeyAeadInPlace, KeyAeadMeta, KeyAeadParams},
    error::Error,
    generic_array::{typenum::Unsigned, GenericArray},
    jwk::{JwkEncoder, ToJwk},
    kdf::{DynKeyExchange, FromKeyDerivation, FromKeyExchange, KeyDerivation},
    random::KeyMaterial,
    repr::{DynPublicBytes, KeyGen, KeyMeta, KeySecretBytes},
    sign::{KeySigVerify, KeySign},
};

mod cbc_hmac;
pub use cbc_hmac::{A128CbcHs256, A256CbcHs512};

mod key_wrap;
pub use key_wrap::{A128Kw, A256Kw};

/// The 'kty' value of a symmetric key JWK
pub static JWK_KEY_TYPE: &'static str = "oct";

/// Trait implemented by supported AES authenticated encryption algorithms
pub trait AesType: Sized + 'static {
    /// The associated algorithm type
    const ALG_TYPE: AesTypes;
    /// The associated JWK algorithm name
    const JWK_ALG: &'static str;

    /// The size of the key secret bytes
    type KeySize: ArrayLength<u8>;
    /// The size of the AEAD encryption nonce
    type NonceSize: ArrayLength<u8>;
    /// The size of the AEAD encryption tag
    type TagSize: ArrayLength<u8>;

    /// Perform AEAD encryption
    fn encrypt_in_place(
        key: &AesKey<Self>,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<usize, Error>;

    /// Perform AEAD decryption
    fn decrypt_in_place(
        key: &AesKey<Self>,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(), Error>;

    /// Calculate the padding required for an encrypted message
    fn padding_length(_msg_len: usize) -> usize {
        0
    }
}

type KeyType<A> = ArrayKey<<A as AesType>::KeySize>;

type NonceSize<A> = <A as AesType>::NonceSize;

type TagSize<A> = <A as AesType>::TagSize;

/// An AES symmetric encryption key
#[derive(Serialize, Deserialize, Zeroize)]
#[serde(
    transparent,
    bound(
        deserialize = "KeyType<T>: for<'a> Deserialize<'a>",
        serialize = "KeyType<T>: Serialize"
    )
)]
// SECURITY: ArrayKey is zeroized on drop
pub struct AesKey<T: AesType>(KeyType<T>);

impl<T: AesType> Clone for AesKey<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: AesType> Debug for AesKey<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("AesKey")
            .field("alg", &T::JWK_ALG)
            .field("key", &self.0)
            .finish()
    }
}

impl<T: AesType> PartialEq for AesKey<T> {
    fn eq(&self, other: &Self) -> bool {
        other.0 == self.0
    }
}

impl<T: AesType> Eq for AesKey<T> {}

impl<T: AesType> AnyKey for AesKey<T> {
    fn algorithm(&self) -> KeyAlg {
        KeyAlg::Aes(T::ALG_TYPE)
    }
}

impl<T: AesType> DynKeyExchange for AesKey<T> {}

impl<T: AesType> KeyMeta for AesKey<T> {
    type KeySize = T::KeySize;
}

impl<T: AesType> KeyGen for AesKey<T> {
    fn generate(rng: impl KeyMaterial) -> Result<Self, Error> {
        Ok(AesKey(KeyType::<T>::generate(rng)))
    }
}

impl<T: AesType> KeySecretBytes for AesKey<T> {
    fn from_secret_bytes(key: &[u8]) -> Result<Self, Error> {
        if key.len() != KeyType::<T>::SIZE {
            return Err(err_msg!(InvalidKeyData));
        }
        Ok(Self(KeyType::<T>::from_slice(key)))
    }

    fn with_secret_bytes<O>(&self, f: impl FnOnce(Option<&[u8]>) -> O) -> O {
        f(Some(self.0.as_ref()))
    }
}

impl<T: AesType> DynPublicBytes for AesKey<T> {
    // null implementation
}

impl<T: AesType> FromKeyDerivation for AesKey<T> {
    fn from_key_derivation<D: KeyDerivation>(mut derive: D) -> Result<Self, Error> {
        Ok(Self(KeyType::<T>::try_new_with(|arr| {
            derive.derive_key_bytes(arr)
        })?))
    }
}

impl<T: AesType> ToJwk for AesKey<T> {
    fn encode_jwk(&self, enc: &mut dyn JwkEncoder) -> Result<(), Error> {
        if enc.is_public() {
            return Err(err_msg!(Unsupported, "Cannot export as a public key"));
        }
        if !enc.is_thumbprint() {
            enc.add_str("alg", T::JWK_ALG)?;
        }
        enc.add_as_base64("k", self.0.as_ref())?;
        enc.add_str("kty", JWK_KEY_TYPE)?;
        Ok(())
    }
}

impl<T: AesType> FromKeyExchange for AesKey<T> {
    fn from_key_exchange(lhs: &dyn AnyKey, rhs: &dyn AnyKey) -> Result<Self, Error> {
        Ok(Self(KeyType::<T>::try_new_with(|arr| {
            let mut w = Fill(arr);
            lhs.write_key_exchange(rhs, &mut w)?;
            if !w.is_filled() {
                return Err(err_msg!(Unsupported, "Insufficient key exchange output"));
            }
            Ok(())
        })?))
    }
}

impl<T: AesType> KeyAeadMeta for AesKey<T> {
    type NonceSize = T::NonceSize;
    type TagSize = T::TagSize;
}

impl<T: AesType> KeyAeadInPlace for AesKey<T> {
    fn encrypt_in_place(
        &self,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<usize, Error> {
        T::encrypt_in_place(&self, buffer, nonce, aad)
    }

    fn decrypt_in_place(
        &self,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(), Error> {
        T::decrypt_in_place(&self, buffer, nonce, aad)
    }

    fn aead_params(&self) -> KeyAeadParams {
        KeyAeadParams {
            nonce_length: NonceSize::<T>::USIZE,
            tag_length: TagSize::<T>::USIZE,
        }
    }

    fn aead_padding(&self, msg_len: usize) -> usize {
        T::padding_length(msg_len)
    }
}

impl<T: AesType> KeySign for AesKey<T> {}

impl<T: AesType> KeySigVerify for AesKey<T> {}

/// 128 bit AES-GCM
pub type A128Gcm = Aes128Gcm;

impl AesType for A128Gcm {
    const ALG_TYPE: AesTypes = AesTypes::A128Gcm;
    const JWK_ALG: &'static str = "A128GCM";

    type KeySize = <Self as NewAead>::KeySize;
    type NonceSize = <Self as AeadCore>::NonceSize;
    type TagSize = <Self as AeadCore>::TagSize;

    #[inline]
    fn encrypt_in_place(
        key: &AesKey<Self>,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<usize, Error> {
        gcm_encrypt_in_place(key, buffer, nonce, aad)
    }

    #[inline]
    fn decrypt_in_place(
        key: &AesKey<Self>,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(), Error> {
        gcm_decrypt_in_place(key, buffer, nonce, aad)
    }
}

/// 256 bit AES-GCM
pub type A256Gcm = Aes256Gcm;

impl AesType for A256Gcm {
    const ALG_TYPE: AesTypes = AesTypes::A256Gcm;
    const JWK_ALG: &'static str = "A256GCM";

    type KeySize = <Self as NewAead>::KeySize;
    type NonceSize = <Self as AeadCore>::NonceSize;
    type TagSize = <Self as AeadCore>::TagSize;

    #[inline]
    fn encrypt_in_place(
        key: &AesKey<Self>,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<usize, Error> {
        gcm_encrypt_in_place(key, buffer, nonce, aad)
    }

    #[inline]
    fn decrypt_in_place(
        key: &AesKey<Self>,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(), Error> {
        gcm_decrypt_in_place(key, buffer, nonce, aad)
    }
}

fn gcm_encrypt_in_place<C>(
    key: &AesKey<C>,
    buffer: &mut dyn ResizeBuffer,
    nonce: &[u8],
    aad: &[u8],
) -> Result<usize, Error>
where
    C: NewAead + AeadInPlace + AesType<KeySize = <C as NewAead>::KeySize>,
{
    if nonce.len() != NonceSize::<C>::USIZE {
        return Err(err_msg!(InvalidNonce));
    }
    let enc = <C as NewAead>::new(key.0.as_ref());
    let tag = enc
        .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, buffer.as_mut())
        .map_err(|_| err_msg!(Encryption, "AEAD encryption error"))?;
    let ctext_len = buffer.as_ref().len();
    buffer.buffer_write(&tag[..])?;
    Ok(ctext_len)
}

fn gcm_decrypt_in_place<C>(
    key: &AesKey<C>,
    buffer: &mut dyn ResizeBuffer,
    nonce: &[u8],
    aad: &[u8],
) -> Result<(), Error>
where
    C: NewAead + AeadInPlace + AesType<KeySize = <C as NewAead>::KeySize>,
{
    if nonce.len() != NonceSize::<C>::USIZE {
        return Err(err_msg!(InvalidNonce));
    }
    let buf_len = buffer.as_ref().len();
    if buf_len < TagSize::<C>::USIZE {
        return Err(err_msg!(Encryption, "Invalid size for encrypted data"));
    }
    let tag_start = buf_len - TagSize::<C>::USIZE;
    let mut tag = GenericArray::default();
    tag.clone_from_slice(&buffer.as_ref()[tag_start..]);
    let enc = <C as NewAead>::new(key.0.as_ref());
    enc.decrypt_in_place_detached(
        GenericArray::from_slice(nonce),
        aad,
        &mut buffer.as_mut()[..tag_start],
        &tag,
    )
    .map_err(|_| err_msg!(Encryption, "AEAD decryption error"))?;
    buffer.buffer_resize(tag_start)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::{SecretBytes, Writer};
    use crate::repr::DynSecretBytes;

    #[cfg(feature = "getrandom")]
    #[test]
    fn encrypt_round_trip() {
        fn test_encrypt_aad<T>()
        where
            T: AesType,
            AesKey<T>: KeyAeadInPlace + KeyAeadMeta,
        {
            let input = b"hello";
            let aad = b"additional data";
            let key = AesKey::<T>::random().unwrap();
            let mut buffer = SecretBytes::from_slice(input);
            let params = key.aead_params();
            let pad_len = key.aead_padding(input.len());
            let nonce = AesKey::<T>::random_nonce();
            key.encrypt_in_place(&mut buffer, &nonce, aad).unwrap();
            let enc_len = buffer.len();
            assert_eq!(enc_len, input.len() + pad_len + params.tag_length);
            assert_ne!(&buffer[..], input);
            let mut dec = buffer.clone();
            key.decrypt_in_place(&mut dec, &nonce, aad).unwrap();
            assert_eq!(&dec[..], input);

            // test tag validation
            buffer.as_mut()[enc_len - 1] = buffer.as_mut()[enc_len - 1].wrapping_add(1);
            assert!(key.decrypt_in_place(&mut buffer, &nonce, aad).is_err());
        }
        test_encrypt_aad::<A128Gcm>();
        test_encrypt_aad::<A256Gcm>();
        test_encrypt_aad::<A128CbcHs256>();
        test_encrypt_aad::<A256CbcHs512>();
    }

    #[cfg(feature = "getrandom")]
    #[test]
    fn test_random() {
        let key = AesKey::<A128CbcHs256>::random().unwrap();
        let nonce = AesKey::<A128CbcHs256>::random_nonce();
        let message = b"hello there";
        let mut buffer = [0u8; 255];
        buffer[0..message.len()].copy_from_slice(&message[..]);
        let mut writer = Writer::from_slice_position(&mut buffer, message.len());
        key.encrypt_in_place(&mut writer, &nonce, &[]).unwrap();
    }

    #[cfg(feature = "getrandom")]
    #[test]
    fn serialize_round_trip() {
        fn test_serialize<T: AesType>() {
            let key = AesKey::<T>::random().unwrap();
            let sk = key.to_secret_bytes().unwrap();
            let bytes = serde_cbor::to_vec(&key).unwrap();
            let deser: &[u8] = serde_cbor::from_slice(bytes.as_ref()).unwrap();
            assert_eq!(deser, sk.as_ref());
        }
        test_serialize::<A128Gcm>();
        test_serialize::<A256Gcm>();
        test_serialize::<A128CbcHs256>();
        test_serialize::<A256CbcHs512>();
        test_serialize::<A128Kw>();
        test_serialize::<A256Kw>();
    }
}
