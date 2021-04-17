use core::fmt::{self, Debug, Formatter};

use aead::{Aead, AeadInPlace, NewAead};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{
    buffer::Writer,
    generic_array::{typenum::Unsigned, GenericArray},
};

use crate::{
    buffer::{ArrayKey, ResizeBuffer, WriteBuffer},
    encrypt::{KeyAeadInPlace, KeyAeadMeta},
    error::Error,
    jwk::{JwkEncoder, ToJwk},
    kdf::{FromKeyExchange, KeyExchange},
    repr::{KeyGen, KeyMeta, KeySecretBytes},
};

pub static JWK_KEY_TYPE: &'static str = "oct";

pub trait AesGcmType {
    type Aead: NewAead + Aead + AeadInPlace;

    const JWK_ALG: &'static str;
}

pub struct A128;

impl AesGcmType for A128 {
    type Aead = Aes128Gcm;

    const JWK_ALG: &'static str = "A128GCM";
}

pub struct A256;

impl AesGcmType for A256 {
    type Aead = Aes256Gcm;

    const JWK_ALG: &'static str = "A256GCM";
}

type KeyType<A> = ArrayKey<<<A as AesGcmType>::Aead as NewAead>::KeySize>;

type NonceSize<A> = <<A as AesGcmType>::Aead as Aead>::NonceSize;

type TagSize<A> = <<A as AesGcmType>::Aead as Aead>::TagSize;

#[derive(Serialize, Deserialize, Zeroize)]
#[serde(
    transparent,
    bound(
        deserialize = "KeyType<T>: for<'a> Deserialize<'a>",
        serialize = "KeyType<T>: Serialize"
    )
)]
// SECURITY: ArrayKey is zeroized on drop
pub struct AesGcmKey<T: AesGcmType>(KeyType<T>);

impl<T: AesGcmType> AesGcmKey<T> {
    pub const KEY_LENGTH: usize = KeyType::<T>::SIZE;
    pub const NONCE_LENGTH: usize = NonceSize::<T>::USIZE;
    pub const TAG_LENGTH: usize = TagSize::<T>::USIZE;

    #[inline]
    pub(crate) fn uninit() -> Self {
        Self(KeyType::<T>::default())
    }
}

impl<T: AesGcmType> Clone for AesGcmKey<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: AesGcmType> Debug for AesGcmKey<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("AesGcmKey")
            .field("alg", &T::JWK_ALG)
            .field("key", &self.0)
            .finish()
    }
}

impl<T: AesGcmType> PartialEq for AesGcmKey<T> {
    fn eq(&self, other: &Self) -> bool {
        other.0 == self.0
    }
}

impl<T: AesGcmType> Eq for AesGcmKey<T> {}

impl<T: AesGcmType> KeyMeta for AesGcmKey<T> {
    type KeySize = <T::Aead as NewAead>::KeySize;
}

impl<T: AesGcmType> KeyGen for AesGcmKey<T> {
    fn generate() -> Result<Self, Error> {
        Ok(AesGcmKey(KeyType::<T>::random()))
    }
}

impl<T: AesGcmType> KeySecretBytes for AesGcmKey<T> {
    fn from_secret_bytes(key: &[u8]) -> Result<Self, Error> {
        if key.len() != <T::Aead as NewAead>::KeySize::USIZE {
            return Err(err_msg!(InvalidKeyData));
        }
        Ok(Self(KeyType::<T>::from_slice(key)))
    }

    fn with_secret_bytes<O>(&self, f: impl FnOnce(Option<&[u8]>) -> O) -> O {
        f(Some(self.0.as_ref()))
    }
}

impl<T: AesGcmType> KeyAeadMeta for AesGcmKey<T> {
    type NonceSize = NonceSize<T>;
    type TagSize = TagSize<T>;
}

impl<T: AesGcmType> KeyAeadInPlace for AesGcmKey<T> {
    /// Encrypt a secret value in place, appending the verification tag
    fn encrypt_in_place<B: ResizeBuffer>(
        &self,
        buffer: &mut B,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(), Error> {
        if nonce.len() != NonceSize::<T>::USIZE {
            return Err(err_msg!(InvalidNonce));
        }
        let nonce = GenericArray::from_slice(nonce);
        let chacha = T::Aead::new(self.0.as_ref());
        let tag = chacha
            .encrypt_in_place_detached(nonce, aad, buffer.as_mut())
            .map_err(|_| err_msg!(Encryption, "AEAD encryption error"))?;
        buffer.write_slice(&tag[..])?;
        Ok(())
    }

    /// Decrypt an encrypted (verification tag appended) value in place
    fn decrypt_in_place<B: ResizeBuffer>(
        &self,
        buffer: &mut B,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(), Error> {
        if nonce.len() != NonceSize::<T>::USIZE {
            return Err(err_msg!(InvalidNonce));
        }
        let nonce = GenericArray::from_slice(nonce);
        let buf_len = buffer.as_ref().len();
        if buf_len < TagSize::<T>::USIZE {
            return Err(err_msg!(Encryption, "Invalid size for encrypted data"));
        }
        let tag_start = buf_len - TagSize::<T>::USIZE;
        let mut tag = GenericArray::default();
        tag.clone_from_slice(&buffer.as_ref()[tag_start..]);
        let chacha = T::Aead::new(self.0.as_ref());
        chacha
            .decrypt_in_place_detached(nonce, aad, &mut buffer.as_mut()[..tag_start], &tag)
            .map_err(|_| err_msg!(Encryption, "AEAD decryption error"))?;
        buffer.buffer_resize(tag_start)?;
        Ok(())
    }

    fn nonce_length() -> usize {
        NonceSize::<T>::USIZE
    }

    fn tag_length() -> usize {
        TagSize::<T>::USIZE
    }
}

impl<T: AesGcmType> ToJwk for AesGcmKey<T> {
    fn to_jwk_encoder<B: WriteBuffer>(&self, enc: &mut JwkEncoder<B>) -> Result<(), Error> {
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

// for direct key agreement (not used currently)
impl<Lhs, Rhs, T> FromKeyExchange<Lhs, Rhs> for AesGcmKey<T>
where
    Lhs: KeyExchange<Rhs>,
    T: AesGcmType,
{
    fn from_key_exchange(lhs: &Lhs, rhs: &Rhs) -> Result<Self, Error> {
        // NOTE: currently requires the exchange to produce a key of the same length,
        // while it may be acceptable to just use the prefix if the output is longer?
        let mut key = Self::uninit();
        let mut buf = Writer::from_slice(key.0.as_mut());
        lhs.key_exchange_buffer(rhs, &mut buf)?;
        if buf.position() != Self::KEY_LENGTH {
            return Err(err_msg!(Usage, "Invalid length for key exchange output"));
        }
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::SecretBytes;

    #[test]
    fn encrypt_round_trip() {
        fn test_encrypt<T: AesGcmType>() {
            let input = b"hello";
            let key = AesGcmKey::<T>::generate().unwrap();
            let mut buffer = SecretBytes::from_slice(input);
            let nonce = AesGcmKey::<T>::random_nonce();
            key.encrypt_in_place(&mut buffer, &nonce, &[]).unwrap();
            assert_eq!(buffer.len(), input.len() + AesGcmKey::<T>::TAG_LENGTH);
            assert_ne!(&buffer[..], input);
            key.decrypt_in_place(&mut buffer, &nonce, &[]).unwrap();
            assert_eq!(&buffer[..], input);
        }
        test_encrypt::<A128>();
        test_encrypt::<A256>();
    }

    #[test]
    fn serialize_round_trip() {
        fn test_serialize<T: AesGcmType>() {
            let key = AesGcmKey::<T>::generate().unwrap();
            let sk = key.to_secret_bytes().unwrap();
            let bytes = serde_cbor::to_vec(&key).unwrap();
            let deser: &[u8] = serde_cbor::from_slice(bytes.as_ref()).unwrap();
            assert_eq!(deser, sk.as_ref());
        }
        test_serialize::<A128>();
        test_serialize::<A256>();
    }
}
