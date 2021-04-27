//! ChaCha20 and XChaCha20 stream ciphers with AEAD

use core::fmt::{self, Debug, Formatter};

use aead::{Aead, AeadInPlace, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::{Chacha20Types, HasKeyAlg, KeyAlg};
use crate::{
    buffer::{ArrayKey, ResizeBuffer, Writer},
    encrypt::{KeyAeadInPlace, KeyAeadMeta, KeyAeadParams},
    error::Error,
    generic_array::{typenum::Unsigned, GenericArray},
    jwk::{JwkEncoder, ToJwk},
    kdf::{FromKeyDerivation, FromKeyExchange, KeyDerivation, KeyExchange},
    random::fill_random_deterministic,
    repr::{KeyGen, KeyMeta, KeySecretBytes},
};

pub static JWK_KEY_TYPE: &'static str = "oct";

pub trait Chacha20Type: 'static {
    type Aead: NewAead + Aead + AeadInPlace;

    const ALG_TYPE: Chacha20Types;
    const JWK_ALG: &'static str;
}

#[derive(Debug)]
pub struct C20P;

impl Chacha20Type for C20P {
    type Aead = ChaCha20Poly1305;

    const ALG_TYPE: Chacha20Types = Chacha20Types::C20P;
    const JWK_ALG: &'static str = "C20P";
}

#[derive(Debug)]
pub struct XC20P;

impl Chacha20Type for XC20P {
    type Aead = XChaCha20Poly1305;

    const ALG_TYPE: Chacha20Types = Chacha20Types::XC20P;
    const JWK_ALG: &'static str = "XC20P";
}

type KeyType<A> = ArrayKey<<<A as Chacha20Type>::Aead as NewAead>::KeySize>;

type NonceSize<A> = <<A as Chacha20Type>::Aead as Aead>::NonceSize;

type TagSize<A> = <<A as Chacha20Type>::Aead as Aead>::TagSize;

#[derive(Serialize, Deserialize, Zeroize)]
#[serde(
    transparent,
    bound(
        deserialize = "KeyType<T>: for<'a> Deserialize<'a>",
        serialize = "KeyType<T>: Serialize"
    )
)]
// SECURITY: ArrayKey is zeroized on drop
pub struct Chacha20Key<T: Chacha20Type>(KeyType<T>);

impl<T: Chacha20Type> Chacha20Key<T> {
    pub const KEY_LENGTH: usize = KeyType::<T>::SIZE;
    pub const NONCE_LENGTH: usize = NonceSize::<T>::USIZE;
    pub const TAG_LENGTH: usize = TagSize::<T>::USIZE;

    #[inline]
    pub(crate) fn uninit() -> Self {
        Self(KeyType::<T>::default())
    }

    // this is consistent with Indy's wallet wrapping key generation
    // FIXME - move to aries_askar, use from_key_secret_bytes
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        let mut key = KeyType::<T>::default();
        fill_random_deterministic(seed, key.as_mut())?;
        Ok(Self(key))
    }
}

impl<T: Chacha20Type> Clone for Chacha20Key<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Chacha20Type> Debug for Chacha20Key<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Chacha20Key")
            .field("alg", &T::JWK_ALG)
            .field("key", &self.0)
            .finish()
    }
}

impl<T: Chacha20Type> PartialEq for Chacha20Key<T> {
    fn eq(&self, other: &Self) -> bool {
        other.0 == self.0
    }
}

impl<T: Chacha20Type> Eq for Chacha20Key<T> {}

impl<T: Chacha20Type> HasKeyAlg for Chacha20Key<T> {
    fn algorithm(&self) -> KeyAlg {
        KeyAlg::Chacha20(T::ALG_TYPE)
    }
}

impl<T: Chacha20Type> KeyMeta for Chacha20Key<T> {
    type KeySize = <T::Aead as NewAead>::KeySize;
}

impl<T: Chacha20Type> KeyGen for Chacha20Key<T> {
    fn generate() -> Result<Self, Error> {
        Ok(Chacha20Key(KeyType::<T>::random()))
    }
}

impl<T: Chacha20Type> KeySecretBytes for Chacha20Key<T> {
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

impl<T: Chacha20Type> FromKeyDerivation for Chacha20Key<T> {
    fn from_key_derivation<D: KeyDerivation>(mut derive: D) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let mut key = KeyType::<T>::default();
        derive.derive_key_bytes(key.as_mut())?;
        Ok(Self(key))
    }
}

impl<T: Chacha20Type> KeyAeadMeta for Chacha20Key<T> {
    type NonceSize = NonceSize<T>;
    type TagSize = TagSize<T>;
}

impl<T: Chacha20Type> KeyAeadInPlace for Chacha20Key<T> {
    /// Encrypt a secret value in place, appending the verification tag
    fn encrypt_in_place(
        &self,
        buffer: &mut dyn ResizeBuffer,
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
        buffer.buffer_write(&tag[..])?;
        Ok(())
    }

    /// Decrypt an encrypted (verification tag appended) value in place
    fn decrypt_in_place(
        &self,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(), Error> {
        if nonce.len() != NonceSize::<T>::USIZE {
            return Err(err_msg!(InvalidNonce));
        }
        let nonce = GenericArray::from_slice(nonce);
        let buf_len = buffer.as_ref().len();
        if buf_len < TagSize::<T>::USIZE {
            return Err(err_msg!(InvalidData, "Invalid size for encrypted data"));
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

    fn aead_params(&self) -> KeyAeadParams {
        KeyAeadParams {
            nonce_length: NonceSize::<T>::USIZE,
            tag_length: TagSize::<T>::USIZE,
        }
    }
}

impl<T: Chacha20Type> ToJwk for Chacha20Key<T> {
    fn to_jwk_encoder(&self, enc: &mut JwkEncoder<'_>) -> Result<(), Error> {
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
impl<Lhs, Rhs, T> FromKeyExchange<Lhs, Rhs> for Chacha20Key<T>
where
    Lhs: KeyExchange<Rhs> + ?Sized,
    Rhs: ?Sized,
    T: Chacha20Type,
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
        fn test_encrypt<T: Chacha20Type>() {
            let input = b"hello";
            let key = Chacha20Key::<T>::generate().unwrap();
            let mut buffer = SecretBytes::from_slice(input);
            let nonce = Chacha20Key::<T>::random_nonce();
            key.encrypt_in_place(&mut buffer, &nonce, &[]).unwrap();
            assert_eq!(buffer.len(), input.len() + Chacha20Key::<T>::TAG_LENGTH);
            assert_ne!(&buffer[..], input);
            key.decrypt_in_place(&mut buffer, &nonce, &[]).unwrap();
            assert_eq!(&buffer[..], input);
        }
        test_encrypt::<C20P>();
        test_encrypt::<XC20P>();
    }

    #[test]
    fn serialize_round_trip() {
        fn test_serialize<T: Chacha20Type>() {
            let key = Chacha20Key::<T>::generate().unwrap();
            let sk = key.to_secret_bytes().unwrap();
            let bytes = serde_cbor::to_vec(&key).unwrap();
            let deser: &[u8] = serde_cbor::from_slice(bytes.as_ref()).unwrap();
            assert_eq!(deser, sk.as_ref());
        }
        test_serialize::<C20P>();
        test_serialize::<XC20P>();
    }
}
