use aead::{Aead, AeadInPlace, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use zeroize::Zeroize;

use crate::generic_array::{typenum::Unsigned, GenericArray};

use crate::{
    buffer::{ArrayKey, ResizeBuffer, WriteBuffer, Writer},
    caps::{KeyGen, KeySecretBytes},
    encrypt::{FromKeyExchange, KeyAeadInPlace, KeyExchange},
    error::Error,
    jwk::{JwkEncoder, ToJwk},
    random::fill_random_deterministic,
};

pub static JWK_KEY_TYPE: &'static str = "oct";

pub trait Chacha20Type {
    type Aead: NewAead + Aead + AeadInPlace;

    const JWK_ALG: &'static str;

    fn key_size() -> usize {
        <Self::Aead as NewAead>::KeySize::USIZE
    }
}

pub struct C20P;

impl Chacha20Type for C20P {
    type Aead = ChaCha20Poly1305;

    const JWK_ALG: &'static str = "C20P";
}

pub struct XC20P;

impl Chacha20Type for XC20P {
    type Aead = XChaCha20Poly1305;

    const JWK_ALG: &'static str = "XC20P";
}

type KeyType<A> = ArrayKey<<<A as Chacha20Type>::Aead as NewAead>::KeySize>;

type NonceSize<A> = <<A as Chacha20Type>::Aead as Aead>::NonceSize;

type TagSize<A> = <<A as Chacha20Type>::Aead as Aead>::TagSize;

#[derive(Clone, Debug, Zeroize)]
// SECURITY: ArrayKey is zeroized on drop
pub struct Chacha20Key<T: Chacha20Type>(KeyType<T>);

impl<T: Chacha20Type> Chacha20Key<T> {
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

impl<T: Chacha20Type> KeyGen for Chacha20Key<T> {
    fn generate() -> Result<Self, Error> {
        Ok(Chacha20Key(KeyType::<T>::random()))
    }
}

impl<T: Chacha20Type> KeySecretBytes for Chacha20Key<T> {
    fn from_key_secret_bytes(key: &[u8]) -> Result<Self, Error> {
        if key.len() != <T::Aead as NewAead>::KeySize::USIZE {
            return Err(err_msg!("Invalid length for chacha20 key"));
        }
        Ok(Self(KeyType::<T>::from_slice(key)))
    }

    fn to_key_secret_buffer<B: WriteBuffer>(&self, out: &mut B) -> Result<(), Error> {
        out.write_slice(self.0.as_ref())
    }
}

// impl<T: Chacha20Type> KeySecretBytes for Box<Chacha20Key<T>> {
//     fn from_key_secret_bytes(key: &[u8]) -> Result<Self, Error> {
//         if key.len() != <T::Aead as NewAead>::KeySize::USIZE {
//             return Err(err_msg!("Invalid length for chacha20 key"));
//         }
//         Ok(init_boxed(|buf| buf.copy_from_slice(key)))
//     }

//     fn to_key_secret_buffer<B: WriteBuffer>(&self, out: &mut B) -> Result<(), Error> {
//         out.write_slice(&self.0[..])
//     }
// }

impl<T: Chacha20Type> KeyAeadInPlace for Chacha20Key<T> {
    /// Encrypt a secret value in place, appending the verification tag
    fn encrypt_in_place<B: ResizeBuffer>(
        &self,
        buffer: &mut B,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(), Error> {
        if nonce.len() != NonceSize::<T>::USIZE {
            return Err(err_msg!(
                "invalid size for nonce (expected {} bytes)",
                NonceSize::<T>::USIZE
            ));
        }
        let nonce = GenericArray::from_slice(nonce);
        let chacha = T::Aead::new(self.0.as_ref());
        let tag = chacha
            .encrypt_in_place_detached(nonce, aad, buffer.as_mut())
            .map_err(|e| err_msg!(Encryption, "{}", e))?;
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
            return Err(err_msg!(
                "invalid size for nonce (expected {} bytes)",
                NonceSize::<T>::USIZE
            ));
        }
        let nonce = GenericArray::from_slice(nonce);
        let buf_len = buffer.as_ref().len();
        if buf_len < TagSize::<T>::USIZE {
            return Err(err_msg!("invalid size for encrypted data"));
        }
        let tag_start = buf_len - TagSize::<T>::USIZE;
        let mut tag = GenericArray::default();
        tag.clone_from_slice(&buffer.as_ref()[tag_start..]);
        let chacha = T::Aead::new(self.0.as_ref());
        chacha
            .decrypt_in_place_detached(nonce, aad, &mut buffer.as_mut()[..tag_start], &tag)
            .map_err(|e| err_msg!(Encryption, "{}", e))?;
        buffer.truncate(tag_start);
        Ok(())
    }

    /// Get the required nonce size for encryption
    fn nonce_size() -> usize {
        NonceSize::<T>::USIZE
    }

    /// Get the size of the verification tag
    fn tag_size() -> usize {
        TagSize::<T>::USIZE
    }
}

impl<T: Chacha20Type> ToJwk for Chacha20Key<T> {
    fn to_jwk_buffer<B: WriteBuffer>(&self, buffer: &mut JwkEncoder<B>) -> Result<(), Error> {
        buffer.add_str("kty", JWK_KEY_TYPE)?;
        if !buffer.is_secret() {
            return Err(err_msg!(Unsupported, "Cannot export as a public key"));
        }
        buffer.add_str("alg", T::JWK_ALG)?;
        buffer.add_as_base64("k", self.0.as_ref())?;
        buffer.add_str("use", "enc")?;
        Ok(())
    }
}

// for direct key agreement (not used currently)
impl<Lhs, Rhs, T> FromKeyExchange<Lhs, Rhs> for Chacha20Key<T>
where
    Lhs: KeyExchange<Rhs>,
    T: Chacha20Type,
{
    fn from_key_exchange(lhs: &Lhs, rhs: &Rhs) -> Result<Self, Error> {
        // NOTE: currently requires the exchange to produce a key of the same length,
        // while it may be acceptable to just use the prefix if the output is longer?
        let mut key = Self::uninit();
        let mut buf = Writer::from_slice(key.0.as_mut());
        lhs.key_exchange_buffer(rhs, &mut buf)?;
        if buf.position() != T::key_size() {
            return Err(err_msg!("invalid length for key exchange output"));
        }
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{buffer::SecretBytes, random::fill_random};

    #[test]
    fn encrypt_round_trip() {
        fn test_encrypt<T: Chacha20Type>() {
            let input = b"hello";
            let key = Chacha20Key::<T>::generate().unwrap();
            let mut buffer = SecretBytes::from_slice(input);
            let mut nonce = GenericArray::<u8, NonceSize<T>>::default();
            fill_random(&mut nonce);
            key.encrypt_in_place(&mut buffer, &nonce, &[]).unwrap();
            assert_eq!(buffer.len(), input.len() + Chacha20Key::<T>::tag_size());
            assert_ne!(&buffer[..], input);
            key.decrypt_in_place(&mut buffer, &nonce, &[]).unwrap();
            assert_eq!(&buffer[..], input);
        }
        test_encrypt::<C20P>();
        test_encrypt::<XC20P>();
    }
}
