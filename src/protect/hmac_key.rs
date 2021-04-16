use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;

use hmac::{
    digest::{BlockInput, FixedOutput, Reset, Update},
    Hmac, Mac, NewMac,
};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{
        buffer::ArrayKey,
        generic_array::{typenum::Unsigned, ArrayLength, GenericArray},
        repr::KeyGen,
    },
    error::Error,
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(
    transparent,
    bound(
        deserialize = "ArrayKey<L>: for<'a> Deserialize<'a>",
        serialize = "ArrayKey<L>: Serialize"
    )
)]
pub struct HmacKey<L: ArrayLength<u8>, H>(ArrayKey<L>, PhantomData<H>);

impl<L: ArrayLength<u8>, H> HmacKey<L, H> {
    #[allow(dead_code)]
    pub fn from_slice(key: &[u8]) -> Result<Self, Error> {
        if key.len() != L::USIZE {
            return Err(err_msg!(Encryption, "invalid length for hmac key"));
        }
        Ok(Self(ArrayKey::from_slice(key), PhantomData))
    }
}

impl<L: ArrayLength<u8>, H> AsRef<GenericArray<u8, L>> for HmacKey<L, H> {
    fn as_ref(&self) -> &GenericArray<u8, L> {
        self.0.as_ref()
    }
}

impl<L: ArrayLength<u8>, H> Debug for HmacKey<L, H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if cfg!(test) {
            f.debug_tuple("HmacKey").field(&*self).finish()
        } else {
            f.debug_tuple("HmacKey").field(&"<secret>").finish()
        }
    }
}

impl<L: ArrayLength<u8>, H> PartialEq for HmacKey<L, H> {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}
impl<L: ArrayLength<u8>, H> Eq for HmacKey<L, H> {}

impl<L: ArrayLength<u8>, H> KeyGen for HmacKey<L, H> {
    fn generate() -> Result<Self, crate::crypto::Error> {
        Ok(Self(ArrayKey::random(), PhantomData))
    }
}

pub trait HmacOutput {
    fn hmac_to(&self, messages: &[&[u8]], output: &mut [u8]) -> Result<(), Error>;
}

impl<L, H> HmacOutput for HmacKey<L, H>
where
    L: ArrayLength<u8>,
    H: BlockInput + Default + Reset + Update + Clone + FixedOutput,
{
    fn hmac_to(&self, messages: &[&[u8]], output: &mut [u8]) -> Result<(), Error> {
        if output.len() > H::OutputSize::USIZE {
            return Err(err_msg!(Encryption, "invalid length for hmac output"));
        }
        let mut hmac =
            Hmac::<H>::new_varkey(self.0.as_ref()).map_err(|e| err_msg!(Encryption, "{}", e))?;
        for msg in messages {
            hmac.update(msg);
        }
        let hash = hmac.finalize().into_bytes();
        output.copy_from_slice(&hash[..output.len()]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generic_array::typenum::U32;
    use sha2::Sha256;

    #[test]
    fn hmac_expected() {
        let key = HmacKey::<U32, Sha256>::from_slice(&hex!(
            "c32ef97a2eed6316ae9b0d3129554358980ee6e0b21b81625229c191a3469f7e"
        ))
        .unwrap();
        let mut output = [0u8; 12];
        key.hmac_to(&[b"test message"], &mut output).unwrap();
        assert_eq!(output, &hex!("4cecfbf6be721395529be686")[..]);
    }
}
