use alloc::boxed::Box;

use zeroize::Zeroize;

use crate::generic_array::typenum::U32;

use crate::{
    buffer::{ArrayKey, WriteBuffer},
    caps::{KeyGen, KeySecretBytes},
    // any::{AnyPrivateKey, AnyPublicKey},
    error::Error,
    jwk::{JwkEncoder, KeyToJwk},
    random::{fill_random, fill_random_deterministic},
};

pub type KeyType = ArrayKey<U32>;

pub static JWK_ALG: &'static str = "C20P";

pub const KEY_LENGTH: usize = KeyType::SIZE;

#[derive(Clone, Debug, Zeroize)]
// SECURITY: ArrayKey is zeroized on drop
pub struct Chacha20Key(KeyType);

impl Chacha20Key {
    // this is consistent with Indy's wallet wrapping key generation
    // FIXME: move to a trait to allow custom impl for Box<Chacha20Key>
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        let mut slf = KeyType::default();
        fill_random_deterministic(seed, &mut slf)?;
        Ok(Self(slf))
    }
}

impl KeyGen for Chacha20Key {
    fn generate() -> Result<Self, Error> {
        Ok(Chacha20Key(KeyType::random()))
    }
}

impl KeySecretBytes for Chacha20Key {
    fn from_key_secret_bytes(key: &[u8]) -> Result<Self, Error> {
        if key.len() != KEY_LENGTH {
            return Err(err_msg!("Invalid length for chacha20 key"));
        }
        Ok(Self(KeyType::from_slice(key)))
    }

    fn to_key_secret_buffer<B: WriteBuffer>(&self, out: &mut B) -> Result<(), Error> {
        out.write_slice(&self.0[..])
    }
}

#[inline]
pub fn init_boxed(f: impl FnOnce(&mut [u8])) -> Box<Chacha20Key> {
    let mut slf = Box::new(Chacha20Key(KeyType::default()));
    f(&mut slf.0);
    slf
}

#[inline]
pub fn try_init_boxed(
    f: impl FnOnce(&mut [u8]) -> Result<(), Error>,
) -> Result<Box<Chacha20Key>, Error> {
    let mut slf = Box::new(Chacha20Key(KeyType::default()));
    f(&mut slf.0)?;
    Ok(slf)
}

impl KeyGen for Box<Chacha20Key> {
    fn generate() -> Result<Self, Error> {
        Ok(init_boxed(fill_random))
    }
}

impl KeySecretBytes for Box<Chacha20Key> {
    fn from_key_secret_bytes(key: &[u8]) -> Result<Self, Error> {
        if key.len() != KEY_LENGTH {
            return Err(err_msg!("Invalid length for chacha20 key"));
        }
        Ok(init_boxed(|buf| buf.copy_from_slice(key)))
    }

    fn to_key_secret_buffer<B: WriteBuffer>(&self, out: &mut B) -> Result<(), Error> {
        out.write_slice(&self.0[..])
    }
}

impl KeyToJwk for Chacha20Key {
    const KTY: &'static str = "oct";

    fn to_jwk_buffer<B: WriteBuffer>(&self, buffer: &mut JwkEncoder<B>) -> Result<(), Error> {
        if !buffer.is_secret() {
            return Err(err_msg!(Unsupported, "Cannot export as a public key"));
        }
        buffer.add_str("alg", JWK_ALG)?;
        buffer.add_as_base64("k", &self.0[..])?;
        buffer.add_str("use", "enc")?;
        Ok(())
    }
}
