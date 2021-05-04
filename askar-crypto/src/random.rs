//! Support for random number generation

#[cfg(feature = "chacha")]
use aead::generic_array::{typenum::Unsigned, GenericArray};
#[cfg(feature = "chacha")]
use chacha20::{
    cipher::{NewStreamCipher, SyncStreamCipher},
    ChaCha20,
};
use rand::{CryptoRng, RngCore};

#[cfg(feature = "alloc")]
use crate::buffer::SecretBytes;
#[cfg(feature = "chacha")]
use crate::error::Error;

#[cfg(feature = "chacha")]
/// The expected length of a seed for `fill_random_deterministic`
pub const DETERMINISTIC_SEED_LENGTH: usize = <ChaCha20 as NewStreamCipher>::KeySize::USIZE;

/// Combined trait for CryptoRng and RngCore
pub trait Rng: CryptoRng + RngCore {}

impl<T: CryptoRng + RngCore> Rng for T {}

/// Perform an operation with a reference to the random number generator
#[inline(always)]
pub fn with_rng<O>(f: impl FnOnce(&mut dyn Rng) -> O) -> O {
    // FIXME may wish to support platforms without 'getrandom' by adding
    // a method to initialize with a custom RNG (or fill_bytes function)
    f(&mut ::rand::rngs::OsRng)
}

/// Fill a mutable slice with random data using the
/// system random number generator.
#[inline(always)]
pub fn fill_random(value: &mut [u8]) {
    with_rng(|rng| rng.fill_bytes(value));
}

#[cfg(feature = "chacha")]
/// Written to be compatible with randombytes_deterministic in libsodium,
/// used to generate a deterministic symmetric encryption key
pub fn fill_random_deterministic(seed: &[u8], output: &mut [u8]) -> Result<(), Error> {
    if seed.len() != DETERMINISTIC_SEED_LENGTH {
        return Err(err_msg!(Usage, "Invalid length for seed"));
    }
    let mut cipher = ChaCha20::new(
        GenericArray::from_slice(seed),
        GenericArray::from_slice(b"LibsodiumDRG"),
    );
    cipher.apply_keystream(output);
    Ok(())
}

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
/// Create a new `SecretBytes` instance with random data.
#[inline(always)]
pub fn random_secret(len: usize) -> SecretBytes {
    SecretBytes::new_with(len, fill_random)
}
