use aead::generic_array::{typenum::Unsigned, GenericArray};
use chacha20::{
    cipher::{NewStreamCipher, SyncStreamCipher},
    ChaCha20,
};
use rand::{rngs::OsRng, RngCore};

#[cfg(feature = "alloc")]
use crate::buffer::SecretBytes;
use crate::error::Error;

pub const SEED_LENGTH: usize = <ChaCha20 as NewStreamCipher>::KeySize::USIZE;

pub type StdRng = OsRng;

#[inline(always)]
pub fn with_rng<O>(f: impl FnOnce(&mut StdRng) -> O) -> O {
    // may need to substitute another RNG depending on the platform
    f(&mut OsRng)
}

/// Fill a mutable slice with random data using the
/// system random number generator.
#[inline(always)]
pub fn fill_random(value: &mut [u8]) {
    with_rng(|rng| rng.fill_bytes(value));
}

/// Written to be compatible with randombytes_deterministic in libsodium,
/// used to generate a deterministic symmetric encryption key
pub fn fill_random_deterministic(seed: &[u8], output: &mut [u8]) -> Result<(), Error> {
    if seed.len() != SEED_LENGTH {
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
/// Create a new `SecretBytes` instance with random data.
#[inline(always)]
pub fn random_secret(len: usize) -> SecretBytes {
    SecretBytes::new_with(len, fill_random)
}
