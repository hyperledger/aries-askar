use std::str::FromStr;

use super::key::LocalKey;
pub use crate::crypto::{
    alg::KeyAlg,
    buffer::{SecretBytes, WriteBuffer},
};
use crate::{
    crypto::{
        alg::x25519::X25519KeyPair,
        encrypt::nacl_box::{
            crypto_box_seal as nacl_box_seal, crypto_box_seal_open as nacl_box_seal_open,
        },
        kdf::{ecdh_1pu::Ecdh1PU, ecdh_es::EcdhEs},
    },
    error::Error,
};

/// Perform message encryption equivalent to libsodium's `crypto_box_seal`
pub fn crypto_box_seal(x25519_key: &LocalKey, message: &[u8]) -> Result<Vec<u8>, Error> {
    if let Some(kp) = x25519_key.inner.downcast_ref::<X25519KeyPair>() {
        let sealed = nacl_box_seal(kp, message)?;
        Ok(sealed.into_vec())
    } else {
        Err(err_msg!(Input, "x25519 keypair required"))
    }
}

/// Perform message decryption equivalent to libsodium's `crypto_box_seal_open`
pub fn crypto_box_seal_open(
    x25519_key: &LocalKey,
    ciphertext: &[u8],
) -> Result<SecretBytes, Error> {
    if let Some(kp) = x25519_key.inner.downcast_ref::<X25519KeyPair>() {
        Ok(nacl_box_seal_open(kp, ciphertext)?)
    } else {
        Err(err_msg!(Input, "x25519 keypair required"))
    }
}

/// Derive an ECDH-1PU shared key for authenticated encryption
pub fn derive_key_ecdh_1pu(
    ephem_key: &LocalKey,
    sender_key: &LocalKey,
    recip_key: &LocalKey,
    alg: &str,
    apu: &[u8],
    apv: &[u8],
) -> Result<LocalKey, Error> {
    let key_alg = KeyAlg::from_str(alg)?;
    let derive = Ecdh1PU::new(
        &*ephem_key,
        &*sender_key,
        &*recip_key,
        alg.as_bytes(),
        apu,
        apv,
    );
    LocalKey::from_key_derivation(key_alg, derive)
}

/// Derive an ECDH-ES shared key for anonymous encryption
pub fn derive_key_ecdh_es(
    ephem_key: &LocalKey,
    recip_key: &LocalKey,
    alg: &str,
    apu: &[u8],
    apv: &[u8],
) -> Result<LocalKey, Error> {
    let key_alg = KeyAlg::from_str(alg)?;
    let derive = EcdhEs::new(&*ephem_key, &*recip_key, alg.as_bytes(), apu, apv);
    LocalKey::from_key_derivation(key_alg, derive)
}
