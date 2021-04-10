use std::convert::TryInto;

use blake2::{digest::Update, digest::VariableOutput, VarBlake2b};
use crypto_box::{
    self as cbox,
    aead::{generic_array::typenum::Unsigned, Aead},
};

use crate::alg::x25519::X25519KeyPair;
use crate::error::Error;
use crate::random::random_vec;

const CBOX_NONCE_SIZE: usize = <cbox::Box as Aead>::NonceSize::USIZE;

fn crypto_box_key<F, T>(key: F) -> Result<T, Error>
where
    F: AsRef<[u8]>,
    T: From<[u8; cbox::KEY_SIZE]>,
{
    let key = key.as_ref();
    if key.len() != cbox::KEY_SIZE {
        Err(err_msg!(Encryption, "Invalid crypto box key length"))
    } else {
        Ok(T::from(key.try_into().unwrap()))
    }
}

pub fn crypto_box_nonce(
    ephemeral_pk: &[u8],
    recip_pk: &[u8],
) -> Result<[u8; CBOX_NONCE_SIZE], Error> {
    let mut key_hash = VarBlake2b::new(CBOX_NONCE_SIZE).unwrap();
    key_hash.update(ephemeral_pk);
    key_hash.update(recip_pk);
    let mut nonce = [0u8; CBOX_NONCE_SIZE];
    key_hash.finalize_variable(|hash| nonce.copy_from_slice(hash));
    Ok(nonce)
}

pub fn crypto_box(
    recip_pk: &[u8],
    sender_sk: &[u8],
    message: &[u8],
    nonce: Option<Vec<u8>>,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let recip_pk: cbox::PublicKey = crypto_box_key(recip_pk)?;
    let sender_sk: cbox::SecretKey = crypto_box_key(sender_sk)?;
    let box_inst = cbox::SalsaBox::new(&recip_pk, &sender_sk);

    let nonce = if let Some(nonce) = nonce {
        nonce.as_slice().into()
    } else {
        random_vec(CBOX_NONCE_SIZE)
    };

    let ciphertext = box_inst
        .encrypt(nonce.as_slice().into(), message)
        .map_err(|_| err_msg!(Encryption, "Error encrypting box"))?;
    Ok((ciphertext, nonce))
}

pub fn crypto_box_open(
    recip_sk: &[u8],
    sender_pk: &[u8],
    ciphertext: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, Error> {
    let recip_sk: cbox::SecretKey = crypto_box_key(recip_sk)?;
    let sender_pk: cbox::PublicKey = crypto_box_key(sender_pk)?;
    let box_inst = cbox::SalsaBox::new(&sender_pk, &recip_sk);

    let plaintext = box_inst
        .decrypt(nonce.into(), ciphertext)
        .map_err(|_| err_msg!(Encryption, "Error decrypting box"))?;
    Ok(plaintext)
}

pub fn crypto_box_seal(recip_pk: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
    let ephem_kp = X25519KeyPair::generate()?;
    let ephem_sk = ephem_kp.private_key();
    let ephem_sk_x: cbox::SecretKey = crypto_box_key(&ephem_sk)?;
    debug_assert_eq!(ephem_sk_x.to_bytes(), ephem_sk.as_ref());
    let ephem_pk_x = ephem_sk_x.public_key();

    let nonce = crypto_box_nonce(ephem_pk_x.as_bytes(), &recip_pk)?.to_vec();
    let (mut boxed, _) = crypto_box(recip_pk, ephem_sk.as_ref(), message, Some(nonce))?;

    let mut result = Vec::<u8>::with_capacity(cbox::KEY_SIZE); // FIXME
    result.extend_from_slice(ephem_pk_x.as_bytes());
    result.append(&mut boxed);
    Ok(result)
}

pub fn crypto_box_seal_open(
    recip_pk: &[u8],
    recip_sk: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let ephem_pk = &ciphertext[..32];
    let boxed = &ciphertext[32..];

    let nonce = crypto_box_nonce(&ephem_pk, &recip_pk)?;
    let decode = crypto_box_open(recip_sk, ephem_pk, boxed, &nonce)?;
    Ok(decode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alg::ed25519::Ed25519KeyPair;

    #[test]
    fn crypto_box_open_expected() {
        let sk = hex::decode("07d0b594683bdb6af5f4eacb1a392687d580a58db196a752dca316dedb7d251d")
            .unwrap();
        let pk = hex::decode("07d0b594683bdb6af5f4eacb1a392687d580a58db196a752dca316dedb7d251c")
            .unwrap();
        let message = b"hello there";
        // let nonce = b"012345678912012345678912".to_vec();
        let (boxed, nonce) = crypto_box(&pk, &sk, message, None).unwrap();

        let open = crypto_box_open(&sk, &pk, &boxed, &nonce).unwrap();
        assert_eq!(open, message);
    }

    #[test]
    fn crypto_box_seal_expected() {
        let kp = Ed25519KeyPair::from_seed(b"000000000000000000000000000Test0").unwrap();
        let kp_x = kp.to_x25519();
        let sk_x = kp_x.private_key();
        let pk_x = kp_x.public_key();

        let message = b"hello there";
        let sealed = crypto_box_seal(&pk_x.to_bytes(), message).unwrap();

        let open = crypto_box_seal_open(&pk_x.to_bytes(), sk_x.as_ref(), &sealed).unwrap();
        assert_eq!(open, message);
    }
}
