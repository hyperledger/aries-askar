//! Compatibility with libsodium's crypto_box construct

use crate::{
    buffer::Writer,
    generic_array::{typenum::Unsigned, GenericArray},
};
use aead::AeadInPlace;
use blake2::{digest::Update, digest::VariableOutput, VarBlake2b};
use crypto_box::{self as cbox, SalsaBox};

use crate::{
    alg::x25519::X25519KeyPair,
    buffer::{ResizeBuffer, SecretBytes, WriteBuffer},
    error::Error,
    repr::{KeyGen, KeyPublicBytes},
};

pub const CBOX_NONCE_SIZE: usize = NonceSize::<SalsaBox>::USIZE;
pub const CBOX_KEY_SIZE: usize = crate::alg::x25519::PUBLIC_KEY_LENGTH;
pub const CBOX_TAG_SIZE: usize = TagSize::<SalsaBox>::USIZE;

type NonceSize<A> = <A as AeadInPlace>::NonceSize;

type TagSize<A> = <A as AeadInPlace>::TagSize;

#[inline]
fn secret_key_from(kp: &X25519KeyPair) -> Result<cbox::SecretKey, Error> {
    if let Some(sk) = kp.secret.as_ref() {
        Ok(cbox::SecretKey::from(sk.to_bytes()))
    } else {
        Err(err_msg!(MissingSecretKey))
    }
}

#[inline]
fn nonce_from(nonce: &[u8]) -> Result<&GenericArray<u8, NonceSize<SalsaBox>>, Error> {
    if nonce.len() == NonceSize::<SalsaBox>::USIZE {
        Ok(GenericArray::from_slice(nonce))
    } else {
        Err(err_msg!(InvalidNonce))
    }
}

pub fn crypto_box<B: ResizeBuffer>(
    recip_pk: &X25519KeyPair,
    sender_sk: &X25519KeyPair,
    buffer: &mut B,
    nonce: &[u8],
) -> Result<(), Error> {
    let sender_sk = secret_key_from(sender_sk)?;
    let nonce = nonce_from(nonce)?;
    let box_inst = SalsaBox::new(&recip_pk.public, &sender_sk);
    let tag = box_inst
        .encrypt_in_place_detached(nonce, &[], buffer.as_mut())
        .map_err(|_| err_msg!(Encryption, "Crypto box AEAD encryption error"))?;
    buffer.buffer_write(&tag[..])?;
    Ok(())
}

pub fn crypto_box_open<B: ResizeBuffer>(
    recip_sk: &X25519KeyPair,
    sender_pk: &X25519KeyPair,
    buffer: &mut B,
    nonce: &[u8],
) -> Result<(), Error> {
    let recip_sk = secret_key_from(recip_sk)?;
    let nonce = nonce_from(nonce)?;
    let buf_len = buffer.as_ref().len();
    if buf_len < TagSize::<SalsaBox>::USIZE {
        return Err(err_msg!(Encryption, "Invalid size for encrypted data"));
    }
    let tag_start = buf_len - TagSize::<SalsaBox>::USIZE;
    let mut tag = GenericArray::default();
    tag.clone_from_slice(&buffer.as_ref()[tag_start..]);

    let box_inst = SalsaBox::new(&sender_pk.public, &recip_sk);

    box_inst
        .decrypt_in_place_detached(nonce, &[], &mut buffer.as_mut()[..tag_start], &tag)
        .map_err(|_| err_msg!(Encryption, "Crypto box AEAD decryption error"))?;
    buffer.buffer_resize(tag_start)?;
    Ok(())
}

pub fn crypto_box_seal_nonce(
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

// Could add a non-alloc version, if needed
pub fn crypto_box_seal(recip_pk: &X25519KeyPair, message: &[u8]) -> Result<SecretBytes, Error> {
    let ephem_kp = X25519KeyPair::generate()?;
    let ephem_pk_bytes = ephem_kp.public.as_bytes();
    let buf_len = CBOX_KEY_SIZE + message.len() + TagSize::<SalsaBox>::USIZE;
    let mut buffer = SecretBytes::with_capacity(buf_len);
    buffer.buffer_write(ephem_pk_bytes)?;
    buffer.buffer_write(message)?;
    let mut writer = Writer::from_vec_skip(buffer.as_vec_mut(), CBOX_KEY_SIZE);
    let nonce = crypto_box_seal_nonce(ephem_pk_bytes, recip_pk.public.as_bytes())?.to_vec();
    crypto_box(recip_pk, &ephem_kp, &mut writer, &nonce[..])?;
    Ok(buffer)
}

pub fn crypto_box_seal_open(
    recip_sk: &X25519KeyPair,
    ciphertext: &[u8],
) -> Result<SecretBytes, Error> {
    let ephem_pk = X25519KeyPair::from_public_bytes(&ciphertext[..CBOX_KEY_SIZE])?;
    let mut buffer = SecretBytes::from_slice(&ciphertext[CBOX_KEY_SIZE..]);
    let nonce = crypto_box_seal_nonce(ephem_pk.public.as_bytes(), recip_sk.public.as_bytes())?;
    crypto_box_open(recip_sk, &ephem_pk, &mut buffer, &nonce)?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::SecretBytes;
    use crate::repr::KeySecretBytes;

    #[test]
    fn crypto_box_round_trip_expected() {
        let sk = X25519KeyPair::from_secret_bytes(&hex!(
            "a8bdb9830f8790d242f66e04b11cc2a14c752a7b63c073f3c68e9adb151cc854"
        ))
        .unwrap();
        let pk = X25519KeyPair::from_public_bytes(&hex!(
            "07d0b594683bdb6af5f4eacb1a392687d580a58db196a752dca316dedb7d251c"
        ))
        .unwrap();
        let message = b"hello there";
        let nonce = b"012345678912012345678912";
        let mut buffer = SecretBytes::from_slice(message);
        crypto_box(&pk, &sk, &mut buffer, nonce).unwrap();
        assert_eq!(
            buffer,
            &hex!("1cc8721d567baa8f2b5583848dc97d373f7aa2223b57780c60f773")[..]
        );

        crypto_box_open(&sk, &pk, &mut buffer, nonce).unwrap();
        assert_eq!(buffer, &message[..]);
    }

    #[test]
    fn crypto_box_seal_round_trip() {
        let recip = X25519KeyPair::generate().unwrap();

        let recip_public =
            X25519KeyPair::from_public_bytes(recip.to_public_bytes().unwrap().as_ref()).unwrap();

        let message = b"hello there";
        let sealed = crypto_box_seal(&recip_public, message).unwrap();
        assert_ne!(sealed, &message[..]);

        let open = crypto_box_seal_open(&recip, &sealed).unwrap();
        assert_eq!(open, &message[..]);
    }
}
