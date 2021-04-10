use chacha20poly1305::{
    aead::{generic_array::typenum::Unsigned, Aead, NewAead, Payload},
    ChaCha20Poly1305, Key as ChaChaKey,
};

pub use crate::alg::ed25519::Ed25519KeyPair as KeyPair;

use std::string::ToString;

use super::nacl_box::*;
// use super::types::*;
use crate::{
    buffer::SecretBytes,
    error::Error,
    random::{random_array, random_vec},
};

pub const PROTECTED_HEADER_ENC: &'static str = "xchacha20poly1305_ietf";
pub const PROTECTED_HEADER_TYP: &'static str = "JWM/1.0";
pub const PROTECTED_HEADER_ALG_AUTH: &'static str = "Authcrypt";
pub const PROTECTED_HEADER_ALG_ANON: &'static str = "Anoncrypt";

type KeySize = <ChaCha20Poly1305 as NewAead>::KeySize;

const NONCE_SIZE: usize = <ChaCha20Poly1305 as Aead>::NonceSize::USIZE;
const TAG_SIZE: usize = <ChaCha20Poly1305 as Aead>::TagSize::USIZE;

pub fn pack_message<M: AsRef<[u8]>>(
    message: M,
    receiver_list: Vec<KeyPair>,
    sender_key: Option<KeyPair>,
) -> Result<Vec<u8>, Error> {
    // break early and error out if no receivers keys are provided
    if receiver_list.is_empty() {
        return Err(err_msg!("No message recipients"));
    }

    // generate content encryption key that will encrypt `message`
    let cek = SecretBytes::from(random_vec(KeySize::to_usize()));

    let base64_protected = if let Some(sender_key) = sender_key {
        // returns authcrypted pack_message format. See Wire message format HIPE for details
        prepare_protected_authcrypt(&cek, receiver_list, &sender_key)?
    } else {
        // returns anoncrypted pack_message format. See Wire message format HIPE for details
        prepare_protected_anoncrypt(&cek, receiver_list)?
    };

    // Use AEAD to encrypt `message` with "protected" data as "associated data"
    let chacha = ChaCha20Poly1305::new(ChaChaKey::from_slice(&cek));
    let nonce = random_array();
    let payload = Payload {
        aad: base64_protected.as_bytes(),
        msg: message.as_ref(),
    };
    let ciphertext = chacha
        .encrypt(&nonce, payload)
        .map_err(|_| err_msg!(Encryption, "Error encrypting payload"))?;
    let iv = b64_encode(nonce);
    let clen = ciphertext.len() - TAG_SIZE;
    let tag = b64_encode(&ciphertext[clen..]);
    let ciphertext = b64_encode(&ciphertext[..clen]);

    format_pack_message(&base64_protected, &ciphertext, &iv, &tag)
}

fn prepare_protected_anoncrypt(cek: &[u8], receiver_list: Vec<KeyPair>) -> Result<String, Error> {
    let mut encrypted_recipients_struct: Vec<Recipient> = Vec::with_capacity(receiver_list.len());

    for their_vk in receiver_list {
        // encrypt cek for recipient
        let their_vk_x = their_vk.to_x25519();
        let enc_cek = crypto_box_seal(&their_vk_x.to_bytes(), cek.as_ref())?;

        // create recipient struct and push to encrypted list
        encrypted_recipients_struct.push(Recipient {
            encrypted_key: b64_encode(enc_cek.as_slice()),
            header: Header {
                kid: their_vk.to_base58(),
                sender: None,
                iv: None,
            },
        });
    }

    b64_encode_protected(encrypted_recipients_struct, false)
}

fn prepare_protected_authcrypt(
    cek: &[u8],
    receiver_list: Vec<PublicKey>,
    sender_key: &KeyPair,
) -> Result<String, Error> {
    let mut encrypted_recipients_struct: Vec<Recipient> = vec![];

    let sender_key_x = sender_key.to_x25519();
    let sender_sk_x = sender_key_x.private_key();
    let sender_pk = sender_key.public_key();

    for their_vk in receiver_list {
        let their_vk_x = their_vk.to_x25519();

        // encrypt cek for recipient
        let (enc_cek, iv) = crypto_box(&their_vk_x.to_bytes(), sender_sk_x.as_ref(), cek, None)?;

        // encrypt sender key for recipient
        let enc_sender = crypto_box_seal(&their_vk_x.to_bytes(), sender_pk.to_base58().as_ref())?;

        // create recipient struct and push to encrypted list
        encrypted_recipients_struct.push(Recipient {
            encrypted_key: b64_encode(enc_cek.as_slice()),
            header: Header {
                kid: their_vk.to_base58(),
                sender: Some(b64_encode(enc_sender.as_slice())),
                iv: Some(b64_encode(iv.as_slice())),
            },
        });
    }

    b64_encode_protected(encrypted_recipients_struct, true)
}

#[inline(always)]
fn b64_decode(input: impl AsRef<[u8]>) -> Result<Vec<u8>, Error> {
    base64::decode_config(input, base64::URL_SAFE).map_err(|_| err_msg!("Error decoding as base64"))
}

#[inline(always)]
fn b64_encode(input: impl AsRef<[u8]>) -> String {
    base64::encode_config(input, base64::URL_SAFE_NO_PAD)
}

fn b64_encode_protected(
    encrypted_recipients_struct: Vec<Recipient>,
    alg_is_authcrypt: bool,
) -> Result<String, Error> {
    let alg_val = if alg_is_authcrypt {
        String::from(PROTECTED_HEADER_ALG_AUTH)
    } else {
        String::from(PROTECTED_HEADER_ALG_ANON)
    };

    // structure protected and base64URL encode it
    let protected_struct = Protected {
        enc: PROTECTED_HEADER_ENC.to_string(),
        typ: PROTECTED_HEADER_TYP.to_string(),
        alg: alg_val,
        recipients: encrypted_recipients_struct,
    };
    let protected_encoded = serde_json::to_string(&protected_struct)
        .map_err(|err| err_msg!(Encryption, "Failed to serialize protected field {}", err))?;

    Ok(b64_encode(protected_encoded.as_bytes()))
}

fn format_pack_message(
    base64_protected: &str,
    ciphertext: &str,
    iv: &str,
    tag: &str,
) -> Result<Vec<u8>, Error> {
    // serialize pack message and return as vector of bytes
    let jwe_struct = JWE {
        protected: base64_protected.to_string(),
        iv: iv.to_string(),
        ciphertext: ciphertext.to_string(),
        tag: tag.to_string(),
    };

    serde_json::to_vec(&jwe_struct).map_err(|_| err_msg!("Error serializing JWE"))
}

pub async fn unpack_message<'f>(
    message: impl AsRef<[u8]>,
    lookup: impl KeyLookup<'f>,
) -> Result<(Vec<u8>, PublicKey, Option<PublicKey>), Error> {
    let jwe =
        serde_json::from_slice(message.as_ref()).map_err(|_| err_msg!("Invalid format for JWE"))?;
    unpack_jwe(&jwe, lookup).await
}

pub async fn unpack_jwe<'f>(
    jwe_struct: &JWE,
    lookup: impl KeyLookup<'f>,
) -> Result<(Vec<u8>, PublicKey, Option<PublicKey>), Error> {
    // decode protected data
    let protected_decoded = b64_decode(&jwe_struct.protected)?;
    let protected: Protected = serde_json::from_slice(&protected_decoded)
        .map_err(|_| err_msg!(Encryption, "Invalid format for protected data"))?;

    // extract recipient that matches a key in the wallet
    let (recipient, recip_pk, recip_sk) =
        if let Some(recip) = find_unpack_recipient(protected, lookup).await? {
            recip
        } else {
            return Err(err_msg!(Encryption, "No matching recipient found"));
        };
    let is_auth_recipient = recipient.header.sender.is_some() && recipient.header.iv.is_some();

    // get cek and sender data
    let (sender_verkey_option, cek) = if is_auth_recipient {
        let (send, cek) = unpack_cek_authcrypt(&recipient, &recip_sk)?;
        (Some(send), cek)
    } else {
        let cek = unpack_cek_anoncrypt(&recipient, &recip_sk)?;
        (None, cek)
    };

    // decrypt message
    let chacha = ChaCha20Poly1305::new_varkey(&cek)
        .map_err(|_| err_msg!(Encryption, "Error creating unpack decryptor for cek"))?;
    let nonce = b64_decode(&jwe_struct.iv)?;
    if nonce.len() != NONCE_SIZE {
        return Err(err_msg!(Encryption, "Invalid size for message nonce"));
    }
    let mut ciphertext = b64_decode(&jwe_struct.ciphertext)?;
    ciphertext.append(b64_decode(&jwe_struct.tag)?.as_mut());
    let payload = Payload {
        aad: jwe_struct.protected.as_bytes(),
        msg: ciphertext.as_slice(),
    };
    let message = chacha
        .decrypt(nonce.as_slice().into(), payload)
        .map_err(|_| err_msg!(Encryption, "Error decrypting message payload"))?;

    Ok((message, recip_pk, sender_verkey_option))
}

fn unpack_cek_authcrypt(
    recipient: &Recipient,
    recip_sk: &KeyPair,
) -> Result<(PublicKey, Vec<u8>), Error> {
    let encrypted_key_vec = b64_decode(&recipient.encrypted_key)?;
    let iv = b64_decode(&recipient.header.iv.as_ref().unwrap())?;
    let enc_sender_vk = b64_decode(&recipient.header.sender.as_ref().unwrap())?;

    // decrypt sender_vk
    let recip_x = recip_sk.to_x25519();
    let recip_sk_x = recip_x.private_key();
    let sender_vk_vec = crypto_box_seal_open(
        &recip_x.public_key().to_bytes(),
        recip_sk_x.as_ref(),
        &enc_sender_vk,
    )?;
    let sender_vk = PublicKey::from_str(
        std::str::from_utf8(&sender_vk_vec)
            .map_err(|_| err_msg!(Encryption, "Invalid sender verkey"))?,
    )?;

    // decrypt cek
    let cek = crypto_box_open(
        recip_sk_x.as_ref(),
        &sender_vk.to_x25519().to_bytes(),
        encrypted_key_vec.as_slice(),
        iv.as_slice(),
    )?;

    Ok((sender_vk, cek))
}

fn unpack_cek_anoncrypt(recipient: &Recipient, recip_sk: &KeyPair) -> Result<Vec<u8>, Error> {
    let encrypted_key = b64_decode(&recipient.encrypted_key)?;

    // decrypt cek
    let recip_x = recip_sk.to_x25519();
    let cek = crypto_box_seal_open(
        &recip_x.public_key().to_bytes(),
        recip_x.private_key().as_ref(),
        &encrypted_key,
    )?;

    Ok(cek)
}

async fn find_unpack_recipient<'f>(
    protected: Protected,
    lookup: impl KeyLookup<'f>,
) -> Result<Option<(Recipient, PublicKey, KeyPair)>, Error> {
    let mut recip_vks = Vec::<PublicKey>::with_capacity(protected.recipients.len());
    for recipient in &protected.recipients {
        let vk = PublicKey::from_str(&recipient.header.kid)?;
        recip_vks.push(vk);
    }
    if let Some((idx, sk)) = lookup.find(&recip_vks).await {
        let recip = protected.recipients.into_iter().nth(idx).unwrap();
        let vk = recip_vks.into_iter().nth(idx).unwrap();
        Ok(Some((recip, vk, sk)))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use async_global_executor::block_on;

    use super::*;

    #[test]
    fn anon_pack_basic() {
        let pk = KeyPair::from_seed(b"000000000000000000000000000Test2")
            .unwrap()
            .public_key();
        let packed = pack_message(b"hello there", vec![pk], None);
        assert!(packed.is_ok());
    }

    #[test]
    fn auth_pack_basic() {
        let sk = KeyPair::from_seed(b"000000000000000000000000000Test1").unwrap();
        let pk = KeyPair::from_seed(b"000000000000000000000000000Test2")
            .unwrap()
            .public_key();
        let packed = pack_message(b"hello there", vec![pk], Some(sk));
        assert!(packed.is_ok());
    }

    #[test]
    fn anon_pack_round_trip() {
        let sk1 = KeyPair::from_seed(b"000000000000000000000000000Test3").unwrap();
        let pk1 = sk1.public_key();

        let input_msg = b"hello there";
        let packed = pack_message(&input_msg, vec![pk1.clone()], None).unwrap();

        let lookup = |find_pks: &Vec<PublicKey>| {
            for (idx, pk) in find_pks.into_iter().enumerate() {
                if pk == &pk1 {
                    return Some((idx, sk1.clone()));
                }
            }
            None
        };

        let lookup_fn = key_lookup_fn(lookup);
        let result = unpack_message(&packed, &lookup_fn);
        let (msg, p_recip, p_send) = block_on(result).unwrap();
        assert_eq!(msg, input_msg);
        assert_eq!(p_recip, pk1);
        assert_eq!(p_send, None);
    }

    #[test]
    fn auth_pack_round_trip() {
        let sk1 = KeyPair::from_seed(b"000000000000000000000000000Test3").unwrap();
        let pk1 = sk1.public_key();
        let sk2 = KeyPair::from_seed(b"000000000000000000000000000Test4").unwrap();
        let pk2 = sk2.public_key();

        let input_msg = b"hello there";
        let packed = pack_message(&input_msg, vec![pk2.clone()], Some(sk1.clone())).unwrap();

        let lookup = |find_pks: &Vec<PublicKey>| {
            for (idx, pk) in find_pks.into_iter().enumerate() {
                if pk == &pk2 {
                    return Some((idx, sk2.clone()));
                }
            }
            None
        };

        let lookup_fn = key_lookup_fn(lookup);
        let result = unpack_message(&packed, &lookup_fn);
        let (msg, p_recip, p_send) = block_on(result).unwrap();
        assert_eq!(msg, input_msg);
        assert_eq!(p_recip, pk2);
        assert_eq!(p_send, Some(pk1));
    }
}
