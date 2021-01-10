use std::fmt::Debug;

use chacha20poly1305::{
    aead::{
        generic_array::typenum::{Unsigned, U32},
        Aead, NewAead,
    },
    ChaCha20Poly1305,
};
use hmac::{Hmac, Mac, NewMac};
use indy_utils::keys::ArrayKey;
use sha2::Sha256;

use serde::{Deserialize, Serialize};

use super::encrypt::{chacha::ChaChaEncrypt, SymEncrypt};
use crate::error::Result;
use crate::keys::EntryEncryptor;
use crate::types::{EncEntryTag, EntryTag, SecretBytes};

const ENC_KEY_BYTES: usize = <ChaCha20Poly1305 as NewAead>::KeySize::USIZE;
const ENC_KEY_SIZE: usize = <ChaCha20Poly1305 as Aead>::NonceSize::USIZE
    + ENC_KEY_BYTES
    + <ChaCha20Poly1305 as Aead>::TagSize::USIZE;

pub type EncKey<E> = ArrayKey<<E as SymEncrypt>::KeySize>;
pub type HmacKey = ArrayKey<U32>;
pub type StoreKey = StoreKeyImpl<ChaChaEncrypt>;

/// A store key combining the keys required to encrypt
/// and decrypt storage records
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(bound(
    deserialize = "EncKey<E>: for<'a> Deserialize<'a>",
    serialize = "EncKey<E>: Serialize"
))]
pub struct StoreKeyImpl<E>
where
    E: SymEncrypt + Debug,
    E::KeySize: Debug,
{
    pub category_key: EncKey<E>,
    pub name_key: EncKey<E>,
    pub value_key: EncKey<E>,
    pub item_hmac_key: HmacKey,
    pub tag_name_key: EncKey<E>,
    pub tag_value_key: EncKey<E>,
    pub tags_hmac_key: HmacKey,
}

impl<E> StoreKeyImpl<E>
where
    E: SymEncrypt + Debug,
    E::KeySize: Debug,
{
    pub fn new() -> Result<Self> {
        Ok(Self {
            category_key: ArrayKey::random(),
            name_key: ArrayKey::random(),
            value_key: ArrayKey::random(),
            item_hmac_key: ArrayKey::random(),
            tag_name_key: ArrayKey::random(),
            tag_value_key: ArrayKey::random(),
            tags_hmac_key: ArrayKey::random(),
        })
    }

    pub fn encrypt_tag_name(&self, name: SecretBytes) -> Result<Vec<u8>> {
        encrypt_searchable::<E>(name, &self.tag_name_key, &self.tags_hmac_key)
    }

    pub fn encrypt_tag_value(&self, value: SecretBytes) -> Result<Vec<u8>> {
        encrypt_searchable::<E>(value, &self.tag_value_key, &self.tags_hmac_key)
    }

    pub fn decrypt_tag_name(&self, enc_tag_name: Vec<u8>) -> Result<SecretBytes> {
        E::decrypt(enc_tag_name, &self.tag_name_key)
    }

    pub fn decrypt_tag_value(&self, enc_tag_value: Vec<u8>) -> Result<SecretBytes> {
        E::decrypt(enc_tag_value, &self.tag_value_key)
    }

    pub fn to_string(&self) -> Result<String> {
        serde_json::to_string(self).map_err(err_map!(Unexpected, "Error serializing store key"))
    }

    pub fn from_slice(input: &[u8]) -> Result<Self> {
        serde_json::from_slice(input).map_err(err_map!(Unsupported, "Invalid store key"))
    }
}

/// Encrypt a value with a predictable nonce, making it searchable
fn encrypt_searchable<E: SymEncrypt>(
    input: SecretBytes,
    enc_key: &ArrayKey<E::KeySize>,
    hmac_key: &HmacKey,
) -> Result<Vec<u8>> {
    let mut nonce_hmac =
        Hmac::<Sha256>::new_varkey(&**hmac_key).map_err(|e| err_msg!(Encryption, "{}", e))?;
    nonce_hmac.update(&*input);
    let nonce_long = nonce_hmac.finalize().into_bytes();
    let nonce = ArrayKey::<E::NonceSize>::from_slice(&nonce_long[0..E::NonceSize::USIZE]);
    E::encrypt(input, enc_key, Some(nonce))
}

impl<E> EntryEncryptor for StoreKeyImpl<E>
where
    E: SymEncrypt + Debug,
    E::KeySize: Debug,
{
    fn prepare_input(input: &[u8]) -> SecretBytes {
        E::prepare_input(input)
    }

    fn encrypt_entry_category(&self, category: SecretBytes) -> Result<Vec<u8>> {
        encrypt_searchable::<E>(category, &self.category_key, &self.item_hmac_key)
    }

    fn encrypt_entry_name(&self, name: SecretBytes) -> Result<Vec<u8>> {
        encrypt_searchable::<E>(name, &self.name_key, &self.item_hmac_key)
    }

    fn encrypt_entry_value(&self, value: SecretBytes) -> Result<Vec<u8>> {
        let value_key = ArrayKey::random();
        let mut value = E::encrypt(value, &value_key, None)?;
        let mut result = E::encrypt(value_key.as_slice().into(), &self.value_key, None)?;
        result.append(&mut value);
        Ok(result)
    }

    fn decrypt_entry_category(&self, enc_category: Vec<u8>) -> Result<String> {
        decode_utf8(E::decrypt(enc_category, &self.category_key)?.into_vec())
    }

    fn decrypt_entry_name(&self, enc_name: Vec<u8>) -> Result<String> {
        decode_utf8(E::decrypt(enc_name, &self.name_key)?.into_vec())
    }

    fn decrypt_entry_value(&self, mut enc_value: Vec<u8>) -> Result<SecretBytes> {
        if enc_value.len() < ENC_KEY_SIZE + E::TagSize::USIZE {
            return Err(err_msg!(
                Encryption,
                "Buffer is too short to represent an encrypted value",
            ));
        }
        let value = enc_value[ENC_KEY_SIZE..].to_vec();
        enc_value.truncate(ENC_KEY_SIZE);
        let value_key = ArrayKey::from_slice(E::decrypt(enc_value, &self.value_key)?);
        E::decrypt(value, &value_key)
    }

    fn encrypt_entry_tags(&self, tags: Vec<EntryTag>) -> Result<Vec<EncEntryTag>> {
        tags.into_iter()
            .map(|tag| match tag {
                EntryTag::Plaintext(name, value) => {
                    let name = self.encrypt_tag_name(name.into())?;
                    Ok(EncEntryTag {
                        name,
                        value: value.into_bytes(),
                        plaintext: true,
                    })
                }
                EntryTag::Encrypted(name, value) => {
                    let name = self.encrypt_tag_name(name.into())?;
                    let value = self.encrypt_tag_value(value.into())?;
                    Ok(EncEntryTag {
                        name,
                        value,
                        plaintext: false,
                    })
                }
            })
            .collect()
    }

    fn decrypt_entry_tags(&self, enc_tags: Vec<EncEntryTag>) -> Result<Vec<EntryTag>> {
        enc_tags.into_iter().try_fold(vec![], |mut acc, tag| {
            let name = decode_utf8(self.decrypt_tag_name(tag.name)?.into_vec())?;
            acc.push(if tag.plaintext {
                let value = decode_utf8(tag.value)?;
                EntryTag::Plaintext(name, value)
            } else {
                let value = decode_utf8(self.decrypt_tag_value(tag.value)?.into_vec())?;
                EntryTag::Encrypted(name, value)
            });
            Result::Ok(acc)
        })
    }
}

#[inline]
fn decode_utf8(value: Vec<u8>) -> Result<String> {
    String::from_utf8(value).map_err(err_map!(Encryption))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Entry;

    #[test]
    fn store_key_round_trip() {
        let key = StoreKey::new().unwrap();
        let test_record = Entry::new(
            "category",
            "name",
            "value",
            Some(vec![
                EntryTag::Plaintext("plain".to_string(), "tag".to_string()),
                EntryTag::Encrypted("enctag".to_string(), "envtagval".to_string()),
            ]),
        );
        let enc_category = key
            .encrypt_entry_category(test_record.category.clone().into())
            .unwrap();
        let enc_name = key
            .encrypt_entry_name(test_record.name.clone().into())
            .unwrap();
        let enc_value = key
            .encrypt_entry_value(test_record.value.clone().into())
            .unwrap();
        let enc_tags = key
            .encrypt_entry_tags(test_record.tags.clone().unwrap())
            .unwrap();
        assert_ne!(test_record.category.as_bytes(), enc_category.as_slice());
        assert_ne!(test_record.name.as_bytes(), enc_name.as_slice());
        assert_ne!(test_record.value, enc_value);

        let cmp_record = Entry::new(
            key.decrypt_entry_category(enc_category).unwrap(),
            key.decrypt_entry_name(enc_name).unwrap(),
            key.decrypt_entry_value(enc_value).unwrap(),
            Some(key.decrypt_entry_tags(enc_tags).unwrap()),
        );
        assert_eq!(test_record, cmp_record);
    }

    #[test]
    fn store_key_searchable() {
        let nonce_size = <ChaChaEncrypt as SymEncrypt>::NonceSize::USIZE;
        let input = SecretBytes::from(&b"hello"[..]);
        let key = ArrayKey::random();
        let hmac_key = ArrayKey::random();
        let enc1 = encrypt_searchable::<ChaChaEncrypt>(input.clone(), &key, &hmac_key).unwrap();
        let enc2 = encrypt_searchable::<ChaChaEncrypt>(input.clone(), &key, &hmac_key).unwrap();
        assert_eq!(&enc1[0..nonce_size], &enc2[0..nonce_size]);
        let dec = ChaChaEncrypt::decrypt(enc1, &key).unwrap();
        assert_eq!(dec, input);
    }

    #[test]
    fn store_key_serde() {
        let key = StoreKey::new().unwrap();
        let key_json = serde_json::to_string(&key).unwrap();
        let key_cmp = serde_json::from_str(&key_json).unwrap();
        assert_eq!(key, key_cmp);
    }
}
