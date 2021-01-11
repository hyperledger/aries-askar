use std::fmt::Debug;

use serde::{Deserialize, Serialize};

use super::encrypt::{aead::ChaChaEncrypt, SymEncrypt, SymEncryptHashKey, SymEncryptKey};
use crate::error::Result;
use crate::keys::EntryEncryptor;
use crate::types::{EncEntryTag, EntryTag, SecretBytes};

pub type EncKey<E> = <E as SymEncrypt>::Key;
pub type HashKey<E> = <E as SymEncrypt>::HashKey;
pub type StoreKey = StoreKeyImpl<ChaChaEncrypt>;

/// A store key combining the keys required to encrypt
/// and decrypt storage records
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(bound(
    deserialize = "EncKey<E>: for<'a> Deserialize<'a>, HashKey<E>: for<'a> Deserialize<'a>",
    serialize = "EncKey<E>: Serialize, HashKey<E>: Serialize"
))]
pub struct StoreKeyImpl<E: SymEncrypt> {
    pub category_key: EncKey<E>,
    pub name_key: EncKey<E>,
    pub value_key: EncKey<E>,
    pub item_hmac_key: HashKey<E>,
    pub tag_name_key: EncKey<E>,
    pub tag_value_key: EncKey<E>,
    pub tags_hmac_key: HashKey<E>,
}

impl<E: SymEncrypt> StoreKeyImpl<E> {
    pub fn new() -> Result<Self> {
        Ok(Self {
            category_key: E::Key::random_key(),
            name_key: E::Key::random_key(),
            value_key: E::Key::random_key(),
            item_hmac_key: E::HashKey::random_hash_key(),
            tag_name_key: E::Key::random_key(),
            tag_value_key: E::Key::random_key(),
            tags_hmac_key: E::HashKey::random_hash_key(),
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

impl<E: SymEncrypt> PartialEq for StoreKeyImpl<E> {
    fn eq(&self, other: &Self) -> bool {
        self.category_key == other.category_key
            && self.name_key == other.name_key
            && self.value_key == other.value_key
            && self.item_hmac_key == other.item_hmac_key
            && self.tag_name_key == other.tag_name_key
            && self.tag_value_key == other.tag_value_key
            && self.tags_hmac_key == other.tags_hmac_key
    }
}
impl<E: SymEncrypt> Eq for StoreKeyImpl<E> {}

/// Encrypt a value with a predictable nonce, making it searchable
fn encrypt_searchable<E: SymEncrypt>(
    input: SecretBytes,
    enc_key: &E::Key,
    hmac_key: &E::HashKey,
) -> Result<Vec<u8>> {
    let nonce = E::hashed_nonce(&input, hmac_key)?;
    E::encrypt(input, enc_key, Some(nonce))
}

impl<E> EntryEncryptor for StoreKeyImpl<E>
where
    E: SymEncrypt,
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
        let value_key = E::Key::random_key();
        let mut value = E::encrypt(value, &value_key, None)?;
        let key_input = E::prepare_input(value_key.as_bytes());
        let mut result = E::encrypt(key_input, &self.value_key, None)?;
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
        let enc_key_size = E::encrypted_size(E::Key::SIZE);
        if enc_value.len() < enc_key_size + E::encrypted_size(0) {
            return Err(err_msg!(
                Encryption,
                "Buffer is too short to represent an encrypted value",
            ));
        }
        let value = enc_value[enc_key_size..].to_vec();
        enc_value.truncate(enc_key_size);
        let value_key = E::Key::from_slice(
            E::decrypt(enc_value, &self.value_key)?
                .into_vec()
                .as_slice(),
        );
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
        const NONCE_SIZE: usize = 12;
        let input = SecretBytes::from(&b"hello"[..]);
        let key = EncKey::<ChaChaEncrypt>::random_key();
        let hmac_key = EncKey::<ChaChaEncrypt>::random();
        let enc1 = encrypt_searchable::<ChaChaEncrypt>(input.clone(), &key, &hmac_key).unwrap();
        let enc2 = encrypt_searchable::<ChaChaEncrypt>(input.clone(), &key, &hmac_key).unwrap();
        assert_eq!(&enc1[0..NONCE_SIZE], &enc2[0..NONCE_SIZE]);
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
