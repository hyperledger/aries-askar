use serde::{Deserialize, Serialize};
use sha2::Sha256;

use super::hmac_key::HmacOutput;
use super::EntryEncryptor;
use crate::{
    crypto::{
        alg::chacha20::{Chacha20Key, C20P},
        buffer::{ArrayKey, ResizeBuffer, SecretBytes, WriteBuffer},
        encrypt::{KeyAeadInPlace, KeyAeadMeta},
        generic_array::typenum::{Unsigned, U32},
        repr::{KeyGen, KeyMeta, KeySecretBytes},
    },
    error::Error,
    storage::entry::{EncEntryTag, EntryTag},
};

pub type StoreKey = StoreKeyImpl<Chacha20Key<C20P>, super::hmac_key::HmacKey<U32, Sha256>>;

/// A store key combining the keys required to encrypt
/// and decrypt storage records
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(bound(
    deserialize = "Key: for<'a> Deserialize<'a>, HmacKey: for<'a> Deserialize<'a>",
    serialize = "Key: Serialize, HmacKey: Serialize"
))]
pub struct StoreKeyImpl<Key, HmacKey> {
    pub category_key: Key,
    pub name_key: Key,
    pub value_key: Key,
    pub item_hmac_key: HmacKey,
    pub tag_name_key: Key,
    pub tag_value_key: Key,
    pub tags_hmac_key: HmacKey,
}

impl<Key, HmacKey> StoreKeyImpl<Key, HmacKey>
where
    Key: KeyGen,
    HmacKey: KeyGen,
{
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            category_key: KeyGen::generate()?,
            name_key: KeyGen::generate()?,
            value_key: KeyGen::generate()?,
            item_hmac_key: KeyGen::generate()?,
            tag_name_key: KeyGen::generate()?,
            tag_value_key: KeyGen::generate()?,
            tags_hmac_key: KeyGen::generate()?,
        })
    }
}

impl<Key, HmacKey> StoreKeyImpl<Key, HmacKey>
where
    Key: Serialize + for<'de> Deserialize<'de>,
    HmacKey: Serialize + for<'de> Deserialize<'de>,
{
    pub fn to_bytes(&self) -> Result<SecretBytes, Error> {
        serde_cbor::to_vec(self)
            .map(SecretBytes::from)
            .map_err(err_map!(Unexpected, "Error serializing store key"))
    }

    pub fn from_slice(input: &[u8]) -> Result<Self, Error> {
        serde_cbor::from_slice(input).map_err(err_map!(Unsupported, "Invalid store key"))
    }
}

impl<Key, HmacKey> StoreKeyImpl<Key, HmacKey>
where
    Key: KeyGen + KeyMeta + KeyAeadInPlace + KeyAeadMeta + KeySecretBytes,
    HmacKey: KeyGen + HmacOutput,
{
    pub fn encrypted_size(len: usize) -> usize {
        len + Key::NonceSize::USIZE + Key::TagSize::USIZE
    }

    /// Encrypt a value with a predictable nonce, making it searchable
    pub fn encrypt_searchable(
        mut buffer: SecretBytes,
        enc_key: &Key,
        hmac_key: &HmacKey,
    ) -> Result<Vec<u8>, Error> {
        let mut nonce = ArrayKey::<Key::NonceSize>::default();
        hmac_key.hmac_to(buffer.as_ref(), nonce.as_mut())?;
        enc_key.encrypt_in_place(&mut buffer, nonce.as_ref(), &[])?;
        buffer.buffer_insert_slice(0, nonce.as_ref())?;
        Ok(buffer.into_vec())
    }

    pub fn encrypt(mut buffer: SecretBytes, enc_key: &Key) -> Result<Vec<u8>, Error> {
        let nonce = ArrayKey::<Key::NonceSize>::random();
        enc_key.encrypt_in_place(&mut buffer, nonce.as_ref(), &[])?;
        buffer.buffer_insert_slice(0, nonce.as_ref())?;
        Ok(buffer.into_vec())
    }

    pub fn decrypt(ciphertext: Vec<u8>, enc_key: &Key) -> Result<SecretBytes, Error> {
        let nonce_len = Key::nonce_length();
        if ciphertext.len() < nonce_len {
            return Err(err_msg!(Encryption, "invalid encrypted value"));
        }
        let mut buffer = SecretBytes::from(ciphertext);
        let nonce = ArrayKey::<Key::NonceSize>::from_slice(&buffer.as_ref()[..nonce_len]);
        buffer.buffer_remove(0..nonce_len)?;
        enc_key.decrypt_in_place(&mut buffer, nonce.as_ref(), &[])?;
        Ok(buffer)
    }

    pub fn encrypt_tag_name(&self, name: SecretBytes) -> Result<Vec<u8>, Error> {
        Self::encrypt_searchable(name, &self.tag_name_key, &self.tags_hmac_key)
    }

    pub fn encrypt_tag_value(&self, value: SecretBytes) -> Result<Vec<u8>, Error> {
        Self::encrypt_searchable(value, &self.tag_value_key, &self.tags_hmac_key)
    }

    pub fn decrypt_tag_name(&self, enc_tag_name: Vec<u8>) -> Result<SecretBytes, Error> {
        Self::decrypt(enc_tag_name, &self.tag_name_key)
    }

    pub fn decrypt_tag_value(&self, enc_tag_value: Vec<u8>) -> Result<SecretBytes, Error> {
        Self::decrypt(enc_tag_value, &self.tag_value_key)
    }
}

impl<Key: PartialEq, HmacKey: PartialEq> PartialEq for StoreKeyImpl<Key, HmacKey> {
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
impl<Key: PartialEq, HmacKey: PartialEq> Eq for StoreKeyImpl<Key, HmacKey> {}

impl<Key, HmacKey> EntryEncryptor for StoreKeyImpl<Key, HmacKey>
where
    Key: KeyGen + KeyMeta + KeyAeadInPlace + KeyAeadMeta + KeySecretBytes,
    HmacKey: KeyGen + HmacOutput,
{
    fn prepare_input(input: &[u8]) -> SecretBytes {
        let mut buf = SecretBytes::with_capacity(Self::encrypted_size(input.len()));
        buf.write_slice(input).unwrap();
        buf
    }

    fn encrypt_entry_category(&self, category: SecretBytes) -> Result<Vec<u8>, Error> {
        Self::encrypt_searchable(category, &self.category_key, &self.item_hmac_key)
    }

    fn encrypt_entry_name(&self, name: SecretBytes) -> Result<Vec<u8>, Error> {
        Self::encrypt_searchable(name, &self.name_key, &self.item_hmac_key)
    }

    fn encrypt_entry_value(&self, value: SecretBytes) -> Result<Vec<u8>, Error> {
        let value_key = Key::generate()?;
        let value = Self::encrypt(value, &value_key)?;
        let key_input = value_key.with_secret_bytes(|sk| Self::prepare_input(sk.unwrap()));
        let mut result = Self::encrypt(key_input, &self.value_key)?;
        result.write_slice(value.as_ref())?;
        Ok(result)
    }

    fn decrypt_entry_category(&self, enc_category: Vec<u8>) -> Result<String, Error> {
        decode_utf8(Self::decrypt(enc_category, &self.category_key)?.into_vec())
    }

    fn decrypt_entry_name(&self, enc_name: Vec<u8>) -> Result<String, Error> {
        decode_utf8(Self::decrypt(enc_name, &self.name_key)?.into_vec())
    }

    fn decrypt_entry_value(&self, mut enc_value: Vec<u8>) -> Result<SecretBytes, Error> {
        let enc_key_size = Self::encrypted_size(Key::KeySize::USIZE);
        if enc_value.len() < enc_key_size + Self::encrypted_size(0) {
            return Err(err_msg!(
                Encryption,
                "Buffer is too short to represent an encrypted value",
            ));
        }
        let value = Vec::from(&enc_value[enc_key_size..]);
        enc_value.buffer_resize(enc_key_size)?;
        let value_key =
            Key::from_secret_bytes(Self::decrypt(enc_value, &self.value_key)?.as_ref())?;
        Self::decrypt(value, &value_key)
    }

    fn encrypt_entry_tags(&self, tags: Vec<EntryTag>) -> Result<Vec<EncEntryTag>, Error> {
        tags.into_iter()
            .map(|tag| match tag {
                EntryTag::Plaintext(name, value) => {
                    let name = self.encrypt_tag_name(name.into())?;
                    Ok(EncEntryTag {
                        name,
                        value: value.into_bytes().into(),
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

    fn decrypt_entry_tags(&self, enc_tags: Vec<EncEntryTag>) -> Result<Vec<EntryTag>, Error> {
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

#[inline(always)]
fn decode_utf8(value: Vec<u8>) -> Result<String, Error> {
    String::from_utf8(value).map_err(err_map!(Encryption))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::entry::Entry;

    #[test]
    fn encrypt_entry_round_trip() {
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
        assert_ne!(test_record.category.as_bytes(), &enc_category[..]);
        assert_ne!(test_record.name.as_bytes(), &enc_name[..]);
        assert_ne!(test_record.value, enc_value);

        let cmp_record = Entry::new(
            key.decrypt_entry_category(enc_category).unwrap(),
            key.decrypt_entry_name(enc_name).unwrap(),
            key.decrypt_entry_value(enc_value).unwrap(),
            Some(key.decrypt_entry_tags(enc_tags).unwrap()),
        );
        assert_eq!(test_record, cmp_record);
    }

    // #[test]
    // fn store_key_searchable() {
    //     const NONCE_SIZE: usize = 12;
    //     let input = SecretBytes::from(&b"hello"[..]);
    //     let key = EncKey::<ChaChaEncrypt>::random_key();
    //     let hmac_key = EncKey::<ChaChaEncrypt>::random();
    //     let enc1 = encrypt_searchable::<ChaChaEncrypt>(input.clone(), &key, &hmac_key).unwrap();
    //     let enc2 = encrypt_searchable::<ChaChaEncrypt>(input.clone(), &key, &hmac_key).unwrap();
    //     assert_eq!(&enc1[0..NONCE_SIZE], &enc2[0..NONCE_SIZE]);
    //     let dec = ChaChaEncrypt::decrypt(enc1, &key).unwrap();
    //     assert_eq!(dec, input);
    // }

    #[test]
    fn serialize_round_trip() {
        let key = StoreKey::new().unwrap();
        let key_cbor = serde_cbor::to_vec(&key).unwrap();
        let key_cmp = serde_cbor::from_slice(&key_cbor).unwrap();
        assert_eq!(key, key_cmp);
    }
}