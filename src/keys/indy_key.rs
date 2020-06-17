use aead::{
    generic_array::{
        typenum::{Unsigned, U32},
        ArrayLength, GenericArray,
    },
    Aead, NewAead,
};
use hmac::{Hmac, Mac};
use ursa::encryption::{random_bytes, symm::chacha20poly1305::ChaCha20Poly1305 as ChaChaKey};
use ursa::hash::sha2::Sha256;

use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{KvError, KvResult};
use crate::types::{EntryEncryptor, KvTag};

const KEY_BYTES: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
pub struct Key<L: ArrayLength<u8>>(GenericArray<u8, L>);

type Key32 = Key<U32>;
type NonceSize = <ChaChaKey as Aead>::NonceSize;
type Nonce = GenericArray<u8, NonceSize>;
type TagSize = <ChaChaKey as Aead>::TagSize;

impl<L: ArrayLength<u8>> Key<L> {
    pub fn new() -> KvResult<Self> {
        Ok(Self(random_bytes().map_err(|_| KvError::Unexpected)?))
    }

    pub fn from_slice<D: AsRef<[u8]>>(data: D) -> Self {
        Self(GenericArray::from_slice(data.as_ref()).clone())
    }

    pub fn extract(self) -> GenericArray<u8, L> {
        self.0
    }
}

impl<L: ArrayLength<u8>> From<GenericArray<u8, L>> for Key<L> {
    fn from(key: GenericArray<u8, L>) -> Self {
        Self(key)
    }
}

impl<L: ArrayLength<u8>> std::ops::Deref for Key<L> {
    type Target = GenericArray<u8, L>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<L: ArrayLength<u8>> Serialize for Key<L> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(hex::encode(&self.0.as_slice()).as_str())
    }
}

impl<'a, L: ArrayLength<u8>> Deserialize<'a> for Key<L> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        deserializer.deserialize_str(KeyVisitor {
            _pd: std::marker::PhantomData,
        })
    }
}

struct KeyVisitor<L: ArrayLength<u8>> {
    _pd: std::marker::PhantomData<L>,
}

impl<'a, L: ArrayLength<u8>> Visitor<'a> for KeyVisitor<L> {
    type Value = Key<L>;

    fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        formatter.write_str(stringify!($name))
    }

    fn visit_str<E>(self, value: &str) -> Result<Key<L>, E>
    where
        E: serde::de::Error,
    {
        let key = hex::decode(value).map_err(E::custom)?;
        Ok(Key(GenericArray::clone_from_slice(key.as_slice())))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct IndyWalletKey {
    pub category_key: Key32,
    pub name_key: Key32,
    pub value_key: Key32,
    pub item_hmac_key: Key32,
    pub tag_name_key: Key32,
    pub tag_value_key: Key32,
    pub tags_hmac_key: Key32,
}

impl IndyWalletKey {
    pub fn new() -> KvResult<Self> {
        Ok(Self {
            category_key: Key::new()?,
            name_key: Key::new()?,
            value_key: Key::new()?,
            item_hmac_key: Key::new()?,
            tag_name_key: Key::new()?,
            tag_value_key: Key::new()?,
            tags_hmac_key: Key::new()?,
        })
    }
}

impl EntryEncryptor for IndyWalletKey {
    fn encrypt_category(&self, category: Vec<u8>) -> KvResult<Vec<u8>> {
        encrypt_searchable(&self.category_key, &self.item_hmac_key, category)
    }

    fn encrypt_name(&self, name: Vec<u8>) -> KvResult<Vec<u8>> {
        encrypt_searchable(&self.name_key, &self.item_hmac_key, name)
    }

    fn encrypt_value(&self, value: Vec<u8>) -> KvResult<Vec<u8>> {
        let value_key = Key(random_bytes().map_err(|_| KvError::EncryptionError)?);
        let mut value = encrypt_non_searchable(&value_key, value)?;
        let mut result = encrypt_non_searchable(&self.value_key, value_key.to_vec())?;
        result.append(&mut value);
        Ok(result)
    }

    fn encrypt_tags(&self, tags: Vec<KvTag>) -> KvResult<Vec<KvTag>> {
        tags.into_iter()
            .map(|tag| match tag {
                tag @ KvTag::Plaintext(..) => Ok(tag),
                KvTag::Encrypted(name, value) => {
                    let name = encrypt_searchable(&self.tag_name_key, &self.tags_hmac_key, name)?;
                    let value =
                        encrypt_searchable(&self.tag_value_key, &self.tags_hmac_key, value)?;
                    Ok(KvTag::Encrypted(name, value))
                }
            })
            .collect()
    }

    fn decrypt_category(&self, enc_category: Vec<u8>) -> KvResult<Vec<u8>> {
        decrypt(&self.category_key, enc_category)
    }

    fn decrypt_name(&self, enc_name: Vec<u8>) -> KvResult<Vec<u8>> {
        decrypt(&self.name_key, enc_name)
    }

    fn decrypt_value(&self, mut enc_value: Vec<u8>) -> KvResult<Vec<u8>> {
        if enc_value.len() < NonceSize::to_usize() + KEY_BYTES + TagSize::to_usize() {
            return Err(KvError::DecryptionError);
        }
        let value = enc_value.split_off(NonceSize::to_usize() + KEY_BYTES + TagSize::to_usize());
        let value_key = Key::from_slice(decrypt(&self.value_key, enc_value)?);
        decrypt(&value_key, value)
    }

    fn decrypt_tags(&self, enc_tags: Vec<KvTag>) -> KvResult<Vec<KvTag>> {
        enc_tags
            .into_iter()
            .map(|tag| match tag {
                tag @ KvTag::Plaintext(..) => Ok(tag),
                KvTag::Encrypted(name, value) => {
                    let name = decrypt(&self.tag_name_key, name)?;
                    let value = decrypt(&self.tag_value_key, value)?;
                    Ok(KvTag::Encrypted(name, value))
                }
            })
            .collect()
    }
}

fn encrypt_searchable(enc_key: &Key32, hmac_key: &Key32, input: Vec<u8>) -> KvResult<Vec<u8>> {
    let key = ChaChaKey::new(enc_key.clone().extract());
    let mut nonce_hmac =
        Hmac::<Sha256>::new_varkey(&**hmac_key).map_err(|_| KvError::EncryptionError)?;
    nonce_hmac.input(&input);
    let result = nonce_hmac.result().code();
    let nonce = Nonce::from_slice(&result[0..NonceSize::to_usize()]);
    let mut enc = key
        .encrypt(nonce, input.as_slice())
        .map_err(|_| KvError::EncryptionError)?;
    let mut result = nonce.to_vec();
    result.append(&mut enc);
    Ok(result)
}

fn encrypt_non_searchable(enc_key: &Key32, input: Vec<u8>) -> KvResult<Vec<u8>> {
    let key = ChaChaKey::new(enc_key.clone().extract());
    let nonce = random_bytes().map_err(|_| KvError::EncryptionError)?;
    let mut enc = key
        .encrypt(&nonce, input.as_slice())
        .map_err(|_| KvError::EncryptionError)?;
    let mut result = nonce.to_vec();
    result.append(&mut enc);
    Ok(result)
}

fn decrypt(enc_key: &Key32, input: Vec<u8>) -> KvResult<Vec<u8>> {
    if input.len() < NonceSize::to_usize() {
        return Err(KvError::DecryptionError);
    }
    let nonce = Nonce::from_slice(&input[0..NonceSize::to_usize()]);
    let key = ChaChaKey::new(enc_key.clone().extract());
    key.decrypt(&nonce, &input[NonceSize::to_usize()..])
        .map_err(|_| KvError::DecryptionError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::KvEntry;
    use serde_json;

    #[test]
    fn test_indy_key_non_searchable() {
        let input = b"hello".to_vec();
        let key = Key32::new().unwrap();
        let enc = encrypt_non_searchable(&key, input.clone()).unwrap();
        assert_eq!(
            enc.len(),
            input.len() + NonceSize::to_usize() + TagSize::to_usize()
        );
    }

    #[test]
    fn test_indy_key_serde() {
        let key = IndyWalletKey::new().unwrap();
        let key_json = serde_json::to_string(&key).unwrap();
        let key_cmp = serde_json::from_str(&key_json).unwrap();
        assert_eq!(key, key_cmp);
    }

    #[test]
    fn test_indy_key_round_trip() {
        let key = IndyWalletKey::new().unwrap();
        let test_record = KvEntry {
            key_id: vec![],
            category: b"category".to_vec(),
            name: b"name".to_vec(),
            value: b"value".to_vec(),
            tags: Some(vec![
                KvTag::Plaintext(b"plain".to_vec(), b"tag".to_vec()),
                KvTag::Encrypted(b"enctag".to_vec(), b"envtagval".to_vec()),
            ]),
            locked: None,
        };
        let enc_record = key.encrypt_entry(test_record.clone()).unwrap();
        assert_ne!(test_record, enc_record);
        assert_eq!(
            test_record.tags.as_ref().unwrap()[0],
            enc_record.tags.as_ref().unwrap()[0]
        );
        let cmp_record = key.decrypt_entry(enc_record).unwrap();
        assert_eq!(test_record, cmp_record);
    }
}
