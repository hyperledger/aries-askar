#[inline]
pub fn decode_utf8(value: Vec<u8>) -> KvResult<String> {
    String::from_utf8(value).map_err(err_map!(Encryption))
}

use hmac::{Hmac, Mac};
use indy_utils::{
    aead::{
        generic_array::{
            typenum::{Unsigned, U32},
            ArrayLength, GenericArray,
        },
        Aead, NewAead,
    },
    base58,
    keys::ArrayKey,
};
use ursa::{
    encryption::{random_bytes, symm::chacha20poly1305::ChaCha20Poly1305 as ChaChaKey},
    hash::sha2::Sha256,
};

use serde::Deserialize;

use crate::error::Result as KvResult;
use crate::keys::EntryEncryptor;
use crate::types::{EncEntryTag, EntryTag};

const ENC_KEY_BYTES: usize = 32;
const ENC_KEY_SIZE: usize = 12 + ENC_KEY_BYTES + 16; // nonce + key_bytes + tag size

pub type EncKey = ArrayKey<U32>;
pub type HmacKey = ArrayKey<U32>;
type NonceSize = <ChaChaKey as Aead>::NonceSize;
type Nonce = GenericArray<u8, NonceSize>;
type TagSize = <ChaChaKey as Aead>::TagSize;

fn random_key<L: ArrayLength<u8>>() -> KvResult<ArrayKey<L>> {
    Ok(ArrayKey::from(random_bytes().map_err(|e| {
        err_msg!(Unexpected, "Error creating key: {}", e)
    })?))
}

fn random_nonce() -> KvResult<Nonce> {
    random_bytes().map_err(|e| err_msg!(Unexpected, "Error creating nonce: {}", e))
}

/// A store key combining the keys required to encrypt
/// and decrypt storage records
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct StoreKey {
    pub category_key: EncKey,
    pub name_key: EncKey,
    pub value_key: EncKey,
    pub item_hmac_key: HmacKey,
    pub tag_name_key: EncKey,
    pub tag_value_key: EncKey,
    pub tags_hmac_key: HmacKey,
}

impl StoreKey {
    pub fn new() -> KvResult<Self> {
        Ok(Self {
            category_key: random_key()?,
            name_key: random_key()?,
            value_key: random_key()?,
            item_hmac_key: random_key()?,
            tag_name_key: random_key()?,
            tag_value_key: random_key()?,
            tags_hmac_key: random_key()?,
        })
    }

    pub fn encrypt_category<B: AsRef<[u8]>>(&self, category: B) -> KvResult<Vec<u8>> {
        encrypt_searchable(&self.category_key, &self.item_hmac_key, category.as_ref())
    }

    pub fn encrypt_name<B: AsRef<[u8]>>(&self, name: B) -> KvResult<Vec<u8>> {
        encrypt_searchable(&self.name_key, &self.item_hmac_key, name.as_ref())
    }

    pub fn encrypt_value<B: AsRef<[u8]>>(&self, value: B) -> KvResult<Vec<u8>> {
        let value_key = random_key()?;
        let mut value = encrypt_non_searchable(&value_key, value.as_ref())?;
        let mut result = encrypt_non_searchable(&self.value_key, value_key.as_ref())?;
        result.append(&mut value);
        Ok(result)
    }

    pub fn encrypt_tag_name<B: AsRef<[u8]>>(&self, name: B) -> KvResult<Vec<u8>> {
        encrypt_searchable(&self.tag_name_key, &self.tags_hmac_key, name.as_ref())
    }

    pub fn encrypt_tag_value<B: AsRef<[u8]>>(&self, value: B) -> KvResult<Vec<u8>> {
        encrypt_searchable(&self.tag_value_key, &self.tags_hmac_key, value.as_ref())
    }

    pub fn decrypt_category<B: AsRef<[u8]>>(&self, enc_category: B) -> KvResult<Vec<u8>> {
        decrypt(&self.category_key, enc_category.as_ref())
    }

    pub fn decrypt_name<B: AsRef<[u8]>>(&self, enc_name: B) -> KvResult<Vec<u8>> {
        decrypt(&self.name_key, enc_name.as_ref())
    }

    pub fn decrypt_value<B: AsRef<[u8]>>(&self, enc_value: B) -> KvResult<Vec<u8>> {
        let enc_value = enc_value.as_ref();
        if enc_value.len() < ENC_KEY_SIZE + TagSize::to_usize() {
            return Err(err_msg!(
                Encryption,
                "Buffer is too short to represent an encrypted value",
            ));
        }
        let value = &enc_value[ENC_KEY_SIZE..];
        let value_key = ArrayKey::from_slice(decrypt(&self.value_key, &enc_value[..ENC_KEY_SIZE])?);
        decrypt(&value_key, value)
    }

    pub fn decrypt_tag_name<B: AsRef<[u8]>>(&self, enc_tag_name: B) -> KvResult<Vec<u8>> {
        decrypt(&self.tag_name_key, enc_tag_name.as_ref())
    }

    pub fn decrypt_tag_value<B: AsRef<[u8]>>(&self, enc_tag_value: B) -> KvResult<Vec<u8>> {
        decrypt(&self.tag_value_key, enc_tag_value.as_ref())
    }
}

/// Encrypt a value with a predictable nonce, making it searchable
pub fn encrypt_searchable(enc_key: &EncKey, hmac_key: &HmacKey, input: &[u8]) -> KvResult<Vec<u8>> {
    let key = ChaChaKey::new(enc_key);
    let mut nonce_hmac =
        Hmac::<Sha256>::new_varkey(&**hmac_key).map_err(|e| err_msg!(Encryption, "{}", e))?;
    nonce_hmac.input(input);
    let result = nonce_hmac.result().code();
    let nonce = Nonce::from_slice(&result[0..NonceSize::to_usize()]);
    let mut enc = key
        .encrypt(nonce, input)
        .map_err(|e| err_msg!(Encryption, "{}", e))?;
    let mut result = nonce.to_vec();
    result.append(&mut enc);
    Ok(result)
}

/// Encrypt a value with a random nonce
pub fn encrypt_non_searchable(enc_key: &EncKey, input: &[u8]) -> KvResult<Vec<u8>> {
    let key = ChaChaKey::new(enc_key);
    let nonce = random_nonce()?;
    let mut enc = key
        .encrypt(&nonce, input)
        .map_err(|e| err_msg!(Encryption, "{}", e))?;
    let mut result = nonce.to_vec();
    result.append(&mut enc);
    Ok(result)
}

/// Written to match randombytes_deterministic in libsodium,
/// used to generate a deterministic wallet raw key.
pub fn random_deterministic(enc_key: &EncKey, len: usize) -> Vec<u8> {
    // ursa does not re-export chacha20 crate
    use chacha20::stream_cipher::{NewStreamCipher, SyncStreamCipher};
    use chacha20::ChaCha20;

    let nonce = GenericArray::from_slice(b"LibsodiumDRG");
    let mut cipher = ChaCha20::new(&enc_key, &nonce);
    let mut data = vec![0; len];
    cipher.apply_keystream(data.as_mut_slice());
    data
}

/// Decrypt a previously encrypted value with nonce attached
pub fn decrypt(enc_key: &EncKey, input: &[u8]) -> KvResult<Vec<u8>> {
    if input.len() < NonceSize::to_usize() + TagSize::to_usize() {
        return Err(err_msg!(Encryption, "Invalid length for encrypted buffer"));
    }
    let nonce = Nonce::from_slice(&input[0..NonceSize::to_usize()]);
    let key = ChaChaKey::new(enc_key);
    key.decrypt(&nonce, &input[NonceSize::to_usize()..])
        .map_err(|e| err_msg!(Encryption, "{}", e))
}

impl EntryEncryptor for StoreKey {
    fn encrypt_entry_category(&self, category: &str) -> KvResult<Vec<u8>> {
        Ok(self.encrypt_category(&category)?)
    }

    fn encrypt_entry_name(&self, name: &str) -> KvResult<Vec<u8>> {
        Ok(self.encrypt_name(&name)?)
    }

    fn encrypt_entry_value(&self, value: &[u8]) -> KvResult<Vec<u8>> {
        Ok(self.encrypt_value(&value)?)
    }

    fn encrypt_entry_tags(&self, tags: &[EntryTag]) -> KvResult<Vec<EncEntryTag>> {
        tags.into_iter()
            .map(|tag| match tag {
                EntryTag::Plaintext(name, value) => {
                    let name = self.encrypt_tag_name(&name)?;
                    Ok(EncEntryTag {
                        name,
                        value: value.as_bytes().to_vec(),
                        plaintext: true,
                    })
                }
                EntryTag::Encrypted(name, value) => {
                    let name = self.encrypt_tag_name(&name)?;
                    let value = self.encrypt_tag_value(&value)?;
                    Ok(EncEntryTag {
                        name,
                        value,
                        plaintext: false,
                    })
                }
            })
            .collect()
    }

    fn decrypt_entry_category(&self, enc_category: &[u8]) -> KvResult<String> {
        decode_utf8(self.decrypt_category(&enc_category)?)
    }

    fn decrypt_entry_name(&self, enc_name: &[u8]) -> KvResult<String> {
        decode_utf8(self.decrypt_name(&enc_name)?)
    }

    fn decrypt_entry_value(&self, enc_value: &[u8]) -> KvResult<Vec<u8>> {
        Ok(self.decrypt_value(&enc_value)?)
    }

    fn decrypt_entry_tags(&self, enc_tags: &[EncEntryTag]) -> KvResult<Vec<EntryTag>> {
        enc_tags.into_iter().try_fold(vec![], |mut acc, tag| {
            let name = decode_utf8(self.decrypt_tag_name(&tag.name)?)?;
            acc.push(if tag.plaintext {
                let value = decode_utf8(tag.value.clone())?;
                EntryTag::Plaintext(name, value)
            } else {
                let value = decode_utf8(self.decrypt_tag_value(&tag.value)?)?;
                EntryTag::Encrypted(name, value)
            });
            KvResult::Ok(acc)
        })
    }
}

#[derive(Deserialize, Debug)]
struct EncStorageKey {
    keys: Vec<u8>,
    master_key_salt: Vec<u8>,
}

pub fn decode_wallet_key(enc_key: &[u8], password: &str) -> KvResult<StoreKey> {
    let key =
        serde_json::from_slice::<EncStorageKey>(enc_key).map_err(err_map!("Invalid wallet key"))?;

    let keys = decrypt_key(key, password)?;
    let data = rmp_serde::from_slice::<[serde_bytes::ByteBuf; 7]>(keys.as_slice()).unwrap();
    let wallet_key = StoreKey {
        category_key: EncKey::from_slice(&data[0]),
        name_key: EncKey::from_slice(&data[1]),
        value_key: EncKey::from_slice(&data[2]),
        item_hmac_key: HmacKey::from_slice(&data[3]),
        tag_name_key: EncKey::from_slice(&data[4]),
        tag_value_key: EncKey::from_slice(&data[5]),
        tags_hmac_key: HmacKey::from_slice(&data[6]),
    };

    Ok(wallet_key)
}

fn decrypt_key(key: EncStorageKey, password: &str) -> KvResult<Vec<u8>> {
    // check for a raw key in base58 format
    if let Ok(raw_key) = base58::decode(password) {
        if raw_key.len() == 32 {
            let master_key = EncKey::from_slice(&raw_key);
            return Ok(decrypt(&master_key, key.keys.as_slice())?);
        }
    }

    let salt = &key.master_key_salt[..16];

    // derive key with libsodium 'moderate' settings
    let master_key = derive_key_argon2(password, salt, 131072, 6);
    if let Ok(keys) = decrypt(&master_key, key.keys.as_slice()) {
        Ok(keys)
    } else {
        // derive key with libsodium 'interactive' settings
        let master_key = derive_key_argon2(password, salt, 32768, 4);
        Ok(decrypt(&master_key, key.keys.as_slice())?)
    }
}

fn derive_key_argon2(password: &str, salt: &[u8], mem_cost: u32, time_cost: u32) -> EncKey {
    let config = argon2::Config {
        variant: argon2::Variant::Argon2i,
        version: argon2::Version::Version13,
        mem_cost,
        time_cost,
        lanes: 1,
        thread_mode: argon2::ThreadMode::Sequential,
        secret: &[],
        ad: &[],
        hash_length: 32,
    };
    let hash = argon2::hash_raw(password.as_bytes(), salt, &config).unwrap();
    EncKey::from_slice(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Entry;

    #[test]
    fn store_key_round_trip() {
        let key = StoreKey::new().unwrap();
        let test_record = Entry {
            category: "category".to_string(),
            name: "name".to_string(),
            value: b"value".to_vec(),
            tags: Some(vec![
                EntryTag::Plaintext("plain".to_string(), "tag".to_string()),
                EntryTag::Encrypted("enctag".to_string(), "envtagval".to_string()),
            ]),
        };
        let enc_category = key.encrypt_entry_category(&test_record.category).unwrap();
        let enc_name = key.encrypt_entry_name(&test_record.name).unwrap();
        let enc_value = key.encrypt_entry_value(&test_record.value).unwrap();
        let enc_tags = key
            .encrypt_entry_tags(&test_record.tags.as_ref().unwrap())
            .unwrap();
        assert_ne!(enc_category.as_slice(), test_record.category.as_bytes());
        assert_ne!(enc_name.as_slice(), test_record.name.as_bytes());
        assert_ne!(enc_value.as_slice(), test_record.value.as_slice());

        let cmp_record = Entry {
            category: key.decrypt_entry_category(&enc_category).unwrap(),
            name: key.decrypt_entry_name(&enc_name).unwrap(),
            value: key.decrypt_entry_value(&enc_value).unwrap(),
            tags: Some(key.decrypt_entry_tags(&enc_tags).unwrap()),
        };
        assert_eq!(test_record, cmp_record);
    }

    #[test]
    fn store_key_non_searchable() {
        let input = b"hello";
        let key = random_key().unwrap();
        let enc = encrypt_non_searchable(&key, input).unwrap();
        assert_eq!(
            enc.len(),
            input.len() + NonceSize::to_usize() + TagSize::to_usize()
        );
        let dec = decrypt(&key, enc.as_slice()).unwrap();
        assert_eq!(dec.as_slice(), input);
    }

    #[test]
    fn store_key_searchable() {
        let input = b"hello";
        let key = random_key().unwrap();
        let hmac_key = random_key().unwrap();
        let enc = encrypt_searchable(&key, &hmac_key, input).unwrap();
        assert_eq!(
            enc.len(),
            input.len() + NonceSize::to_usize() + TagSize::to_usize()
        );
        let dec = decrypt(&key, enc.as_slice()).unwrap();
        assert_eq!(dec.as_slice(), input);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn store_key_serde() {
        let key = WalletKey::new().unwrap();
        let key_json = serde_json::to_string(&key).unwrap();
        let key_cmp = serde_json::from_str(&key_json).unwrap();
        assert_eq!(key, key_cmp);
    }

    #[test]
    fn random_det() {
        let key = EncKey::from_slice(b"00000000000000000000000000000My1");
        let ret = random_deterministic(&key, ENC_KEY_BYTES);
        assert_eq!(
            base58::encode(ret),
            "CwMHrEQJnwvuE8q9zbR49jyYtVxVBHNTjCPEPk1aV3cP"
        );
    }
}
