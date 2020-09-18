use serde::Deserialize;

use indy_utils::base58;
pub use indy_utils::keys::wallet::{decrypt, EncKey, HmacKey, WalletKey as StoreKey};

use crate::error::Result as KvResult;
use crate::keys::EntryEncryptor;
use crate::types::{EncEntryTag, EntryTag};

#[inline]
pub fn decode_utf8(value: Vec<u8>) -> KvResult<String> {
    String::from_utf8(value).map_err(err_map!(Encryption))
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
    fn test_indy_key_round_trip() {
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
        let (enc_record, enc_tags) = key.encrypt_entry(&test_record).unwrap();
        assert!(enc_record.category.as_ref() != test_record.category.as_bytes());
        assert!(enc_record.name.as_ref() != test_record.name.as_bytes());
        assert!(enc_record.value.as_ref() != test_record.value.as_slice());
        assert!(enc_tags.is_some());
        let cmp_record = key.decrypt_entry(&enc_record, enc_tags.as_ref()).unwrap();
        assert_eq!(test_record, cmp_record);
    }
}
