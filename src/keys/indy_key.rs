use serde::Deserialize;

use indy_utils::base58;
pub use indy_utils::keys::wallet::{decrypt, EncKey, HmacKey, WalletKey as IndyWalletKey};

use crate::error::{KvError, KvResult};
use crate::types::{EntryEncryptor, KvTag};

impl EntryEncryptor for IndyWalletKey {
    fn encrypt_category(&self, category: &[u8]) -> KvResult<Vec<u8>> {
        Ok(self.encrypt_category(&category)?)
    }

    fn encrypt_name(&self, name: &[u8]) -> KvResult<Vec<u8>> {
        Ok(self.encrypt_name(&name)?)
    }

    fn encrypt_value(&self, value: &[u8]) -> KvResult<Vec<u8>> {
        Ok(self.encrypt_value(&value)?)
    }

    fn encrypt_tags(&self, tags: Vec<KvTag>) -> KvResult<Vec<KvTag>> {
        tags.into_iter()
            .map(|tag| match tag {
                tag @ KvTag::Plaintext(..) => Ok(tag),
                KvTag::Encrypted(name, value) => {
                    let name = self.encrypt_tag_name(&name)?;
                    let value = self.encrypt_tag_value(&value)?;
                    Ok(KvTag::Encrypted(name, value))
                }
            })
            .collect()
    }

    fn decrypt_category(&self, enc_category: &[u8]) -> KvResult<Vec<u8>> {
        Ok(self.decrypt_category(&enc_category)?)
    }

    fn decrypt_name(&self, enc_name: &[u8]) -> KvResult<Vec<u8>> {
        Ok(self.decrypt_name(&enc_name)?)
    }

    fn decrypt_value(&self, enc_value: &[u8]) -> KvResult<Vec<u8>> {
        Ok(self.decrypt_value(&enc_value)?)
    }

    fn decrypt_tags(&self, enc_tags: Vec<KvTag>) -> KvResult<Vec<KvTag>> {
        enc_tags
            .into_iter()
            .map(|tag| match tag {
                tag @ KvTag::Plaintext(..) => Ok(tag),
                KvTag::Encrypted(name, value) => {
                    let name = self.decrypt_tag_name(&name)?;
                    let value = self.decrypt_tag_value(&value)?;
                    Ok(KvTag::Encrypted(name, value))
                }
            })
            .collect()
    }
}

#[derive(Deserialize, Debug)]
struct EncWalletKey {
    keys: Vec<u8>,
    master_key_salt: Vec<u8>,
}

pub fn decode_wallet_key(enc_key: &[u8], password: &str) -> KvResult<IndyWalletKey> {
    let key = serde_json::from_slice::<EncWalletKey>(enc_key)
        .map_err(|e| KvError::InputError(format!("Invalid wallet key: {}", e.to_string())))?;

    let keys = decrypt_key(key, password)?;
    let data = rmp_serde::from_slice::<[serde_bytes::ByteBuf; 7]>(keys.as_slice()).unwrap();
    let wallet_key = IndyWalletKey {
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

fn decrypt_key(key: EncWalletKey, password: &str) -> KvResult<Vec<u8>> {
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
    use crate::types::KvEntry;

    #[test]
    fn test_indy_key_round_trip() {
        let key = IndyWalletKey::new().unwrap();
        let test_record = KvEntry {
            key_id: 1,
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
