use indy_utils::keys::wallet::WalletKey as IndyWalletKey;

use crate::error::KvResult;
use crate::types::{EntryEncryptor, KvTag};

impl EntryEncryptor for IndyWalletKey {
    fn encrypt_category(&self, category: Vec<u8>) -> KvResult<Vec<u8>> {
        Ok(self.encrypt_category(&category)?)
    }

    fn encrypt_name(&self, name: Vec<u8>) -> KvResult<Vec<u8>> {
        Ok(self.encrypt_name(&name)?)
    }

    fn encrypt_value(&self, value: Vec<u8>) -> KvResult<Vec<u8>> {
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

    fn decrypt_category(&self, enc_category: Vec<u8>) -> KvResult<Vec<u8>> {
        Ok(self.decrypt_category(&enc_category)?)
    }

    fn decrypt_name(&self, enc_name: Vec<u8>) -> KvResult<Vec<u8>> {
        Ok(self.decrypt_name(&enc_name)?)
    }

    fn decrypt_value(&self, enc_value: Vec<u8>) -> KvResult<Vec<u8>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::KvEntry;

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
