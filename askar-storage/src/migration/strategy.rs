use super::{
    EncryptionKey, IndyKey, IndySdkToAriesAskarMigration, ProfileKey, UpdatedIndyItem,
    CHACHAPOLY_NONCE_LEN,
};
use crate::crypto::buffer::SecretBytes;
use crate::crypto::encrypt::KeyAeadInPlace;
use crate::crypto::repr::KeySecretBytes;
use crate::entry::EntryTag;
use crate::protect::EntryEncryptor;
use crate::Error;

#[derive(Default)]
pub(crate) struct IndyItem {
    id: u32,
    typ: Vec<u8>,
    name: Vec<u8>,
    value: Option<Vec<u8>>,
    tags: Vec<EntryTag>,
}

// TODO: should tags_enc and tags_plain be empty in the example?
#[derive(sqlx::FromRow, Debug)]
pub(crate) struct IndyRow {
    id: u32,
    #[sqlx(rename = "type")]
    typ: Vec<u8>,
    name: Vec<u8>,
    value: Option<Vec<u8>>,
    key: Vec<u8>,
    tags_enc: Option<String>,
    tags_plain: Option<String>,
}

pub(crate) struct Strategy {}

impl Strategy {
    pub fn decrypt_merged(enc_value: &[u8], key: &EncryptionKey) -> Result<Vec<u8>, Error> {
        let (nonce, ciphertext) = enc_value.split_at(CHACHAPOLY_NONCE_LEN.into());

        let mut buffer = SecretBytes::from_slice(ciphertext);

        key.decrypt_in_place(&mut buffer, nonce, &[])?;

        Ok(buffer.to_vec())
    }

    pub fn decrypt_tags(
        tags: &str,
        name_key: &EncryptionKey,
        value_key: Option<&EncryptionKey>,
    ) -> Result<Vec<(String, String)>, Error> {
        let mut ret = vec![];
        for tag in tags.split(',') {
            let mut t = tag.split(':');

            let tag_name = hex::decode(t.next().unwrap())
                .map_err(err_map!(Input, "tag is not valid hex encoded"))?;
            let tag_value = hex::decode(t.next().unwrap())
                .map_err(err_map!(Input, "tag is not valid hex encoded"))?;

            let name = String::from_utf8(Self::decrypt_merged(&tag_name, name_key)?)
                .map_err(err_map!(Input, "tag name is not valid utf-8"))?;
            let value = String::from_utf8(match value_key {
                None => tag_value,
                Some(value_key) => Self::decrypt_merged(&tag_value, value_key)?,
            })
            .map_err(err_map!(Input, "tag value is not valid utf-8"))?;
            ret.push((name, value));
        }
        Ok(ret)
    }

    pub fn decrypt_item(row: IndyRow, keys: &IndyKey) -> Result<IndyItem, Error> {
        let value_key = Self::decrypt_merged(&row.key, &keys.value_key)?;
        let value_key = EncryptionKey::from_secret_bytes(&value_key)?;
        let value = match row.value {
            Some(ref value) => Some(Self::decrypt_merged(value, &value_key)?),
            None => None,
        };
        let mut tags: Vec<EntryTag> = vec![];

        let resp = match row.tags_enc {
            None => vec![],
            Some(tags_enc) => Self::decrypt_tags(
                tags_enc.as_str(),
                &keys.tag_name_key,
                Some(&keys.tag_value_key),
            )?,
        };
        for (name, value) in resp {
            tags.push(EntryTag::Encrypted(name, value));
        }

        let resp_plain = match row.tags_plain {
            None => vec![],
            Some(tags_plain) => Self::decrypt_tags(tags_plain.as_str(), &keys.tag_name_key, None)?,
        };
        for (name, value) in resp_plain {
            tags.push(EntryTag::Plaintext(name, value));
        }

        let indy_item = IndyItem {
            id: row.id,
            typ: Self::decrypt_merged(&row.typ, &keys.type_key)?,
            name: Self::decrypt_merged(&row.name, &keys.name_key)?,
            value,
            tags,
        };

        Ok(indy_item)
    }

    pub fn update_item(item: IndyItem, key: &ProfileKey) -> Result<UpdatedIndyItem, Error> {
        let value = match item.value {
            Some(v) => key.encrypt_entry_value(&item.typ, &item.name, v.into())?,
            None => Default::default(),
        };

        let updated_indy_item = UpdatedIndyItem {
            id: item.id,
            category: key.encrypt_entry_category(item.typ.into())?,
            name: key.encrypt_entry_name(item.name.into())?,
            value,
            tags: key.encrypt_entry_tags(item.tags)?,
        };

        Ok(updated_indy_item)
    }

    pub async fn update_items(
        conn: &mut IndySdkToAriesAskarMigration,
        indy_key: &IndyKey,
        profile_key: &ProfileKey,
    ) -> Result<(), Error> {
        loop {
            let rows = conn.fetch_pending_items::<IndyRow>(1).await?;
            match rows {
                None => break,
                Some(rows) => {
                    let mut upd = vec![];
                    for row in rows {
                        let result = Self::decrypt_item(row, indy_key)?;
                        upd.push(Self::update_item(result, profile_key)?);
                    }
                    conn.update_items_in_db(upd).await?;
                }
            }
        }

        Ok(())
    }
}
