use super::{
    IndyKey, IndySdkToAriesAskarMigration, ProfileKey, CHACHAPOLY_KEY_LEN, CHACHAPOLY_NONCE_LEN,
};
use crate::crypto::generic_array::typenum::U32;
use crate::protect::hmac_key::{HmacDerive, HmacKey};
use crate::Error;
use askar_crypto::alg::chacha20::{Chacha20Key, C20P};
use askar_crypto::buffer::SecretBytes;
use askar_crypto::encrypt::KeyAeadInPlace;
use askar_crypto::kdf::KeyDerivation;
use askar_crypto::repr::KeySecretBytes;
use rand::RngCore;
use sha2::Sha256;

pub type IndyTag = (u8, Vec<u8>, Vec<u8>);

#[derive(Default)]
pub(crate) struct IndyItem {
    id: u32,
    typ: Vec<u8>,
    name: Vec<u8>,
    value: Option<Vec<u8>>,
    tags: Vec<IndyTag>,
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

#[derive(Default)]
pub(crate) struct UpdatedIndyItem {
    pub(crate) id: u32,
    pub(crate) category: Vec<u8>,
    pub(crate) name: Vec<u8>,
    pub(crate) value: Vec<u8>,
    pub(crate) tags: Vec<IndyTag>,
}

pub(crate) struct Strategy {}

impl Strategy {
    pub fn encrypt_merged(
        message: &[u8],
        key: &Chacha20Key<C20P>,
        hmac_key: Option<&HmacKey<Sha256, U32>>,
    ) -> Result<Vec<u8>, Error> {
        let mut nonce = [0u8; CHACHAPOLY_NONCE_LEN as usize];
        match hmac_key {
            None => rand::thread_rng().fill_bytes(&mut nonce),
            Some(hmac_key) => {
                hmac_key
                    .hmac_deriver(&[message])
                    .derive_key_bytes(&mut nonce)?;
            }
        };

        let mut ciphertext = SecretBytes::from_slice(message);
        key.encrypt_in_place(&mut ciphertext, &nonce, &[])?;
        let mut res = vec![];
        res.append(&mut nonce.to_vec());
        res.append(&mut ciphertext.into_vec());
        Ok(res)
    }

    fn encrypt_value(
        category: Vec<u8>,
        name: Vec<u8>,
        value: Vec<u8>,
        hmac_key: &HmacKey<Sha256, U32>,
    ) -> Result<Vec<u8>, Error> {
        let hasher = hmac_key;
        // length of bytes might be incorrect
        let category_len = &category.len().to_be_bytes()[4..];
        let name_len = &name.len().to_be_bytes()[4..];

        let mut value_key = [0u8; CHACHAPOLY_KEY_LEN as usize];
        hasher
            .hmac_deriver(&[category_len, &category, name_len, &name])
            .derive_key_bytes(&mut value_key)?;

        let key = Chacha20Key::<C20P>::from_secret_bytes(&value_key)?;

        Self::encrypt_merged(&value, &key, None)
    }

    pub fn decrypt_merged(enc_value: &[u8], key: &Chacha20Key<C20P>) -> Result<Vec<u8>, Error> {
        let (nonce, ciphertext) = enc_value.split_at(CHACHAPOLY_NONCE_LEN.into());

        let mut buffer = SecretBytes::from_slice(ciphertext);

        key.decrypt_in_place(&mut buffer, nonce, &[])?;

        Ok(buffer.to_vec())
    }

    pub fn decrypt_tags(
        tags: &str,
        name_key: &Chacha20Key<C20P>,
        value_key: Option<&Chacha20Key<C20P>>,
    ) -> Result<Vec<(Vec<u8>, Vec<u8>)>, Error> {
        let mut ret: Vec<(Vec<u8>, Vec<u8>)> = vec![];
        for tag in tags.split(',') {
            let t = tag.split(':').collect::<Vec<&str>>();

            let tag_name =
                hex::decode(t[0]).map_err(err_map!(Input, "tag is not valid hex encoded"))?;
            let tag_value =
                hex::decode(t[1]).map_err(err_map!(Input, "tag is not valid hex encoded"))?;

            let name = Self::decrypt_merged(&tag_name, name_key)?;
            let value = match value_key {
                // TODO: what is tag[1] from python
                None => tag_value,
                Some(value_key) => Self::decrypt_merged(&tag_value, value_key)?,
            };
            ret.push((name, value));
        }
        Ok(ret)
    }

    pub fn decrypt_item(row: IndyRow, keys: &IndyKey) -> Result<IndyItem, Error> {
        let value_key = Self::decrypt_merged(&row.key, &keys.value_key)?;
        let value_key = Chacha20Key::<C20P>::from_secret_bytes(&value_key)?;
        let value = match row.value {
            Some(ref value) => Some(Self::decrypt_merged(value, &value_key)?),
            None => None,
        };
        let mut tags: Vec<IndyTag> = vec![];

        let resp = match row.tags_enc {
            None => vec![],
            Some(tags_enc) => Self::decrypt_tags(
                tags_enc.as_str(),
                &keys.tag_name_key,
                Some(&keys.tag_value_key),
            )?,
        };
        for (k, v) in resp {
            tags.push((0, k, v));
        }

        let resp_plain = match row.tags_plain {
            None => vec![],
            Some(tags_plain) => Self::decrypt_tags(tags_plain.as_str(), &keys.tag_name_key, None)?,
        };
        for (k, v) in resp_plain {
            tags.push((1, k, v));
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
        let mut tags: Vec<IndyTag> = vec![];

        for (plain, mut k, mut v) in item.tags {
            if plain != 0 {
                v = Self::encrypt_merged(&v, &key.tag_value_key, Some(&key.tags_hmac_key))?;
            }
            k = Self::encrypt_merged(&k, &key.tag_name_key, Some(&key.tags_hmac_key))?;
            tags.push((plain, k, v));
        }

        let updated_indy_item = UpdatedIndyItem {
            id: item.id,
            category: Self::encrypt_merged(
                item.typ.as_slice(),
                &key.category_key,
                Some(&key.item_hmac_key),
            )?
            .to_vec(),
            name: Self::encrypt_merged(
                item.name.as_slice(),
                &key.name_key,
                Some(&key.item_hmac_key),
            )?,
            value: Self::encrypt_value(
                item.typ,
                item.name,
                item.value.unwrap(),
                &key.item_hmac_key,
            )?,
            tags,
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
                        let result = Self::decrypt_item(row, &indy_key)?;
                        upd.push(Self::update_item(result, &profile_key)?);
                    }
                    conn.update_items_in_db(upd).await?;
                }
            }
        }

        Ok(())
    }
}
