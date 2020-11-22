use std::collections::{BTreeMap, HashMap};
use std::io::{stdout, Write};

use futures_lite::stream::StreamExt;
use indy_utils::base58;
use itertools::Itertools;
use serde::Serialize;
use sqlx::{sqlite::SqliteRow as DbRow, Row, SqlitePool as DbPool};

use super::{
    error::Result,
    keys::kdf::argon2::Level,
    keys::store::{decrypt, EncKey, HmacKey, StoreKey},
    types::{Entry, EntryTag},
};

const CHUNK_SIZE: usize = 20;

#[derive(Debug, Serialize)]
struct PrintEntry {
    category: String,
    name: String,
    value: String,
    tags: HashMap<String, String>,
}

impl PrintEntry {
    pub fn new(entry: Entry) -> Self {
        let value = String::from_utf8(entry.value.to_vec()).expect("Error parsing value as utf-8");
        let mut tags = HashMap::new();
        if let Some(entry_tags) = entry.tags {
            for tag in entry_tags {
                match tag {
                    EntryTag::Encrypted(name, value) => {
                        tags.insert(name, value);
                    }
                    EntryTag::Plaintext(name, value) => {
                        tags.insert(format!("~{}", name), value);
                    }
                }
            }
        }
        Self {
            category: entry.category,
            name: entry.name,
            value,
            tags,
        }
    }
}

// test method for dumping the contents of the wallet
pub async fn print_records<'a>(path: &str, password: &str) -> Result<()> {
    let pool = DbPool::connect(path).await?;

    let wallet_key = {
        let metadata = sqlx::query("SELECT value from metadata")
            .fetch_one(&pool)
            .await?;
        let enc_key = metadata.try_get(0)?;
        decode_wallet_key(enc_key, &password)?
    };

    let tag_q = format!(
        "SELECT * FROM (SELECT 1 as encrypted, item_id, name, value FROM tags_encrypted
            UNION SELECT 0 as encrypted, item_id, name, value FROM tags_plaintext)
            WHERE item_id IN ({})",
        std::iter::repeat("?")
            .take(CHUNK_SIZE)
            .intersperse(", ")
            .collect::<String>()
    );

    let mut rows = sqlx::query("SELECT id, type, name, value, key FROM items").fetch(&pool);
    let mut done = false;
    let mut chunk = Vec::with_capacity(CHUNK_SIZE);
    let mut ids = Vec::with_capacity(CHUNK_SIZE);
    let mut writer = stdout();

    while !done {
        chunk.clear();
        ids.clear();
        let mut tag_query = sqlx::query(&tag_q);
        for idx in 0..CHUNK_SIZE {
            if let Some(enc_row) = rows.next().await {
                let (row_id, row) = decode_row(&wallet_key, enc_row?)?;
                chunk.push(row);
                ids.push(row_id);
                tag_query = tag_query.bind(row_id);
            } else {
                for _ in idx..CHUNK_SIZE {
                    tag_query = tag_query.bind(0);
                }
                done = true;
                break;
            }
        }

        let mut tags = collect_tags(&wallet_key, tag_query.fetch_all(&pool).await?)?;
        for (idx, id) in ids.iter().enumerate() {
            chunk[idx].tags = tags.remove(id);
        }
        for entry in chunk.drain(..) {
            serde_json::to_writer_pretty(&writer, &PrintEntry::new(entry)).unwrap();
            writer.write(b"\n").unwrap();
        }
    }
    drop(rows);

    pool.close().await;
    Ok(())
}

#[inline]
fn get_slice<'a>(row: &'a DbRow, index: usize) -> Result<&'a [u8]> {
    row.try_get(index)
        .map_err(err_map!(Unexpected, "Error fetching column"))
}

fn decode_row(key: &StoreKey, row: DbRow) -> Result<(i64, Entry)> {
    let value_key_enc = get_slice(&row, 4)?;
    let value_key = EncKey::from_slice(decrypt(&key.value_key, value_key_enc)?);
    let value = decrypt(&value_key, get_slice(&row, 3)?)?;

    let entry = Entry::new(
        decode_utf8(key.decrypt_category(get_slice(&row, 1)?)?)?,
        decode_utf8(key.decrypt_name(get_slice(&row, 2)?)?)?,
        value,
        None,
    );
    Ok((row.try_get(0)?, entry))
}

fn collect_tags(key: &StoreKey, tags: Vec<DbRow>) -> Result<BTreeMap<i64, Vec<EntryTag>>> {
    let mut result = BTreeMap::new();
    for row in tags {
        let entry = result.entry(row.try_get(1)?).or_insert_with(Vec::new);
        let name = decode_utf8(key.decrypt_tag_name(get_slice(&row, 2)?)?)?;
        if row.try_get(0)? {
            // encrypted value
            let value = decode_utf8(key.decrypt_tag_value(get_slice(&row, 3)?)?)?;
            entry.push(EntryTag::Encrypted(name, value))
        } else {
            let value = decode_utf8(get_slice(&row, 3)?.to_vec())?;
            entry.push(EntryTag::Plaintext(name, value));
        };
    }
    Ok(result)
}

#[derive(Deserialize, Debug)]
struct EncStorageKey {
    keys: Vec<u8>,
    master_key_salt: Vec<u8>,
}

pub fn decode_wallet_key(enc_key: &[u8], password: &str) -> Result<StoreKey> {
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

fn decrypt_key(key: EncStorageKey, password: &str) -> Result<Vec<u8>> {
    // check for a raw key in base58 format
    if let Ok(raw_key) = base58::decode(password) {
        if raw_key.len() == 32 {
            let master_key = EncKey::from_slice(&raw_key);
            return Ok(decrypt(&master_key, key.keys.as_slice())?);
        }
    }

    let salt = &key.master_key_salt[..16];

    // derive key with libsodium 'moderate' settings
    let master_key = Level::Moderate.derive_key(salt, password)?;
    if let Ok(keys) = decrypt(&master_key, key.keys.as_slice()) {
        Ok(keys)
    } else {
        // derive key with libsodium 'interactive' settings
        let master_key = Level::Interactive.derive_key(salt, password)?;
        Ok(decrypt(&master_key, key.keys.as_slice())?)
    }
}

#[inline]
fn decode_utf8(value: Vec<u8>) -> Result<String> {
    String::from_utf8(value).map_err(err_map!(Encryption))
}
