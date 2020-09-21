use std::collections::BTreeMap;

use futures_lite::stream::StreamExt;

use itertools::Itertools;

use sqlx::{sqlite::SqliteRow as DbRow, Row, SqlitePool as DbPool};

use super::{types::EntryTag, Entry, Result as KvResult};
use crate::keys::store::{decode_utf8, decode_wallet_key, decrypt, EncKey, StoreKey};

const CHUNK_SIZE: usize = 20;

// test method for dumping the contents of the wallet
pub async fn print_records<'a>(path: &str, password: &str) -> KvResult<()> {
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
        println!("{:#?}", chunk);
    }
    drop(rows);

    pool.close().await;
    Ok(())
}

#[inline]
fn get_slice<'a>(row: &'a DbRow, index: usize) -> Result<&'a [u8], sqlx::Error> {
    row.try_get(index)
}

fn decode_row(key: &StoreKey, row: DbRow) -> KvResult<(i64, Entry)> {
    let value_key_enc = get_slice(&row, 4)?;
    let value_key = EncKey::from_slice(decrypt(&key.value_key, value_key_enc)?);
    let value = decrypt(&value_key, get_slice(&row, 3)?)?;

    let entry = Entry {
        category: decode_utf8(key.decrypt_category(get_slice(&row, 1)?)?)?,
        name: decode_utf8(key.decrypt_name(get_slice(&row, 2)?)?)?,
        value,
        tags: None,
    };
    Ok((row.try_get(0)?, entry))
}

fn collect_tags(key: &StoreKey, tags: Vec<DbRow>) -> KvResult<BTreeMap<i64, Vec<EntryTag>>> {
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
