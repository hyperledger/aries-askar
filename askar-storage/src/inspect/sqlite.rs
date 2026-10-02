//! Read-only access to SQLite storage rows without expiry or kind filtering.

use std::str::FromStr;

use sqlx::{sqlite::SqliteConnectOptions, Connection, Row, SqliteConnection};

use super::{RawItem, RawProfile, RawTag};
use crate::{backend::sqlite::SqliteStoreOptions, Error};

/// Open a SQLite store read-only in a snapshot transaction.
pub async fn open(uri: &str) -> Result<SqliteConnection, Error> {
    let options = SqliteStoreOptions::new(uri)?;
    let connect = SqliteConnectOptions::from_str(&options.path)
        .map_err(err_map!(Input, "Invalid SQLite path"))?
        .read_only(true);
    let mut connection = SqliteConnection::connect_with(&connect)
        .await
        .map_err(err_map!(Backend, "Error opening SQLite store"))?;
    sqlx::query("BEGIN")
        .execute(&mut connection)
        .await
        .map_err(err_map!(Backend, "Error starting inspection snapshot"))?;
    Ok(connection)
}

/// Read the wrapping-key reference recorded in the database.
pub async fn key_reference(connection: &mut SqliteConnection) -> Result<String, Error> {
    let version: String = sqlx::query_scalar("SELECT value FROM config WHERE name = 'version'")
        .fetch_one(&mut *connection)
        .await
        .map_err(err_map!(Backend, "Error reading store version"))?;
    if version != "1" {
        return Err(err_msg!(Unsupported, "Unsupported store version"));
    }
    sqlx::query_scalar("SELECT value FROM config WHERE name = 'key'")
        .fetch_one(connection)
        .await
        .map_err(err_map!(Backend, "Error reading store key reference"))
}

/// List profiles without attempting to decrypt their keys.
pub async fn profiles(connection: &mut SqliteConnection) -> Result<Vec<RawProfile>, Error> {
    let rows = sqlx::query("SELECT id, name, profile_key FROM profiles ORDER BY id")
        .fetch_all(connection)
        .await
        .map_err(err_map!(Backend, "Error reading profiles"))?;
    rows.into_iter()
        .map(|row| {
            Ok(RawProfile {
                id: row.try_get("id").map_err(err_map!(Backend))?,
                name: row.try_get("name").map_err(err_map!(Backend))?,
                profile_key: row.try_get("profile_key").map_err(err_map!(Backend))?,
            })
        })
        .collect()
}

/// Fetch the next page of rows and their tags, including expired and KMS rows.
pub async fn page(
    connection: &mut SqliteConnection,
    profile_id: i64,
    after_id: i64,
    limit: i64,
) -> Result<Vec<RawItem>, Error> {
    if limit <= 0 {
        return Err(err_msg!(Input, "Page size must be positive"));
    }
    let rows = sqlx::query(
        "SELECT id, kind, category, name, value, expiry FROM items
         WHERE profile_id = ? AND id > ? ORDER BY id LIMIT ?",
    )
    .bind(profile_id)
    .bind(after_id)
    .bind(limit)
    .fetch_all(&mut *connection)
    .await
    .map_err(err_map!(Backend, "Error reading items"))?;
    let mut items: Vec<RawItem> = rows
        .into_iter()
        .map(|row| {
            Ok(RawItem {
                id: row.try_get("id").map_err(err_map!(Backend))?,
                kind: row.try_get("kind").map_err(err_map!(Backend))?,
                category: row.try_get("category").map_err(err_map!(Backend))?,
                name: row.try_get("name").map_err(err_map!(Backend))?,
                value: row.try_get("value").map_err(err_map!(Backend))?,
                expiry: row.try_get("expiry").map_err(err_map!(Backend))?,
                tags: Vec::new(),
            })
        })
        .collect::<Result<_, Error>>()?;
    if let Some(last_id) = items.last().map(|item| item.id) {
        let tags = sqlx::query(
            "SELECT it.item_id, it.name, it.value, it.plaintext FROM items_tags it
             JOIN items i ON i.id = it.item_id
             WHERE i.profile_id = ? AND i.id > ? AND i.id <= ? ORDER BY it.item_id, it.id",
        )
        .bind(profile_id)
        .bind(after_id)
        .bind(last_id)
        .fetch_all(connection)
        .await
        .map_err(err_map!(Backend, "Error reading item tags"))?;
        for row in tags {
            let item_id: i64 = row.try_get("item_id").map_err(err_map!(Backend))?;
            let position = items
                .binary_search_by_key(&item_id, |item| item.id)
                .map_err(|_| err_msg!(Backend, "Tag has no item in inspection page"))?;
            items[position].tags.push(RawTag {
                name: row.try_get("name").map_err(err_map!(Backend))?,
                value: row.try_get("value").map_err(err_map!(Backend))?,
                plaintext: row.try_get("plaintext").map_err(err_map!(Backend))?,
            });
        }
    }
    Ok(items)
}
