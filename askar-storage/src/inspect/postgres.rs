//! Read-only access to PostgreSQL storage rows without expiry or kind filtering.

use std::str::FromStr;

use sqlx::{postgres::PgConnectOptions, Connection, PgConnection, Row};

use super::{RawItem, RawProfile, RawTag};
use crate::{backend::postgres::PostgresStoreOptions, Error};

/// Open a Postgres store in a read-only, repeatable-read transaction.
pub async fn open(uri: &str) -> Result<PgConnection, Error> {
    let options = PostgresStoreOptions::new(uri)?;
    let mut connect = PgConnectOptions::from_str(&options.uri)
        .map_err(err_map!(Input, "Invalid Postgres URI"))?
        .options([("default_transaction_read_only", "on")]);
    if let Some(schema) = &options.schema {
        connect = connect.options([("search_path", schema.as_str())]);
    }
    let mut connection = PgConnection::connect_with(&connect)
        .await
        .map_err(err_map!(Backend, "Error opening Postgres store"))?;
    sqlx::query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut connection)
        .await
        .map_err(err_map!(Backend, "Error starting inspection snapshot"))?;
    Ok(connection)
}

/// Read the wrapping-key reference recorded in the database.
pub async fn key_reference(connection: &mut PgConnection) -> Result<String, Error> {
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
pub async fn profiles(connection: &mut PgConnection) -> Result<Vec<RawProfile>, Error> {
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
    connection: &mut PgConnection,
    profile_id: i64,
    after_id: i64,
    limit: i64,
) -> Result<Vec<RawItem>, Error> {
    if limit <= 0 {
        return Err(err_msg!(Input, "Page size must be positive"));
    }
    let rows = sqlx::query(
        "SELECT id, kind, category, name, value, expiry FROM items
         WHERE profile_id = $1 AND id > $2 ORDER BY id LIMIT $3",
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
            let kind: i16 = row.try_get("kind").map_err(err_map!(Backend))?;
            Ok(RawItem {
                id: row.try_get("id").map_err(err_map!(Backend))?,
                kind: i64::from(kind),
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
             WHERE i.profile_id = $1 AND i.id > $2 AND i.id <= $3 ORDER BY it.item_id, it.id",
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
            let plaintext: i16 = row.try_get("plaintext").map_err(err_map!(Backend))?;
            items[position].tags.push(RawTag {
                name: row.try_get("name").map_err(err_map!(Backend))?,
                value: row.try_get("value").map_err(err_map!(Backend))?,
                plaintext: plaintext != 0,
            });
        }
    }
    Ok(items)
}
