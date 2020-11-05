use std::fmt::{self, Debug, Formatter};

use async_stream::try_stream;
use futures_lite::stream::StreamExt;

use sqlx::{
    pool::PoolConnection,
    sqlite::{Sqlite, SqlitePool},
    Acquire, Done, Executor, Row, Transaction,
};

use super::db_utils::{
    decode_tags, encode_tag_filter, expiry_timestamp, extend_query, CloseDbSession, DbSession,
    DbSessionRef, QueryParams, QueryPrepare, PAGE_SIZE,
};
use super::error::Result;
use super::future::BoxFuture;
use super::keys::{store::StoreKey, AsyncEncryptor};
use super::store::{Backend, KeyCache, QueryBackend, Scan};
use super::types::{EncEntryTag, Entry, EntryKind, EntryOperation, EntryTag, ProfileId};
use super::wql;

mod provision;
pub use provision::SqliteStoreOptions;

const COUNT_QUERY: &'static str = "SELECT COUNT(*) FROM items i
    WHERE profile_id = ?1 AND kind = ?2 AND category = ?3
    AND (expiry IS NULL OR expiry > DATETIME('now'))";
const DELETE_QUERY: &'static str = "DELETE FROM items
    WHERE profile_id = ?1 AND kind = ?2 AND category = ?3 AND name = ?4";
const FETCH_QUERY: &'static str = "SELECT i.id, i.value,
    (SELECT GROUP_CONCAT(it.plaintext || ':' || HEX(it.name) || ':' || HEX(it.value))
        FROM items_tags it WHERE it.item_id = i.id) AS tags
    FROM items i WHERE i.profile_id = ?1 AND i.kind = ?2
    AND i.category = ?3 AND i.name = ?4
    AND (i.expiry IS NULL OR i.expiry > DATETIME('now'))";
const INSERT_QUERY: &'static str =
    "INSERT OR IGNORE INTO items (profile_id, kind, category, name, value, expiry)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6)";
const SCAN_QUERY: &'static str = "SELECT i.id, i.name, i.value,
    (SELECT GROUP_CONCAT(it.plaintext || ':' || HEX(it.name) || ':' || HEX(it.value))
        FROM items_tags it WHERE it.item_id = i.id) AS tags
    FROM items i WHERE i.profile_id = ?1 AND i.kind = ?2 AND i.category = ?3
    AND (i.expiry IS NULL OR i.expiry > DATETIME('now'))";
const TAG_INSERT_QUERY: &'static str = "INSERT INTO items_tags
    (item_id, name, value, plaintext) VALUES (?1, ?2, ?3, ?4)";

pub struct SqliteStore {
    conn_pool: SqlitePool,
    default_profile: String,
    key_cache: KeyCache,
    uri: String,
}

impl SqliteStore {
    pub(crate) fn new(
        conn_pool: SqlitePool,
        default_profile: String,
        key_cache: KeyCache,
        uri: String,
    ) -> Self {
        Self {
            conn_pool,
            default_profile,
            key_cache,
            uri,
        }
    }

    async fn get_profile_key<'e, E: Executor<'e, Database = Sqlite>>(
        &self,
        exec: E,
        name: Option<String>,
    ) -> Result<(ProfileId, AsyncEncryptor<StoreKey>)> {
        if let Some((pid, key)) = self.key_cache.get_profile(
            name.as_ref()
                .map(String::as_str)
                .unwrap_or(self.default_profile.as_str()),
        ) {
            Ok((pid, AsyncEncryptor(Some(key))))
        } else {
            // FIXME fetch from database
            unimplemented!()
        }
    }
}

impl Debug for SqliteStore {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteStore")
            .field("default_profile", &self.default_profile)
            .field("uri", &self.uri)
            .finish()
    }
}

impl QueryPrepare for SqliteStore {
    type DB = Sqlite;
}

impl Backend for SqliteStore {
    type Session = DbSession<'static, PoolConnection<Sqlite>, Sqlite>;
    type Transaction = DbSession<'static, Transaction<'static, Sqlite>, Sqlite>;

    fn scan(
        &self,
        profile: Option<String>,
        kind: EntryKind,
        category: String,
        tag_filter: Option<wql::Query>,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> BoxFuture<Result<Scan<'static, Entry>>> {
        Box::pin(async move {
            let mut conn = self.conn_pool.acquire().await?;
            let (profile_id, key) = self.get_profile_key(&mut conn, profile).await?;
            let active = DbSessionRef::Owned(DbSession::new(conn, false, profile_id, key));
            perform_scan(active, kind, category, tag_filter, offset, limit).await
        })
    }

    fn session(&self, profile: Option<String>) -> BoxFuture<Result<Self::Session>> {
        Box::pin(async move {
            let mut conn = self.conn_pool.acquire().await?;
            let (profile_id, key) = self.get_profile_key(&mut conn, profile).await?;
            Ok(DbSession::new(conn, false, profile_id, key))
        })
    }

    fn transaction(&self, profile: Option<String>) -> BoxFuture<Result<Self::Transaction>> {
        Box::pin(async move {
            let mut txn = self.conn_pool.begin().await?;
            let (profile_id, key) = self.get_profile_key(&mut txn, profile).await?;
            Ok(DbSession::new(txn, true, profile_id, key))
        })
    }

    fn close(&self) -> BoxFuture<Result<()>> {
        Box::pin(async move {
            self.conn_pool.close().await;
            Ok(())
        })
    }
}

impl<E> QueryBackend for DbSession<'static, E, Sqlite>
where
    E: CloseDbSession + Send,
    for<'e> &'e mut E: Executor<'e, Database = Sqlite> + Acquire<'e, Database = Sqlite>,
{
    fn count<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        tag_filter: Option<wql::Query>,
    ) -> BoxFuture<'q, Result<i64>> {
        Box::pin(async move {
            let category = self.key.encrypt_entry_category(category).await?;
            let mut params = QueryParams::new();
            params.push(self.profile_id);
            params.push(kind as i16);
            params.push(category);
            let tag_filter =
                encode_tag_filter::<SqliteStore>(tag_filter, self.key.0.clone(), params.len())
                    .await?;
            let query =
                extend_query::<SqliteStore>(COUNT_QUERY, &mut params, tag_filter, None, None)?;
            let count = sqlx::query_scalar_with(query.as_str(), params)
                .fetch_one(&mut self.exec)
                .await?;
            Ok(count)
        })
    }

    fn fetch(
        &mut self,
        kind: EntryKind,
        category: &str,
        name: &str,
    ) -> BoxFuture<Result<Option<Entry>>> {
        let raw_category = category.to_string();
        let raw_name = name.to_string();

        Box::pin(async move {
            let (category, name) = self
                .key
                .encrypt_entry_category_name(&raw_category, &raw_name)
                .await?;
            if let Some(row) = sqlx::query(FETCH_QUERY)
                .bind(self.profile_id)
                .bind(kind as i16)
                .bind(&category)
                .bind(&name)
                .fetch_optional(&mut self.exec)
                .await?
            {
                let value = self.key.decrypt_entry_value(row.try_get(1)?).await?;
                let enc_tags =
                    decode_tags(row.try_get(2)?).map_err(|_| err_msg!("Error decoding tags"))?;
                let tags = Some(self.key.decrypt_entry_tags(&enc_tags).await?);

                Ok(Some(Entry {
                    category: raw_category,
                    name: raw_name,
                    value,
                    tags,
                }))
            } else {
                Ok(None)
            }
        })
    }

    fn fetch_all<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        tag_filter: Option<wql::Query>,
        limit: Option<i64>,
    ) -> BoxFuture<'q, Result<Vec<Entry>>> {
        let category = category.to_string();
        Box::pin(async move {
            let active = DbSessionRef::Borrowed(self);
            let mut scan = perform_scan(active, kind, category, tag_filter, None, limit).await?;
            let mut results = vec![];
            loop {
                if let Some(rows) = scan.fetch_next().await? {
                    results.extend(rows);
                } else {
                    break;
                }
            }
            Ok(results)
        })
    }

    fn update<'q>(
        &'q mut self,
        kind: EntryKind,
        operation: EntryOperation,
        category: &'q str,
        name: &'q str,
        value: Option<&'q [u8]>,
        tags: Option<&'q [EntryTag]>,
        expiry_ms: Option<i64>,
    ) -> BoxFuture<'q, Result<()>> {
        Box::pin(async move {
            let (enc_category, enc_name) =
                self.key.encrypt_entry_category_name(category, name).await?;

            match operation {
                EntryOperation::Insert => {
                    let (enc_value, enc_tags) = self
                        .key
                        .encrypt_entry_value_tags(value.unwrap(), tags)
                        .await?;
                    //let mut txn = self.transaction().await?;
                    perform_insert(
                        DbSessionRef::Borrowed(&mut *self),
                        kind,
                        &enc_category,
                        &enc_name,
                        &enc_value,
                        enc_tags,
                        expiry_ms,
                    )
                    .await?;
                    //txn.exec.commit().await?;
                    Ok(())
                }

                EntryOperation::Replace => {
                    let (enc_value, enc_tags) = self
                        .key
                        .encrypt_entry_value_tags(value.unwrap(), tags)
                        .await?;
                    perform_remove(
                        DbSessionRef::Borrowed(&mut *self),
                        kind,
                        &enc_category,
                        &enc_name,
                        false,
                    )
                    .await?;
                    Ok(perform_insert(
                        DbSessionRef::Borrowed(&mut *self),
                        kind,
                        &enc_category,
                        &enc_name,
                        &enc_value,
                        enc_tags,
                        expiry_ms,
                    )
                    .await?)
                }

                EntryOperation::Remove => Ok(perform_remove(
                    DbSessionRef::Borrowed(&mut *self),
                    kind,
                    &enc_category,
                    &enc_name,
                    false,
                )
                .await?),
            }
        })
    }

    fn close(self, commit: bool) -> BoxFuture<'static, Result<()>> {
        self.exec.close(commit)
    }
}

async fn perform_insert<'q, 's, E>(
    mut active: DbSessionRef<'q, 's, E, Sqlite>,
    kind: EntryKind,
    enc_category: &[u8],
    enc_name: &[u8],
    enc_value: &[u8],
    enc_tags: Option<Vec<EncEntryTag>>,
    expiry_ms: Option<i64>,
) -> Result<()>
where
    for<'e> &'e mut E: Executor<'e, Database = Sqlite>,
{
    trace!("Insert entry");
    let done = sqlx::query(INSERT_QUERY)
        .bind(active.profile_id)
        .bind(kind as i16)
        .bind(enc_category)
        .bind(enc_name)
        .bind(enc_value)
        .bind(expiry_ms.map(expiry_timestamp).transpose()?)
        .execute(&mut active.exec)
        .await?;
    if done.rows_affected() == 0 {
        return Err(err_msg!(Duplicate, "Duplicate row"));
    }
    let row_id = done.last_insert_rowid();
    if let Some(tags) = enc_tags {
        for tag in tags {
            sqlx::query(TAG_INSERT_QUERY)
                .bind(row_id)
                .bind(&tag.name)
                .bind(&tag.value)
                .bind(tag.plaintext as i16)
                .execute(&mut active.exec)
                .await?;
        }
    }
    Ok(())
}

async fn perform_remove<'q, 's, E>(
    mut active: DbSessionRef<'q, 's, E, Sqlite>,
    kind: EntryKind,
    enc_category: &[u8],
    enc_name: &[u8],
    ignore_error: bool,
) -> Result<()>
where
    for<'e> &'e mut E: Executor<'e, Database = Sqlite>,
{
    trace!("Remove entry");
    let done = sqlx::query(DELETE_QUERY)
        .bind(active.profile_id)
        .bind(kind as i16)
        .bind(enc_category)
        .bind(enc_name)
        .execute(&mut active.exec)
        .await?;
    if done.rows_affected() == 0 && !ignore_error {
        Err(err_msg!(NotFound, "Entry not found"))
    } else {
        Ok(())
    }
}

async fn perform_scan<'q, 's, E>(
    mut active: DbSessionRef<'q, 's, E, Sqlite>,
    kind: EntryKind,
    category: String,
    tag_filter: Option<wql::Query>,
    offset: Option<i64>,
    limit: Option<i64>,
) -> Result<Scan<'q, Entry>>
where
    E: Send,
    for<'e> &'e mut E: Executor<'e, Database = Sqlite>,
{
    let raw_category = category;
    let category = active.key.encrypt_entry_category(&raw_category).await?;

    let scan = try_stream! {
        let mut params = QueryParams::new();
        params.push(active.profile_id);
        params.push(kind as i16);
        params.push(category.clone());
        let tag_filter = encode_tag_filter::<SqliteStore>(tag_filter, active.key.0.clone(), params.len()).await?;
        let query = extend_query::<SqliteStore>(SCAN_QUERY, &mut params, tag_filter, offset, limit)?;
        let mut batch = Vec::<Entry>::with_capacity(PAGE_SIZE);
        let key = active.key.clone();

        let mut rows = sqlx::query_with(query.as_str(), params).fetch(&mut active.exec);
        while let Some(row) = rows.next().await {
            let row = row?;
            let (name, value) = key.decrypt_entry_name_value(row.try_get(1)?, row.try_get(2)?).await?;
            let enc_tags = decode_tags(row.try_get(3)?).map_err(|_| err_msg!("Error decoding tags"))?;
            let tags = Some(key.decrypt_entry_tags(&enc_tags).await?);
            batch.push(Entry {
                category: raw_category.clone(),
                name,
                value,
                tags
            });

            if batch.len() == PAGE_SIZE {
                yield batch.split_off(0);
            }
        }
        drop(rows);
        drop(active);

        if !batch.is_empty() {
            yield batch;
        }
    };
    Ok(Scan::new(scan, PAGE_SIZE))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db_utils::replace_arg_placeholders;
    use crate::future::block_on;
    use crate::store::{ProvisionStore, ProvisionStoreSpec};

    #[test]
    fn sqlite_check_expiry_timestamp() {
        block_on(async {
            let spec = ProvisionStoreSpec::create_default().await?;
            let db = SqliteStoreOptions::in_memory()
                .provision_store(spec)
                .await?;
            let ts = expiry_timestamp(1000).unwrap();
            let check = sqlx::query("SELECT datetime('now'), ?1, ?1 > datetime('now')")
                .bind(ts)
                .fetch_one(&db.inner().conn_pool)
                .await?;
            let now: String = check.try_get(0)?;
            let cmp_ts: String = check.try_get(1)?;
            let cmp: bool = check.try_get(2)?;
            if !cmp {
                panic!("now ({}) > expiry timestamp ({})", now, cmp_ts);
            }
            Result::Ok(())
        })
        .unwrap();
    }

    #[test]
    fn sqlite_query_placeholders() {
        assert_eq!(
            &replace_arg_placeholders::<SqliteStore>("This $$ is $10 a $$ string!", 3),
            "This ?3 is ?12 a ?5 string!",
        );
        assert_eq!(
            &replace_arg_placeholders::<SqliteStore>("This $a is a string!", 1),
            "This $a is a string!",
        );
    }
}
