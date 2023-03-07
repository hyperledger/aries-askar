use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use async_stream::try_stream;
use futures_lite::{
    pin,
    stream::{Stream, StreamExt},
};

use sqlx::{
    pool::PoolConnection,
    sqlite::{Sqlite, SqlitePool},
    Database, Error as SqlxError, Row, TransactionManager,
};

use crate::{
    backend::{
        db_utils::{
            decode_tags, decrypt_scan_batch, encode_profile_key, encode_tag_filter,
            expiry_timestamp, extend_query, prepare_tags, random_profile_name, DbSession,
            DbSessionActive, DbSessionRef, DbSessionTxn, EncScanEntry, ExtDatabase, QueryParams,
            QueryPrepare, PAGE_SIZE,
        },
        types::{Backend, QueryBackend},
    },
    error::Error,
    future::{unblock, BoxFuture},
    protect::{EntryEncryptor, KeyCache, PassKey, ProfileId, ProfileKey, StoreKeyMethod},
    storage::{EncEntryTag, Entry, EntryKind, EntryOperation, EntryTag, Scan, TagFilter},
};

mod provision;
pub use provision::SqliteStoreOptions;

const COUNT_QUERY: &str = "SELECT COUNT(*) FROM items i
    WHERE profile_id = ?1 AND kind = ?2 AND category = ?3
    AND (expiry IS NULL OR expiry > DATETIME('now'))";
const DELETE_QUERY: &str = "DELETE FROM items
    WHERE profile_id = ?1 AND kind = ?2 AND category = ?3 AND name = ?4";
const FETCH_QUERY: &str = "SELECT i.id, i.value,
    (SELECT GROUP_CONCAT(it.plaintext || ':' || HEX(it.name) || ':' || HEX(it.value))
        FROM items_tags it WHERE it.item_id = i.id) AS tags
    FROM items i WHERE i.profile_id = ?1 AND i.kind = ?2
    AND i.category = ?3 AND i.name = ?4
    AND (i.expiry IS NULL OR i.expiry > DATETIME('now'))";
const INSERT_QUERY: &str =
    "INSERT OR IGNORE INTO items (profile_id, kind, category, name, value, expiry)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6)";
const UPDATE_QUERY: &str = "UPDATE items SET value=?5, expiry=?6 WHERE profile_id=?1 AND kind=?2
    AND category=?3 AND name=?4 RETURNING id";
const SCAN_QUERY: &str = "SELECT i.id, i.name, i.value,
    (SELECT GROUP_CONCAT(it.plaintext || ':' || HEX(it.name) || ':' || HEX(it.value))
        FROM items_tags it WHERE it.item_id = i.id) AS tags
    FROM items i WHERE i.profile_id = ?1 AND i.kind = ?2 AND i.category = ?3
    AND (i.expiry IS NULL OR i.expiry > DATETIME('now'))";
const DELETE_ALL_QUERY: &str = "DELETE FROM items AS i
    WHERE i.profile_id = ?1 AND i.kind = ?2 AND i.category = ?3";
const TAG_INSERT_QUERY: &str = "INSERT INTO items_tags
    (item_id, name, value, plaintext) VALUES (?1, ?2, ?3, ?4)";
const TAG_DELETE_QUERY: &str = "DELETE FROM items_tags
    WHERE item_id=?1";

/// A Sqlite database store
pub struct SqliteStore {
    conn_pool: SqlitePool,
    default_profile: String,
    key_cache: Arc<KeyCache>,
    path: String,
}

impl SqliteStore {
    pub(crate) fn new(
        conn_pool: SqlitePool,
        default_profile: String,
        key_cache: KeyCache,
        path: String,
    ) -> Self {
        Self {
            conn_pool,
            default_profile,
            key_cache: Arc::new(key_cache),
            path,
        }
    }
}

impl Debug for SqliteStore {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteStore")
            .field("default_profile", &self.default_profile)
            .field("path", &self.path)
            .finish()
    }
}

impl QueryPrepare for SqliteStore {
    type DB = Sqlite;
}

impl Backend for SqliteStore {
    type Session = DbSession<Sqlite>;

    fn create_profile(&self, name: Option<String>) -> BoxFuture<'_, Result<String, Error>> {
        let name = name.unwrap_or_else(random_profile_name);
        Box::pin(async move {
            let store_key = self.key_cache.store_key.clone();
            let (profile_key, enc_key) = unblock(move || {
                let profile_key = ProfileKey::new()?;
                let enc_key = encode_profile_key(&profile_key, &store_key)?;
                Result::<_, Error>::Ok((profile_key, enc_key))
            })
            .await?;
            let mut conn = self.conn_pool.acquire().await?;
            let done =
                sqlx::query("INSERT OR IGNORE INTO profiles (name, profile_key) VALUES (?1, ?2)")
                    .bind(&name)
                    .bind(enc_key)
                    .execute(&mut conn)
                    .await?;
            if done.rows_affected() == 0 {
                return Err(err_msg!(Duplicate, "Duplicate profile name"));
            }
            self.key_cache
                .add_profile(
                    name.clone(),
                    done.last_insert_rowid(),
                    Arc::new(profile_key),
                )
                .await;
            Ok(name)
        })
    }

    fn get_profile_name(&self) -> &str {
        self.default_profile.as_str()
    }

    fn remove_profile(&self, name: String) -> BoxFuture<'_, Result<bool, Error>> {
        Box::pin(async move {
            let mut conn = self.conn_pool.acquire().await?;
            Ok(sqlx::query("DELETE FROM profiles WHERE name=?")
                .bind(&name)
                .execute(&mut conn)
                .await?
                .rows_affected()
                != 0)
        })
    }

    fn rekey_backend(
        &mut self,
        method: StoreKeyMethod,
        pass_key: PassKey<'_>,
    ) -> BoxFuture<'_, Result<(), Error>> {
        let pass_key = pass_key.into_owned();
        Box::pin(async move {
            let (store_key, store_key_ref) = unblock(move || method.resolve(pass_key)).await?;
            let store_key = Arc::new(store_key);
            let mut txn = self.conn_pool.begin().await?;
            let mut rows = sqlx::query("SELECT id, profile_key FROM profiles").fetch(&mut txn);
            let mut upd_keys = BTreeMap::<ProfileId, Vec<u8>>::new();
            while let Some(row) = rows.next().await {
                let row = row?;
                let pid = row.try_get(0)?;
                let enc_key = row.try_get(1)?;
                let profile_key = self.key_cache.load_key(enc_key).await?;
                let upd_key = unblock({
                    let store_key = store_key.clone();
                    move || encode_profile_key(&profile_key, &store_key)
                })
                .await?;
                upd_keys.insert(pid, upd_key);
            }
            drop(rows);
            for (pid, key) in upd_keys {
                if sqlx::query("UPDATE profiles SET profile_key=?1 WHERE id=?2")
                    .bind(key)
                    .bind(pid)
                    .execute(&mut txn)
                    .await?
                    .rows_affected()
                    != 1
                {
                    return Err(err_msg!(Backend, "Error updating profile key"));
                }
            }
            if sqlx::query("UPDATE config SET value=?1 WHERE name='key'")
                .bind(store_key_ref.into_uri())
                .execute(&mut txn)
                .await?
                .rows_affected()
                != 1
            {
                return Err(err_msg!(Backend, "Error updating store key"));
            }
            txn.commit().await?;
            self.key_cache = Arc::new(KeyCache::new(store_key));
            Ok(())
        })
    }

    fn scan(
        &self,
        profile: Option<String>,
        kind: EntryKind,
        category: String,
        tag_filter: Option<TagFilter>,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> BoxFuture<'_, Result<Scan<'static, Entry>, Error>> {
        Box::pin(async move {
            let session = self.session(profile, false)?;
            let mut active = session.owned_ref();
            let (profile_id, key) = acquire_key(&mut *active).await?;
            let scan = perform_scan(
                active,
                profile_id,
                key.clone(),
                kind,
                category.clone(),
                tag_filter,
                offset,
                limit,
            );
            let stream = scan.then(move |enc_rows| {
                let category = category.clone();
                let key = key.clone();
                unblock(move || decrypt_scan_batch(category, enc_rows?, &key))
            });
            Ok(Scan::new(stream, PAGE_SIZE))
        })
    }

    fn session(&self, profile: Option<String>, transaction: bool) -> Result<Self::Session, Error> {
        Ok(DbSession::new(
            self.conn_pool.clone(),
            self.key_cache.clone(),
            profile.unwrap_or_else(|| self.default_profile.clone()),
            transaction,
        ))
    }

    fn close(&self) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            self.conn_pool.close().await;
            Ok(())
        })
    }
}

impl QueryBackend for DbSession<Sqlite> {
    fn count<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        tag_filter: Option<TagFilter>,
    ) -> BoxFuture<'q, Result<i64, Error>> {
        let category = ProfileKey::prepare_input(category.as_bytes());

        Box::pin(async move {
            let (profile_id, key) = acquire_key(&mut *self).await?;
            let mut params = QueryParams::new();
            params.push(profile_id);
            params.push(kind as i16);
            let (enc_category, tag_filter) = unblock({
                let params_len = params.len() + 1; // plus category
                move || {
                    Result::<_, Error>::Ok((
                        key.encrypt_entry_category(category)?,
                        encode_tag_filter::<SqliteStore>(tag_filter, &key, params_len)?,
                    ))
                }
            })
            .await?;
            params.push(enc_category);
            let query =
                extend_query::<SqliteStore>(COUNT_QUERY, &mut params, tag_filter, None, None)?;
            let mut active = acquire_session(&mut *self).await?;
            let count = sqlx::query_scalar_with(query.as_str(), params)
                .fetch_one(active.connection_mut())
                .await?;
            Ok(count)
        })
    }

    fn fetch(
        &mut self,
        kind: EntryKind,
        category: &str,
        name: &str,
        _for_update: bool,
    ) -> BoxFuture<'_, Result<Option<Entry>, Error>> {
        let category = category.to_string();
        let name = name.to_string();

        Box::pin(async move {
            let (profile_id, key) = acquire_key(&mut *self).await?;
            let (enc_category, enc_name) = unblock({
                let key = key.clone();
                let category = ProfileKey::prepare_input(category.as_bytes());
                let name = ProfileKey::prepare_input(name.as_bytes());
                move || {
                    Result::<_, Error>::Ok((
                        key.encrypt_entry_category(category)?,
                        key.encrypt_entry_name(name)?,
                    ))
                }
            })
            .await?;
            let mut active = acquire_session(&mut *self).await?;
            if let Some(row) = sqlx::query(FETCH_QUERY)
                .bind(profile_id)
                .bind(kind as i16)
                .bind(enc_category)
                .bind(enc_name)
                .fetch_optional(active.connection_mut())
                .await?
            {
                let value = row.try_get(1)?;
                let tags = row.try_get(2)?;
                let (category, name, value, tags) = unblock(move || {
                    let value = key.decrypt_entry_value(category.as_ref(), name.as_ref(), value)?;
                    let enc_tags = decode_tags(tags)
                        .map_err(|_| err_msg!(Unexpected, "Error decoding entry tags"))?;
                    let tags = key.decrypt_entry_tags(enc_tags)?;
                    Result::<_, Error>::Ok((category, name, value, tags))
                })
                .await?;
                Ok(Some(Entry::new(category, name, value, tags)))
            } else {
                Ok(None)
            }
        })
    }

    fn fetch_all<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        tag_filter: Option<TagFilter>,
        limit: Option<i64>,
        _for_update: bool,
    ) -> BoxFuture<'q, Result<Vec<Entry>, Error>> {
        let category = category.to_string();
        Box::pin(async move {
            let mut active = self.borrow_mut();
            let (profile_id, key) = acquire_key(&mut *active).await?;
            let scan = perform_scan(
                active,
                profile_id,
                key.clone(),
                kind,
                category.clone(),
                tag_filter,
                None,
                limit,
            );
            pin!(scan);
            let mut enc_rows = vec![];
            while let Some(rows) = scan.try_next().await? {
                enc_rows.extend(rows)
            }
            unblock(move || decrypt_scan_batch(category, enc_rows, &key)).await
        })
    }

    fn remove_all<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        tag_filter: Option<TagFilter>,
    ) -> BoxFuture<'q, Result<i64, Error>> {
        let category = ProfileKey::prepare_input(category.as_bytes());

        Box::pin(async move {
            let (profile_id, key) = acquire_key(&mut *self).await?;
            let mut params = QueryParams::new();
            params.push(profile_id);
            params.push(kind as i16);
            let (enc_category, tag_filter) = unblock({
                let params_len = params.len() + 1; // plus category
                move || {
                    Result::<_, Error>::Ok((
                        key.encrypt_entry_category(category)?,
                        encode_tag_filter::<SqliteStore>(tag_filter, &key, params_len)?,
                    ))
                }
            })
            .await?;
            params.push(enc_category);
            let query =
                extend_query::<SqliteStore>(DELETE_ALL_QUERY, &mut params, tag_filter, None, None)?;

            let mut active = acquire_session(&mut *self).await?;
            let removed = sqlx::query_with(query.as_str(), params)
                .execute(active.connection_mut())
                .await?
                .rows_affected();
            Ok(removed as i64)
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
    ) -> BoxFuture<'q, Result<(), Error>> {
        let category = ProfileKey::prepare_input(category.as_bytes());
        let name = ProfileKey::prepare_input(name.as_bytes());

        match operation {
            op @ EntryOperation::Insert | op @ EntryOperation::Replace => {
                let value = ProfileKey::prepare_input(value.unwrap());
                let tags = tags.map(prepare_tags);
                Box::pin(async move {
                    let (_, key) = acquire_key(&mut *self).await?;
                    let (enc_category, enc_name, enc_value, enc_tags) = unblock(move || {
                        let enc_value =
                            key.encrypt_entry_value(category.as_ref(), name.as_ref(), value)?;
                        Result::<_, Error>::Ok((
                            key.encrypt_entry_category(category)?,
                            key.encrypt_entry_name(name)?,
                            enc_value,
                            tags.transpose()?
                                .map(|t| key.encrypt_entry_tags(t))
                                .transpose()?,
                        ))
                    })
                    .await?;
                    let mut active = acquire_session(&mut *self).await?;
                    let mut txn = active.as_transaction().await?;
                    perform_insert(
                        &mut txn,
                        kind,
                        &enc_category,
                        &enc_name,
                        &enc_value,
                        enc_tags,
                        expiry_ms,
                        op == EntryOperation::Insert,
                    )
                    .await?;
                    txn.commit().await?;
                    Ok(())
                })
            }

            EntryOperation::Remove => Box::pin(async move {
                let (_, key) = acquire_key(&mut *self).await?;
                let (enc_category, enc_name) = unblock(move || {
                    Result::<_, Error>::Ok((
                        key.encrypt_entry_category(category)?,
                        key.encrypt_entry_name(name)?,
                    ))
                })
                .await?;
                let mut active = acquire_session(&mut *self).await?;
                perform_remove(&mut active, kind, &enc_category, &enc_name, false).await
            }),
        }
    }

    fn close(self, commit: bool) -> BoxFuture<'static, Result<(), Error>> {
        Box::pin(DbSession::close(self, commit))
    }
}

impl ExtDatabase for Sqlite {
    fn start_transaction(
        conn: &mut PoolConnection<Self>,
        nested: bool,
    ) -> BoxFuture<'_, std::result::Result<(), SqlxError>> {
        // FIXME - this is a horrible workaround because there is currently
        // no good way to start an immediate transaction with sqlx. Without this
        // adjustment, updates will run into 'database is locked' errors.
        Box::pin(async move {
            <Sqlite as Database>::TransactionManager::begin(&mut *conn).await?;
            if !nested {
                // a no-op write transaction
                sqlx::query("DELETE FROM config WHERE 0")
                    .execute(&mut *conn)
                    .await?;
            }
            Ok(())
        })
    }
}

async fn acquire_key(
    session: &mut DbSession<Sqlite>,
) -> Result<(ProfileId, Arc<ProfileKey>), Error> {
    if let Some(ret) = session.profile_and_key() {
        Ok(ret)
    } else {
        session.make_active(&resolve_profile_key).await?;
        Ok(session.profile_and_key().unwrap())
    }
}

async fn acquire_session(
    session: &mut DbSession<Sqlite>,
) -> Result<DbSessionActive<'_, Sqlite>, Error> {
    session.make_active(&resolve_profile_key).await
}

async fn resolve_profile_key(
    conn: &mut PoolConnection<Sqlite>,
    cache: Arc<KeyCache>,
    profile: String,
) -> Result<(ProfileId, Arc<ProfileKey>), Error> {
    if let Some((pid, key)) = cache.get_profile(profile.as_str()).await {
        Ok((pid, key))
    } else if let Some(row) = sqlx::query("SELECT id, profile_key FROM profiles WHERE name=?1")
        .bind(profile.as_str())
        .fetch_optional(conn)
        .await?
    {
        let pid = row.try_get(0)?;
        let key = Arc::new(cache.load_key(row.try_get(1)?).await?);
        cache.add_profile(profile, pid, key.clone()).await;
        Ok((pid, key))
    } else {
        Err(err_msg!(NotFound, "Profile not found"))
    }
}

#[allow(clippy::too_many_arguments)]
async fn perform_insert(
    active: &mut DbSessionTxn<'_, Sqlite>,
    kind: EntryKind,
    enc_category: &[u8],
    enc_name: &[u8],
    enc_value: &[u8],
    enc_tags: Option<Vec<EncEntryTag>>,
    expiry_ms: Option<i64>,
    new_row: bool,
) -> Result<(), Error> {
    let row_id = if new_row {
        trace!("Insert entry");
        let done = sqlx::query(INSERT_QUERY)
            .bind(active.profile_id)
            .bind(kind as i16)
            .bind(enc_category)
            .bind(enc_name)
            .bind(enc_value)
            .bind(expiry_ms.map(expiry_timestamp).transpose()?)
            .execute(active.connection_mut())
            .await?;
        if done.rows_affected() == 0 {
            return Err(err_msg!(Duplicate, "Duplicate row"));
        }
        done.last_insert_rowid()
    } else {
        trace!("Update entry");
        let row_id: i64 = sqlx::query_scalar(UPDATE_QUERY)
            .bind(active.profile_id)
            .bind(kind as i16)
            .bind(enc_category)
            .bind(enc_name)
            .bind(enc_value)
            .bind(expiry_ms.map(expiry_timestamp).transpose()?)
            .fetch_one(active.connection_mut())
            .await
            .map_err(|_| err_msg!(NotFound, "Error updating existing row"))?;
        sqlx::query(TAG_DELETE_QUERY)
            .bind(row_id)
            .execute(active.connection_mut())
            .await?;
        row_id
    };
    if let Some(tags) = enc_tags {
        for tag in tags {
            sqlx::query(TAG_INSERT_QUERY)
                .bind(row_id)
                .bind(&tag.name)
                .bind(&tag.value)
                .bind(tag.plaintext as i16)
                .execute(active.connection_mut())
                .await?;
        }
    }
    Ok(())
}

async fn perform_remove<'q>(
    active: &mut DbSessionActive<'q, Sqlite>,
    kind: EntryKind,
    enc_category: &[u8],
    enc_name: &[u8],
    ignore_error: bool,
) -> Result<(), Error> {
    trace!("Remove entry");
    let done = sqlx::query(DELETE_QUERY)
        .bind(active.profile_id)
        .bind(kind as i16)
        .bind(enc_category)
        .bind(enc_name)
        .execute(active.connection_mut())
        .await?;
    if done.rows_affected() == 0 && !ignore_error {
        Err(err_msg!(NotFound, "Entry not found"))
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn perform_scan(
    mut active: DbSessionRef<'_, Sqlite>,
    profile_id: ProfileId,
    key: Arc<ProfileKey>,
    kind: EntryKind,
    category: String,
    tag_filter: Option<TagFilter>,
    offset: Option<i64>,
    limit: Option<i64>,
) -> impl Stream<Item = Result<Vec<EncScanEntry>, Error>> + '_ {
    try_stream! {
        let mut params = QueryParams::new();
        params.push(profile_id);
        params.push(kind as i16);
        let (enc_category, tag_filter) = unblock({
            let key = key.clone();
            let category = ProfileKey::prepare_input(category.as_bytes());
            let params_len = params.len() + 1; // plus category
            move || {
                Result::<_, Error>::Ok((
                    key.encrypt_entry_category(category)?,
                    encode_tag_filter::<SqliteStore>(tag_filter, &key, params_len)?
                ))
            }
        }).await?;
        params.push(enc_category);
        let query = extend_query::<SqliteStore>(SCAN_QUERY, &mut params, tag_filter, offset, limit)?;

        let mut batch = Vec::with_capacity(PAGE_SIZE);

        let mut acquired = acquire_session(&mut *active).await?;
        let mut rows = sqlx::query_with(query.as_str(), params).fetch(acquired.connection_mut());
        while let Some(row) = rows.try_next().await? {
            batch.push(EncScanEntry {
                name: row.try_get(1)?, value: row.try_get(2)?, tags: row.try_get(3)?
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::db_utils::replace_arg_placeholders;
    use crate::future::block_on;
    use crate::protect::{generate_raw_store_key, StoreKeyMethod};

    #[test]
    fn sqlite_check_expiry_timestamp() {
        block_on(async {
            let key = generate_raw_store_key(None)?;
            let db = SqliteStoreOptions::in_memory()
                .provision(StoreKeyMethod::RawKey, key, None, false)
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
            Result::<_, Error>::Ok(())
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
