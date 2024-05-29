use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;
use base64::{encode};
use sqlx::Column;
use sqlx::TypeInfo;
use async_stream::try_stream;
use futures_lite::{
    pin,
    stream::{Stream, StreamExt},
};

use sqlx::{
    pool::PoolConnection,
    sqlite::{Sqlite, SqlitePool},
    Acquire, Database, Error as SqlxError, Row, TransactionManager,
};

use super::{
    db_utils::{
        decode_tags, decrypt_scan_batch, encode_profile_key, encode_tag_filter, expiry_timestamp,
        extend_query, prepare_tags, random_profile_name, Connection, DbSession, DbSessionActive,
        DbSessionRef, DbSessionTxn, EncScanEntry, ExtDatabase, QueryParams, QueryPrepare,
        PAGE_SIZE,
    },
    Backend, BackendSession,
};
use crate::{
    entry::{EncEntryTag, Entry, EntryKind, EntryOperation, EntryTag, Scan, TagFilter},
    error::Error,
    future::{unblock, BoxFuture},
    protect::{EntryEncryptor, KeyCache, PassKey, ProfileId, ProfileKey, StoreKeyMethod},
};

mod provision;
pub use provision::SqliteStoreOptions;

const CONFIG_FETCH_QUERY: &str = "SELECT value FROM config WHERE name = ?1";
const CONFIG_UPDATE_QUERY: &str = "INSERT OR REPLACE INTO config (name, value) VALUES (?1, ?2)";
const COUNT_QUERY: &str = "SELECT COUNT(*) FROM items i
    WHERE profile_id = ?1
    AND (kind = ?2 OR ?2 IS NULL)
    AND (category = ?3 OR ?3 IS NULL)
    AND (expiry IS NULL OR expiry > DATETIME('now'))";
const DELETE_QUERY: &str = "DELETE FROM items
    WHERE profile_id = ?1 AND kind = ?2 AND category = ?3 AND name = ?4";
const FETCH_QUERY: &str = "SELECT i.id, i.value,
    (SELECT GROUP_CONCAT(it.plaintext || ':' || HEX(it.name) || ':' || HEX(it.value))
        FROM items_tags it WHERE it.item_id = i.id) AS tags
    FROM items i WHERE i.profile_id = ?1 AND i.kind = ?2
    AND i.category = ?3 AND i.name = ?4
    AND (i.expiry IS NULL OR i.expiry > DATETIME('now'))";
const FETCH_QUERY_ALL: &str = "
    SELECT *
    FROM items i;
    ";
    
    const COUNT_QUERY_WITH_TAGS: &str = "
    SELECT COUNT(*)
    FROM items i
    JOIN items_tags it ON i.id = it.item_id
    WHERE i.profile_id = ?1
    AND (?2 IS NULL OR i.kind = ?2)
    AND (?3 IS NULL OR i.category = ?3)
    AND (i.expiry IS NULL OR i.expiry > DATETIME('now'))
    AND (it.tag = ?4)";


const INSERT_QUERY: &str =
    "INSERT OR IGNORE INTO items (profile_id, kind, category, name, value, expiry)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6)";
const UPDATE_QUERY: &str = "UPDATE items SET value=?5, expiry=?6 WHERE profile_id=?1 AND kind=?2
    AND category=?3 AND name=?4 RETURNING id";
const SCAN_QUERY: &str = "SELECT i.id, i.kind, i.category, i.name, i.value,
    (SELECT GROUP_CONCAT(it.plaintext || ':' || HEX(it.name) || ':' || HEX(it.value))
        FROM items_tags it WHERE it.item_id = i.id) AS tags
    FROM items i WHERE i.profile_id = ?1
    AND (i.kind = ?2 OR ?2 IS NULL)
    AND (i.category = ?3 OR ?3 IS NULL)
    AND (i.expiry IS NULL OR i.expiry > DATETIME('now'))";
const DELETE_ALL_QUERY: &str = "DELETE FROM items AS i
    WHERE i.profile_id = ?1
    AND (i.kind = ?2 OR ?2 IS NULL)
    AND (i.category = ?3 OR ?3 IS NULL)";
const TAG_INSERT_QUERY: &str = "INSERT INTO items_tags
    (item_id, name, value, plaintext) VALUES (?1, ?2, ?3, ?4)";
const TAG_DELETE_QUERY: &str = "DELETE FROM items_tags
    WHERE item_id=?1";

/// A Sqlite database store
pub struct SqliteBackend {
    conn_pool: SqlitePool,
    active_profile: String,
    key_cache: Arc<KeyCache>,
    path: String,
}

impl SqliteBackend {
    pub(crate) fn new(
        conn_pool: SqlitePool,
        active_profile: String,
        key_cache: KeyCache,
        path: String,
    ) -> Self {
        Self {
            conn_pool,
            active_profile,
            key_cache: Arc::new(key_cache),
            path,
        }
    }
}

impl Debug for SqliteBackend {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteStore")
            .field("active_profile", &self.active_profile)
            .field("path", &self.path)
            .finish()
    }
}

impl QueryPrepare for SqliteBackend {
    type DB = Sqlite;
}

impl Backend for SqliteBackend {
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
                    .execute(conn.as_mut())
                    .await?;
            conn.return_to_pool().await;
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

    fn get_active_profile(&self) -> String {
        self.active_profile.clone()
    }

    fn get_default_profile(&self) -> BoxFuture<'_, Result<String, Error>> {
        Box::pin(async move {
            let mut conn = self.conn_pool.acquire().await?;
            let profile: Option<String> = sqlx::query_scalar(CONFIG_FETCH_QUERY)
                .bind("default_profile")
                .fetch_one(conn.as_mut())
                .await
                .map_err(err_map!(Backend, "Error fetching default profile name"))?;
            conn.return_to_pool().await;
            Ok(profile.unwrap_or_default())
        })
    }

    fn set_default_profile(&self, profile: String) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            let mut conn = self.conn_pool.acquire().await?;
            sqlx::query(CONFIG_UPDATE_QUERY)
                .bind("default_profile")
                .bind(profile)
                .execute(conn.as_mut())
                .await
                .map_err(err_map!(Backend, "Error setting default profile name"))?;
            conn.return_to_pool().await;
            Ok(())
        })
    }

    fn list_profiles(&self) -> BoxFuture<'_, Result<Vec<String>, Error>> {
        Box::pin(async move {
            let mut conn = self.conn_pool.acquire().await?;
            let rows = sqlx::query("SELECT name FROM profiles")
                .fetch_all(conn.as_mut())
                .await
                .map_err(err_map!(Backend, "Error fetching profile list"))?;
            conn.return_to_pool().await;
            let names = rows.into_iter().flat_map(|r| r.try_get(0)).collect();
            Ok(names)
        })
    }

    fn remove_profile(&self, name: String) -> BoxFuture<'_, Result<bool, Error>> {
        Box::pin(async move {
            let mut conn = self.conn_pool.acquire().await?;
            let ret = sqlx::query("DELETE FROM profiles WHERE name=?")
                .bind(&name)
                .execute(conn.as_mut())
                .await
                .map_err(err_map!(Backend, "Error removing profile"))?
                .rows_affected()
                != 0;
            conn.return_to_pool().await;
            Ok(ret)
        })
    }

    fn rekey(
        &mut self,
        method: StoreKeyMethod,
        pass_key: PassKey<'_>,
    ) -> BoxFuture<'_, Result<(), Error>> {
        let pass_key = pass_key.into_owned();
        Box::pin(async move {
            let (store_key, store_key_ref) = unblock(move || method.resolve(pass_key)).await?;
            let store_key = Arc::new(store_key);
            let mut conn = self.conn_pool.acquire().await?;
            let mut txn = conn.begin().await?;
            let mut rows = sqlx::query("SELECT id, profile_key FROM profiles").fetch(txn.as_mut());
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
                    .execute(txn.as_mut())
                    .await?
                    .rows_affected()
                    != 1
                {
                    return Err(err_msg!(Backend, "Error updating profile key"));
                }
            }
            if sqlx::query("UPDATE config SET value=?1 WHERE name='key'")
                .bind(store_key_ref.into_uri())
                .execute(txn.as_mut())
                .await?
                .rows_affected()
                != 1
            {
                return Err(err_msg!(Backend, "Error updating store key"));
            }
            txn.commit().await?;
            conn.return_to_pool().await;
            self.key_cache = Arc::new(KeyCache::new(store_key));
            Ok(())
        })
    }

    fn scan(
        &self,
        profile: Option<String>,
        kind: Option<EntryKind>,
        category: Option<String>,
        tag_filter: Option<TagFilter>,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> BoxFuture<'_, Result<Scan<'static, Entry>, Error>> {
        Box::pin(async move {
            let session = self.session(profile, false)?;
            let mut active = session.owned_ref();
            let (profile_id, key) = acquire_key(&mut active).await?;
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
            profile.unwrap_or_else(|| self.active_profile.clone()),
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

impl BackendSession for DbSession<Sqlite> {
    

    fn count<'q>(
        &'q mut self,
        kind: Option<EntryKind>,
        category: Option<&'q str>,
        tag_filter: Option<TagFilter>,
    ) -> BoxFuture<'q, Result<i64, Error>> {
        Box::pin(async move {
            let (profile_id, _key) = acquire_key(&mut *self).await?;
            let mut params = QueryParams::new();
            params.push(profile_id);
            params.push(kind.map(|k| k as i16));
            params.push(category);
    
            let query = if let Some(tag_filter) = tag_filter {
                let params_len = params.len();
                let tag_filter_query = encode_tag_filter::<SqliteBackend>(Some(tag_filter), &_key, params_len)?;
                extend_query::<SqliteBackend>(COUNT_QUERY_WITH_TAGS, &mut params, Some(tag_filter_query).expect("REASON"), None, None)?
                
            } else {
                extend_query::<SqliteBackend>(COUNT_QUERY, &mut params, None, None, None)?
            };
    
            let mut active = acquire_session(&mut *self).await?;
            let count = sqlx::query_scalar_with(query.as_str(), params)
                .fetch_one(active.connection_mut())
                .await
                .map_err(err_map!(Backend, "Error performing count query"))?;
            Ok(count)
        })
    }


    // vinay remove enc from here this stops the fetchkey
    // fn fetch(
    //     &mut self,
    //     kind: EntryKind,
    //     category: &str,
    //     name: &str,
    //     _for_update: bool,
    // ) -> BoxFuture<'_, Result<Option<Entry>, Error>> {
    //     let category = category.to_string();
    //     let name = name.to_string();

    //     Box::pin(async move {
    //         let (profile_id, key) = acquire_key(&mut *self).await?;
    //         let (enc_category, enc_name) = unblock({
    //             let key = key.clone();
    //             let category = ProfileKey::prepare_input(category.as_bytes());
    //             let name = ProfileKey::prepare_input(name.as_bytes());
    //             move || {
    //                 Result::<_, Error>::Ok((
    //                     key.encrypt_entry_category(category)?,
    //                     key.encrypt_entry_name(name)?,
    //                 ))
    //             }
    //         })
    //         .await?;
    //         let mut active = acquire_session(&mut *self).await?;
    //         if let Some(row) = sqlx::query(FETCH_QUERY)
    //             .bind(profile_id)
    //             .bind(kind as i16)
    //             .bind(enc_category)
    //             .bind(enc_name)
    //             .fetch_optional(active.connection_mut())
    //             .await
    //             .map_err(err_map!(Backend, "Error performing fetch query"))?
    //         {
    //             let value = row.try_get(1)?;
    //             let tags = row.try_get(2)?;
    //             let (category, name, value, tags) = unblock(move || {
    //                 let value = key.decrypt_entry_value(category.as_ref(), name.as_ref(), value)?;
    //                 let enc_tags = decode_tags(tags)
    //                     .map_err(|_| err_msg!(Unexpected, "Error decoding entry tags"))?;
    //                 let tags = key.decrypt_entry_tags(enc_tags)?;
    //                 Result::<_, Error>::Ok((category, name, value, tags))
    //             })
    //             .await?;
    //             Ok(Some(Entry::new(kind, category, name, value, tags)))
    //         } else {
    //             Ok(None)
    //         }
    //     })
    // }

    // use serde_json::Value;
    // fn fetch<'a>(
    //     &'a mut self,
    //     kind: EntryKind,
    //     category: &'a str,
    //     name: &'a str,
    //     _for_update: bool,
    // ) -> BoxFuture<'a, Result<Option<Entry>, Error>> {
    //     let category_bytes = category.as_bytes();
    //     let name_bytes = name.as_bytes();
    //     Box::pin(async move {
    //         println!("Starting fetch operation...");
    //         println!("Category: {}", category);
    //         println!("Name: {}", name);
    //         println!("Kind: {:?}", kind);
    //         let mut active = acquire_session(&mut *self).await?;
    //         println!("Session acquired.");
            
    //         let rows = sqlx::query(FETCH_QUERY_ALL)
    //         .fetch_all(active.connection_mut())
    //         .await
    //         .map_err(err_map!(Backend, "Error performing fetch all query"))?;

    //     println!("Fetched rows count: {}", rows.len());
    //     for (index, row) in rows.iter().enumerate() {
    //         let id: i32 = row.try_get("id").unwrap_or(-1);
    //         let value_bytes: Vec<u8> = row.try_get("value").unwrap_or_else(|_| Vec::new());
    //         let value_string = String::from_utf8(value_bytes.clone())
    //                             .unwrap_or_else(|_| encode(&value_bytes)); // Convert non-UTF-8 data to Base64

    //         let category: String = row.try_get("category").unwrap_or("N/A".to_string());
    //         let name: String = row.try_get("name").unwrap_or("N/A".to_string());
    //         let tags: String = row.try_get("tags").unwrap_or("N/A".to_string());
    //         let profile = row.try_get("profile_id").unwrap_or(-1);

    //         println!("Row {}: ID: {}, Value: '{}', Category: '{}', Name: '{}', Tags: '{}', Profile ID: {}", 
    //                  index, id, value_string, category, name, tags, profile);
    //     }

    // //     const FETCH_QUERY: &str = "SELECT i.id, i.value,
    // // (SELECT GROUP_CONCAT(it.plaintext || ':' || HEX(it.name) || ':' || HEX(it.value))
    // //     FROM items_tags it WHERE it.item_id = i.id) AS tags
    // // FROM items i WHERE i.profile_id = ?1 AND i.kind = ?2
    // // AND i.category = ?3 AND i.name = ?4
    // // AND (i.expiry IS NULL OR i.expiry > DATETIME('now'))";
    //     #[derive(sqlx::FromRow, Debug)]
    //     struct Entry {
    //         id: i64,
    //         value: Vec<u8>, // Assuming binary data; adjust as needed.
    //         category: String,
    //         name: String,
    //         tags: String, // Assuming tags are aggregated into a single string.
    //     }

    //     println!("Fetching row with kind: {:?}, category: '{}', name: '{}'", kind as i16, category, name);
    //         // Now, try to fetch a specific optional row using the correct type
    //         if let Some(row) = sqlx::query_as::<_, Entry>(FETCH_QUERY)
    //             .bind(kind as i16)
    //             .bind(category)
    //             .bind(name)
    //             .fetch_optional(active.connection_mut())
    //             .await
    //             .map_err(err_map!(Backend, "Error performing fetch query"))?
    //         {
    //             let value = row.try_get::<i32, _>(0)?;  // Correct type for value
    //             let tags_value = row.try_get::<i32, _>(1)?;  // Correct type for tags
    
    //             println!("Fetched value: {}", value);
    //             println!("Fetched tags value: {}", tags_value);
    
    //             // Convert integers to strings or handle appropriately
    //             let value_bytes = value.to_string().into_bytes();
    //             let tags_string = format!("{}", tags_value);
    
    //             let tags = if !tags_string.is_empty() {
    //                 vec![EntryTag::Plaintext(tags_string.clone(), tags_string)]
    //             } else {
    //                 vec![]
    //             };
        
    //             println!("Entry created with kind: {:?}, category: '{}', name: '{}', tags count: {}", kind, category, name, tags.len());
    //             Ok(Some(Entry::new(kind, category.to_string(), name.to_string(), value_bytes, tags)))
    //         } else {
    //             println!("No data found for category '{}' and name '{}'", category, name);
    //             Ok(None)
    //         }
    //     })
    // }


    fn fetch<'a>(
        &'a mut self,
        kind: EntryKind,
        category: &'a str,
        name: &'a str,
        _for_update: bool,
    ) -> BoxFuture<'a, Result<Option<Entry>, Error>> {
        Box::pin(async move {
            println!("Starting fetch operation...");
            println!("Category: {}", category);
            println!("Name: {}", name);
            println!("Kind: {:?}", kind);
            let (profile_id, key) = acquire_key(&mut *self).await?;
            let mut active = acquire_session(&mut *self).await?;
            println!("Session acquired.");
    
            // Assuming FETCH_QUERY_ALL fetches everything without filters
            // let rows = sqlx::query(FETCH_QUERY_ALL)
            //     .fetch_all(active.connection_mut())
            //     .await
            //     .map_err(err_map!(Backend, "Error performing fetch all query"))?;
    
            // println!("Fetched rows count: {}", rows.len());
            // for (index, row) in rows.iter().enumerate() {
            //     let id: i32 = row.try_get("id").unwrap_or(-1);
            //     let value_bytes: Vec<u8> = row.try_get("value").unwrap_or_else(|_| Vec::new());
            //     let value_string = String::from_utf8(value_bytes.clone())
            //                         .unwrap_or_else(|_| encode(&value_bytes)); // Convert non-UTF-8 data to Base64
            //     let category: String = row.try_get("category").unwrap_or("N/A".to_string());
            //     let name: String = row.try_get("name").unwrap_or("N/A".to_string());
            //     let tags: String = row.try_get("tags").unwrap_or("N/A".to_string());
            //     let profile_id: i32 = row.try_get("profile_id").unwrap_or(-1);
    
            //     println!("Row {}: ID: {}, Value: '{}', Category: '{}', Name: '{}', Tags: '{}', Profile ID: {}", 
            //              index, id, value_string, category, name, tags, profile_id);
            // }
    //         const FETCH_QUERY: &str = "SELECT i.id, i.value,
    // (SELECT GROUP_CONCAT(it.plaintext || ':' || HEX(it.name) || ':' || HEX(it.value))
    //     FROM items_tags it WHERE it.item_id = i.id) AS tags
    // FROM items i WHERE i.profile_id = ?1 AND i.kind = ?2
    // AND i.category = ?3 AND i.name = ?4
    // AND (i.expiry IS NULL OR i.expiry > DATETIME('now'))";
            // Now, try to fetch a specific optional row using the correct type
            println!("Fetching row with kind: {:?}, category: '{}', name: '{}'", kind as i16, category, name);
            if let Some(row) = sqlx::query(FETCH_QUERY)
                .bind(profile_id)
                .bind(kind as i16)
                .bind(category)
                .bind(name)
                .fetch_optional(active.connection_mut())
                .await
                .map_err(err_map!(Backend, "Error performing fetch query"))?
            {

                // print whole row
                for (index, column) in row.columns().iter().enumerate() {
                    let column_name = column.name();
                    let value = match column.type_info().name() {
                        "INTEGER" => {
                            let val: Result<i64, _> = row.try_get(index);
                            match val {
                                Ok(v) => format!("{}", v),
                                Err(_) => "<unreadable>".to_string(),
                            }
                        },
                        "TEXT" => {
                            let val: Result<String, _> = row.try_get(index);
                            match val {
                                Ok(v) => v,
                                Err(_) => "<unreadable>".to_string(),
                            }
                        },
                        "BLOB" => {
                            let val: Result<Vec<u8>, _> = row.try_get(index);
                            match val {
                                Ok(v) => format!("{:?}", v),
                                Err(_) => "<unreadable>".to_string(),
                            }
                        },
                        "NULL" => "NULL".to_string(),
                        "REAL" => {
                            let val: Result<f64, _> = row.try_get(index);
                            match val {
                                Ok(v) => format!("{}", v),
                                Err(_) => "<unreadable>".to_string(),
                            }
                        },
                        "BOOLEAN" => {
                            let val: Result<bool, _> = row.try_get(index);
                            match val {
                                Ok(v) => format!("{}", v),
                                Err(_) => "<unreadable>".to_string(),
                            }
                        },
                        "DATETIME" => {
                            let val: Result<String, _> = row.try_get(index);
                            match val {
                                Ok(v) => v,
                                Err(_) => "<unreadable>".to_string(),
                            }
                        },
                        "NUMERIC" => {
                            let val: Result<String, _> = row.try_get(index);
                            match val {
                                Ok(v) => v,
                                Err(_) => "<unreadable>".to_string(),
                            }
                        },
                        "DECIMAL" => {
                            let val: Result<String, _> = row.try_get(index);
                            match val {
                                Ok(v) => v,
                                Err(_) => "<unreadable>".to_string(),
                            }
                        },
                        "VARCHAR" => {
                            let val: Result<String, _> = row.try_get(index);
                            match val {
                                Ok(v) => v,
                                Err(_) => "<unreadable>".to_string(),
                            }
                        },
                        "CHAR" => {
                            let val: Result<String, _> = row.try_get(index);
                            match val {
                                Ok(v) => v,
                                Err(_) => "<unreadable>".to_string(),
                            }
                        },
                        "NVARCHAR" => {
                            let val: Result<String, _> = row.try_get(index);
                            match val {
                                Ok(v) => v,
                                Err(_) => "<unreadable>".to_string(),
                            }
                        },
                        "NCHAR" => {
                            let val: Result<String, _> = row.try_get(index);
                            match val {
                                Ok(v) => v,
                                Err(_) => "<unreadable>".to_string(),
                            }
                        },
                        "NVARCHAR2" => {
                            let val: Result<String, _> = row.try_get(index);
                            match val {
                                Ok(v) => v,
                                Err(_) => "<unreadable>".to_string(),
                            }
                        },
                        "NCHAR2" => {
                            let val: Result<String, _> = row.try_get(index);
                            match val {
                                Ok(v) => v,
                                Err(_) => "<unreadable>".to_string(),
                            }
                        },




                        _ => "<unsupported type>".to_string(),
                    };
                    println!("{}: {}", column_name, value);
                }
                let id: i64 = row.try_get("id").unwrap_or(-1);
                let value_bytes: Vec<u8> = row.try_get("value").unwrap_or_else(|_| Vec::new());
                let value_string = String::from_utf8(value_bytes.clone())
                                    .unwrap_or_else(|_| encode(&value_bytes));
                let tags_string: String = row.try_get("tags").unwrap_or_default();
                // let mut tags: Vec<EntryTag> = tags_string.split(',')
                //     .map(|s| EntryTag::from(s.trim()))
                //     .collect();
                
                // // Add dummy tags
                // tags.push(EntryTag { tag: "DummyTag1".to_string() });
                // tags.push(EntryTag { tag: "DummyTag2".to_string() });
    
                println!("Fetched value: '{}'", value_string);
                println!("Fetched tags: '{}'", tags_string);
    
                // Construct your entry directly here
                let entry = Entry { // Define this inline if Entry is defined elsewhere
                    kind:kind,
                    value: value_bytes.into(),
                    category: category.to_string(),
                    name: name.to_string(),
                    tags: vec![],
                };
    
                println!("Entry created with kind: {:?}, category: '{}', name: '{}'", kind, category, name);
                Ok(Some(entry))
            } else {
                println!("No data found for category '{}' and name '{}'", category, name);
                Ok(None)
            }
        })
    }
    

    fn fetch_all<'q>(
        &'q mut self,
        kind: Option<EntryKind>,
        category: Option<&'q str>,
        tag_filter: Option<TagFilter>,
        limit: Option<i64>,
        _for_update: bool,
    ) -> BoxFuture<'q, Result<Vec<Entry>, Error>> {
        let category = category.map(|c| c.to_string());
        Box::pin(async move {
            let mut active = self.borrow_mut();
            let (profile_id, key) = acquire_key(&mut active).await?;
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
        kind: Option<EntryKind>,
        category: Option<&'q str>,
        tag_filter: Option<TagFilter>,
    ) -> BoxFuture<'q, Result<i64, Error>> {
        let enc_category = category.map(|c| ProfileKey::prepare_input(c.as_bytes()));

        Box::pin(async move {
            let (profile_id, key) = acquire_key(&mut *self).await?;
            let mut params = QueryParams::new();
            params.push(profile_id);
            params.push(kind.map(|k| k as i16));
            params.push(category);

            let params_len = params.len();
            let tag_filter = if let Some(tf) = tag_filter {
                encode_tag_filter::<SqliteBackend>(Some(tf), &key, params_len)?
                
            } else {
                None
            };
            // let (enc_category, tag_filter) = unblock({
            //     let params_len = params.len() + 1; // plus category
            //     move || {
            //         Result::<_, Error>::Ok((
            //             enc_category
            //                 .map(|c| key.encrypt_entry_category(c))
            //                 .transpose()?,
            //             encode_tag_filter::<SqliteBackend>(tag_filter, &key, params_len)?,
            //         ))
            //     }
            // })
            // .await?;
            // params.push(enc_category);
            // params.push(tag_filter);
            let query = extend_query::<SqliteBackend>(
                DELETE_ALL_QUERY,
                &mut params,
                None,
                None,
                None,
            )?;

            let mut active = acquire_session(&mut *self).await?;
            let removed = sqlx::query_with(query.as_str(), params)
                .execute(active.connection_mut())
                .await?
                .rows_affected();
            Ok(removed as i64)
        })
    }

    // fn remove_all<'q>(
    //     &'q mut self,
    //     kind: Option<EntryKind>,
    //     category: Option<&'q str>,
    //     tag_filter: Option<TagFilter>,
    // ) -> BoxFuture<'q, Result<i64, Error>> {
    //     Box::pin(async move {
    //         let mut params = QueryParams::new();
    //         params.push(kind.map(|k| k as i16));
    //         params.push(category);  // Directly pushing the category string
    //         let (profile_id, key) = acquire_key(&mut *self).await?;
    //         let tag_filter = if let Some(tf) = tag_filter {
    //             encode_tag_filter::<SqliteBackend>(Som(tf), &key,params.len())? // Adjust if necessary
    //         } else {
    //             None
    //         };
    //         params.push(tag_filter);
    
    //         let query = extend_query::<SqliteBackend>(
    //             DELETE_ALL_QUERY,
    //             &mut params,
    //             None,
    //             None,
    //             None,
    //         )?;
    
    //         let mut active = acquire_session(&mut *self).await?;
    //         let removed = sqlx::query_with(query.as_str(), params)
    //             .execute(active.connection_mut())
    //             .await?
    //             .rows_affected();
    //         Ok(removed as i64)
    //     })
    // }

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
        // let category_bytes = category.as_bytes();
        // let name_bytes = name;
    
        println!("Starting update operation: {:?}", operation);
        println!("Category: {}, Name: {}", category, name);
    
        match operation {
            EntryOperation::Insert | EntryOperation::Replace => {
                let value = value.unwrap_or_default();
                println!("Value length: {}", value.len());
                Box::pin(async move {
                    let tags = match tags.map(prepare_tags).transpose() {
                        Ok(value) => {
                            println!("Tags prepared successfully.");
                            value
                        },
                        Err(e) => {
                            println!("Failed to prepare tags: {:?}", e);
                            return Err(e);
                        },
                    };
    
                    println!("Acquiring session...");
                    let mut active = acquire_session(&mut *self).await?;
                    let mut txn = active.as_transaction().await?;
                    println!("Session and transaction acquired, performing insert...");
                    // print category_bytes, name_bytes, value, tags, expiry_ms, operation == EntryOperation::Insert
                    println!("Category bytes: {:?}", category);
                    println!("Name bytes: {:?}", name);
                    // print tags 
                    println!("Tags: {:?}", tags);
                    match perform_insert(
                        &mut txn,
                        kind,
                        category,
                        name,
                        value,
                        tags,  
                        expiry_ms,
                        operation == EntryOperation::Insert,
                    ).await {
                        Ok(_) => println!("Insert operation successful."),
                        Err(e) => println!("Insert operation failed: {:?}", e),
                    }
                    txn.commit().await?;
                    println!("Transaction committed.");
                    Ok(())
                })
            }
            EntryOperation::Remove => Box::pin(async move {
                println!("Acquiring session for remove operation...");
                let mut active = match acquire_session(&mut *self).await {
                    Ok(session) => session,
                    Err(e) => return Err(e), // Propagate error
                };
                println!("Session acquired, performing remove...");
                match perform_remove(&mut active, kind, category, name, false).await {
                    Ok(_) => {
                        println!("Remove operation successful.");
                        Ok(()) // Return Ok for success
                    },
                    Err(e) => {
                        println!("Remove operation failed: {:?}", e);
                        Err(e) // Propagate error
                    },
                }
            })
            ,
        }
    }
    
    
    

    fn ping(&mut self) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            let mut sess = acquire_session(&mut *self).await?;
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM profiles WHERE id=$1")
                .bind(sess.profile_id)
                .fetch_one(sess.connection_mut())
                .await
                .map_err(err_map!(Backend, "Error pinging session"))?;
            if count == 0 {
                Err(err_msg!(NotFound, "Session profile has been removed"))
            } else {
                Ok(())
            }
        })
    }

    fn close(&mut self, commit: bool) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(self.close(commit))
    }
}

impl ExtDatabase for Sqlite {
    fn start_transaction(
        conn: &mut Connection<Self>,
        nested: bool,
    ) -> BoxFuture<'_, std::result::Result<(), SqlxError>> {
        // FIXME - this is a horrible workaround because there is currently
        // no good way to start an immediate transaction with sqlx. Without this
        // adjustment, updates will run into 'database is locked' errors.
        Box::pin(async move {
            <Sqlite as Database>::TransactionManager::begin(conn).await?;
            if !nested {
                // a no-op write transaction
                sqlx::query("DELETE FROM config WHERE 0")
                    .execute(conn)
                    .await?;
            }
            Ok(())
        })
    }
}

async fn acquire_key(
    session: &mut DbSession<Sqlite>,
) -> Result<(ProfileId, Arc<ProfileKey>), Error> {
    acquire_session(session).await?;
    Ok(session.profile_and_key().unwrap())
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
    _in_txn: bool,
) -> Result<(ProfileId, Arc<ProfileKey>), Error> {
    if let Some((pid, key)) = cache.get_profile(profile.as_str()).await {
        Ok((pid, key))
    } else if let Some(row) = sqlx::query("SELECT id, profile_key FROM profiles WHERE name=?1")
        .bind(profile.as_str())
        .fetch_optional(conn.as_mut())
        .await
        .map_err(err_map!(Backend, "Error fetching profile key"))?
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
    enc_category: &str,
    enc_name: &str,
    enc_value: &[u8],
    enc_tags: Option<Vec<EntryTag>>,
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
            .await
            .map_err(err_map!(Backend, "Error inserting new entry"))?;
        if done.rows_affected() == 0 {
            return Err(err_msg!(Duplicate, "Duplicate entry"));
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
            .map_err(|_| err_msg!(NotFound, "Error updating existing entry"))?;
        sqlx::query(TAG_DELETE_QUERY)
            .bind(row_id)
            .execute(active.connection_mut())
            .await
            .map_err(err_map!(Backend, "Error removing existing entry tags"))?;
        row_id
    };
    // if let Some(tags) = enc_tags {
    //     for tag in tags {
    //         sqlx::query(TAG_INSERT_QUERY)
    //             .bind(row_id)
    //             .bind("tag")
    //             .bind("tag")
    //             .bind(true as i16)
    //             .execute(active.connection_mut())
    //             .await
    //             .map_err(err_map!(Backend, "Error inserting entry tags"))?;
    //     }
    // }
    Ok(())
}

async fn perform_remove<'q>(
    active: &mut DbSessionActive<'q, Sqlite>,
    kind: EntryKind,
    enc_category: &str,
    enc_name: &str,
    ignore_error: bool,
) -> Result<(), Error> {
    trace!("Remove entry");
    let done = sqlx::query(DELETE_QUERY)
        .bind(active.profile_id)
        .bind(kind as i16)
        .bind(enc_category)
        .bind(enc_name)
        .execute(active.connection_mut())
        .await
        .map_err(err_map!(Backend, "Error removing entry"))?;
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
    kind: Option<EntryKind>,
    category: Option<String>,
    tag_filter: Option<TagFilter>,
    offset: Option<i64>,
    limit: Option<i64>,
) -> impl Stream<Item = Result<Vec<EncScanEntry>, Error>> + '_ {
    try_stream! {
        let mut params = QueryParams::new();
        params.push(profile_id);
        params.push(kind.map(|k| k as i16));
        let (enc_category, tag_filter) = unblock({
            let key = key.clone();
            let enc_category = category.as_ref().map(|c| ProfileKey::prepare_input(c.as_bytes()));
            let params_len = params.len() + 1; // plus category
            move || {
                Result::<_, Error>::Ok((
                    enc_category.map(|c| key.encrypt_entry_category(c)).transpose()?,
                    encode_tag_filter::<SqliteBackend>(tag_filter, &key, params_len)?
                ))
            }
        }).await?;
        params.push(enc_category);
        let query = extend_query::<SqliteBackend>(SCAN_QUERY, &mut params, tag_filter, offset, limit)?;

        let mut batch = Vec::with_capacity(PAGE_SIZE);

        let mut acquired = acquire_session(&mut active).await?;
        let mut rows = sqlx::query_with(query.as_str(), params).fetch(acquired.connection_mut());
        while let Some(row) = rows.try_next().await? {
            let kind: u32 = row.try_get(1)?;
            let kind = EntryKind::try_from(kind as usize)?;
            batch.push(EncScanEntry {
                kind, category: row.try_get(2)?, name: row.try_get(3)?, value: row.try_get(4)?, tags: row.try_get(5)?
            });
            if batch.len() == PAGE_SIZE {
                yield batch.split_off(0);
            }
        }
        drop(rows);
        if active.is_owned() {
            active.close(false).await?;
        }
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
                .fetch_one(&db.conn_pool)
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
            &replace_arg_placeholders::<SqliteBackend>("This $$ is $10 a $$ string!", 3),
            "This ?3 is ?12 a ?5 string!",
        );
        assert_eq!(
            &replace_arg_placeholders::<SqliteBackend>("This $a is a string!", 1),
            "This $a is a string!",
        );
    }
}
