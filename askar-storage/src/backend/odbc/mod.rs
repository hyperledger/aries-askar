use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;
use std::collections::BTreeMap;

use odbc_api::{
    buffers::{RowVec},
    Cursor,
    IntoParameter,
    parameter::{InputParameter, VarCharArray},
    Preallocated,
};

use odbc_api::sys;

use super::{
    db_utils::{
        encode_profile_key,
        expiry_timestamp,
        prepare_tags,
        random_profile_name
    },
    Backend, BackendSession,
};
use crate::{
    backend::OrderBy,
    entry::{EncEntryTag, Entry, EntryKind, EntryOperation, EntryTag, Scan, TagFilter},
    error::Error,
    future::{BoxFuture, unblock},
    protect::{EntryEncryptor, KeyCache, PassKey, ProfileId, ProfileKey, StoreKeyMethod},
    wql::{
        sql::TagSqlEncoder,
        tags::{tag_query, TagQueryEncoder},
    },
};

use r2d2::PooledConnection;

mod provision;
pub use self::provision::OdbcStoreOptions;

mod r2d2_connection_pool;
use crate::odbc::r2d2_connection_pool::OdbcConnectionManager;

// All of our SQL queries.  Each of these queries conform to the SQL-92 standard.
const UPDATE_CONFIG_PROFILE: &str = "UPDATE config SET value = ? WHERE name='default_profile'";
const UPDATE_CONFIG_KEY: &str = "UPDATE config SET value=? WHERE name='key'";
const GET_DEFAULT_PROFILE: &str = "SELECT value FROM config WHERE name='default_profile'";

const GET_PROFILE_ID: &str = "SELECT id from profiles WHERE name=? and profile_key=?";
const GET_PROFILE_NAMES: &str = "SELECT name FROM profiles";
const GET_PROFILE_COUNT_FOR_NAME: &str = "SELECT COUNT(name) from profiles WHERE name=?";
const GET_PROFILES: &str = "SELECT id, profile_key FROM profiles";
const GET_PROFILE: &str = "SELECT id, profile_key FROM profiles WHERE name=?";
const INSERT_PROFILE: &str = "INSERT INTO profiles (name, profile_key) VALUES (?, ?)";
const UPDATE_PROFILE: &str = "UPDATE profiles SET profile_key=? WHERE id=?";
const DELETE_PROFILE: &str = "DELETE FROM profiles WHERE name=?";

const GET_ITEM_ID: &str = "SELECT id FROM items WHERE profile_id=? AND kind=? AND category=? AND name=?";
const INSERT_ITEM: &str = "INSERT INTO items (profile_id, kind, category, name, value, expiry) VALUES (?, ?, ?, ?, ?, NULL)";
const INSERT_ITEM_WITH_EXPIRY: &str = "INSERT INTO items (profile_id, kind, category, name, value, expiry) VALUES (?, ?, ?, ?, ?, ?)";
const UPDATE_ITEM: &str = "UPDATE items SET value=?, expiry=NULL WHERE profile_id=? AND kind=?
    AND category=? AND name=?";
const UPDATE_ITEM_WITH_EXPIRY: &str = "UPDATE items SET value=?, expiry=? WHERE profile_id=? AND kind=?
    AND category=? AND name=?";
const DELETE_ITEM: &str = "DELETE FROM items WHERE profile_id = ? AND kind = ? AND category = ? AND name = ?";
const COUNT_ITEMS: &str = "SELECT COUNT(*) FROM items i
    WHERE profile_id = ?
    AND (kind = ? OR ? IS NULL)
    AND (category = ? OR ? IS NULL)
    AND (expiry IS NULL OR expiry > CURRENT_TIMESTAMP)";
const GET_ITEM: &str = "SELECT id, value
    FROM items WHERE profile_id = ? AND kind = ?
    AND category = ? AND name = ?
    AND (expiry IS NULL OR expiry > CURRENT_TIMESTAMP)";

const INSERT_TAG: &str = "INSERT INTO items_tags (item_id, name, value, plaintext) VALUES (?, ?, ?, ?)";
const DELETE_TAG: &str = "DELETE FROM items_tags WHERE item_id=?";
const GET_TAGS_FOR_ITEM: &str = "select name, value, plaintext from items_tags where item_id = ?";

// XXX: Still to be done
//      - clean all warnings!

/// A ODBC database store
pub struct OdbcBackend {
    pool: r2d2::Pool<OdbcConnectionManager>,
    active_profile: String,
    key_cache: Arc<KeyCache>,
}

impl OdbcBackend {
    pub(crate) fn new(
        pool: r2d2::Pool<OdbcConnectionManager>,
        active_profile: String,
        key_cache: KeyCache,
    ) -> Self {
        Self {
            pool,
            active_profile,
            key_cache: Arc::new(key_cache),
        }
    }
}

impl Backend for OdbcBackend {
    type Session = OdbcSession;

    fn create_profile(&self, name: Option<String>) -> BoxFuture<'_, Result<String, Error>> {
        let name = name.unwrap_or_else(random_profile_name);

        Box::pin(async move {
            // Create the profile key.
            let store_key = self.key_cache.store_key.clone();
            let (profile_key, enc_key) = unblock(move || {
                let profile_key = ProfileKey::new()?;
                let enc_key = encode_profile_key(&profile_key, &store_key)?;
                Result::<_, Error>::Ok((profile_key, enc_key))
            })
            .await?;

            // Store the profile name and key.
            self.pool.get().unwrap().raw().execute(INSERT_PROFILE,
                (&name.clone().into_parameter(), &enc_key.clone().into_parameter()))?;

            // Retrieve the profile ID from the table.
            let mut pid: i64 = 0;

            self.pool.get().unwrap().raw().execute(GET_PROFILE_ID,
                (&name.clone().into_parameter(), &enc_key.clone().into_parameter()))
            .unwrap().unwrap()
            .next_row().unwrap().unwrap()
            .get_data(1, &mut pid)?;

            // Add the details to the key cache.
            self.key_cache
                    .add_profile(name.clone(), pid, Arc::new(profile_key))
                    .await;

            Ok(name)
        })
    }

    fn get_active_profile(&self) -> String {
        self.active_profile.clone()
    }

    fn get_default_profile(&self) -> BoxFuture<'_, Result<String, Error>> {
        Box::pin(async move {
            let mut profile_buf = Vec::new();

            self.pool.get().unwrap().raw().execute(GET_DEFAULT_PROFILE, ())
                .unwrap().unwrap()
                .next_row().unwrap().unwrap()
                .get_text(1, &mut profile_buf)?;

            Ok(String::from_utf8(profile_buf).unwrap())
        })
    }

    fn set_default_profile(&self, profile: String) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            self.pool.get().unwrap().raw().execute(UPDATE_CONFIG_PROFILE,
                    (&profile.into_parameter()))?;
            Ok(())
        })
    }

    fn list_profiles(&self) -> BoxFuture<'_, Result<Vec<String>, Error>> {
        Box::pin(async move {
            let mut names: Vec<String> = Vec::new();

            match self.pool.get().unwrap().raw().execute(GET_PROFILE_NAMES, ()) {
                Ok(cursor) => {
                    let row_set_buffer = RowVec::<(VarCharArray<1024>,)>::new(10);
                    let mut block_cursor = cursor.unwrap().bind_buffer(row_set_buffer).unwrap();
                    let batch = block_cursor.fetch().unwrap().unwrap();

                    for idx in 0..batch.num_rows() {
                        names.push(batch[idx].0.as_str().unwrap().unwrap().to_string());
                    }
                }
                Err(_error) => {
                    return Err(err_msg!(Unsupported, "Configuration data not found"));
                }
            };
            Ok(names)
        })
    }

    fn remove_profile(&self, name: String) -> BoxFuture<'_, Result<bool, Error>> {
        Box::pin(async move {
            let mut ret = false;

            // Determine whether the profile currently exists.  We use this to
            // determine whether to delete the profile, along with the return
            // value from this function (true == deleted / false == unknown profile).
            let mut count: i64 = 0;

            self.pool.get().unwrap().raw().execute(GET_PROFILE_COUNT_FOR_NAME,
                        (&name.clone().into_parameter()))
                .unwrap().unwrap()
                .next_row().unwrap().unwrap()
                .get_data(1, &mut count)?;

            if count > 0 {
                self.pool.get().unwrap().raw().execute(DELETE_PROFILE,
                    (&name.into_parameter()))?;

                ret = true;
            }

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
            let binding = self.pool.get().unwrap();
            let mut upd_keys = BTreeMap::<ProfileId, Vec<u8>>::new();

            // Retrieve and temporarily store the current keys for each
            // of the profiles.
            match binding.raw().execute(GET_PROFILES, ()) {
                Ok(cursor) => {
                    let mut unwrapped = cursor.unwrap();

                    while let Some(mut row) = unwrapped.next_row()? {
                        let mut pid: i64 = 0;
                        let mut enc_key = Vec::new();

                        row.get_data(1, &mut pid)?;
                        row.get_binary(2, &mut enc_key).unwrap();

                        upd_keys.insert(pid, enc_key);
                    }
                }
                Err(_error) => {
                    return Err(err_msg!(Unsupported, "Configuration data not found"));
                }
            };

            // Iterate over the cached keys, updating the profile with the new
            // key.
            for (pid, key) in upd_keys {
                let profile_key = self.key_cache.load_key(key).await?;
                let upd_key = unblock({
                    let store_key = store_key.clone();
                    move || encode_profile_key(&profile_key, &store_key)
                })
                .await?;

                binding.raw().execute(UPDATE_PROFILE,
                    (&upd_key.into_parameter(), &pid.into_parameter()))?;
            }

            // We finally need to save the new store key.
            binding.raw().execute(UPDATE_CONFIG_KEY,
                    (&store_key_ref.into_uri().into_parameter()))?;

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
        order_by: Option<OrderBy>,
        descending: bool,
    ) -> BoxFuture<'_, Result<Scan<'static, Entry>, Error>> {
        // XXX: Still to be done
        Box::pin(async move { Err(err_msg!(Unsupported, "mod::scan()")) })
    }

    fn session(&self, profile: Option<String>, transaction: bool) -> Result<Self::Session, Error> {
        Ok(OdbcSession::new(
            self.key_cache.clone(),
            profile.unwrap_or_else(|| self.active_profile.clone()),
            self.pool.get().unwrap(),
            transaction,
        ))
    }

    fn close(&self) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move { Ok(()) })
    }
}

impl Debug for OdbcBackend {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("OdbcStore")
            .field("active_profile", &self.active_profile)
            .finish()
    }
}

/// A ODBC session
#[derive(Debug)]
pub struct OdbcSession {
    cache: Arc<KeyCache>,
    profile: String,
    connection: PooledConnection<OdbcConnectionManager>,
    transaction: bool,
}

impl OdbcSession {
    pub(crate) fn new(
        cache: Arc<KeyCache>,
        profile: String,
        connection: PooledConnection<OdbcConnectionManager>,
        transaction: bool,
    ) -> Self
    {
        connection.raw().set_autocommit(!transaction);

        Self {
            cache: cache,
            profile: profile,
            connection: connection,
            transaction: transaction,
        }
    }

    async fn acquire_key(&mut self) -> Result<(ProfileId, Arc<ProfileKey>), Error> {
        // Check to see whether the key already exists in our cache...
        if let Some((pid, key)) = self.cache.get_profile(self.profile.as_str()).await {
            Ok((pid, key))
        } else {
            // The key isn't already cached and so we need to try and load the key
            // from the database.
            let mut pid: i64 = 0;
            let mut enc_key = Vec::new();

            if let Some(mut cursor) = self.connection.raw().execute(GET_PROFILE, (&self.profile.clone().into_parameter()))?
            {
                let mut row = cursor.next_row().unwrap().unwrap();
                row.get_data(1, &mut pid)?;
                row.get_binary(2, &mut enc_key)?;
            } else {
                return Err(err_msg!(NotFound, "Profile not found"));
            }

            // Load and cache the key.
            let key = Arc::new(self.cache.load_key(enc_key).await?);
            self.cache.add_profile(self.profile.clone(), pid, key.clone()).await;

            Ok((pid, key))
        }
    }

    fn getDecodedTags(&self, item_id: i64, mut statement: &mut Preallocated<'_>, mut key: &Arc<ProfileKey>) -> Result<Vec<EntryTag>, Error> {
        // Retrieve the tags from the database.
        if let Some(mut cursor) = statement.execute(GET_TAGS_FOR_ITEM, &item_id)? {
            // We use a RowVec buffer to iterate over the rows as it is more efficent
            // than retrieving the rows one at a time.  This just means that we need
            // to limit the size of the name and value columns to 1K.
            type Row = (VarCharArray<1024>, VarCharArray<1024>, i32);
            let max_rows_in_batch = 50;
            let buffer = RowVec::<Row>::new(max_rows_in_batch);

            let mut block_cursor = cursor.bind_buffer(buffer)?;

            let mut enc_tags: Vec<EncEntryTag> = vec![];
            while let Some(batch) = block_cursor.fetch()? {
                // Iterate over each row, retrieving the name, value and
                // plaintext fields.
                for (name, value, plaintext) in batch.iter() {
                    enc_tags.push(EncEntryTag {
                        name: name.as_bytes().ok_or_else(|| err_msg!(Unexpected, "Failed to retrieve the tag name"))?.to_vec(),
                        value: value.as_bytes().ok_or_else(|| err_msg!(Unexpected, "Failed to retrieve the tag value"))?.to_vec(),
                        plaintext: (*plaintext == 1),
                    });
                }
            }

            Ok(key.decrypt_entry_tags(enc_tags)?)
        } else {
            let tags: Vec<EntryTag> = Vec::new();
            Ok(tags)
        }
    }
}

impl BackendSession for OdbcSession {
    fn count<'q>(
        &'q mut self,
        kind: Option<EntryKind>,
        category: Option<&'q str>,
        tag_filter: Option<TagFilter>,
    ) -> BoxFuture<'q, Result<i64, Error>> {
        let enc_category = category.map(|c| ProfileKey::prepare_input(c.as_bytes()));

        Box::pin(async move {
            // Create the tag filter and parameters.
            let (profile_id, key) = self.acquire_key().await?;
            let (enc_category, tag_filter) = unblock({
                move || {
                    Result::<_, Error>::Ok((
                        enc_category
                            .map(|c| key.encrypt_entry_category(c))
                            .transpose()?,
                        encode_odbc_tag_filter(tag_filter, &key)?,
                    ))
                }
            })
            .await?;

            // Construct the full list of parameters for the query.
            let sql_kind = kind.map(|k| k as i64).unwrap();
            let mut count: i64 = 0;

            let mut params: Vec<Box<dyn InputParameter>> = vec![
                Box::new(profile_id.clone().into_parameter()),
                Box::new(sql_kind),
                Box::new(sql_kind),
                Box::new(enc_category.clone().into_parameter()),
                Box::new(enc_category.clone().into_parameter()),
            ];

            // Construct the full query.
            let query = extend_odbc_query(
                COUNT_ITEMS,
                &mut params,
                tag_filter,
                None,
                false,
            )?;

            // Execute the query.
            self.connection.raw().execute(&query, params.as_slice())
                .unwrap().unwrap()
                .next_row().unwrap().unwrap()
                .get_data(1, &mut count)?;

            Ok(count)
        })
    }

    fn fetch(
        &mut self,
        kind: EntryKind,
        category: &str,
        name: &str,
        for_update: bool,
    ) -> BoxFuture<'_, Result<Option<Entry>, Error>> {
        let category = category.to_string();
        let name = name.to_string();

        Box::pin(async move {
            // Create the 'select' fields.
            let (pid, key) = self.acquire_key().await?;
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

            let mut statement = self.connection.raw().preallocate().unwrap();

            // Retrieve the item from the database.
            let mut item_id: i64 = 0;
            let mut value: Vec<u8> = Vec::new();

            if let Ok(Some(mut row)) = statement.execute(GET_ITEM, (
                &pid.into_parameter(),
                &(kind as i16).into_parameter(),
                &enc_category.clone().into_parameter(),
                &enc_name.clone().into_parameter()
            ))?.unwrap().next_row() {
                row.get_binary(2, &mut value).unwrap();
                row.get_data(1, &mut item_id)?;
            } else {
                return Ok(None);
            }

            // Build up the response.
            let dvalue = key.decrypt_entry_value(category.as_ref(), name.as_ref(), value)?;
            let tags: Vec<EntryTag> = self.getDecodedTags(item_id, &mut statement, &key)?;

            Ok(Some(Entry::new(kind, category, name, dvalue, tags)))
        })
    }

    fn fetch_all<'q>(
        &'q mut self,
        kind: Option<EntryKind>,
        category: Option<&'q str>,
        tag_filter: Option<TagFilter>,
        limit: Option<i64>,
        order_by: Option<OrderBy>,
        descending: bool,
        for_update: bool,
    ) -> BoxFuture<'q, Result<Vec<Entry>, Error>> {
        // XXX: Still to be done
        let category = category.map(|c| c.to_string());
        Box::pin(async move { Err(err_msg!(Unsupported, "mod::fetch_all()")) })
    }

    fn remove_all<'q>(
        &'q mut self,
        kind: Option<EntryKind>,
        category: Option<&'q str>,
        tag_filter: Option<TagFilter>,
    ) -> BoxFuture<'q, Result<i64, Error>> {
        // XXX: Still to be done
        let enc_category = category.map(|c| ProfileKey::prepare_input(c.as_bytes()));

        Box::pin(async move { Err(err_msg!(Unsupported, "mod::remove_all()")) })
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
                let value = ProfileKey::prepare_input(value.unwrap_or_default());
                let tags = tags.map(prepare_tags);
                Box::pin(async move {
                    // Locate the correct key and then encrypt our various fields.
                    let (pid, key) = self.acquire_key().await?;
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

                    let mut statement = self.connection.raw().preallocate().unwrap();

                    // Work out the expiry time.
                    let mut expiryStr: String = String::new();

                    if let Some(mut expiry) = expiry_ms.map(expiry_timestamp).transpose()? {
                        // ODBC expects the time stamp to be in a string, of the format:
                        //   YYYY-MM-DD HH:MM:SS.MSEC
                        expiryStr = format!("{}", expiry.format("%Y-%m-%d %H:%M:%S.%6f"));
                    }

                    // Now we need to store the fields in the database.
                    if op == EntryOperation::Insert {
                        if expiryStr.is_empty() {
                            statement.execute(INSERT_ITEM,
                                (
                                    &pid.into_parameter(),
                                    &(kind as i16).into_parameter(),
                                    &enc_category.clone().into_parameter(),
                                    &enc_name.clone().into_parameter(),
                                    &enc_value.into_parameter()
                                ))?;
                        } else {
                            statement.execute(INSERT_ITEM_WITH_EXPIRY,
                                (
                                    &pid.into_parameter(),
                                    &(kind as i16).into_parameter(),
                                    &enc_category.clone().into_parameter(),
                                    &enc_name.clone().into_parameter(),
                                    &enc_value.into_parameter(),
                                    &expiryStr.into_parameter()
                                ))?;
                        }
                    } else {
                        if expiryStr.is_empty() {
                            statement.execute(UPDATE_ITEM,
                                (
                                    &enc_value.into_parameter(),
                                    &pid.into_parameter(),
                                    &(kind as i16).into_parameter(),
                                    &enc_category.clone().into_parameter(),
                                    &enc_name.clone().into_parameter()
                                ))?;
                        } else {
                            statement.execute(UPDATE_ITEM_WITH_EXPIRY,
                                (
                                    &enc_value.into_parameter(),
                                    &expiryStr.into_parameter(),
                                    &pid.into_parameter(),
                                    &(kind as i16).into_parameter(),
                                    &enc_category.clone().into_parameter(),
                                    &enc_name.clone().into_parameter()
                                ))?;
                        }

                        // We also want to delete all existing tags for this
                        // item.

                        statement.execute(DELETE_TAG,
                            (&pid.into_parameter()))?;
                    }

                    // Now we need to update the tags table.
                    if let Some(tags) = enc_tags {
                        // Retrieve the item identifier.
                        let mut item_id: i64 = 0;

                        statement.execute(GET_ITEM_ID,
                            (
                                &pid.into_parameter(),
                                &(kind as i16).into_parameter(),
                                &enc_category.clone().into_parameter(),
                                &enc_name.clone().into_parameter()
                            ))
                            .unwrap().unwrap()
                            .next_row().unwrap().unwrap()
                            .get_data(1, &mut item_id)?;

                        // Update each of the tags.
                        let mut prepared = self.connection.raw().prepare(INSERT_TAG).unwrap();

                        for tag in tags {
                            prepared.execute(
                                (
                                    &item_id.into_parameter(),
                                    &tag.name.into_parameter(),
                                    &tag.value.into_parameter(),
                                    &(tag.plaintext as i16).into_parameter()
                                ))?;
                        }
                    }

                    Ok(())
                })
            }

            EntryOperation::Remove => Box::pin(async move {
                // Create the encrypted category and name.
                let (pid, key) = self.acquire_key().await?;
                let (enc_category, enc_name) = unblock(move || {
                    Result::<_, Error>::Ok((
                        key.encrypt_entry_category(category)?,
                        key.encrypt_entry_name(name)?,
                    ))
                })
                .await?;

                // Issue the delete.  We don't return an error if the
                // item doesn't currently exist.
                self.connection.raw().execute(DELETE_ITEM,
                    (
                        &pid.into_parameter(),
                        &(kind as i16).into_parameter(),
                        &enc_category.into_parameter(),
                        &enc_name.into_parameter()
                    ))?;

                Ok(())
            }),
        }
    }

    fn ping(&mut self) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            let mut count: i64 = 0;

            self.connection.raw().execute(GET_PROFILE_COUNT_FOR_NAME,
                        (&self.profile.clone().into_parameter()))
                .unwrap().unwrap()
                .next_row().unwrap().unwrap()
                .get_data(1, &mut count)?;
            if count == 0 {
                Err(err_msg!(NotFound, "Session profile has been removed"))
            } else {
                Ok(())
            }
        })
    }

    fn close(&mut self, commit: bool) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            if self.transaction {
                if commit {
                    self.connection.raw().commit()?;
                } else {
                    self.connection.raw().rollback()?;
                }
                self.connection.raw().set_autocommit(true);
            }
            Ok(())
        })
    }
}

fn encode_odbc_tag_filter(
    tag_filter: Option<TagFilter>,
    key: &ProfileKey,
) -> Result<Option<(String, Vec<Vec<u8>>)>, Error> {
    if let Some(tag_filter) = tag_filter {
        let tag_query = tag_query(tag_filter.query)?;
        let mut enc = TagSqlEncoder::new(
            |name| key.encrypt_tag_name(ProfileKey::prepare_input(name.as_bytes())),
            |value| key.encrypt_tag_value(ProfileKey::prepare_input(value.as_bytes())),
        );
        if let Some(filter) = enc.encode_query(&tag_query)? {
            let filter = replace_odbc_arg_placeholders(&filter);
            Ok(Some((filter, enc.arguments)))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

fn replace_odbc_arg_placeholders(
    filter: &str,
) -> String {
    let mut buffer: String = String::with_capacity(filter.len());
    let mut remain = filter;
    while let Some(start_offs) = remain.find('$') {
        let mut iter = remain[(start_offs + 1)..].chars();
        if let Some((end_offs)) = iter.next().and_then(|c| match c {
            '$' => Some(start_offs + 2),
            '0'..='9' => {
                let mut end_offs = start_offs + 2;
                for c in iter {
                    if c.is_ascii_digit() {
                        end_offs += 1;
                    } else {
                        break;
                    }
                }
                Some(
                    end_offs,
                )
            }
            _ => None,
        }) {
            buffer.push_str(&remain[..start_offs]);
            buffer.push_str("?");
            remain = &remain[end_offs..];
        } else {
            buffer.push_str(&remain[..=start_offs]);
            remain = &remain[(start_offs + 1)..];
        }
    }
    buffer.push_str(remain);
    buffer
}

fn extend_odbc_query(
    query: &str,
    args: &mut Vec<Box<dyn InputParameter>>,
    tag_filter: Option<(String, Vec<Vec<u8>>)>,
    order_by: Option<OrderBy>,
    descending: bool,
) -> Result<String, Error>
{
    let mut query = query.to_string();
    if let Some((filter_clause, filter_args)) = tag_filter {
        for arg in filter_args.iter() {
            args.push(Box::new(arg.clone().into_parameter()));
        }
        query.push_str(" AND "); // assumes WHERE already occurs
        query.push_str(&filter_clause);
    };

    // Only add ordering if the query starts with SELECT
    if query.trim_start().to_uppercase().starts_with("SELECT") {
        if let Some(order_by_value) = order_by {
            query = order_by_odbc_query(query, order_by_value, descending);
        };
    }
    Ok(query)
}

fn order_by_odbc_query(mut query: String, order_by: OrderBy, descending: bool) -> String {
    query.push_str(" ORDER BY ");
    match order_by {
        OrderBy::Id => query.push_str("id"),
    }
    if descending {
        query.push_str(" DESC");
    }
    query
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn odbc_simple_and_convert_args_works() {
        assert_eq!(
            &replace_odbc_arg_placeholders("This $1 is $2 a $3 string!"),
            "This ? is ? a ? string!",
        );
    }
}
