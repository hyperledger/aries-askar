use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;
use std::collections::BTreeMap;

use odbc_api::{
    buffers::{RowVec},
    Cursor,
    IntoParameter,
    parameter::{VarCharArray}
};

use super::{
    db_utils::{random_profile_name, encode_profile_key},
    Backend, BackendSession,
};
use crate::{
    backend::OrderBy,
    entry::{Entry, EntryKind, EntryOperation, EntryTag, Scan, TagFilter},
    error::Error,
    future::{BoxFuture, unblock},
    protect::{EntryEncryptor, KeyCache, PassKey, ProfileId, ProfileKey, StoreKeyMethod},
};

mod provision;
pub use self::provision::OdbcStoreOptions;

mod r2d2_connection_pool;
use crate::odbc::r2d2_connection_pool::OdbcConnectionManager;

/*
The following queries will need to be updated:

    CONFIG_UPDATE_QUERY:
        - change to retrieve and then either insert or update (2 queries)

    FETCH_QUERY:
        - change to use an inner join

    UPDATE_QUERY:
        - change to two queies, one to update and another to retrieve the id

    SCAN_QUERY:
        - change to use an inner join

    CONFIG_FETCH_QUERY:
    COUNT_QUERY:
    DELETE_QUERY:
    INSERT_QUERY:
    DELETE_ALL_QUERY:
    TAG_INSERT_QUERY:
    TAG_DELETE_QUERY:
        - standard query
*/

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
            self.pool.get().unwrap().raw().execute("INSERT INTO profiles (name, profile_key) VALUES (?, ?)",
                (&name.clone().into_parameter(), &enc_key.clone().into_parameter()))?;

            // Retrieve the profile ID from the table.
            let mut pid: i64 = 0;

            self.pool.get().unwrap().raw().execute(
                "SELECT id from profiles WHERE name=? and profile_key=?",
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

            self.pool.get().unwrap().raw().execute(
                    "SELECT value FROM config WHERE name='default_profile'", ())
                .unwrap().unwrap()
                .next_row().unwrap().unwrap()
                .get_text(1, &mut profile_buf)?;

            Ok(String::from_utf8(profile_buf).unwrap())
        })
    }

    fn set_default_profile(&self, profile: String) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            self.pool.get().unwrap().raw().execute("UPDATE config SET value = ? WHERE name='default_profile'",
                    (&profile.into_parameter()))?;
            Ok(())
        })
    }

    fn list_profiles(&self) -> BoxFuture<'_, Result<Vec<String>, Error>> {
        Box::pin(async move {
            let mut names: Vec<String> = Vec::new();

            match self.pool.get().unwrap().raw().execute("SELECT name FROM profiles", ()) {
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

            self.pool.get().unwrap().raw().execute(
                    "SELECT COUNT(name) from profiles WHERE name=?",
                        (&name.clone().into_parameter()))
                .unwrap().unwrap()
                .next_row().unwrap().unwrap()
                .get_data(1, &mut count)?;

            if count > 0 {
                self.pool.get().unwrap().raw().execute("DELETE FROM profiles WHERE name=?",
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
            match binding.raw().execute(
                "SELECT id, profile_key FROM profiles", ()) {
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

                binding.raw().execute("UPDATE profiles SET profile_key=? WHERE id=?",
                    (&upd_key.into_parameter(), &pid.into_parameter()))?;
            }

            // We finally need to save the new store key.
            binding.raw().execute("UPDATE config SET value=? WHERE name='key'",
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
        Box::pin(async move { Err(err_msg!(Unsupported, "mod::scan()")) })
    }

    fn session(&self, profile: Option<String>, transaction: bool) -> Result<Self::Session, Error> {
        return Err(err_msg!(Unsupported, "mod::session()"));
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
pub struct OdbcSession {}

impl OdbcSession {}

impl BackendSession for OdbcSession {
    fn count<'q>(
        &'q mut self,
        kind: Option<EntryKind>,
        category: Option<&'q str>,
        tag_filter: Option<TagFilter>,
    ) -> BoxFuture<'q, Result<i64, Error>> {
        let enc_category = category.map(|c| ProfileKey::prepare_input(c.as_bytes()));

        Box::pin(async move { Ok(5) })
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

        Box::pin(async move { Ok(None) })
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
        let category = category.map(|c| c.to_string());
        Box::pin(async move { Err(err_msg!(Unsupported, "mod::fetch_all()")) })
    }

    fn remove_all<'q>(
        &'q mut self,
        kind: Option<EntryKind>,
        category: Option<&'q str>,
        tag_filter: Option<TagFilter>,
    ) -> BoxFuture<'q, Result<i64, Error>> {
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

        Box::pin(async move { Err(err_msg!(Unsupported, "mod::update()")) })
    }

    fn ping(&mut self) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move { Err(err_msg!(Unsupported, "mod::ping()")) })
    }

    fn close(&mut self, commit: bool) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(self.close(commit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::db_utils::replace_arg_placeholders;

    /*
    #[test]
    fn odbc_simple_and_convert_args_works() {
        assert_eq!(
            &replace_arg_placeholders::<OdbcBackend>("This $$ is $10 a $$ string!", 3),
            "This $3 is $12 a $5 string!",
        );
    }
    */
}
