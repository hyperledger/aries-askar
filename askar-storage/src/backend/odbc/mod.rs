use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use super::{
    db_utils::random_profile_name,
    Backend, BackendSession,
};
use crate::{
    backend::OrderBy,
    entry::{Entry, EntryKind, EntryOperation, EntryTag, Scan, TagFilter},
    error::Error,
    future::BoxFuture,
    protect::{EntryEncryptor, KeyCache, PassKey, ProfileKey, StoreKeyMethod},
};

mod provision;
pub use self::provision::OdbcStoreOptions;

mod r2d2_connection_pool;
use crate::odbc::r2d2_connection_pool::OdbcConnectionManager;

#[cfg(any(test, feature = "odbc_test"))]
mod test_db;
#[cfg(any(test, feature = "odbc_test"))]
pub use self::test_db::TestDB;

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

/*
const CONFIG_FETCH_QUERY: &str = "SELECT value FROM config WHERE name = $1";
const CONFIG_UPDATE_QUERY: &str = "INSERT INTO config (name, value) VALUES ($1, $2)
    ON CONFLICT(name) DO UPDATE SET value = excluded.value";
const COUNT_QUERY: &str = "SELECT COUNT(*) FROM items i
    WHERE profile_id = $1
    AND (kind = $2 OR $2 IS NULL)
    AND (category = $3 OR $3 IS NULL)
    AND (expiry IS NULL OR expiry > CURRENT_TIMESTAMP)";
const DELETE_QUERY: &str = "DELETE FROM items
    WHERE profile_id = $1 AND kind = $2 AND category = $3 AND name = $4";
const FETCH_QUERY: &str = "SELECT id, value,
    (SELECT ARRAY_TO_STRING(ARRAY_AGG(it.plaintext || ':'
        || ENCODE(it.name, 'hex') || ':' || ENCODE(it.value, 'hex')), ',')
        FROM items_tags it WHERE it.item_id = i.id) tags
    FROM items i
    WHERE profile_id = $1 AND kind = $2 AND category = $3 AND name = $4
    AND (expiry IS NULL OR expiry > CURRENT_TIMESTAMP)";
const FETCH_QUERY_UPDATE: &str = "SELECT id, value,
    (SELECT ARRAY_TO_STRING(ARRAY_AGG(it.plaintext || ':'
        || ENCODE(it.name, 'hex') || ':' || ENCODE(it.value, 'hex')), ',')
        FROM items_tags it WHERE it.item_id = i.id) tags
    FROM items i
    WHERE profile_id = $1 AND kind = $2 AND category = $3 AND name = $4
    AND (expiry IS NULL OR expiry > CURRENT_TIMESTAMP) FOR NO KEY UPDATE";
const INSERT_QUERY: &str = "INSERT INTO items (profile_id, kind, category, name, value, expiry)
    VALUES ($1, $2, $3, $4, $5, $6)
    ON CONFLICT DO NOTHING RETURNING id";
const UPDATE_QUERY: &str = "UPDATE items SET value=$5, expiry=$6
    WHERE profile_id=$1 AND kind=$2 AND category=$3 AND name=$4
    RETURNING id";
const SCAN_QUERY: &str = "SELECT id, kind, category, name, value,
    (SELECT ARRAY_TO_STRING(ARRAY_AGG(it.plaintext || ':'
        || ENCODE(it.name, 'hex') || ':' || ENCODE(it.value, 'hex')), ',')
        FROM items_tags it WHERE it.item_id = i.id) tags
    FROM items i WHERE profile_id = $1
    AND (kind = $2 OR $2 IS NULL)
    AND (category = $3 OR $3 IS NULL)
    AND (expiry IS NULL OR expiry > CURRENT_TIMESTAMP)";
const DELETE_ALL_QUERY: &str = "DELETE FROM items i
    WHERE profile_id = $1
    AND (kind = $2 OR $2 IS NULL)
    AND (category = $3 OR $3 IS NULL)";
const TAG_INSERT_QUERY: &str = "INSERT INTO items_tags
    (item_id, name, value, plaintext) VALUES ($1, $2, $3, $4)";
const TAG_DELETE_QUERY: &str = "DELETE FROM items_tags
    WHERE item_id=$1";
 */

/// A ODBC database store
pub struct OdbcBackend {
    active_profile: String,
    key_cache: Arc<KeyCache>,
    host: String,
    name: String,
}

impl OdbcBackend {
    pub(crate) fn new(
        active_profile: String,
        key_cache: KeyCache,
        host: String,
        name: String,
    ) -> Self {
        Self {
            active_profile,
            key_cache: Arc::new(key_cache),
            host,
            name,
        }
    }
}

impl Backend for OdbcBackend {
    type Session = OdbcSession;

    fn create_profile(&self, name: Option<String>) -> BoxFuture<'_, Result<String, Error>> {
        let name = name.unwrap_or_else(random_profile_name);
        Box::pin(async move { Err(err_msg!(Unsupported, "mod::create_profile()")) })
    }

    fn get_active_profile(&self) -> String {
        self.active_profile.clone()
    }

    fn get_default_profile(&self) -> BoxFuture<'_, Result<String, Error>> {
        Box::pin(async move { Err(err_msg!(Unsupported, "mod::get_default_profile()")) })
    }

    fn set_default_profile(&self, profile: String) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move { Err(err_msg!(Unsupported, "mod::set_default_profile()")) })
    }

    fn list_profiles(&self) -> BoxFuture<'_, Result<Vec<String>, Error>> {
        Box::pin(async move { Err(err_msg!(Unsupported, "mod::list_profiles()")) })
    }

    fn remove_profile(&self, name: String) -> BoxFuture<'_, Result<bool, Error>> {
        Box::pin(async move { Err(err_msg!(Unsupported, "mod::remove_profile()")) })
    }

    fn rekey(
        &mut self,
        method: StoreKeyMethod,
        pass_key: PassKey<'_>,
    ) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move { Err(err_msg!(Unsupported, "mod::rekey()")) })
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
        Box::pin(async move { Err(err_msg!(Unsupported, "mod::close()")) })
    }
}

impl Debug for OdbcBackend {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("OdbcStore")
            .field("active_profile", &self.active_profile)
            .field("host", &self.host)
            .field("name", &self.name)
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
