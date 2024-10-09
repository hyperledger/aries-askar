//! Store wrapper for running tests against a odbc database

use std::time::Duration;

use super::provision::OdbcStoreOptions;
use super::OdbcBackend;
use crate::{
    any::{into_any_backend, AnyBackend},
    backend::{
        db_utils::{init_keys, random_profile_name},
        Backend,
    },
    error::Error,
    future::{sleep, spawn_ok, timeout, unblock},
    protect::{generate_raw_store_key, KeyCache, StoreKeyMethod},
};

#[derive(Debug)]
/// Postgres test database wrapper instance
pub struct TestDB {
    inst: Option<AnyBackend>,
}

impl TestDB {
    /// Access the backend instance
    pub fn backend(&self) -> AnyBackend {
        self.inst.clone().expect("Database not opened")
    }

    /// Provision a new instance of the test database.
    /// This method blocks until the database lock can be acquired.
    pub async fn provision(db_url: &str) -> Result<TestDB, Error> {
        let key = generate_raw_store_key(None)?;
        let (profile_key, enc_profile_key, store_key, store_key_ref) =
            unblock(|| init_keys(StoreKeyMethod::RawKey, key)).await?;
        let default_profile = random_profile_name();

        let opts = OdbcStoreOptions::new(db_url)?;

        /*
        // delete existing tables
        reset_db(&mut init_txn).await?;

        // create tables and add default profile
        let profile_id = init_db(
            init_txn,
            &default_profile,
            store_key_ref,
            enc_profile_key,
            &opts.username,
        )
        .await?;

        let mut key_cache = KeyCache::new(store_key);
        key_cache.add_profile_mut(default_profile.clone(), profile_id, profile_key);
        let inst = into_any_backend(OdbcBackend::new(
            default_profile,
            key_cache,
            opts.host,
            opts.name,
        ));

        Ok(TestDB {
            inst: Some(inst),
            lock_txn: Some(lock_txn),
        })
        */

        Err(err_msg!(Unsupported, "test_db::provision()"))
    }

    /// Explicitly close the test database
    pub async fn close(mut self) -> Result<(), Error> {
        Ok(())
    }
}
