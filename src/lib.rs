#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate zeroize;

use async_trait::async_trait;

mod error;
use error::KvResult;

mod pool;

#[cfg(feature = "postgres")]
pub mod postgres;

#[cfg(feature = "sqlite")]
pub mod sqlite;

mod kms;
mod types;
mod wql;

use types::{
    ClientId, KvEntry, KvFetchOptions, KvKeySelect, KvLockOperation, KvLockToken, KvScanToken,
    KvUpdateEntry,
};

#[async_trait]
pub trait KvProvisionStore {
    async fn provision(&self) -> KvResult<()>;
}

/// Common trait for all key-value storage backends
#[async_trait]
pub trait KvStore {
    type LockToken: KvLockToken;
    type ScanToken: KvScanToken;

    /// Count the number of entries for a given record category
    async fn count(
        &self,
        client_key: KvKeySelect,
        category: &[u8],
        tag_filter: Option<wql::Query>,
    ) -> KvResult<u64>;

    /// Query the current value for the record at `(client_id, category, name)`
    ///
    /// If no specific `key_id` is provided then all keys for the given `client_id`
    /// are searched in reverse order of creation, returning the first result found if any.
    async fn fetch(
        &self,
        client_key: KvKeySelect,
        category: &[u8],
        name: &[u8],
        options: KvFetchOptions,
    ) -> KvResult<Option<KvEntry>>;

    /// Start a new query for particular `client_id` and `category`
    ///
    /// If `key_id` is provided, restrict results to records for the particular key.
    /// Results are not guaranteed to be ordered.
    /// Pass in the previous `scan_token` value to fetch the next set of records.
    /// An empty `scan_token` is returned once all records have been visited.
    async fn scan_start(
        &self,
        client_key: KvKeySelect,
        category: &[u8],
        options: KvFetchOptions,
        tag_filter: Option<wql::Query>,
        max_rows: Option<u64>,
    ) -> KvResult<Self::ScanToken>;

    /// Fetch results for a scan query
    ///
    /// Pass in the previous `scan_token` value to fetch the next set of records.
    /// An empty `scan_token` is returned once all records have been visited.
    async fn scan_next(
        &self,
        scan_token: Self::ScanToken,
    ) -> KvResult<(Vec<KvEntry>, Option<Self::ScanToken>)>;

    /// Atomically set multiple values with optional expiry times
    ///
    /// Stores values with the latest key for the provided `client_id` unless `key_id` is
    /// provided. Creates a new entry or updates an existing one.
    ///
    /// If lock_token is provided, the lock is verified before committing the changes. If
    /// `release_lock` is specified then the lock is released as part of the transaction.
    /// Provide NULL for the value to remove existing records
    /// Returns false if the lock was lost or one of the keys could not be assigned
    async fn update(
        &self,
        entries: Vec<KvUpdateEntry>,
        with_lock: Option<KvLockOperation<Self::LockToken>>,
    ) -> KvResult<()>;

    /// Establish an advisory lock on a particular record identifier
    ///
    /// The lock is automatically released after `max_duration_ms` in case the client runs
    /// into an error and does not release it manually. If `acquire_timeout_ms` is specified,
    /// then the operation blocks until a lock can be obtained or the timeout occurs.
    ///
    /// Returns a opaque token used to distinguish separate client locks.
    /// Also returns the value of the record at `(client_id, category, name)` or `None`.
    /// Does not prevent other clients from reading or writing the record unless they also
    /// wait to obtain a lock.
    async fn create_lock(
        &self,
        client_id: ClientId,
        category: &[u8],
        name: &[u8],
        max_duration_ms: Option<u64>,
        acquire_timeout_ms: Option<u64>,
    ) -> KvResult<(Self::LockToken, Option<KvEntry>)>;

    /// Verify an existing lock and optionally extend the duration
    async fn refresh_lock(
        &self,
        token: Self::LockToken,
        max_duration_ms: Option<u64>,
    ) -> KvResult<Self::LockToken>;
}
