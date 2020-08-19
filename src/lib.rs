use async_trait::async_trait;

mod error;
use error::KvResult;

pub(crate) mod db_utils;

pub mod indy_compat;

#[cfg(feature = "postgres")]
pub mod postgres;

#[cfg(feature = "sqlite")]
pub mod sqlite;

mod keys;
mod types;
mod wql;

use types::{KvEntry, KvFetchOptions, KvKeySelect, KvLockOperation, KvUpdateEntry};

#[async_trait]
pub trait KvProvisionStore {
    async fn provision(&self) -> KvResult<()>;
}

/// Common trait for all key-value storage backends
#[async_trait]
pub trait KvStore {
    type LockToken: Send + Sync + Sized + 'static;
    type ScanToken: Send + Sync + Sized + 'static;

    /// Count the number of entries for a given record category
    async fn count(
        &self,
        profile_key: KvKeySelect,
        category: &[u8],
        tag_filter: Option<wql::Query>,
    ) -> KvResult<i64>;

    /// Query the current value for the record at `(key_id, category, name)`
    ///
    /// A specific `key_id` may be given, otherwise all relevant keys for the provided
    /// `profile_id` are searched in reverse order of creation, returning the first
    /// result found if any.
    async fn fetch(
        &self,
        profile_key: KvKeySelect,
        category: &[u8],
        name: &[u8],
        options: KvFetchOptions,
    ) -> KvResult<Option<KvEntry>>;

    /// Start a new query for a particular `key_id` and `category`
    ///
    /// If `key_id` is provided, restrict results to records for the particular key.
    /// Otherwise, all relevant keys for the given `profile_id` are searched.
    /// Results are not guaranteed to be ordered.
    async fn scan_start(
        &self,
        profile_key: KvKeySelect,
        category: &[u8],
        options: KvFetchOptions,
        tag_filter: Option<wql::Query>,
        offset: Option<i64>,
        max_rows: Option<i64>,
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
    /// Stores values with the latest key for the provided `profile_id` unless `key_id` is
    /// provided. Creates a new entry or updates an existing one.
    ///
    /// The `with_lock` argument can be used to specify a lock operation: verify an
    /// existing record lock, or verify it and release it upon completion of the update.
    /// Provide NULL for the entry value to remove existing records
    /// Returns an error if the lock was lost or one of the keys could not be assigned.
    async fn update(
        &self,
        entries: Vec<KvUpdateEntry>,
        with_lock: Option<KvLockOperation<Self::LockToken>>,
    ) -> KvResult<()>;

    /// Establish an advisory lock on a particular record
    ///
    /// The `entry` parameter defines the `category` and `name` of the record, as well
    /// as its key information. If the record does not exist, then it will be created
    /// with the default `value`, `tags`, and `expiry` provided.
    ///
    /// The maximum duration of a lock is defined by the backend and its configuration
    /// parameters. If `acquire_timeout_ms` is specified, then the operation blocks
    /// until either a lock can be obtained or the timeout occurs.
    ///
    /// Returns a pair of an optional lock token (None if no lock was acquired) and a
    /// `KvEntry` representing the current record at that key, whether pre-existing or
    /// newly inserted.
    ///
    /// Other clients are not prevented from reading or writing the record unless they
    /// also try to obtain a lock.
    async fn create_lock(
        &self,
        entry: KvUpdateEntry,
        acquire_timeout_ms: Option<i64>,
    ) -> KvResult<(Option<Self::LockToken>, KvEntry)>;
}
