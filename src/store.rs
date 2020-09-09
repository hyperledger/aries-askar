use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use async_trait::async_trait;

use super::keys::{
    store_key::StoreKey,
    wrap::{generate_raw_wrap_key, WrapKey, WrapKeyMethod},
};
use super::options::IntoOptions;
use super::types::{KeyId, KvEntry, KvFetchOptions, KvUpdateEntry, ProfileId};
use super::wql;
use super::{ErrorKind, Result};

pub struct KeyCache {
    profile_active_keys: BTreeMap<ProfileId, KeyId>,
    store_keys: BTreeMap<KeyId, Arc<StoreKey>>,
    wrap_key: Option<WrapKey>,
}

impl KeyCache {
    pub fn new(wrap_key: Option<WrapKey>) -> Self {
        Self {
            profile_active_keys: BTreeMap::new(),
            store_keys: BTreeMap::new(),
            wrap_key,
        }
    }

    pub fn set_profile_key(&mut self, pid: ProfileId, kid: KeyId, key: StoreKey) {
        self.profile_active_keys.insert(pid, kid);
        self.store_keys.insert(kid, Arc::new(key));
    }

    pub fn get_profile_key(&self, pid: ProfileId) -> Option<(KeyId, Option<Arc<StoreKey>>)> {
        self.profile_active_keys
            .get(&pid)
            .map(|kid| (*kid, self.store_keys.get(kid).cloned()))
    }

    pub fn get_wrap_key(&self) -> Option<&WrapKey> {
        self.wrap_key.as_ref()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScanToken {
    pub id: usize,
}

impl ScanToken {
    const COUNT: AtomicUsize = AtomicUsize::new(0);

    pub fn next() -> Self {
        Self {
            id: Self::COUNT.fetch_add(1, Ordering::AcqRel),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LockToken {
    pub id: usize,
}

impl LockToken {
    const COUNT: AtomicUsize = AtomicUsize::new(0);

    pub fn next() -> Self {
        Self {
            id: Self::COUNT.fetch_add(1, Ordering::AcqRel),
        }
    }
}

/// Common trait for all key-value storage backends
#[async_trait]
pub trait KvStore {
    /// Count the number of entries for a given record category
    async fn count(
        &self,
        profile_id: Option<ProfileId>,
        category: &[u8],
        tag_filter: Option<wql::Query>,
    ) -> Result<i64>;

    /// Query the current value for the record at `(key_id, category, name)`
    ///
    /// A specific `key_id` may be given, otherwise all relevant keys for the provided
    /// `profile_id` are searched in reverse order of creation, returning the first
    /// result found if any.
    async fn fetch(
        &self,
        profile_id: Option<ProfileId>,
        category: &[u8],
        name: &[u8],
        options: KvFetchOptions,
    ) -> Result<Option<KvEntry>>;

    /// Start a new query for a particular `key_id` and `category`
    ///
    /// If `key_id` is provided, restrict results to records for the particular key.
    /// Otherwise, all relevant keys for the given `profile_id` are searched.
    /// Results are not guaranteed to be ordered.
    async fn scan_start(
        &self,
        profile_id: Option<ProfileId>,
        category: &[u8],
        options: KvFetchOptions,
        tag_filter: Option<wql::Query>,
        offset: Option<i64>,
        max_rows: Option<i64>,
    ) -> Result<ScanToken>;

    /// Fetch results for a scan query
    ///
    /// Pass in the previous `scan_token` value to fetch the next set of records.
    /// An empty `scan_token` is returned once all records have been visited.
    async fn scan_next(&self, scan_token: ScanToken) -> Result<(Vec<KvEntry>, Option<ScanToken>)>;

    /// Atomically set multiple values with optional expiry times
    ///
    /// Stores values with the latest key for the provided `profile_id` unless `key_id` is
    /// provided. Creates a new entry or updates an existing one.
    ///
    /// The `with_lock` argument can be used to specify a lock operation: verify an
    /// existing record lock, or verify it and release it upon completion of the update.
    /// Provide NULL for the entry value to remove existing records
    /// Returns an error if the lock was lost or one of the keys could not be assigned.
    async fn update(&self, entries: Vec<KvUpdateEntry>, with_lock: Option<LockToken>)
        -> Result<()>;

    /// Establish an advisory lock on a particular record
    ///
    /// The `lock_info` parameter defines the `category` and `name` of the record, as well
    /// as its key information. If the record does not exist then it will be created
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
        lock_info: KvUpdateEntry,
        options: KvFetchOptions,
        acquire_timeout_ms: Option<i64>,
    ) -> Result<Option<(LockToken, KvEntry)>>;
}

pub struct KvProvisionSpec {
    pub enc_store_key: Vec<u8>,
    pub pass_key: Option<String>,
    pub profile_id: String,
    pub store_key: StoreKey,
    pub wrap_key: Option<WrapKey>,
    pub wrap_key_ref: String,
}

impl KvProvisionSpec {
    pub async fn create(method: WrapKeyMethod, pass_key: Option<String>) -> Result<Self> {
        let store_key = StoreKey::new()?;
        let key_data = serde_json::to_vec(&store_key).map_err(err_map!(Unexpected))?;
        let (enc_store_key, wrap_key, wrap_key_ref) = method
            .wrap_data(&key_data, pass_key.as_ref().map(String::as_str))
            .await?;
        let profile_id = uuid::Uuid::new_v4().to_string();
        Ok(Self {
            enc_store_key: enc_store_key.into_owned(),
            pass_key,
            profile_id,
            store_key,
            wrap_key,
            wrap_key_ref: wrap_key_ref.into_uri(),
        })
    }

    pub async fn create_default() -> Result<Self> {
        let key = generate_raw_wrap_key()?;
        Self::create(WrapKeyMethod::RawKey, Some(key)).await
    }
}

#[async_trait]
pub trait KvProvisionStore {
    type Store;

    async fn provision_store(self, spec: KvProvisionSpec) -> Result<Self::Store>;
}

#[async_trait]
impl KvProvisionStore for &str {
    type Store = Box<dyn KvStore>;

    async fn provision_store(self, spec: KvProvisionSpec) -> Result<Self::Store> {
        let opts = self.into_options()?;
        let store: Box<dyn KvStore> = match opts.schema.as_ref() {
            #[cfg(feature = "postgres")]
            "postgres" => Box::new(
                super::postgres::KvPostgresOptions::new(opts)?
                    .provision_store(spec)
                    .await?,
            ),

            #[cfg(feature = "sqlite")]
            "sqlite" => Box::new(
                super::sqlite::KvSqliteOptions::new(opts)?
                    .provision_store(spec)
                    .await?,
            ),

            _ => return Err(ErrorKind::Unsupported.into()),
        };
        Ok(store)
    }
}
