use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use futures_lite::stream::{Stream, StreamExt};

use super::keys::{
    store_key::StoreKey,
    wrap::{generate_raw_wrap_key, WrapKey, WrapKeyMethod},
};
use super::options::IntoOptions;
use super::types::{Entry, EntryFetchOptions, KeyId, ProfileId, UpdateEntry};
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

/// Common trait for all key-value storage backends
#[async_trait]
pub trait Store {
    /// Count the number of entries for a given record category
    async fn count(
        &self,
        profile_id: Option<ProfileId>,
        category: String,
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
        category: String,
        name: String,
        options: EntryFetchOptions,
    ) -> Result<Option<Entry>>;

    /// Start a new query for a particular `key_id` and `category`
    ///
    /// If `key_id` is provided, restrict results to records for the particular key.
    /// Otherwise, all relevant keys for the given `profile_id` are searched.
    /// Results are not guaranteed to be ordered.
    async fn scan(
        &self,
        profile_id: Option<ProfileId>,
        category: String,
        options: EntryFetchOptions,
        tag_filter: Option<wql::Query>,
        offset: Option<i64>,
        max_rows: Option<i64>,
    ) -> Result<EntryScan>;

    /// Atomically set multiple values with optional expiry times
    ///
    /// Stores values with the latest key for the provided `profile_id` unless `key_id` is
    /// provided. Creates a new entry or updates an existing one.
    ///
    /// The `with_lock` argument can be used to specify a lock operation: verify an
    /// existing record lock, or verify it and release it upon completion of the update.
    /// Provide NULL for the entry value to remove existing records
    /// Returns an error if the lock was lost or one of the keys could not be assigned.
    async fn update(&self, profile_id: Option<ProfileId>, entries: Vec<UpdateEntry>) -> Result<()>;

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
    /// `Entry` representing the current record at that key, whether pre-existing or
    /// newly inserted.
    ///
    /// Other clients are not prevented from reading or writing the record unless they
    /// also try to obtain a lock.
    async fn create_lock(
        &self,
        profile_id: Option<ProfileId>,
        lock_info: UpdateEntry,
        acquire_timeout_ms: Option<i64>,
    ) -> Result<(Entry, EntryLock)>;

    /// Close the store instance, waiting for any shutdown procedures to complete.
    async fn close(&self) -> Result<()>;
}

pub struct EntryScan {
    stream: Option<Pin<Box<dyn Stream<Item = Result<Vec<Entry>>> + Send>>>,
    page_size: usize,
}

impl EntryScan {
    pub fn new<S>(stream: S, page_size: usize) -> Self
    where
        S: Stream<Item = Result<Vec<Entry>>> + Send + 'static,
    {
        Self {
            stream: Some(stream.boxed()),
            page_size,
        }
    }

    pub async fn fetch_next(&mut self) -> Result<Option<Vec<Entry>>> {
        if let Some(mut s) = self.stream.take() {
            match s.next().await {
                Some(Ok(val)) => {
                    if val.len() == self.page_size {
                        self.stream.replace(s);
                    }
                    Ok(Some(val))
                }
                Some(Err(err)) => Err(err),
                None => Ok(None),
            }
        } else {
            Ok(None)
        }
    }
}

pub struct EntryLock {
    update_fn: Box<
        dyn FnOnce(Vec<UpdateEntry>) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send,
    >,
}

impl EntryLock {
    pub fn new<F, G>(update: F) -> Self
    where
        F: FnOnce(Vec<UpdateEntry>) -> G + Send + 'static,
        G: Future<Output = Result<()>> + Send + 'static,
    {
        Self {
            update_fn: Box::new(|entries| Box::pin(update(entries))),
        }
    }

    pub async fn update(self, entries: Vec<UpdateEntry>) -> Result<()> {
        let fut = (self.update_fn)(entries);
        fut.await
    }
}

#[derive(Debug)]
pub struct ProvisionStoreSpec {
    pub enc_store_key: Vec<u8>,
    pub pass_key: Option<String>,
    pub profile_id: String,
    pub store_key: StoreKey,
    pub wrap_key: Option<WrapKey>,
    pub wrap_key_ref: String,
}

impl ProvisionStoreSpec {
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
pub trait ProvisionStore {
    type Store;

    async fn provision_store(self, spec: ProvisionStoreSpec) -> Result<Self::Store>;
}

pub type ArcStore = Arc<dyn Store + Send + Sync>;

#[async_trait]
impl ProvisionStore for &str {
    type Store = ArcStore;

    async fn provision_store(self, spec: ProvisionStoreSpec) -> Result<Self::Store> {
        let opts = self.into_options()?;
        let store: ArcStore = match opts.schema.as_ref() {
            #[cfg(feature = "postgres")]
            "postgres" => Arc::new(
                super::postgres::PostgresStoreOptions::new(opts)?
                    .provision_store(spec)
                    .await?,
            ),

            #[cfg(feature = "sqlite")]
            "sqlite" => {
                let opts = super::sqlite::SqliteStoreOptions::new(opts)?;
                debug!("SQLite provision with options: {:?}", &opts);
                Arc::new(opts.provision_store(spec).await?)
            }

            _ => return Err(ErrorKind::Unsupported.into()),
        };
        Ok(store)
    }
}
