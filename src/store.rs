use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use futures_lite::stream::{Stream, StreamExt};
use indy_utils::{
    keys::{EncodedVerKey, KeyType as IndyKeyAlg, PrivateKey},
    pack::{pack_message, unpack_message, KeyLookup},
    Validatable,
};

use super::keys::{
    store::StoreKey,
    wrap::{generate_raw_wrap_key, WrapKey, WrapKeyMethod},
    KeyAlg, KeyCategory, KeyEntry, KeyParams,
};
use super::options::IntoOptions;
use super::types::{Entry, EntryFetchOptions, EntryKind, EntryTag, ProfileId, UpdateEntry};
use super::wql;
use super::{Result};

pub struct KeyCache {
    profile_info: HashMap<String, (ProfileId, Arc<StoreKey>)>,
    wrap_key: WrapKey,
}

impl KeyCache {
    pub fn new(wrap_key: WrapKey) -> Self {
        Self {
            profile_info: HashMap::new(),
            wrap_key,
        }
    }

    pub async fn load_key(&self, ciphertext: Vec<u8>) -> Result<StoreKey> {
        serde_json::from_slice(&self.wrap_key.unwrap_data(ciphertext).await?)
            .map_err(err_map!(Unsupported, "Invalid store key"))
    }

    pub fn add_profile(&mut self, ident: String, pid: ProfileId, key: StoreKey) {
        self.profile_info.insert(ident, (pid, Arc::new(key)));
    }

    pub fn get_profile(&self, name: &str) -> Option<(ProfileId, Arc<StoreKey>)> {
        self.profile_info.get(name).cloned()
    }

    #[allow(unused)]
    pub fn get_wrap_key(&self) -> &WrapKey {
        &self.wrap_key
    }
}

/// Common trait for all key-value storage backends
#[async_trait]
pub trait RawStore: Send + Sync {
    async fn count(
        &self,
        profile: Option<String>,
        kind: EntryKind,
        category: String,
        tag_filter: Option<wql::Query>,
    ) -> Result<i64>;

    async fn fetch(
        &self,
        profile: Option<String>,
        kind: EntryKind,
        category: String,
        name: String,
        options: EntryFetchOptions,
    ) -> Result<Option<Entry>>;

    async fn scan(
        &self,
        profile: Option<String>,
        kind: EntryKind,
        category: String,
        options: EntryFetchOptions,
        tag_filter: Option<wql::Query>,
        offset: Option<i64>,
        max_rows: Option<i64>,
    ) -> Result<Scan<Entry>>;

    async fn update(
        &self,
        profile: Option<String>,
        kind: EntryKind,
        entries: Vec<UpdateEntry>,
    ) -> Result<()>;

    async fn create_lock(
        &self,
        profile: Option<String>,
        kind: EntryKind,
        lock_info: UpdateEntry,
        acquire_timeout_ms: Option<i64>,
    ) -> Result<(Entry, EntryLock)>;

    async fn close(&self) -> Result<()>;
}

#[async_trait]
impl<T: RawStore + ?Sized + Send + Sync> RawStore for Arc<T> {
    #[inline]
    async fn count(
        &self,
        profile: Option<String>,
        kind: EntryKind,
        category: String,
        tag_filter: Option<wql::Query>,
    ) -> Result<i64> {
        T::count(&*self, profile, kind, category, tag_filter).await
    }

    #[inline]
    async fn fetch(
        &self,
        profile: Option<String>,
        kind: EntryKind,
        category: String,
        name: String,
        options: EntryFetchOptions,
    ) -> Result<Option<Entry>> {
        T::fetch(&*self, profile, kind, category, name, options).await
    }

    #[inline]
    async fn scan(
        &self,
        profile: Option<String>,
        kind: EntryKind,
        category: String,
        options: EntryFetchOptions,
        tag_filter: Option<wql::Query>,
        offset: Option<i64>,
        max_rows: Option<i64>,
    ) -> Result<Scan<Entry>> {
        T::scan(
            &*self, profile, kind, category, options, tag_filter, offset, max_rows,
        )
        .await
    }

    #[inline]
    async fn update(
        &self,
        profile: Option<String>,
        kind: EntryKind,
        entries: Vec<UpdateEntry>,
    ) -> Result<()> {
        T::update(&*self, profile, kind, entries).await
    }

    #[inline]
    async fn create_lock(
        &self,
        profile: Option<String>,
        kind: EntryKind,
        lock_info: UpdateEntry,
        acquire_timeout_ms: Option<i64>,
    ) -> Result<(Entry, EntryLock)> {
        T::create_lock(&*self, profile, kind, lock_info, acquire_timeout_ms).await
    }

    async fn close(&self) -> Result<()> {
        T::close(&*self).await
    }
}

#[derive(Debug)]
pub struct Store<T: RawStore + ?Sized> {
    pub(crate) inner: Arc<T>,
}

impl<T: RawStore> Store<T> {
    pub(crate) fn new(inner: T) -> Self {
        Self {
            inner: Arc::new(inner),
        }
    }

    pub(crate) fn into_inner(self) -> Arc<T> {
        self.inner
    }

    pub(crate) fn into_any(self) -> Store<dyn RawStore>
    where
        T: 'static,
    {
        Store {
            inner: self.inner as Arc<dyn RawStore>,
        }
    }
}

impl<T: RawStore + ?Sized> Store<T> {
    /// Count the number of entries for a given record category
    pub async fn count(
        &self,
        profile: Option<String>,
        category: String,
        tag_filter: Option<wql::Query>,
    ) -> Result<i64> {
        self.inner
            .count(profile, EntryKind::Item, category, tag_filter)
            .await
    }

    /// Query the current value for the record at `(key_id, category, name)`
    ///
    /// A specific `key_id` may be given, otherwise all relevant keys for the provided
    /// `profile_id` are searched in reverse order of creation, returning the first
    /// result found if any.
    pub async fn fetch(
        &self,
        profile: Option<String>,
        category: String,
        name: String,
        options: EntryFetchOptions,
    ) -> Result<Option<Entry>> {
        self.inner
            .fetch(profile, EntryKind::Item, category, name, options)
            .await
    }

    /// Start a new query for a particular `key_id` and `category`
    ///
    /// If `key_id` is provided, restrict results to records for the particular key.
    /// Otherwise, all relevant keys for the given `profile_id` are searched.
    /// Results are not guaranteed to be ordered.
    pub async fn scan(
        &self,
        profile: Option<String>,
        category: String,
        options: EntryFetchOptions,
        tag_filter: Option<wql::Query>,
        offset: Option<i64>,
        max_rows: Option<i64>,
    ) -> Result<Scan<Entry>> {
        self.inner
            .scan(
                profile,
                EntryKind::Item,
                category,
                options,
                tag_filter,
                offset,
                max_rows,
            )
            .await
    }

    /// Atomically set multiple values with optional expiry times
    ///
    /// Stores values with the latest key for the provided `profile_id` unless `key_id` is
    /// provided. Creates a new entry or updates an existing one.
    ///
    /// The `with_lock` argument can be used to specify a lock operation: verify an
    /// existing record lock, or verify it and release it upon completion of the update.
    /// Provide NULL for the entry value to remove existing records
    /// Returns an error if the lock was lost or one of the keys could not be assigned.
    pub async fn update(&self, profile: Option<String>, entries: Vec<UpdateEntry>) -> Result<()> {
        self.inner.update(profile, EntryKind::Item, entries).await
    }

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
    pub async fn create_lock(
        &self,
        profile: Option<String>,
        lock_info: UpdateEntry,
        acquire_timeout_ms: Option<i64>,
    ) -> Result<(Entry, EntryLock)> {
        self.inner
            .create_lock(profile, EntryKind::Item, lock_info, acquire_timeout_ms)
            .await
    }

    pub async fn create_keypair(
        &self,
        profile: Option<String>,
        alg: KeyAlg,
        metadata: Option<String>,
        seed: Option<&[u8]>,
        tags: Option<Vec<EntryTag>>,
        // backend
    ) -> Result<KeyEntry> {
        match alg {
            KeyAlg::ED25519 => (),
            _ => return Err(err_msg!("Unsupported key algorithm")),
        }

        let sk = match seed {
            None => PrivateKey::generate(Some(IndyKeyAlg::ED25519)),
            Some(s) => PrivateKey::from_seed(s),
        }
        .map_err(err_map!(Unexpected, "Error generating keypair"))?;

        let pk = sk
            .public_key()
            .map_err(err_map!(Unexpected, "Error generating public key"))?;

        let category = KeyCategory::KeyPair;
        let ident = pk
            .as_base58()
            .map_err(err_map!(Unexpected, "Error encoding public key"))?
            .long_form();

        let params = KeyParams {
            alg,
            metadata,
            reference: None,
            pub_key: Some(pk.key_bytes()),
            prv_key: Some(sk.key_bytes()),
        };

        let keypair = UpdateEntry {
            category: category.as_str().to_owned(),
            name: ident.clone(),
            value: Some(params.to_vec()?),
            tags: tags.clone(),
            expire_ms: None,
        };

        let (lock_entry, lock) = self
            .inner
            .create_lock(profile, EntryKind::Key, keypair, None)
            .await?;

        if !lock.is_new_record() {
            return Err(err_msg!(Duplicate, "Duplicate key record"));
        }

        Ok(KeyEntry {
            category,
            ident,
            params,
            tags,
        })
    }

    // pub async fn import_key(&self, key: KeyEntry) -> Result<()> {
    //     Ok(())
    // }

    pub async fn fetch_key(
        &self,
        profile: Option<String>,
        category: KeyCategory,
        ident: String,
        options: EntryFetchOptions,
    ) -> Result<Option<KeyEntry>> {
        // normalize ident
        let ident = EncodedVerKey::from_str(&ident)
            .and_then(|k| k.as_base58())
            .map_err(err_map!("Invalid key"))?
            .long_form();

        Ok(
            if let Some(row) = self
                .inner
                .fetch(
                    profile,
                    EntryKind::Key,
                    category.as_str().to_owned(),
                    ident,
                    EntryFetchOptions::new(options.retrieve_tags),
                )
                .await?
            {
                let params = KeyParams::from_slice(&row.value)?;
                Some(KeyEntry {
                    category: KeyCategory::from_str(&row.category).unwrap(),
                    ident: row.name.clone(),
                    params,
                    tags: row.tags.clone(),
                })
            } else {
                None
            },
        )
    }

    pub async fn remove_key(
        &self,
        profile: Option<String>,
        category: KeyCategory,
        ident: String,
    ) -> Result<()> {
        let update = UpdateEntry {
            category: category.as_str().to_owned(),
            name: ident,
            value: None,
            tags: None,
            expire_ms: None,
        };
        self.inner
            .update(profile, EntryKind::Key, vec![update])
            .await
    }

    pub async fn scan_keys(
        &self,
        profile: Option<String>,
        category: String,
        options: EntryFetchOptions,
        tag_filter: Option<wql::Query>,
        offset: Option<i64>,
        max_rows: Option<i64>,
    ) -> Result<Scan<KeyEntry>> {
        unimplemented!();
    }

    pub async fn update_key_metadata(
        &self,
        profile: Option<String>,
        category: KeyCategory,
        ident: String,
        metadata: Option<String>,
    ) -> Result<()> {
        unimplemented!();
    }

    // update_key_tags

    pub async fn sign_message(
        &self,
        profile: Option<String>,
        key_ident: String,
        data: Vec<u8>,
    ) -> Result<Vec<u8>> {
        if let Some(key) = self
            .fetch_key(
                profile,
                KeyCategory::KeyPair,
                key_ident,
                EntryFetchOptions::new(false),
            )
            .await?
        {
            let sk = key.private_key()?;
            sk.sign(&data)
                .map_err(|e| err_msg!("Signature error: {}", e))
        } else {
            return Err(err_msg!("Unknown key")); // FIXME add new error class
        }
    }

    pub async fn verify_signature(
        &self,
        signer_vk: String,
        data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool> {
        let vk = EncodedVerKey::from_str(&signer_vk).map_err(err_map!("Invalid verkey"))?;
        Ok(vk
            .decode()
            .map_err(err_map!("Unsupported verkey"))?
            .verify_signature(&data, &signature)
            .unwrap_or(false))
    }

    pub async fn pack_message(
        &self,
        profile: Option<String>,
        recipient_vks: Vec<String>,
        from_key_ident: Option<String>,
        data: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let sign_key = if let Some(ident) = from_key_ident {
            let sk = self
                .fetch_key(
                    profile,
                    KeyCategory::KeyPair,
                    ident,
                    EntryFetchOptions::new(false),
                )
                .await?
                .ok_or_else(|| err_msg!("Unknown sender key"))?;
            Some(sk.private_key()?)
        } else {
            None
        };
        let vks = recipient_vks
            .into_iter()
            .map(|vk| {
                let vk =
                    EncodedVerKey::from_str(&vk).map_err(err_map!("Invalid recipient verkey"))?;
                vk.validate()?;
                Ok(vk)
            })
            .collect::<Result<Vec<EncodedVerKey>>>()?;
        Ok(pack_message(data, vks, sign_key).map_err(err_map!("Error packing message"))?)
    }

    pub async fn unpack_message(
        &self,
        profile: Option<String>,
        data: Vec<u8>,
    ) -> Result<(Vec<u8>, EncodedVerKey, Option<EncodedVerKey>)> {
        struct Lookup<T: RawStore + ?Sized> {
            profile: Option<String>,
            store: Store<T>,
        }

        impl<T: RawStore + ?Sized> KeyLookup for Lookup<T> {
            fn find<'f>(
                &'f self,
                keys: &'f Vec<EncodedVerKey>,
            ) -> std::pin::Pin<Box<dyn Future<Output = Option<(usize, PrivateKey)>> + Send + 'f>>
            {
                let profile = self.profile.clone();
                let store = self.store.clone();
                Box::pin(async move {
                    for (idx, key) in keys.into_iter().enumerate() {
                        if let Ok(Some(key)) = store
                            .fetch_key(
                                profile.clone(),
                                KeyCategory::KeyPair,
                                key.long_form(),
                                EntryFetchOptions::new(false),
                            )
                            .await
                        {
                            if let Ok(sk) = key.private_key() {
                                return Some((idx, sk));
                            }
                        }
                    }
                    return None;
                })
            }
        }

        let lookup = Lookup {
            profile,
            store: self.clone(),
        };
        match unpack_message(data, lookup).await {
            Ok((message, recip, sender)) => Ok((message, recip, sender)),
            Err(err) => Err(err_msg!("Error unpacking message").with_cause(err)),
        }
    }

    /// Close the store instance, waiting for any shutdown procedures to complete.
    pub async fn close(&self) -> Result<()> {
        self.inner.close().await
    }
}

impl<T: RawStore + ?Sized> Clone for Store<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

pub struct Scan<T> {
    stream: Option<Pin<Box<dyn Stream<Item = Result<Vec<T>>> + Send>>>,
    page_size: usize,
}

impl<T> Scan<T> {
    pub fn new<S>(stream: S, page_size: usize) -> Self
    where
        S: Stream<Item = Result<Vec<T>>> + Send + 'static,
    {
        Self {
            stream: Some(stream.boxed()),
            page_size,
        }
    }

    pub async fn fetch_next(&mut self) -> Result<Option<Vec<T>>> {
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
    new_record: bool,
    update_fn: Box<
        dyn FnOnce(Vec<UpdateEntry>) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send,
    >,
}

impl EntryLock {
    pub fn new<F, G>(new_record: bool, update: F) -> Self
    where
        F: FnOnce(Vec<UpdateEntry>) -> G + Send + 'static,
        G: Future<Output = Result<()>> + Send + 'static,
    {
        Self {
            new_record,
            update_fn: Box::new(|entries| Box::pin(update(entries))),
        }
    }

    pub fn is_new_record(&self) -> bool {
        self.new_record
    }

    pub async fn update(self, entries: Vec<UpdateEntry>) -> Result<()> {
        let fut = (self.update_fn)(entries);
        fut.await
    }
}

#[derive(Debug)]
pub struct ProvisionStoreSpec {
    pub enc_store_key: Vec<u8>,
    pub profile_name: String,
    pub store_key: StoreKey,
    pub wrap_key: WrapKey,
    pub wrap_key_ref: String,
}

impl ProvisionStoreSpec {
    pub async fn create(method: WrapKeyMethod, pass_key: Option<&str>) -> Result<Self> {
        let store_key = StoreKey::new()?;
        let key_data = serde_json::to_vec(&store_key).map_err(err_map!(Unexpected))?;
        let (wrap_key, wrap_key_ref) = method.resolve(pass_key).await?;
        let enc_store_key = wrap_key.wrap_data(key_data).await?;
        let profile_name = uuid::Uuid::new_v4().to_string();
        Ok(Self {
            enc_store_key,
            profile_name,
            store_key,
            wrap_key,
            wrap_key_ref: wrap_key_ref.into_uri(),
        })
    }

    pub async fn create_default() -> Result<Self> {
        let key = generate_raw_wrap_key(None)?;
        Self::create(WrapKeyMethod::RawKey, Some(&key)).await
    }
}

#[async_trait]
pub trait OpenStore {
    type Store;

    async fn open_store(self, pass_key: Option<&str>) -> Result<Self::Store>;
}

pub type AnyStore = Store<dyn RawStore>;

#[async_trait]
pub trait ProvisionStore: OpenStore {
    async fn provision_store(self, spec: ProvisionStoreSpec) -> Result<Self::Store>;
}

#[async_trait]
impl OpenStore for &str {
    type Store = AnyStore;

    async fn open_store(self, pass_key: Option<&str>) -> Result<Self::Store> {
        let opts = self.into_options()?;
        debug!("Open store with options: {:?}", &opts);

        Ok(match opts.schema.as_ref() {
            #[cfg(feature = "postgres")]
            "postgres" => {
                let opts = super::postgres::PostgresStoreOptions::new(opts)?;
                opts.open_store(pass_key).await?.into_any()
            }

            #[cfg(feature = "sqlite")]
            "sqlite" => {
                let opts = super::sqlite::SqliteStoreOptions::new(opts)?;
                opts.open_store(pass_key).await?.into_any()
            }

            _ => return Err(err_msg!(Unsupported, "Invalid backend: {}", &opts.schema)),
        })
    }
}

#[async_trait]
impl ProvisionStore for &str {
    async fn provision_store(self, spec: ProvisionStoreSpec) -> Result<<Self as OpenStore>::Store> {
        let opts = self.into_options()?;
        debug!("Provision store with options: {:?}", &opts);

        let inner: Arc<dyn RawStore> = match opts.schema.as_ref() {
            #[cfg(feature = "postgres")]
            "postgres" => {
                let opts = super::postgres::PostgresStoreOptions::new(opts)?;
                opts.provision_store(spec).await?.into_inner()
            }

            #[cfg(feature = "sqlite")]
            "sqlite" => {
                let opts = super::sqlite::SqliteStoreOptions::new(opts)?;
                opts.provision_store(spec).await?.into_inner()
            }

            _ => return Err(err_msg!(Unsupported, "Invalid backend: {}", &opts.schema)),
        };
        Ok(Store { inner })
    }
}
