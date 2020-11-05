use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;

use futures_lite::stream::{Stream, StreamExt};
use indy_utils::{
    keys::{EncodedVerKey, KeyType as IndyKeyAlg, PrivateKey},
    pack::{pack_message, unpack_message, KeyLookup},
    Validatable,
};
use zeroize::Zeroize;

use super::future::BoxFuture;
use super::keys::{
    store::StoreKey,
    wrap::{generate_raw_wrap_key, WrapKey, WrapKeyMethod},
    KeyAlg, KeyCategory, KeyEntry, KeyParams,
};
use super::types::{Entry, EntryKind, EntryOperation, EntryTag, ProfileId};
use super::wql;
use super::Result;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryFetchOptions {
    pub for_update: bool,
}

impl Default for QueryFetchOptions {
    fn default() -> Self {
        Self { for_update: false }
    }
}

pub trait Backend: Send + Sync {
    type Session: QueryBackend;
    type Transaction: QueryBackend;

    fn scan(
        &self,
        profile: Option<String>,
        kind: EntryKind,
        category: String,
        tag_filter: Option<wql::Query>,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> BoxFuture<Result<Scan<'static, Entry>>>;

    fn session(&self, profile: Option<String>) -> BoxFuture<Result<Self::Session>>;

    fn transaction(&self, profile: Option<String>) -> BoxFuture<Result<Self::Transaction>>;

    fn close(&self) -> BoxFuture<Result<()>>;
}

pub trait QueryBackend: Send {
    fn count<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        tag_filter: Option<wql::Query>,
    ) -> BoxFuture<'q, Result<i64>>;

    fn fetch<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        name: &'q str,
    ) -> BoxFuture<'q, Result<Option<Entry>>>;

    fn fetch_all<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        tag_filter: Option<wql::Query>,
        limit: Option<i64>,
    ) -> BoxFuture<'q, Result<Vec<Entry>>>;

    fn update<'q>(
        &'q mut self,
        kind: EntryKind,
        operation: EntryOperation,
        category: &'q str,
        name: &'q str,
        value: Option<&'q [u8]>,
        tags: Option<&'q [EntryTag]>,
        expiry_ms: Option<i64>,
    ) -> BoxFuture<'q, Result<()>>;

    fn close(self, commit: bool) -> BoxFuture<'static, Result<()>>;
}

pub struct Store<B: Backend>(B);

impl<B: Backend> Store<B> {
    pub(crate) fn new(inner: B) -> Self {
        Self(inner)
    }

    #[cfg(test)]
    pub(crate) fn inner(&self) -> &B {
        &self.0
    }

    pub(crate) fn into_inner(self) -> B {
        self.0
    }
}

impl<B: Backend> Store<B> {
    pub async fn scan(
        &self,
        profile: Option<String>,
        category: String,
        tag_filter: Option<wql::Query>,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> Result<Scan<'static, Entry>> {
        Ok(self
            .0
            .scan(
                profile,
                EntryKind::Item,
                category,
                tag_filter,
                offset,
                limit,
            )
            .await?)
    }

    pub async fn session(&self, profile: Option<String>) -> Result<Session<B::Session>> {
        Ok(Session::new(self.0.session(profile).await?))
    }

    pub async fn transaction(&self, profile: Option<String>) -> Result<Session<B::Transaction>> {
        Ok(Session::new(self.0.transaction(profile).await?))
    }

    /// Close the store instance, waiting for any shutdown procedures to complete.
    pub async fn close(self) -> Result<()> {
        Ok(self.0.close().await?)
    }

    pub(crate) async fn arc_close(self: Arc<Self>) -> Result<()> {
        Ok(self.0.close().await?)
    }
}

pub struct Session<Q: QueryBackend>(Q);

impl<Q: QueryBackend> Session<Q> {
    pub(crate) fn new(inner: Q) -> Self {
        Self(inner)
    }
}

impl<Q: QueryBackend> Session<Q> {
    /// Count the number of entries for a given record category
    pub async fn count(&mut self, category: &str, tag_filter: Option<wql::Query>) -> Result<i64> {
        Ok(self.0.count(EntryKind::Item, category, tag_filter).await?)
    }

    /// Query the current value for the record at `(key_id, category, name)`
    ///
    /// A specific `key_id` may be given, otherwise all relevant keys for the provided
    /// `profile_id` are searched in reverse order of creation, returning the first
    /// result found if any.
    pub async fn fetch(&mut self, category: &str, name: &str) -> Result<Option<Entry>> {
        Ok(self.0.fetch(EntryKind::Item, category, name).await?)
    }

    pub async fn fetch_all(
        &mut self,
        category: &str,
        tag_filter: Option<wql::Query>,
        limit: Option<i64>,
    ) -> Result<Vec<Entry>> {
        Ok(self
            .0
            .fetch_all(EntryKind::Item, category, tag_filter, limit)
            .await?)
    }

    pub async fn insert(
        &mut self,
        category: &str,
        name: &str,
        value: &[u8],
        tags: Option<&[EntryTag]>,
        expiry_ms: Option<i64>,
    ) -> Result<()> {
        Ok(self
            .0
            .update(
                EntryKind::Item,
                EntryOperation::Insert,
                category,
                name,
                Some(value),
                tags,
                expiry_ms,
            )
            .await?)
    }

    pub async fn remove(&mut self, category: &str, name: &str) -> Result<()> {
        Ok(self
            .0
            .update(
                EntryKind::Item,
                EntryOperation::Remove,
                category,
                name,
                None,
                None,
                None,
            )
            .await?)
    }

    pub async fn replace(
        &mut self,
        category: &str,
        name: &str,
        value: &[u8],
        tags: Option<&[EntryTag]>,
        expiry_ms: Option<i64>,
    ) -> Result<()> {
        Ok(self
            .0
            .update(
                EntryKind::Item,
                EntryOperation::Remove,
                category,
                name,
                Some(value),
                tags,
                expiry_ms,
            )
            .await?)
    }

    pub async fn update(
        &mut self,
        operation: EntryOperation,
        category: &str,
        name: &str,
        value: Option<&[u8]>,
        tags: Option<&[EntryTag]>,
        expiry_ms: Option<i64>,
    ) -> Result<()> {
        Ok(self
            .0
            .update(
                EntryKind::Item,
                operation,
                category,
                name,
                value,
                tags,
                expiry_ms,
            )
            .await?)
    }

    pub async fn create_keypair(
        &mut self,
        alg: KeyAlg,
        metadata: Option<&str>,
        seed: Option<&[u8]>,
        tags: Option<&[EntryTag]>,
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
            metadata: metadata.map(str::to_string),
            reference: None,
            pub_key: Some(pk.key_bytes()),
            prv_key: Some(sk.key_bytes()),
        };
        let mut value = params.to_vec()?;

        self.0
            .update(
                EntryKind::Key,
                EntryOperation::Insert,
                category.as_str(),
                &ident,
                Some(value.as_slice()),
                tags.clone(),
                None,
            )
            .await?;
        value.zeroize();

        Ok(KeyEntry {
            category,
            ident,
            params,
            tags: tags.map(|t| t.to_vec()),
        })
    }

    // pub async fn import_key(&self, key: KeyEntry) -> Result<()> {
    //     Ok(())
    // }

    pub async fn fetch_key(
        &mut self,
        category: KeyCategory,
        ident: &str,
    ) -> Result<Option<KeyEntry>> {
        // normalize ident
        let ident = EncodedVerKey::from_str(&ident)
            .and_then(|k| k.as_base58())
            .map_err(err_map!("Invalid key"))?
            .long_form();

        Ok(
            if let Some(row) = self
                .0
                .fetch(EntryKind::Key, category.as_str(), &ident)
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

    pub async fn remove_key(&mut self, category: KeyCategory, ident: &str) -> Result<()> {
        // normalize ident
        let ident = EncodedVerKey::from_str(&ident)
            .and_then(|k| k.as_base58())
            .map_err(err_map!("Invalid key"))?
            .long_form();

        self.0
            .update(
                EntryKind::Key,
                EntryOperation::Remove,
                category.as_str(),
                &ident,
                None,
                None,
                None,
            )
            .await
    }

    // pub async fn scan_keys(
    //     &self,
    //     profile: Option<String>,
    //     category: String,
    //     options: EntryFetchOptions,
    //     tag_filter: Option<wql::Query>,
    //     offset: Option<i64>,
    //     max_rows: Option<i64>,
    // ) -> Result<Scan<KeyEntry>> {
    //     unimplemented!();
    // }

    // pub async fn update_key_metadata(
    //     &self,
    //     profile: Option<String>,
    //     category: KeyCategory,
    //     ident: String,
    //     metadata: Option<String>,
    // ) -> Result<()> {
    //     unimplemented!();
    // }

    // update_key_tags

    pub async fn sign_message(&mut self, key_ident: &str, data: &[u8]) -> Result<Vec<u8>> {
        if let Some(key) = self.fetch_key(KeyCategory::KeyPair, key_ident).await? {
            let sk = key.private_key()?;
            sk.sign(&data)
                .map_err(|e| err_msg!("Signature error: {}", e))
        } else {
            return Err(err_msg!("Unknown key")); // FIXME add new error class
        }
    }

    pub async fn pack_message(
        &mut self,
        recipient_vks: impl IntoIterator<Item = &str>,
        from_key_ident: Option<&str>,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let sign_key = if let Some(ident) = from_key_ident {
            let sk = self
                .fetch_key(KeyCategory::KeyPair, ident)
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
        &mut self,
        data: &[u8],
    ) -> Result<(Vec<u8>, EncodedVerKey, Option<EncodedVerKey>)> {
        match unpack_message(data, self).await {
            Ok((message, recip, sender)) => Ok((message, recip, sender)),
            Err(err) => Err(err_msg!("Error unpacking message").with_cause(err)),
        }
    }

    pub async fn commit(self) -> Result<()> {
        Ok(self.0.close(true).await?)
    }

    pub async fn rollback(self) -> Result<()> {
        Ok(self.0.close(false).await?)
    }
}

impl<'a, Q: QueryBackend> KeyLookup<'a> for &'a mut Session<Q> {
    fn find<'f>(
        self,
        keys: &'f Vec<EncodedVerKey>,
    ) -> std::pin::Pin<Box<dyn Future<Output = Option<(usize, PrivateKey)>> + Send + 'f>>
    where
        'a: 'f,
    {
        Box::pin(async move {
            for (idx, key) in keys.into_iter().enumerate() {
                if let Ok(Some(key)) = self.fetch_key(KeyCategory::KeyPair, &key.key).await {
                    if let Ok(sk) = key.private_key() {
                        return Some((idx, sk));
                    }
                }
            }
            return None;
        })
    }
}

pub struct Scan<'s, T> {
    stream: Option<Pin<Box<dyn Stream<Item = Result<Vec<T>>> + Send + 's>>>,
    page_size: usize,
}

impl<'s, T> Scan<'s, T> {
    pub fn new<S>(stream: S, page_size: usize) -> Self
    where
        S: Stream<Item = Result<Vec<T>>> + Send + 's,
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

pub trait ProvisionStore<'a> {
    type Store;

    fn provision_store(self, spec: ProvisionStoreSpec) -> BoxFuture<'a, Result<Self::Store>>;
}

pub trait OpenStore<'a>: ProvisionStore<'a> {
    fn open_store(self, pass_key: Option<&'a str>) -> BoxFuture<'a, Result<Self::Store>>;
}
