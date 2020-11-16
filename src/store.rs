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

use super::error::Result;
use super::future::BoxFuture;
use super::keys::{wrap::WrapKeyMethod, KeyAlg, KeyCategory, KeyEntry, KeyParams, PassKey};
use super::types::{Entry, EntryKind, EntryOperation, EntryTag, TagFilter};

/// Represents a generic backend implementation
pub trait Backend: Send + Sync {
    type Session: QueryBackend;
    type Transaction: QueryBackend;

    fn create_profile(&self, name: Option<String>) -> BoxFuture<Result<String>>;

    fn get_profile_name(&self) -> &str;

    fn remove_profile(&self, name: String) -> BoxFuture<Result<bool>>;

    fn scan(
        &self,
        profile: Option<String>,
        kind: EntryKind,
        category: String,
        tag_filter: Option<TagFilter>,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> BoxFuture<Result<Scan<'static, Entry>>>;

    fn session(&self, profile: Option<String>) -> BoxFuture<Result<Self::Session>>;

    fn transaction(&self, profile: Option<String>) -> BoxFuture<Result<Self::Transaction>>;

    fn rekey_backend(&mut self, method: WrapKeyMethod, key: PassKey<'_>) -> BoxFuture<Result<()>>;

    fn close(&self) -> BoxFuture<Result<()>>;
}

/// Create, open, or remove a generic backend implementation
pub trait ManageBackend<'a> {
    type Store;

    fn open_backend(
        self,
        method: Option<WrapKeyMethod>,
        pass_key: PassKey<'a>,
        profile: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Self::Store>>;

    fn provision_backend(
        self,
        method: WrapKeyMethod,
        pass_key: PassKey<'a>,
        profile: Option<&'a str>,
        recreate: bool,
    ) -> BoxFuture<'a, Result<Self::Store>>;

    fn remove_backend(self) -> BoxFuture<'a, Result<bool>>;
}

/// Query from a generic backend implementation
pub trait QueryBackend: Send {
    fn count<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        tag_filter: Option<TagFilter>,
    ) -> BoxFuture<'q, Result<i64>>;

    fn fetch<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        name: &'q str,
        for_update: bool,
    ) -> BoxFuture<'q, Result<Option<Entry>>>;

    fn fetch_all<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        tag_filter: Option<TagFilter>,
        limit: Option<i64>,
        for_update: bool,
    ) -> BoxFuture<'q, Result<Vec<Entry>>>;

    fn remove_all<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        tag_filter: Option<TagFilter>,
    ) -> BoxFuture<'q, Result<i64>>;

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

#[derive(Debug)]
/// An instance of an opened store
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
    /// Get the default profile name used when starting a scan or a session
    pub fn get_profile_name(&self) -> &str {
        self.0.get_profile_name()
    }

    /// Replace the wrapping key on a store
    pub async fn rekey(&mut self, method: WrapKeyMethod, pass_key: PassKey<'_>) -> Result<()> {
        Ok(self.0.rekey_backend(method, pass_key).await?)
    }

    /// Create a new profile with the given profile name
    pub async fn create_profile(&self, name: Option<String>) -> Result<String> {
        Ok(self.0.create_profile(name).await?)
    }

    /// Remove an existing profile with the given profile name
    pub async fn remove_profile(&self, name: String) -> Result<bool> {
        Ok(self.0.remove_profile(name).await?)
    }

    /// Create a new scan instance against the store
    ///
    /// The result will keep an open connection to the backend until it is consumed
    pub async fn scan(
        &self,
        profile: Option<String>,
        category: String,
        tag_filter: Option<TagFilter>,
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

    /// Create a new session against the store
    pub async fn session(&self, profile: Option<String>) -> Result<Session<B::Session>> {
        Ok(Session::new(self.0.session(profile).await?))
    }

    /// Create a new transaction session against the store
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

/// An active connection to the store backend
pub struct Session<Q: QueryBackend>(Q);

impl<Q: QueryBackend> Session<Q> {
    pub(crate) fn new(inner: Q) -> Self {
        Self(inner)
    }
}

impl<Q: QueryBackend> Session<Q> {
    /// Count the number of entries for a given record category
    pub async fn count(&mut self, category: &str, tag_filter: Option<TagFilter>) -> Result<i64> {
        Ok(self.0.count(EntryKind::Item, category, tag_filter).await?)
    }

    /// Retrieve the current record at `(category, name)`.
    ///
    /// Specify `for_update` when in a transaction to create an update lock on the
    /// associated record, if supported by the store backend
    pub async fn fetch(
        &mut self,
        category: &str,
        name: &str,
        for_update: bool,
    ) -> Result<Option<Entry>> {
        Ok(self
            .0
            .fetch(EntryKind::Item, category, name, for_update)
            .await?)
    }

    /// Retrieve all records matching the given `category` and `tag_filter`.
    ///
    /// Unlike `Store::scan`, this method may be used within a transaction. It should
    /// not be used for very large result sets due to correspondingly large memory
    /// requirements
    pub async fn fetch_all(
        &mut self,
        category: &str,
        tag_filter: Option<TagFilter>,
        limit: Option<i64>,
        for_update: bool,
    ) -> Result<Vec<Entry>> {
        Ok(self
            .0
            .fetch_all(EntryKind::Item, category, tag_filter, limit, for_update)
            .await?)
    }

    /// Insert a new record into the store
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

    /// Remove a record from the store
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

    /// Replace the value and tags of a record in the store
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
                EntryOperation::Replace,
                category,
                name,
                Some(value),
                tags,
                expiry_ms,
            )
            .await?)
    }

    /// Remove all records in the store matching a given `category` and `tag_filter`
    pub async fn remove_all(
        &mut self,
        category: &str,
        tag_filter: Option<TagFilter>,
    ) -> Result<i64> {
        Ok(self
            .0
            .remove_all(EntryKind::Item, category, tag_filter)
            .await?)
    }

    /// Perform a record update
    ///
    /// This may correspond to an record insert, replace, or remove depending on
    /// the provided `operation`
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

    /// Create a new keypair in the store
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
            _ => return Err(err_msg!(Unsupported, "Unsupported key algorithm")),
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

    /// Fetch an existing key from the store
    ///
    /// Specify `for_update` when in a transaction to create an update lock on the
    /// associated record, if supported by the store backend
    pub async fn fetch_key(
        &mut self,
        category: KeyCategory,
        ident: &str,
        for_update: bool,
    ) -> Result<Option<KeyEntry>> {
        // normalize ident
        let ident = EncodedVerKey::from_str(&ident)
            .and_then(|k| k.as_base58())
            .map_err(err_map!("Invalid key"))?
            .long_form();

        Ok(
            if let Some(row) = self
                .0
                .fetch(EntryKind::Key, category.as_str(), &ident, for_update)
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

    /// Remove an existing key from the store
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
    //     tag_filter: Option<TagFilter>,
    //     offset: Option<i64>,
    //     max_rows: Option<i64>,
    // ) -> Result<Scan<KeyEntry>> {
    //     unimplemented!();
    // }

    /// Replace the metadata and tags on an existing key in the store
    pub async fn update_key(
        &mut self,
        category: KeyCategory,
        ident: &str,
        metadata: Option<&str>,
        tags: Option<&[EntryTag]>,
    ) -> Result<()> {
        // normalize ident
        let ident = EncodedVerKey::from_str(&ident)
            .and_then(|k| k.as_base58())
            .map_err(err_map!("Invalid key"))?
            .long_form();

        let row = self
            .0
            .fetch(EntryKind::Key, category.as_str(), &ident, true)
            .await?
            .ok_or_else(|| err_msg!(NotFound, "Key entry not found"))?;

        let mut params = KeyParams::from_slice(&row.value)?;
        params.metadata = metadata.map(str::to_string);
        let mut value = params.to_vec()?;

        self.0
            .update(
                EntryKind::Key,
                EntryOperation::Replace,
                category.as_str(),
                &ident,
                Some(&value),
                tags,
                None,
            )
            .await?;
        value.zeroize();

        Ok(())
    }

    /// Sign a message using an existing keypair in the store identified by `key_ident`
    pub async fn sign_message(&mut self, key_ident: &str, data: &[u8]) -> Result<Vec<u8>> {
        if let Some(key) = self
            .fetch_key(KeyCategory::KeyPair, key_ident, false)
            .await?
        {
            let sk = key.private_key()?;
            sk.sign(&data)
                .map_err(|e| err_msg!(Unexpected, "Signature error: {}", e))
        } else {
            return Err(err_msg!(NotFound, "Unknown key"));
        }
    }

    /// Pack a message using an existing keypair in the store identified by `key_ident`
    ///
    /// This uses the `pack` algorithm defined for DIDComm v1
    pub async fn pack_message(
        &mut self,
        recipient_vks: impl IntoIterator<Item = &str>,
        from_key_ident: Option<&str>,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let sign_key = if let Some(ident) = from_key_ident {
            let sk = self
                .fetch_key(KeyCategory::KeyPair, ident, false)
                .await?
                .ok_or_else(|| err_msg!(NotFound, "Unknown sender key"))?;
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

    /// Unpack a DIDComm v1 message, automatically looking up any associated keypairs
    pub async fn unpack_message(
        &mut self,
        data: &[u8],
    ) -> Result<(Vec<u8>, EncodedVerKey, Option<EncodedVerKey>)> {
        match unpack_message(data, self).await {
            Ok((message, recip, sender)) => Ok((message, recip, sender)),
            Err(err) => Err(err_msg!(Unexpected, "Error unpacking message").with_cause(err)),
        }
    }

    /// Commit the pending transaction
    pub async fn commit(self) -> Result<()> {
        Ok(self.0.close(true).await?)
    }

    /// Roll back the pending transaction
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
                if let Ok(Some(key)) = self.fetch_key(KeyCategory::KeyPair, &key.key, false).await {
                    if let Ok(sk) = key.private_key() {
                        return Some((idx, sk));
                    }
                }
            }
            return None;
        })
    }
}

/// An active record scan of a store backend
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
