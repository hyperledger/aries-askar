use std::{
    fmt::{self, Debug, Display, Formatter},
    pin::Pin,
    str::FromStr,
    sync::Arc,
};

use futures_lite::stream::{Stream, StreamExt};
use zeroize::Zeroize;

use super::entry::{Entry, EntryKind, EntryOperation, EntryTag, TagFilter};
use crate::{
    error::Error,
    future::BoxFuture,
    keys::{KeyEntry, KeyParams, LocalKey},
    protect::{PassKey, StoreKeyMethod},
};

/// Represents a generic backend implementation
pub trait Backend: Send + Sync {
    /// The type of session managed by this backend
    type Session: QueryBackend;

    /// Create a new profile
    fn create_profile(&self, name: Option<String>) -> BoxFuture<'_, Result<String, Error>>;

    /// Get the name of the active profile
    fn get_profile_name(&self) -> &str;

    /// Remove an existing profile
    fn remove_profile(&self, name: String) -> BoxFuture<'_, Result<bool, Error>>;

    /// Create a [`Scan`] against the store
    fn scan(
        &self,
        profile: Option<String>,
        kind: EntryKind,
        category: String,
        tag_filter: Option<TagFilter>,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> BoxFuture<'_, Result<Scan<'static, Entry>, Error>>;

    /// Create a new session against the store
    fn session(&self, profile: Option<String>, transaction: bool) -> Result<Self::Session, Error>;

    /// Replace the wrapping key of the store
    fn rekey_backend(
        &mut self,
        method: StoreKeyMethod,
        key: PassKey<'_>,
    ) -> BoxFuture<'_, Result<(), Error>>;

    /// Close the store instance
    fn close(&self) -> BoxFuture<'_, Result<(), Error>>;
}

/// Create, open, or remove a generic backend implementation
pub trait ManageBackend<'a> {
    /// The type of store being managed
    type Store;

    /// Open an existing store
    fn open_backend(
        self,
        method: Option<StoreKeyMethod>,
        pass_key: PassKey<'a>,
        profile: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Self::Store, Error>>;

    /// Provision a new store
    fn provision_backend(
        self,
        method: StoreKeyMethod,
        pass_key: PassKey<'a>,
        profile: Option<&'a str>,
        recreate: bool,
    ) -> BoxFuture<'a, Result<Self::Store, Error>>;

    /// Remove an existing store
    fn remove_backend(self) -> BoxFuture<'a, Result<bool, Error>>;
}

/// Query from a generic backend implementation
pub trait QueryBackend: Send {
    /// Count the number of matching records in the store
    fn count<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        tag_filter: Option<TagFilter>,
    ) -> BoxFuture<'q, Result<i64, Error>>;

    /// Fetch a single record from the store by category and name
    fn fetch<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        name: &'q str,
        for_update: bool,
    ) -> BoxFuture<'q, Result<Option<Entry>, Error>>;

    /// Fetch all matching records from the store
    fn fetch_all<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        tag_filter: Option<TagFilter>,
        limit: Option<i64>,
        for_update: bool,
    ) -> BoxFuture<'q, Result<Vec<Entry>, Error>>;

    /// Remove all matching records from the store
    fn remove_all<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        tag_filter: Option<TagFilter>,
    ) -> BoxFuture<'q, Result<i64, Error>>;

    /// Insert or replace a record in the store
    fn update<'q>(
        &'q mut self,
        kind: EntryKind,
        operation: EntryOperation,
        category: &'q str,
        name: &'q str,
        value: Option<&'q [u8]>,
        tags: Option<&'q [EntryTag]>,
        expiry_ms: Option<i64>,
    ) -> BoxFuture<'q, Result<(), Error>>;

    /// Close the current store session
    fn close(self, commit: bool) -> BoxFuture<'static, Result<(), Error>>;
}

#[derive(Debug)]
/// An instance of an opened store
pub struct Store<B: Backend>(B);

impl<B: Backend> Store<B> {
    pub(crate) fn new(inner: B) -> Self {
        Self(inner)
    }

    #[cfg(test)]
    #[allow(unused)]
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
    pub async fn rekey(
        &mut self,
        method: StoreKeyMethod,
        pass_key: PassKey<'_>,
    ) -> Result<(), Error> {
        Ok(self.0.rekey_backend(method, pass_key).await?)
    }

    /// Create a new profile with the given profile name
    pub async fn create_profile(&self, name: Option<String>) -> Result<String, Error> {
        Ok(self.0.create_profile(name).await?)
    }

    /// Remove an existing profile with the given profile name
    pub async fn remove_profile(&self, name: String) -> Result<bool, Error> {
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
    ) -> Result<Scan<'static, Entry>, Error> {
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
    pub async fn session(&self, profile: Option<String>) -> Result<Session<B::Session>, Error> {
        // FIXME - add 'immediate' flag
        Ok(Session::new(self.0.session(profile, false)?))
    }

    /// Create a new transaction session against the store
    pub async fn transaction(&self, profile: Option<String>) -> Result<Session<B::Session>, Error> {
        Ok(Session::new(self.0.session(profile, true)?))
    }

    /// Close the store instance, waiting for any shutdown procedures to complete.
    pub async fn close(self) -> Result<(), Error> {
        Ok(self.0.close().await?)
    }

    pub(crate) async fn arc_close(self: Arc<Self>) -> Result<(), Error> {
        Ok(self.0.close().await?)
    }
}

/// An active connection to the store backend
#[derive(Debug)]
pub struct Session<Q: QueryBackend>(Q);

impl<Q: QueryBackend> Session<Q> {
    pub(crate) fn new(inner: Q) -> Self {
        Self(inner)
    }
}

impl<Q: QueryBackend> Session<Q> {
    /// Count the number of entries for a given record category
    pub async fn count(
        &mut self,
        category: &str,
        tag_filter: Option<TagFilter>,
    ) -> Result<i64, Error> {
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
    ) -> Result<Option<Entry>, Error> {
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
    ) -> Result<Vec<Entry>, Error> {
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
    ) -> Result<(), Error> {
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
    pub async fn remove(&mut self, category: &str, name: &str) -> Result<(), Error> {
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
    ) -> Result<(), Error> {
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
    ) -> Result<i64, Error> {
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
    ) -> Result<(), Error> {
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

    /// Insert a local key instance into the store
    pub async fn insert_key(
        &mut self,
        name: &str,
        key: &LocalKey,
        metadata: Option<&str>,
        tags: Option<&[EntryTag]>,
        expiry_ms: Option<i64>,
    ) -> Result<(), Error> {
        let data = key.encode()?;
        let params = KeyParams {
            metadata: metadata.map(str::to_string),
            reference: None,
            data: Some(data),
        };
        let value = params.to_bytes()?;
        let mut ins_tags = Vec::with_capacity(10);
        let alg = key.algorithm();
        if !alg.is_empty() {
            ins_tags.push(EntryTag::Encrypted("alg".to_string(), alg.to_string()));
        }
        let thumb = key.to_jwk_thumbprint()?;
        if !thumb.is_empty() {
            ins_tags.push(EntryTag::Encrypted("thumb".to_string(), thumb));
        }
        if let Some(tags) = tags {
            for t in tags {
                ins_tags.push(t.map_ref(|k, v| (format!("user:{}", k), v.to_string())));
            }
        }
        self.0
            .update(
                EntryKind::Kms,
                EntryOperation::Insert,
                KmsCategory::CryptoKey.as_str(),
                name,
                Some(value.as_ref()),
                Some(ins_tags.as_slice()),
                expiry_ms,
            )
            .await?;
        Ok(())
    }

    /// Fetch an existing key from the store
    ///
    /// Specify `for_update` when in a transaction to create an update lock on the
    /// associated record, if supported by the store backend
    pub async fn fetch_key(
        &mut self,
        name: &str,
        for_update: bool,
    ) -> Result<Option<KeyEntry>, Error> {
        Ok(
            if let Some(row) = self
                .0
                .fetch(
                    EntryKind::Kms,
                    KmsCategory::CryptoKey.as_str(),
                    name,
                    for_update,
                )
                .await?
            {
                Some(KeyEntry::from_entry(row)?)
            } else {
                None
            },
        )
    }

    /// Remove an existing key from the store
    pub async fn remove_key(&mut self, name: &str) -> Result<(), Error> {
        self.0
            .update(
                EntryKind::Kms,
                EntryOperation::Remove,
                KmsCategory::CryptoKey.as_str(),
                name,
                None,
                None,
                None,
            )
            .await
    }

    /// Replace the metadata and tags on an existing key in the store
    pub async fn replace_key(
        &mut self,
        name: &str,
        metadata: Option<&str>,
        tags: Option<&[EntryTag]>,
        expiry_ms: Option<i64>,
    ) -> Result<(), Error> {
        let row = self
            .0
            .fetch(EntryKind::Kms, KmsCategory::CryptoKey.as_str(), name, true)
            .await?
            .ok_or_else(|| err_msg!(NotFound, "Key entry not found"))?;

        let mut params = KeyParams::from_slice(&row.value)?;
        params.metadata = metadata.map(str::to_string);
        let value = params.to_bytes()?;

        let mut upd_tags = Vec::with_capacity(10);
        if let Some(tags) = tags {
            for t in tags {
                upd_tags.push(t.map_ref(|k, v| (format!("user:{}", k), v.to_string())));
            }
        }
        for t in row.tags {
            if !t.name().starts_with("user:") {
                upd_tags.push(t);
            }
        }

        self.0
            .update(
                EntryKind::Kms,
                EntryOperation::Replace,
                KmsCategory::CryptoKey.as_str(),
                name,
                Some(value.as_ref()),
                tags,
                expiry_ms,
            )
            .await?;

        Ok(())
    }

    /// Commit the pending transaction
    pub async fn commit(self) -> Result<(), Error> {
        Ok(self.0.close(true).await?)
    }

    /// Roll back the pending transaction
    pub async fn rollback(self) -> Result<(), Error> {
        Ok(self.0.close(false).await?)
    }
}

/// An active record scan of a store backend
pub struct Scan<'s, T> {
    stream: Option<Pin<Box<dyn Stream<Item = Result<Vec<T>, Error>> + Send + 's>>>,
    page_size: usize,
}

impl<'s, T> Scan<'s, T> {
    pub(crate) fn new<S>(stream: S, page_size: usize) -> Self
    where
        S: Stream<Item = Result<Vec<T>, Error>> + Send + 's,
    {
        Self {
            stream: Some(stream.boxed()),
            page_size,
        }
    }

    /// Fetch the next set of result rows
    pub async fn fetch_next(&mut self) -> Result<Option<Vec<T>>, Error> {
        if let Some(mut s) = self.stream.take() {
            match s.try_next().await? {
                Some(val) => {
                    if val.len() == self.page_size {
                        self.stream.replace(s);
                    }
                    Ok(Some(val))
                }
                None => Ok(None),
            }
        } else {
            Ok(None)
        }
    }
}

impl<S> Debug for Scan<'_, S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scan")
            .field("page_size", &self.page_size)
            .finish()
    }
}

/// Supported categories of KMS entries
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
pub(crate) enum KmsCategory {
    /// A stored key or keypair
    CryptoKey,
}

impl KmsCategory {
    /// Get a reference to a string representing the `KmsCategory`
    pub fn as_str(&self) -> &str {
        match self {
            Self::CryptoKey => "cryptokey",
        }
    }

    /// Convert the `KmsCategory` into an owned string
    pub fn to_string(&self) -> String {
        self.as_str().to_string()
    }
}

impl AsRef<str> for KmsCategory {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for KmsCategory {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "cryptokey" => Self::CryptoKey,
            _ => return Err(err_msg!("Unknown KMS category: {}", s)),
        })
    }
}

impl Display for KmsCategory {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
