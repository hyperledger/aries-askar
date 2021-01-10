use super::error::Result;
use super::future::BoxFuture;
use super::keys::{wrap::WrapKeyMethod, PassKey};
use super::options::IntoOptions;
use super::store::{Backend, ManageBackend, QueryBackend, Scan, Session, Store};
use super::types::{Entry, EntryKind, EntryOperation, EntryTag, TagFilter};

#[cfg(feature = "postgres")]
use super::postgres::PostgresStore;

#[cfg(feature = "sqlite")]
use super::sqlite::SqliteStore;

pub type AnyStore = Store<AnyBackend>;

pub type AnySession = Session<AnyQueryBackend>;

#[derive(Debug)]
pub enum AnyBackend {
    #[cfg(feature = "postgres")]
    Postgres(PostgresStore),

    #[cfg(feature = "sqlite")]
    Sqlite(SqliteStore),

    #[allow(unused)]
    Other,
}

macro_rules! with_backend {
    ($slf:ident, $ident:ident, $body:expr) => {
        match $slf {
            #[cfg(feature = "postgres")]
            Self::Postgres($ident) => $body,

            #[cfg(feature = "sqlite")]
            Self::Sqlite($ident) => $body,

            _ => unreachable!(),
        }
    };
}

impl Backend for AnyBackend {
    type Session = AnyQueryBackend;

    fn create_profile(&self, name: Option<String>) -> BoxFuture<'_, Result<String>> {
        with_backend!(self, store, store.create_profile(name))
    }

    fn get_profile_name(&self) -> &str {
        with_backend!(self, store, store.get_profile_name())
    }

    fn remove_profile(&self, name: String) -> BoxFuture<'_, Result<bool>> {
        with_backend!(self, store, store.remove_profile(name))
    }

    fn scan(
        &self,
        profile: Option<String>,
        kind: EntryKind,
        category: String,
        tag_filter: Option<TagFilter>,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> BoxFuture<'_, Result<Scan<'static, Entry>>> {
        with_backend!(
            self,
            store,
            store.scan(profile, kind, category, tag_filter, offset, limit)
        )
    }

    fn session(&self, profile: Option<String>, transaction: bool) -> Result<Self::Session> {
        match self {
            #[cfg(feature = "postgres")]
            Self::Postgres(store) => {
                let session = store.session(profile, transaction)?;
                Ok(AnyQueryBackend::PostgresSession(session))
            }

            #[cfg(feature = "sqlite")]
            Self::Sqlite(store) => {
                // FIXME - avoid double boxed futures by exposing public method
                let session = store.session(profile, transaction)?;
                Ok(AnyQueryBackend::SqliteSession(session))
            }

            _ => unreachable!(),
        }
    }

    fn rekey_backend(
        &mut self,
        method: WrapKeyMethod,
        pass_key: PassKey<'_>,
    ) -> BoxFuture<'_, Result<()>> {
        with_backend!(self, store, store.rekey_backend(method, pass_key))
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        with_backend!(self, store, store.close())
    }
}

#[derive(Debug)]
pub enum AnyQueryBackend {
    #[cfg(feature = "postgres")]
    PostgresSession(<PostgresStore as Backend>::Session),

    #[cfg(feature = "sqlite")]
    SqliteSession(<SqliteStore as Backend>::Session),

    #[allow(unused)]
    Other,
}

impl QueryBackend for AnyQueryBackend {
    fn count<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        tag_filter: Option<TagFilter>,
    ) -> BoxFuture<'q, Result<i64>> {
        match self {
            #[cfg(feature = "postgres")]
            Self::PostgresSession(session) => session.count(kind, category, tag_filter),

            #[cfg(feature = "sqlite")]
            Self::SqliteSession(session) => session.count(kind, category, tag_filter),

            _ => unreachable!(),
        }
    }

    fn fetch<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        name: &'q str,
        for_update: bool,
    ) -> BoxFuture<'q, Result<Option<Entry>>> {
        match self {
            #[cfg(feature = "postgres")]
            Self::PostgresSession(session) => session.fetch(kind, category, name, for_update),

            #[cfg(feature = "sqlite")]
            Self::SqliteSession(session) => session.fetch(kind, category, name, for_update),

            _ => unreachable!(),
        }
    }

    fn fetch_all<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        tag_filter: Option<TagFilter>,
        limit: Option<i64>,
        for_update: bool,
    ) -> BoxFuture<'q, Result<Vec<Entry>>> {
        match self {
            #[cfg(feature = "postgres")]
            Self::PostgresSession(session) => {
                session.fetch_all(kind, category, tag_filter, limit, for_update)
            }

            #[cfg(feature = "sqlite")]
            Self::SqliteSession(session) => {
                session.fetch_all(kind, category, tag_filter, limit, for_update)
            }

            _ => unreachable!(),
        }
    }

    fn remove_all<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        tag_filter: Option<TagFilter>,
    ) -> BoxFuture<'q, Result<i64>> {
        match self {
            #[cfg(feature = "postgres")]
            Self::PostgresSession(session) => session.remove_all(kind, category, tag_filter),

            #[cfg(feature = "sqlite")]
            Self::SqliteSession(session) => session.remove_all(kind, category, tag_filter),

            _ => unreachable!(),
        }
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
    ) -> BoxFuture<'q, Result<()>> {
        match self {
            #[cfg(feature = "postgres")]
            Self::PostgresSession(session) => {
                session.update(kind, operation, category, name, value, tags, expiry_ms)
            }

            #[cfg(feature = "sqlite")]
            Self::SqliteSession(session) => {
                session.update(kind, operation, category, name, value, tags, expiry_ms)
            }

            _ => unreachable!(),
        }
    }

    fn close(self, commit: bool) -> BoxFuture<'static, Result<()>> {
        match self {
            #[cfg(feature = "postgres")]
            Self::PostgresSession(session) => Box::pin(session.close(commit)),

            #[cfg(feature = "sqlite")]
            Self::SqliteSession(session) => Box::pin(session.close(commit)),

            _ => unreachable!(),
        }
    }
}

impl<'a> ManageBackend<'a> for &'a str {
    type Store = AnyStore;

    fn open_backend(
        self,
        method: Option<WrapKeyMethod>,
        pass_key: PassKey<'a>,
        profile: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Self::Store>> {
        Box::pin(async move {
            let opts = self.into_options()?;
            debug!("Open store with options: {:?}", &opts);

            match opts.schema.as_ref() {
                #[cfg(feature = "postgres")]
                "postgres" => {
                    let opts = super::postgres::PostgresStoreOptions::new(opts)?;
                    let mgr = opts.open(method, pass_key, profile).await?;
                    Ok(Store::new(AnyBackend::Postgres(mgr.into_inner())))
                }

                #[cfg(feature = "sqlite")]
                "sqlite" => {
                    let opts = super::sqlite::SqliteStoreOptions::new(opts)?;
                    let mgr = opts.open(method, pass_key, profile).await?;
                    Ok(Store::new(AnyBackend::Sqlite(mgr.into_inner())))
                }

                _ => Err(err_msg!(Unsupported, "Invalid backend: {}", &opts.schema)),
            }
        })
    }

    fn provision_backend(
        self,
        method: WrapKeyMethod,
        pass_key: PassKey<'a>,
        profile: Option<&'a str>,
        recreate: bool,
    ) -> BoxFuture<'a, Result<Self::Store>> {
        Box::pin(async move {
            let opts = self.into_options()?;
            debug!("Provision store with options: {:?}", &opts);

            match opts.schema.as_ref() {
                #[cfg(feature = "postgres")]
                "postgres" => {
                    let opts = super::postgres::PostgresStoreOptions::new(opts)?;
                    let mgr = opts.provision(method, pass_key, profile, recreate).await?;
                    Ok(Store::new(AnyBackend::Postgres(mgr.into_inner())))
                }

                #[cfg(feature = "sqlite")]
                "sqlite" => {
                    let opts = super::sqlite::SqliteStoreOptions::new(opts)?;
                    let mgr = opts.provision(method, pass_key, profile, recreate).await?;
                    Ok(Store::new(AnyBackend::Sqlite(mgr.into_inner())))
                }

                _ => Err(err_msg!(Unsupported, "Invalid backend: {}", &opts.schema)),
            }
        })
    }

    fn remove_backend(self) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async move {
            let opts = self.into_options()?;
            debug!("Remove store with options: {:?}", &opts);

            match opts.schema.as_ref() {
                #[cfg(feature = "postgres")]
                "postgres" => {
                    let opts = super::postgres::PostgresStoreOptions::new(opts)?;
                    Ok(opts.remove().await?)
                }

                #[cfg(feature = "sqlite")]
                "sqlite" => {
                    let opts = super::sqlite::SqliteStoreOptions::new(opts)?;
                    Ok(opts.remove().await?)
                }

                _ => Err(err_msg!(Unsupported, "Invalid backend: {}", &opts.schema)),
            }
        })
    }
}
