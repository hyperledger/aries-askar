use super::error::Result;
use super::future::BoxFuture;
use super::options::IntoOptions;
use super::store::{
    Backend, OpenStore, ProvisionStore, ProvisionStoreSpec, QueryBackend, Scan, Session, Store,
};
use super::types::{Entry, EntryKind, EntryOperation, EntryTag};
use super::wql;

#[cfg(feature = "sqlite")]
use super::sqlite::SqliteStore;

pub type AnyStore = Store<AnyBackend>;

pub type AnySession = Session<AnyQueryBackend>;

pub enum AnyBackend {
    #[cfg(feature = "sqlite")]
    Sqlite(SqliteStore),
    #[allow(unused)]
    Other,
}

impl Backend for AnyBackend {
    type Session = AnyQueryBackend;
    type Transaction = AnyQueryBackend;

    fn scan(
        &self,
        profile: Option<String>,
        kind: EntryKind,
        category: String,
        tag_filter: Option<wql::Query>,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> BoxFuture<Result<Scan<Entry>>> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::Sqlite(store) => store.scan(profile, kind, category, tag_filter, offset, limit),

            _ => unreachable!(),
        }
    }

    fn session(&self, profile: Option<String>) -> BoxFuture<Result<Self::Session>> {
        Box::pin(async move {
            match self {
                #[cfg(feature = "sqlite")]
                Self::Sqlite(store) => {
                    // FIXME - avoid double boxed futures by exposing public method
                    let session = store.session(profile).await?;
                    Ok(AnyQueryBackend::SqliteSession(session))
                }
                _ => unreachable!(),
            }
        })
    }

    fn transaction(&self, profile: Option<String>) -> BoxFuture<Result<Self::Transaction>> {
        Box::pin(async move {
            match self {
                #[cfg(feature = "sqlite")]
                Self::Sqlite(store) => {
                    // FIXME - avoid double boxed futures by exposing public method
                    let session = store.transaction(profile).await?;
                    Ok(AnyQueryBackend::SqliteTxn(session))
                }
                _ => unreachable!(),
            }
        })
    }

    fn close(&self) -> BoxFuture<Result<()>> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::Sqlite(store) => store.close(),

            _ => unreachable!(),
        }
    }
}

pub enum AnyQueryBackend {
    #[cfg(feature = "sqlite")]
    SqliteSession(<SqliteStore as Backend>::Session),
    #[cfg(feature = "sqlite")]
    SqliteTxn(<SqliteStore as Backend>::Transaction),
    #[allow(unused)]
    Other,
}

impl QueryBackend for AnyQueryBackend {
    fn count<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        tag_filter: Option<wql::Query>,
    ) -> BoxFuture<'q, Result<i64>> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SqliteSession(session) => session.count(kind, category, tag_filter),
            #[cfg(feature = "sqlite")]
            Self::SqliteTxn(txn) => txn.count(kind, category, tag_filter),

            _ => unreachable!(),
        }
    }

    fn fetch<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        name: &'q str,
    ) -> BoxFuture<'q, Result<Option<Entry>>> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SqliteSession(session) => session.fetch(kind, category, name),
            #[cfg(feature = "sqlite")]
            Self::SqliteTxn(txn) => txn.fetch(kind, category, name),

            _ => unreachable!(),
        }
    }

    // async fn fetch_all(
    //     self,
    //     profile: Option<String>,
    //     kind: EntryKind,
    //     category: String,
    //     options: EntryFetchOptions,
    //     tag_filter: Option<wql::Query>,
    //     offset: Option<i64>,
    //     max_rows: Option<i64>,
    // ) -> Result<Vec<Entry>>;

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
            #[cfg(feature = "sqlite")]
            Self::SqliteSession(session) => {
                session.update(kind, operation, category, name, value, tags, expiry_ms)
            }
            #[cfg(feature = "sqlite")]
            Self::SqliteTxn(txn) => {
                txn.update(kind, operation, category, name, value, tags, expiry_ms)
            }

            _ => unreachable!(),
        }
    }

    fn close(self, commit: bool) -> BoxFuture<'static, Result<()>> {
        match self {
            #[cfg(feature = "sqlite")]
            Self::SqliteSession(session) => session.close(commit),
            #[cfg(feature = "sqlite")]
            Self::SqliteTxn(txn) => txn.close(commit),

            _ => unreachable!(),
        }
    }
}

impl<'a> ProvisionStore<'a> for &'a str {
    type Store = AnyStore;

    fn provision_store(self, spec: ProvisionStoreSpec) -> BoxFuture<'a, Result<Self::Store>> {
        Box::pin(async move {
            let opts = self.into_options()?;
            debug!("Provision store with options: {:?}", &opts);

            match opts.schema.as_ref() {
                #[cfg(feature = "postgres")]
                "postgres" => {
                    let opts = super::postgres::PostgresStoreOptions::new(opts)?;
                    opts.provision_store(spec).await?.into_inner()
                }

                #[cfg(feature = "sqlite")]
                "sqlite" => {
                    let opts = super::sqlite::SqliteStoreOptions::new(opts)?;
                    let mgr = opts.provision_store(spec).await?;
                    Ok(Store::new(AnyBackend::Sqlite(mgr.into_inner())))
                }

                _ => Err(err_msg!(Unsupported, "Invalid backend: {}", &opts.schema)),
            }
        })
    }
}

impl<'a> OpenStore<'a> for &'a str {
    fn open_store(
        self,
        pass_key: Option<&'a str>,
    ) -> BoxFuture<'a, Result<<Self as ProvisionStore>::Store>> {
        Box::pin(async move {
            let opts = self.into_options()?;
            debug!("Open store with options: {:?}", &opts);

            match opts.schema.as_ref() {
                #[cfg(feature = "postgres")]
                "postgres" => {
                    let opts = super::postgres::PostgresStoreOptions::new(opts)?;
                    opts.open_store(pass_key).await?.into_any()
                }

                #[cfg(feature = "sqlite")]
                "sqlite" => {
                    let opts = super::sqlite::SqliteStoreOptions::new(opts)?;
                    let mgr = opts.open_store(pass_key).await?;
                    Ok(Store::new(AnyBackend::Sqlite(mgr.into_inner())))
                }

                _ => Err(err_msg!(Unsupported, "Invalid backend: {}", &opts.schema)),
            }
        })
    }
}
