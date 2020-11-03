use super::error::Result;
use super::future::BoxFuture;
use super::options::IntoOptions;
use super::store::{
    Backend, OpenStore, ProvisionStore, ProvisionStoreSpec, QueryBackend, Scan, Store,
};
use super::types::{Entry, EntryKind};
use super::wql;

#[cfg(feature = "sqlite")]
use super::sqlite::SqliteStore;

pub type AnyStore = Store<AnyBackend>;

pub enum AnyBackend {
    #[cfg(feature = "sqlite")]
    Sqlite(SqliteStore),
    #[allow(unused)]
    Other,
}

impl Backend for AnyBackend {
    type Session = Box<dyn QueryBackend>;
    type Transaction = Box<dyn QueryBackend>;

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
                    Ok(Box::new(session) as Box<dyn QueryBackend>)
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
                    Ok(Box::new(session) as Box<dyn QueryBackend>)
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
