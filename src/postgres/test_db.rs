use sqlx::{
    postgres::{PgPool, Postgres},
    Executor, Transaction,
};

use super::provision::init_db;
use super::PostgresStore;
use crate::error::Result;
use crate::store::{ProvisionStoreSpec, Store};

pub struct TestDB {
    inst: Store<PostgresStore>,
    #[allow(unused)]
    txn: Transaction<'static, Postgres>,
}

impl TestDB {
    #[allow(unused)]
    pub async fn provision() -> Result<TestDB> {
        let path = match std::env::var("POSTGRES_URL") {
            Ok(p) if !p.is_empty() => p,
            _ => panic!("'POSTGRES_URL' must be defined"),
        };
        let conn_pool = PgPool::connect(path.as_str()).await?;

        // we hold a transaction open with a common advisory lock key.
        // this will block until any existing TestDB instance is dropped
        let mut txn = conn_pool.begin().await?;
        txn.execute("SELECT pg_advisory_xact_lock(99999);").await?;

        let spec = ProvisionStoreSpec::create_default().await?;
        let (default_profile, key_cache) = init_db(&conn_pool, spec, true).await?;
        let inst = Store::new(PostgresStore::new(conn_pool, default_profile, key_cache));

        Ok(TestDB { inst, txn })
    }
}

impl std::ops::Deref for TestDB {
    type Target = Store<PostgresStore>;

    fn deref(&self) -> &Self::Target {
        &self.inst
    }
}
