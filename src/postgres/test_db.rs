use sqlx::{postgres::Postgres, Executor, Transaction};

use super::provision::{init_db, reset_db, PostgresStoreOptions};
use super::PostgresStore;
use crate::db_utils::ProvisionStoreSpec;
use crate::error::Result;
use crate::keys::wrap::{generate_raw_wrap_key, WrapKeyMethod};
use crate::store::Store;

pub struct TestDB {
    inst: Store<PostgresStore>,
    #[allow(unused)]
    lock_txn: Transaction<'static, Postgres>,
}

impl TestDB {
    #[allow(unused)]
    pub async fn provision() -> Result<TestDB> {
        let path = match std::env::var("POSTGRES_URL") {
            Ok(p) if !p.is_empty() => p,
            _ => panic!("'POSTGRES_URL' must be defined"),
        };
        let key = generate_raw_wrap_key(None)?;
        let spec = ProvisionStoreSpec::create(WrapKeyMethod::RawKey, Some(&key)).await?;

        let opts = PostgresStoreOptions::new(path.as_str())?;
        let conn_pool = opts.create_db_pool().await?;

        // we hold a transaction open with a common advisory lock value.
        // this will block until any existing TestDB instance is dropped
        let mut lock_txn = conn_pool.begin().await?;
        lock_txn
            .execute("SELECT pg_advisory_xact_lock(99999);")
            .await?;

        let mut init_txn = conn_pool.begin().await?;
        reset_db(&mut *init_txn).await?;
        let (default_profile, key_cache) = init_db(init_txn, spec).await?;
        let inst = Store::new(PostgresStore::new(
            conn_pool,
            default_profile,
            key_cache,
            opts.host,
            opts.name,
        ));

        Ok(TestDB { inst, lock_txn })
    }
}

impl std::ops::Deref for TestDB {
    type Target = Store<PostgresStore>;

    fn deref(&self) -> &Self::Target {
        &self.inst
    }
}
