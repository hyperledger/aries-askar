use aries_store_kv::{KvProvisionStore, Result as KvResult};

mod utils;

macro_rules! db_tests {
    ($init:expr) => {
        use suspend::block_on;

        #[test]
        fn init() {
            block_on($init).unwrap();
        }

        #[test]
        fn fetch_fail() {
            block_on(async {
                let db = $init.await?;
                super::utils::db_fetch_fail(&*db).await?;
                KvResult::Ok(())
            })
            .unwrap()
        }

        #[test]
        fn add_fetch() {
            block_on(async {
                let db = $init.await?;
                super::utils::db_add_fetch(&*db).await?;
                KvResult::Ok(())
            })
            .unwrap()
        }

        #[test]
        fn add_fetch_tags() {
            block_on(async {
                let db = $init.await?;
                super::utils::db_add_fetch_tags(&*db).await?;
                KvResult::Ok(())
            })
            .unwrap()
        }

        #[test]
        fn count() {
            block_on(async {
                let db = $init.await?;
                super::utils::db_count(&*db).await?;
                KvResult::Ok(())
            })
            .unwrap()
        }

        #[test]
        fn scan() {
            block_on(async {
                let db = $init.await?;
                super::utils::db_scan(&*db).await?;
                KvResult::Ok(())
            })
            .unwrap()
        }

        #[test]
        fn create_lock_non_existing() {
            block_on(async {
                let db = $init.await?;
                super::utils::db_create_lock_non_existing(&*db).await?;
                KvResult::Ok(())
            })
            .unwrap()
        }

        #[test]
        fn create_lock_timeout() {
            block_on(async {
                let db = $init.await?;
                super::utils::db_create_lock_timeout(&*db).await?;
                KvResult::Ok(())
            })
            .unwrap()
        }
    };
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use aries_store_kv::sqlite::{KvSqlite, KvSqliteOptions};
    use aries_store_kv::KvProvisionSpec;

    async fn init_db() -> KvResult<Box<KvSqlite>> {
        let spec = KvProvisionSpec::create_default().await?;
        let db = KvSqliteOptions::in_memory().provision_store(spec).await?;
        Ok(Box::new(db))
    }

    db_tests!(init_db());

    #[test]
    fn provision_from_str() {
        suspend::block_on(async {
            let db_url = "sqlite://:memory:";
            let spec = KvProvisionSpec::create_default().await?;
            let _db = db_url.provision_store(spec).await?;
            KvResult::Ok(())
        })
        .unwrap();

        assert!(suspend::block_on(async {
            let db_url = "not-sqlite://test-db";
            let spec = KvProvisionSpec::create_default().await?;
            let _db = db_url.provision_store(spec).await?;
            KvResult::Ok(())
        })
        .is_err());
    }
}

#[cfg(all(feature = "pg_test", feature = "postgres"))]
mod postgres {
    use super::*;
    use aries_store_kv::postgres::{KvPostgres, TestDB};

    async fn init_db<'t>() -> KvResult<TestDB<'t>> {
        let db = KvPostgres::provision_test_db().await?;
        Ok(db)
    }

    db_tests!(init_db());
}
