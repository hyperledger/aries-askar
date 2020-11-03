use aries_askar::Result as KvResult;

mod utils;

macro_rules! db_tests {
    ($init:expr) => {
        use aries_askar::future::block_on;

        #[test]
        fn init() {
            block_on($init).unwrap();
        }

        #[test]
        fn fetch_fail() {
            block_on(async {
                let db = $init.await?;
                super::utils::db_fetch_fail(&db).await?;
                KvResult::Ok(())
            })
            .unwrap()
        }

        #[test]
        fn add_duplicate_fail() {
            block_on(async {
                let db = $init.await?;
                super::utils::db_add_duplicate_fail(&db).await?;
                KvResult::Ok(())
            })
            .unwrap()
        }

        #[test]
        fn add_fetch() {
            block_on(async {
                let db = $init.await?;
                super::utils::db_add_fetch(&db).await?;
                KvResult::Ok(())
            })
            .unwrap()
        }

        #[test]
        fn count() {
            block_on(async {
                let db = $init.await?;
                super::utils::db_count(&db).await?;
                KvResult::Ok(())
            })
            .unwrap()
        }

        #[test]
        fn scan() {
            block_on(async {
                let db = $init.await?;
                super::utils::db_scan(&db).await?;
                KvResult::Ok(())
            })
            .unwrap()
        }

        #[test]
        fn keypair_create_fetch() {
            block_on(async {
                let db = $init.await?;
                super::utils::db_keypair_create_fetch(&db).await?;
                KvResult::Ok(())
            })
            .unwrap()
        }

        #[test]
        fn keypair_sign_verify() {
            block_on(async {
                let db = $init.await?;
                super::utils::db_keypair_sign_verify(&db).await?;
                KvResult::Ok(())
            })
            .unwrap()
        }

        #[test]
        fn keypair_pack_unpack_anon() {
            block_on(async {
                let db = $init.await?;
                super::utils::db_keypair_pack_unpack_anon(&db).await?;
                KvResult::Ok(())
            })
            .unwrap()
        }

        #[test]
        fn keypair_pack_unpack_auth() {
            block_on(async {
                let db = $init.await?;
                super::utils::db_keypair_pack_unpack_auth(&db).await?;
                KvResult::Ok(())
            })
            .unwrap()
        }

        #[test]
        fn txn_rollback() {
            block_on(async {
                let db = $init.await?;
                super::utils::db_txn_rollback(&db).await?;
                KvResult::Ok(())
            })
            .unwrap()
        }

        #[test]
        fn txn_drop() {
            block_on(async {
                let db = $init.await?;
                super::utils::db_txn_drop(&db).await?;
                KvResult::Ok(())
            })
            .unwrap()
        }

        #[test]
        fn session_drop() {
            block_on(async {
                let db = $init.await?;
                super::utils::db_session_drop(&db).await?;
                KvResult::Ok(())
            })
            .unwrap()
        }

        #[test]
        fn txn_commit() {
            block_on(async {
                let db = $init.await?;
                super::utils::db_txn_commit(&db).await?;
                KvResult::Ok(())
            })
            .unwrap()
        }
    };
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use aries_askar::sqlite::{SqliteStore, SqliteStoreOptions};
    use aries_askar::{ProvisionStore, ProvisionStoreSpec, Store};

    async fn init_db() -> KvResult<Store<SqliteStore>> {
        let spec = ProvisionStoreSpec::create_default().await?;
        let db = SqliteStoreOptions::in_memory()
            .provision_store(spec)
            .await?;
        Ok(db)
    }

    db_tests!(init_db());

    #[test]
    fn provision_from_str() {
        block_on(async {
            let db_url = "sqlite://:memory:";
            let spec = ProvisionStoreSpec::create_default().await?;
            let _db = db_url.provision_store(spec).await?;
            KvResult::Ok(())
        })
        .unwrap();

        assert!(block_on(async {
            let db_url = "not-sqlite://test-db";
            let spec = ProvisionStoreSpec::create_default().await?;
            let _db = db_url.provision_store(spec).await?;
            KvResult::Ok(())
        })
        .is_err());
    }
}

#[cfg(feature = "pg_test")]
mod postgres {
    use super::*;
    use aries_askar::postgres::{test_db::TestDB};

    async fn init_db() -> KvResult<TestDB> {
        let db = TestDB::provision().await?;
        Ok(db)
    }

    db_tests!(init_db());
}
