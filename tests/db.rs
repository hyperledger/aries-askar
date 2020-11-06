mod utils;

macro_rules! db_tests {
    ($init:expr) => {
        use aries_askar::future::block_on;

        #[test]
        fn init() {
            block_on($init);
        }

        #[test]
        fn fetch_fail() {
            block_on(async {
                let db = $init.await;
                super::utils::db_fetch_fail(&db).await;
            })
        }

        #[test]
        fn insert_fetch() {
            block_on(async {
                let db = $init.await;
                super::utils::db_insert_fetch(&db).await;
            })
        }

        #[test]
        fn insert_duplicate() {
            block_on(async {
                let db = $init.await;
                super::utils::db_insert_duplicate(&db).await;
            })
        }

        #[test]
        fn insert_remove() {
            block_on(async {
                let db = $init.await;
                super::utils::db_insert_remove(&db).await;
            })
        }

        #[test]
        fn remove_missing() {
            block_on(async {
                let db = $init.await;
                super::utils::db_remove_missing(&db).await;
            })
        }

        #[test]
        fn replace_fetch() {
            block_on(async {
                let db = $init.await;
                super::utils::db_replace_fetch(&db).await;
            })
        }

        #[test]
        fn replace_missing() {
            block_on(async {
                let db = $init.await;
                super::utils::db_replace_missing(&db).await;
            })
        }

        #[test]
        fn count() {
            block_on(async {
                let db = $init.await;
                super::utils::db_count(&db).await;
            })
        }

        #[test]
        fn scan() {
            block_on(async {
                let db = $init.await;
                super::utils::db_scan(&db).await;
            })
        }

        #[test]
        fn keypair_create_fetch() {
            block_on(async {
                let db = $init.await;
                super::utils::db_keypair_create_fetch(&db).await;
            })
        }

        #[test]
        fn keypair_sign_verify() {
            block_on(async {
                let db = $init.await;
                super::utils::db_keypair_sign_verify(&db).await;
            })
        }

        #[test]
        fn keypair_pack_unpack_anon() {
            block_on(async {
                let db = $init.await;
                super::utils::db_keypair_pack_unpack_anon(&db).await;
            })
        }

        #[test]
        fn keypair_pack_unpack_auth() {
            block_on(async {
                let db = $init.await;
                super::utils::db_keypair_pack_unpack_auth(&db).await;
            })
        }

        #[test]
        fn txn_rollback() {
            block_on(async {
                let db = $init.await;
                super::utils::db_txn_rollback(&db).await;
            })
        }

        #[test]
        fn txn_drop() {
            block_on(async {
                let db = $init.await;
                super::utils::db_txn_drop(&db).await;
            })
        }

        #[test]
        fn session_drop() {
            block_on(async {
                let db = $init.await;
                super::utils::db_session_drop(&db).await;
            })
        }

        #[test]
        fn txn_commit() {
            block_on(async {
                let db = $init.await;
                super::utils::db_txn_commit(&db).await;
            })
        }
    };
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use aries_askar::sqlite::{SqliteStore, SqliteStoreOptions};
    use aries_askar::{ProvisionStore, ProvisionStoreSpec, Store};

    async fn init_db() -> Store<SqliteStore> {
        env_logger::builder().is_test(true).try_init().unwrap_or(());
        let spec = ProvisionStoreSpec::create_default()
            .await
            .expect("Error creating provision spec");
        SqliteStoreOptions::in_memory()
            .provision_store(spec)
            .await
            .expect("Error provisioning sqlite store")
    }

    db_tests!(init_db());

    #[test]
    fn provision_from_str() {
        block_on(async {
            let db_url = "sqlite://:memory:";
            let spec = ProvisionStoreSpec::create_default()
                .await
                .expect("Error creating provision spec");
            let _db = db_url
                .provision_store(spec)
                .await
                .expect("Error provisioning store");
        });

        block_on(async {
            let db_url = "not-sqlite://test-db";
            let spec = ProvisionStoreSpec::create_default()
                .await
                .expect("Error creating provision spec");
            let _db = db_url
                .provision_store(spec)
                .await
                .expect_err("Expected provision failure");
        });
    }
}

#[cfg(feature = "pg_test")]
mod postgres {
    use aries_askar::postgres::test_db::TestDB;

    async fn init_db() -> TestDB {
        env_logger::builder().is_test(true).try_init().unwrap_or(());
        TestDB::provision()
            .await
            .expect("Error provisioning postgres test database")
    }

    db_tests!(init_db());
}
