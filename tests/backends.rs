mod utils;

macro_rules! backend_tests {
    ($init:expr) => {
        use aries_askar::future::block_on;

        #[test]
        fn init() {
            block_on($init);
        }

        #[test]
        fn create_remove_profile() {
            block_on(async {
                let db = $init.await;
                super::utils::db_create_remove_profile(&db).await;
            })
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
        fn remove_all() {
            block_on(async {
                let db = $init.await;
                super::utils::db_remove_all(&db).await;
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

        #[test]
        fn txn_fetch_for_update() {
            block_on(async {
                let db = $init.await;
                super::utils::db_txn_fetch_for_update(&db).await;
            })
        }
    };
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use aries_askar::sqlite::{SqliteStore, SqliteStoreOptions};
    use aries_askar::{generate_raw_wrap_key, ManageBackend, Store, WrapKeyMethod};
    use std::path::Path;

    #[test]
    fn create_remove_db() {
        env_logger::builder().is_test(true).try_init().unwrap_or(());
        let fname = format!("sqlite-test-{}.db", uuid::Uuid::new_v4().to_string());
        assert_eq!(
            Path::new(&fname).exists(),
            false,
            "Oops, should be a unique filename"
        );

        let key = generate_raw_wrap_key(None).expect("Error creating raw key");
        block_on(async move {
            assert_eq!(
                SqliteStoreOptions::new(fname.as_str())
                    .expect("Error initializing sqlite store options")
                    .remove_backend()
                    .await
                    .expect("Error removing sqlite store"),
                false
            );

            let store = SqliteStoreOptions::new(fname.as_str())
                .expect("Error initializing sqlite store options")
                .provision_backend(WrapKeyMethod::RawKey, key.as_ref(), None, false)
                .await
                .expect("Error provisioning sqlite store");
            assert_eq!(Path::new(&fname).exists(), true);

            let store2 = SqliteStoreOptions::new(fname.as_str())
                .expect("Error initializing sqlite store options")
                .open_backend(Some(WrapKeyMethod::RawKey), key.as_ref(), None)
                .await
                .expect("Error opening sqlite store");
            store2.close().await.expect("Error closing sqlite store");

            store.close().await.expect("Error closing sqlite store");
            assert_eq!(Path::new(&fname).exists(), true);

            assert_eq!(
                SqliteStoreOptions::new(fname.as_str())
                    .expect("Error initializing sqlite store options")
                    .remove_backend()
                    .await
                    .expect("Error removing sqlite store"),
                true
            );
            assert_eq!(Path::new(&fname).exists(), false);
        })
    }

    #[test]
    fn rekey_db() {
        env_logger::builder().is_test(true).try_init().unwrap_or(());
        let fname = format!("sqlite-test-{}.db", uuid::Uuid::new_v4().to_string());
        let key1 = generate_raw_wrap_key(None).expect("Error creating raw key");
        let key2 = generate_raw_wrap_key(None).expect("Error creating raw key");
        assert_ne!(key1, key2);

        block_on(async move {
            let mut store = SqliteStoreOptions::new(fname.as_str())
                .expect("Error initializing sqlite store options")
                .provision_backend(WrapKeyMethod::RawKey, key1.as_ref(), None, false)
                .await
                .expect("Error provisioning sqlite store");

            store
                .rekey(WrapKeyMethod::RawKey, key2.as_ref())
                .await
                .expect("Error rekeying database");

            SqliteStoreOptions::new(fname.as_str())
                .expect("Error initializing sqlite store options")
                .open_backend(Some(WrapKeyMethod::RawKey), key2.as_ref(), None)
                .await
                .expect("Error opening rekeyed store")
                .close()
                .await
                .expect("Error closing store");

            store.close().await.expect("Error closing store");

            SqliteStoreOptions::new(fname.as_str())
                .expect("Error initializing sqlite store options")
                .remove_backend()
                .await
                .expect("Error removing sqlite store");
        })
    }

    async fn init_db() -> Store<SqliteStore> {
        env_logger::builder().is_test(true).try_init().unwrap_or(());
        let key = generate_raw_wrap_key(None).expect("Error creating raw key");
        SqliteStoreOptions::in_memory()
            .provision(WrapKeyMethod::RawKey, key, None, false)
            .await
            .expect("Error provisioning sqlite store")
    }

    backend_tests!(init_db());

    #[test]
    fn provision_from_str() {
        let key = generate_raw_wrap_key(None).expect("Error creating raw key");

        block_on(async {
            let db_url = "sqlite://:memory:";
            let _db = db_url
                .provision_backend(WrapKeyMethod::RawKey, key.as_ref(), None, false)
                .await
                .expect("Error provisioning store");
        });

        block_on(async {
            let db_url = "not-sqlite://test-db";
            let _db = db_url
                .provision_backend(WrapKeyMethod::RawKey, key.as_ref(), None, false)
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

    backend_tests!(init_db());
}
