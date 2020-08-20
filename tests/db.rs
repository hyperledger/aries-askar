use aries_store_kv::{KvProvisionStore, KvResult};

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
    };
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use aries_store_kv::sqlite::KvSqlite;

    async fn init_db() -> KvResult<Box<KvSqlite>> {
        let db = KvSqlite::open_in_memory().await?;
        db.provision().await?;
        Ok(Box::new(db))
    }

    db_tests!(init_db());
}

#[cfg(all(feature = "pg_test", feature = "postgres"))]
mod postgres {
    use super::*;
    use aries_store_kv::postgres::{KvPostgres, TestDB};

    async fn init_db<'t>() -> KvResult<TestDB<'t>> {
        let db = KvPostgres::open_test().await?;
        db.provision().await?;
        Ok(db)
    }

    db_tests!(init_db());
}
