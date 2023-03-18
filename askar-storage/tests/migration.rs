#![cfg(all(feature = "sqlite", feature = "migration"))]

use std::path::PathBuf;

use askar_storage::future::block_on;
use askar_storage::migration::IndySdkToAriesAskarMigration;
use askar_storage::Error;

const DB_TEMPLATE_PATH: &str = "./tests/indy_wallet_sqlite.db";
const DB_UPGRADE_PATH: &str = "./tests/indy_wallet_sqlite_upgraded.db";

/// Create a copy of the input DB for migration
fn prepare_db() {
    let tpl_paths = [
        PathBuf::from(DB_TEMPLATE_PATH),
        PathBuf::from(format!("{}-shm", DB_TEMPLATE_PATH)),
        PathBuf::from(format!("{}-wal", DB_TEMPLATE_PATH)),
    ];
    let upd_paths = [
        PathBuf::from(DB_UPGRADE_PATH),
        PathBuf::from(format!("{}-shm", DB_UPGRADE_PATH)),
        PathBuf::from(format!("{}-wal", DB_UPGRADE_PATH)),
    ];
    for (tpl, upd) in tpl_paths.iter().zip(upd_paths) {
        if tpl.exists() {
            std::fs::copy(tpl, upd).expect("Error copying wallet database");
        } else {
            std::fs::remove_file(upd).ok();
        }
    }
}

#[test]
fn test_sqlite_migration() {
    prepare_db();

    let res = block_on(async {
        let wallet_name = "walletwallet.0";
        let wallet_key = "GfwU1DC7gEZNs3w41tjBiZYj7BNToDoFEqKY6wZXqs1A";
        let migrator =
            IndySdkToAriesAskarMigration::connect(DB_UPGRADE_PATH, wallet_name, wallet_key, "RAW")
                .await?;
        migrator.migrate().await?;
        Result::<_, Error>::Ok(())
    });

    // We still need some indication if something returned with an error
    res.expect("Migration failed");
}
