use aries_store_kv::future::block_on;
use aries_store_kv::indy_compat::print_records;

#[test]
fn test_print_records() {
    let db = "tests/faber.agent372766/sqlite.db";
    let key = "Faber.Agent372766";
    block_on(print_records(db, key)).unwrap();
}
