use aries_store_kv::indy_compat::print_records;

#[test]
fn test_print_records() {
    let db = "tests/faber.agent372766/sqlite.db";
    let key = "Faber.Agent372766";
    print_records(db.to_string(), key.to_string()).unwrap();
}
