use aries_askar::{
    future::block_on,
    kms::{KeyAlg, LocalKey},
    Store, StoreKeyMethod,
};

const ERR_RAW_KEY: &str = "Error creating raw store key";
const ERR_SESSION: &str = "Error creating store session";
const ERR_OPEN: &str = "Error opening test store instance";
const ERR_REQ_ROW: &str = "Row required";
const ERR_CLOSE: &str = "Error closing test store instance";

#[test]
fn store_copy() {
    block_on(async {
        let pass_key = Store::new_raw_key(None).expect(ERR_RAW_KEY);
        let db = Store::provision(
            "sqlite://:memory:",
            StoreKeyMethod::RawKey,
            pass_key,
            None,
            true,
        )
        .await
        .expect(ERR_OPEN);

        let keypair =
            LocalKey::generate_with_rng(KeyAlg::Ed25519, false).expect("Error creating keypair");

        let mut conn = db.session(None).await.expect(ERR_SESSION);

        let key_name = "testkey";
        let metadata = "meta";
        conn.insert_key(key_name, &keypair, Some(metadata), None, None, None)
            .await
            .expect("Error inserting key");

        let row_cat = "testcat";
        let row_name = "testrow";
        let row_value = "testval";
        conn.insert(row_cat, row_name, row_value.as_bytes(), None, None)
            .await
            .expect("Error inserting row");

        drop(conn);

        let pass_key_copy = Store::new_raw_key(None).expect(ERR_RAW_KEY);
        let copied = db
            .copy_to(
                "sqlite://:memory:",
                StoreKeyMethod::RawKey,
                pass_key_copy,
                true,
                None
            )
            .await
            .expect("Error copying store");

        let mut conn = copied.session(None).await.expect(ERR_SESSION);
        let found = conn
            .fetch_key(key_name, false)
            .await
            .expect("Error fetching key")
            .expect(ERR_REQ_ROW);
        assert_eq!(found.algorithm(), Some(KeyAlg::Ed25519.as_str()));
        assert_eq!(found.name(), key_name);
        assert_eq!(found.metadata(), Some(metadata));
        assert!(found.is_local());
        found.load_local_key().expect("Error loading key");

        let found = conn
            .fetch(row_cat, row_name, false)
            .await
            .expect("Error loading row");
        assert!(found.is_some());

        db.close().await.expect(ERR_CLOSE);
    })
}
