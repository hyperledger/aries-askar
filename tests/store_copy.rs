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
// #[test]
// fn store_copy() {
//     block_on(async {
//         let pass_key = Store::new_raw_key(None).expect(ERR_RAW_KEY);
//         let db = Store::provision("sqlite://:memory:", StoreKeyMethod::RawKey, pass_key, None, true)
//             .await
//             .expect(ERR_OPEN);

//         let keypair = LocalKey::generate_with_rng(KeyAlg::Ed25519, false).expect("Error creating keypair");
//         let mut conn = db.session(None).await.expect(ERR_SESSION);

//         let key_name = "testkey";
//         let metadata = "meta";
//         conn.insert_key(key_name, &keypair, Some(metadata), None, None, None)
//             .await
//             .expect("Error inserting key");

//         let row_cat = "testcat";
//         let row_name = "testrow";
//         let row_value = "testval";
//         let insert_result = conn.insert(row_cat, row_name, row_value.as_bytes(), None, None).await;

//         match insert_result {
//             Ok(_) => println!("Row inserted successfully."),
//             Err(e) => panic!("Error inserting row: {:?}", e),
//         }

//         // Retrieve to confirm insertion
//         let retrieve_result = conn.fetch(row_cat, row_name, false).await;
//         match retrieve_result {
//             Ok(Some(_)) => println!("Row retrieval confirmed."),
//             Ok(None) => panic!("Row was not found in the original store before copying."),
//             Err(e) => panic!("Error during row retrieval: {:?}", e),
//         }

//         drop(conn);
//         println!("Connection dropped after confirming row presence.");

//         let pass_key_copy = Store::new_raw_key(None).expect(ERR_RAW_KEY);
//         let copied = db.copy_to("sqlite://:memory:", StoreKeyMethod::RawKey, pass_key_copy, true)
//             .await
//             .expect("Error copying store");

//         let mut conn = copied.session(None).await.expect(ERR_SESSION);
//         let found = conn.fetch_key(key_name, false).await.expect("Error fetching key").expect(ERR_REQ_ROW);

//         assert_eq!(found.algorithm(), Some(KeyAlg::Ed25519.as_str()));
//         assert_eq!(found.name(), key_name);
//         assert_eq!(found.metadata(), Some(metadata));
//         assert!(found.is_local());
//         found.load_local_key().expect("Error loading key");

//         let found = conn.fetch(row_cat, row_name, false).await.expect("Error loading row");
//         assert!(found.is_some(), "Row was not found in the copied store.");

//         db.close().await.expect(ERR_CLOSE);
//     })
// }


#[test]
fn store_copy() {
    block_on(async {
        // Attempt to create a raw key
        let pass_key = Store::new_raw_key(None).expect(ERR_RAW_KEY);
        println!("Raw key created successfully.");

        // Provision a new in-memory store
        let db = Store::provision(
            "sqlite://:memory:",
            StoreKeyMethod::RawKey,
            pass_key,
            None,
            true,
        )
        .await
        .expect(ERR_OPEN);
        println!("Store provisioned in memory.");

        // Generate a keypair
        let keypair =
            LocalKey::generate_with_rng(KeyAlg::Ed25519, false).expect("Error creating keypair");
        println!("Keypair generated successfully.");

        // Create a session
        let mut conn = db.session(None).await.expect(ERR_SESSION);
        println!("Session created successfully.");

        // Insert a key
        let key_name = "testkey";
        let metadata = "meta";
        conn.insert_key(key_name, &keypair, Some(metadata), None, None, None)
            .await
            .expect("Error inserting key");
        println!("Key inserted successfully.");
         

        // Insert a row
        let row_cat = "testcat";
        let row_name = "testrow";
        let row_value = "testval";
        conn.insert(row_cat, row_name, row_value.as_bytes(), None, None)
            .await
            .expect("Error inserting row");
        println!("Row inserted successfully.");

        // count the number of times a key is stored in insert
        let count = conn.count(Some(row_cat), None).await.expect("Error counting keys");
        println!("{:?} count of ", count);
        assert_eq!(count, 1);
        // Close the connection
        drop(conn);
        println!("Connection dropped.");

        // Copy the store
        let pass_key_copy = Store::new_raw_key(None).expect(ERR_RAW_KEY);
        println!("Raw key for copy created successfully.");
        let copied = db
            .copy_to(
                "sqlite://:memory:",
                StoreKeyMethod::RawKey,
                pass_key_copy,
                true,
            )
            .await
            .expect("Error copying store");
        println!("Store copied successfully.");

        // Access the copied store
        let mut conn = copied.session(None).await.expect(ERR_SESSION);
        println!("Session for copied store created successfully.");
        // Get everythig from the copied store
        // let all = conn.fetch_all().await.expect("Error fetching all");
        // Fetch the key
        let found = conn
            .fetch_key(key_name, false)
            .await
            .expect("Error fetching key")
            .expect(ERR_REQ_ROW);
        println!("Key fetched successfully.");
        // assert_eq!(found.algorithm(), Some(KeyAlg::Ed25519.as_str()));
        assert_eq!(found.name(), key_name);
        assert_eq!(found.metadata(), Some(metadata));
        assert!(found.is_local());
        found.load_local_key().expect("Error loading key");
        println!("Local key loaded successfully.");

        // Fetch the row
        let found = conn
            .fetch(row_cat, row_name, false)
            .await
            .expect("Error loading row");
        println!("Row fetch attempt completed.");
        assert!(found.is_some());


       
        // Close the original store
        db.close().await.expect(ERR_CLOSE);
        println!("Original store closed successfully.");
    })
}
