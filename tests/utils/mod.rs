use std::{fmt::Debug, future::Future, ops::Deref, pin::Pin, sync::Arc};

use aries_askar::{Backend, Entry, EntryTag, Error, ErrorKind, Store, TagFilter};

use tokio::task::spawn;

const ERR_PROFILE: &'static str = "Error creating profile";
const ERR_SESSION: &'static str = "Error starting session";
const ERR_TRANSACTION: &'static str = "Error starting transaction";
const ERR_COMMIT: &'static str = "Error committing transaction";
const ERR_COUNT: &'static str = "Error performing count";
const ERR_FETCH: &'static str = "Error fetching test row";
const ERR_FETCH_ALL: &'static str = "Error fetching all test rows";
const ERR_REQ_ROW: &'static str = "Expected row";
const ERR_REQ_ERR: &'static str = "Expected error";
const ERR_INSERT: &'static str = "Error inserting test row";
const ERR_REPLACE: &'static str = "Error replacing test row";
const ERR_REMOVE_ALL: &'static str = "Error removing test rows";
const ERR_SCAN: &'static str = "Error starting scan";
const ERR_SCAN_NEXT: &'static str = "Error fetching scan rows";
// const ERR_CREATE_KEYPAIR: &'static str = "Error creating keypair";
// const ERR_FETCH_KEY: &'static str = "Error fetching key";
// const ERR_SIGN: &'static str = "Error signing message";
// const ERR_VERIFY: &'static str = "Error verifying signature";

pub trait TestStore: Clone + Deref<Target = Store<Self::DB>> + Send + Sync {
    type DB: Backend + Debug + 'static;

    fn close(self) -> Pin<Box<dyn Future<Output = Result<(), Error>>>>;
}

impl<B: Backend + Debug + 'static> TestStore for Arc<Store<B>> {
    type DB = B;

    fn close(self) -> Pin<Box<dyn Future<Output = Result<(), Error>>>> {
        let db = Arc::try_unwrap(self).unwrap();
        Box::pin(db.close())
    }
}

pub async fn db_create_remove_profile(db: impl TestStore) {
    let profile = db.create_profile(None).await.expect(ERR_PROFILE);
    assert_eq!(
        db.remove_profile(profile)
            .await
            .expect("Error removing profile"),
        true
    );
    assert_eq!(
        db.remove_profile("not a profile".to_string())
            .await
            .expect("Error removing profile"),
        false
    );
}

pub async fn db_fetch_fail(db: impl TestStore) {
    let mut conn = db.session(None).await.expect(ERR_SESSION);
    let result = conn.fetch("cat", "name", false).await.expect(ERR_FETCH);
    assert_eq!(result.is_none(), true);
}

pub async fn db_insert_fetch(db: impl TestStore) {
    let test_row = Entry::new(
        "category",
        "name",
        "value",
        vec![
            EntryTag::Encrypted("t1".to_string(), "v1".to_string()),
            EntryTag::Plaintext("t2".to_string(), "v2".to_string()),
        ],
    );

    let mut conn = db.session(None).await.expect(ERR_SESSION);

    conn.insert(
        &test_row.category,
        &test_row.name,
        &test_row.value,
        Some(test_row.tags.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    let row = conn
        .fetch(&test_row.category, &test_row.name, false)
        .await
        .expect(ERR_FETCH)
        .expect(ERR_REQ_ROW);
    assert_eq!(row, test_row);

    let rows = conn
        .fetch_all(&test_row.category, None, None, false)
        .await
        .expect(ERR_FETCH_ALL);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0], test_row);
}

pub async fn db_insert_duplicate(db: impl TestStore) {
    let test_row = Entry::new("category", "name", "value", Vec::new());

    let mut conn = db.session(None).await.expect(ERR_SESSION);

    conn.insert(
        &test_row.category,
        &test_row.name,
        &test_row.value,
        Some(test_row.tags.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    let err = conn
        .insert(
            &test_row.category,
            &test_row.name,
            &test_row.value,
            Some(test_row.tags.as_slice()),
            None,
        )
        .await
        .expect_err(ERR_REQ_ERR);
    assert_eq!(err.kind(), ErrorKind::Duplicate);
}

pub async fn db_insert_remove(db: impl TestStore) {
    let test_row = Entry::new("category", "name", "value", Vec::new());

    let mut conn = db.session(None).await.expect(ERR_SESSION);

    conn.insert(
        &test_row.category,
        &test_row.name,
        &test_row.value,
        Some(test_row.tags.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    conn.remove(&test_row.category, &test_row.name)
        .await
        .expect(ERR_REQ_ROW);
}

pub async fn db_remove_missing(db: impl TestStore) {
    let mut conn = db.session(None).await.expect(ERR_SESSION);

    let err = conn.remove("cat", "name").await.expect_err(ERR_REQ_ERR);
    assert_eq!(err.kind(), ErrorKind::NotFound);
}

pub async fn db_replace_fetch(db: impl TestStore) {
    let test_row = Entry::new("category", "name", "value", Vec::new());

    let mut conn = db.session(None).await.expect(ERR_SESSION);

    conn.insert(
        &test_row.category,
        &test_row.name,
        &test_row.value,
        Some(test_row.tags.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    let mut replace_row = test_row.clone();
    replace_row.value = "new value".into();
    conn.replace(
        &replace_row.category,
        &replace_row.name,
        &replace_row.value,
        Some(replace_row.tags.as_slice()),
        None,
    )
    .await
    .expect(ERR_REPLACE);

    let row = conn
        .fetch(&replace_row.category, &replace_row.name, false)
        .await
        .expect(ERR_FETCH)
        .expect(ERR_REQ_ROW);
    assert_eq!(row, replace_row);
}

pub async fn db_replace_missing(db: impl TestStore) {
    let test_row = Entry::new("category", "name", "value", Vec::new());

    let mut conn = db.session(None).await.expect(ERR_SESSION);

    let err = conn
        .replace(
            &test_row.category,
            &test_row.name,
            &test_row.value,
            Some(test_row.tags.as_slice()),
            None,
        )
        .await
        .expect_err(ERR_REQ_ERR);
    assert_eq!(err.kind(), ErrorKind::NotFound);
}

pub async fn db_count(db: impl TestStore) {
    let category = "category".to_string();
    let test_rows = vec![Entry::new(&category, "name", "value", Vec::new())];

    let mut conn = db.session(None).await.expect(ERR_SESSION);

    for upd in test_rows.iter() {
        conn.insert(
            &upd.category,
            &upd.name,
            &upd.value,
            Some(upd.tags.as_slice()),
            None,
        )
        .await
        .expect(ERR_INSERT);
    }

    let tag_filter = None;
    let count = conn.count(&category, tag_filter).await.expect(ERR_COUNT);
    assert_eq!(count, 1);

    let tag_filter = Some(TagFilter::is_eq("sometag", "someval"));
    let count = conn.count(&category, tag_filter).await.expect(ERR_COUNT);
    assert_eq!(count, 0);
}

pub async fn db_count_exist(db: impl TestStore) {
    let test_row = Entry::new(
        "category",
        "name",
        "value",
        vec![
            EntryTag::Encrypted("enc".to_string(), "v1".to_string()),
            EntryTag::Plaintext("plain".to_string(), "v2".to_string()),
        ],
    );

    let mut conn = db.session(None).await.expect(ERR_SESSION);

    conn.insert(
        &test_row.category,
        &test_row.name,
        &test_row.value,
        Some(test_row.tags.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    assert_eq!(
        conn.count(
            &test_row.category,
            Some(TagFilter::exist(vec!["enc".to_string()]))
        )
        .await
        .expect(ERR_COUNT),
        1
    );

    assert_eq!(
        conn.count(
            &test_row.category,
            Some(TagFilter::exist(vec!["~plain".to_string()]))
        )
        .await
        .expect(ERR_COUNT),
        1
    );

    assert_eq!(
        conn.count(
            &test_row.category,
            Some(TagFilter::exist(vec!["~enc".to_string()]))
        )
        .await
        .expect(ERR_COUNT),
        0
    );

    assert_eq!(
        conn.count(
            &test_row.category,
            Some(TagFilter::exist(vec!["plain".to_string()]))
        )
        .await
        .expect(ERR_COUNT),
        0
    );

    assert_eq!(
        conn.count(
            &test_row.category,
            Some(TagFilter::exist(vec!["other".to_string()]))
        )
        .await
        .expect(ERR_COUNT),
        0
    );

    assert_eq!(
        conn.count(
            &test_row.category,
            Some(TagFilter::exist(vec![
                "enc".to_string(),
                "other".to_string()
            ]))
        )
        .await
        .expect(ERR_COUNT),
        0
    );

    assert_eq!(
        conn.count(
            &test_row.category,
            Some(TagFilter::all_of(vec![
                TagFilter::exist(vec!["enc".to_string()]),
                TagFilter::exist(vec!["~plain".to_string()])
            ]))
        )
        .await
        .expect(ERR_COUNT),
        1
    );

    assert_eq!(
        conn.count(
            &test_row.category,
            Some(TagFilter::any_of(vec![
                TagFilter::exist(vec!["~enc".to_string()]),
                TagFilter::exist(vec!["~plain".to_string()])
            ]))
        )
        .await
        .expect(ERR_COUNT),
        1
    );

    assert_eq!(
        conn.count(
            &test_row.category,
            Some(TagFilter::all_of(vec![
                TagFilter::exist(vec!["~enc".to_string()]),
                TagFilter::exist(vec!["~plain".to_string()])
            ]))
        )
        .await
        .expect(ERR_COUNT),
        0
    );

    assert_eq!(
        conn.count(
            &test_row.category,
            Some(TagFilter::not(TagFilter::exist(vec![
                "enc".to_string(),
                "other".to_string()
            ]),))
        )
        .await
        .expect(ERR_COUNT),
        0
    );
}

pub async fn db_scan(db: impl TestStore) {
    let category = "category".to_string();
    let test_rows = vec![Entry::new(
        &category,
        "name",
        "value",
        vec![
            EntryTag::Encrypted("t1".to_string(), "v1".to_string()),
            EntryTag::Plaintext("t2".to_string(), "v2".to_string()),
        ],
    )];

    let mut conn = db.session(None).await.expect(ERR_SESSION);

    for upd in test_rows.iter() {
        conn.insert(
            &upd.category,
            &upd.name,
            &upd.value,
            Some(upd.tags.as_slice()),
            None,
        )
        .await
        .expect(ERR_INSERT);
    }
    drop(conn);

    let tag_filter = None;
    let offset = None;
    let limit = None;
    let mut scan = db
        .scan(None, category.clone(), tag_filter, offset, limit)
        .await
        .expect(ERR_SCAN);
    let rows = scan.fetch_next().await.expect(ERR_SCAN_NEXT);
    assert_eq!(rows, Some(test_rows));
    let rows = scan.fetch_next().await.expect(ERR_SCAN_NEXT);
    assert_eq!(rows, None);

    let tag_filter = Some(TagFilter::is_eq("sometag", "someval"));
    let mut scan = db
        .scan(None, category.clone(), tag_filter, offset, limit)
        .await
        .expect(ERR_SCAN);
    let rows = scan.fetch_next().await.expect(ERR_SCAN_NEXT);
    assert_eq!(rows, None);
}

pub async fn db_remove_all(db: impl TestStore) {
    let test_rows = vec![
        Entry::new(
            "category",
            "item1",
            "value",
            vec![
                EntryTag::Encrypted("t1".to_string(), "del".to_string()),
                EntryTag::Plaintext("t2".to_string(), "del".to_string()),
            ],
        ),
        Entry::new(
            "category",
            "item2",
            "value",
            vec![
                EntryTag::Encrypted("t1".to_string(), "del".to_string()),
                EntryTag::Plaintext("t2".to_string(), "del".to_string()),
            ],
        ),
        Entry::new(
            "category",
            "item3",
            "value",
            vec![
                EntryTag::Encrypted("t1".to_string(), "keep".to_string()),
                EntryTag::Plaintext("t2".to_string(), "keep".to_string()),
            ],
        ),
    ];

    let mut conn = db.session(None).await.expect(ERR_SESSION);

    for test_row in test_rows.iter() {
        conn.insert(
            &test_row.category,
            &test_row.name,
            &test_row.value,
            Some(test_row.tags.as_slice()),
            None,
        )
        .await
        .expect(ERR_INSERT);
    }

    // could detect that a second transaction would block here?
    // depends on the backend. just checking that no SQL errors occur for now.
    let removed = conn
        .remove_all(
            "category",
            Some(TagFilter::all_of(vec![
                TagFilter::is_eq("t1", "del"),
                TagFilter::is_eq("~t2", "del"),
            ])),
        )
        .await
        .expect(ERR_REMOVE_ALL);
    assert_eq!(removed, 2);
}

// pub async fn db_keypair_create_fetch(db: impl TestStore) {
//     let mut conn = db.session(None).await.expect(ERR_SESSION);

//     let metadata = "meta".to_owned();
//     let key_info = conn
//         .create_keypair(KeyAlg::Ed25519, Some(&metadata), None, None)
//         .await
//         .expect(ERR_CREATE_KEYPAIR);
//     assert_eq!(key_info.params.metadata, Some(metadata));

//     let found = conn
//         .fetch_key(key_info.category.clone(), &key_info.ident, false)
//         .await
//         .expect(ERR_FETCH_KEY);
//     assert_eq!(Some(key_info), found);
// }

// pub async fn db_keypair_sign_verify(db: impl TestStore) {
//     let mut conn = db.session(None).await.expect(ERR_SESSION);

//     let key_info = conn
//         .create_keypair(KeyAlg::Ed25519, None, None, None)
//         .await
//         .expect(ERR_CREATE_KEYPAIR);

//     let message = b"message".to_vec();
//     let sig = conn
//         .sign_message(&key_info.ident, &message)
//         .await
//         .expect(ERR_SIGN);

//     assert_eq!(
//         verify_signature(&key_info.ident, &message, &sig).expect(ERR_VERIFY),
//         true
//     );

//     assert_eq!(
//         verify_signature(&key_info.ident, b"bad input", &sig).expect(ERR_VERIFY),
//         false
//     );

//     assert_eq!(
//         verify_signature(
//             &key_info.ident,
//             // [0u8; 64]
//             b"xt19s1sp2UZCGhy9rNyb1FtxdKiDGZZPNFnc1KiM9jYYEuHxuwNeFf1oQKsn8zv6yvYBGhXa83288eF4MqN1oDq",
//             &sig
//         ).expect(ERR_VERIFY),
//         false
//     );

//     assert_eq!(
//         verify_signature(&key_info.ident, &message, b"bad sig").is_err(),
//         true
//     );

//     let err = verify_signature("not a key", &message, &sig).expect_err(ERR_REQ_ERR);
//     assert_eq!(err.kind(), ErrorKind::Input);
// }

// pub async fn db_keypair_pack_unpack_anon(db: impl TestStore) {
//     let mut conn = db.session(None).await.expect(ERR_SESSION);

//     let recip_key = conn
//         .create_keypair(KeyAlg::Ed25519, None, None, None)
//         .await
//         .expect(ERR_CREATE_KEYPAIR);

//     let msg = b"message".to_vec();

//     let packed = conn
//         .pack_message(vec![recip_key.ident.as_str()], None, &msg)
//         .await
//         .expect(ERR_PACK);

//     let (unpacked, p_recip, p_send) = conn.unpack_message(&packed).await.expect(ERR_UNPACK);
//     assert_eq!(unpacked, msg);
//     assert_eq!(p_recip.to_string(), recip_key.ident);
//     assert_eq!(p_send, None);
// }

// pub async fn db_keypair_pack_unpack_auth(db: impl TestStore) {
//     let mut conn = db.session(None).await.expect(ERR_SESSION);

//     let sender_key = conn
//         .create_keypair(KeyAlg::Ed25519, None, None, None)
//         .await
//         .expect(ERR_CREATE_KEYPAIR);
//     let recip_key = conn
//         .create_keypair(KeyAlg::Ed25519, None, None, None)
//         .await
//         .expect(ERR_CREATE_KEYPAIR);

//     let msg = b"message".to_vec();

//     let packed = conn
//         .pack_message(
//             vec![recip_key.ident.as_str()],
//             Some(&sender_key.ident),
//             &msg,
//         )
//         .await
//         .expect(ERR_PACK);

//     let (unpacked, p_recip, p_send) = conn.unpack_message(&packed).await.expect(ERR_UNPACK);
//     assert_eq!(unpacked, msg);
//     assert_eq!(p_recip.to_string(), recip_key.ident);
//     assert_eq!(p_send.map(|k| k.to_string()), Some(sender_key.ident));
// }

pub async fn db_txn_rollback(db: impl TestStore) {
    let test_row = Entry::new("category", "name", "value", Vec::new());

    let mut conn = db.transaction(None).await.expect(ERR_TRANSACTION);

    conn.insert(
        &test_row.category,
        &test_row.name,
        &test_row.value,
        Some(test_row.tags.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    conn.rollback()
        .await
        .expect("Error rolling back transaction");

    let mut conn = db.session(None).await.expect("Error starting new session");

    let row = conn
        .fetch(&test_row.category, &test_row.name, false)
        .await
        .expect("Error fetching test row");
    assert_eq!(row, None);
}

pub async fn db_txn_drop(db: impl TestStore) {
    let test_row = Entry::new("category", "name", "value", Vec::new());

    let mut conn = db
        .transaction(None)
        .await
        .expect("Error starting new transaction");

    conn.insert(
        &test_row.category,
        &test_row.name,
        &test_row.value,
        Some(test_row.tags.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    drop(conn);

    let mut conn = db.session(None).await.expect("Error starting new session");

    let row = conn
        .fetch(&test_row.category, &test_row.name, false)
        .await
        .expect("Error fetching test row");
    assert_eq!(row, None);
}

// test that session does NOT have transaction rollback behaviour
pub async fn db_session_drop(db: impl TestStore) {
    let test_row = Entry::new("category", "name", "value", Vec::new());

    let mut conn = db.session(None).await.expect(ERR_SESSION);

    conn.insert(
        &test_row.category,
        &test_row.name,
        &test_row.value,
        Some(test_row.tags.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    drop(conn);

    let mut conn = db.session(None).await.expect(ERR_SESSION);

    let row = conn
        .fetch(&test_row.category, &test_row.name, false)
        .await
        .expect(ERR_FETCH);
    assert_eq!(row, Some(test_row));
}

pub async fn db_txn_commit(db: impl TestStore) {
    let test_row = Entry::new("category", "name", "value", Vec::new());

    let mut conn = db.transaction(None).await.expect(ERR_TRANSACTION);

    conn.insert(
        &test_row.category,
        &test_row.name,
        &test_row.value,
        Some(test_row.tags.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    conn.commit().await.expect(ERR_COMMIT);

    let mut conn = db.session(None).await.expect(ERR_SESSION);

    let row = conn
        .fetch(&test_row.category, &test_row.name, false)
        .await
        .expect(ERR_FETCH);
    assert_eq!(row, Some(test_row));
}

pub async fn db_txn_fetch_for_update(db: impl TestStore) {
    let test_row = Entry::new("category", "name", "value", Vec::new());

    let mut conn = db.transaction(None).await.expect(ERR_TRANSACTION);

    conn.insert(
        &test_row.category,
        &test_row.name,
        &test_row.value,
        Some(test_row.tags.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    // could detect that a second transaction would block here?
    // depends on the backend. just checking that no SQL errors occur for now.
    let row = conn
        .fetch(&test_row.category, &test_row.name, true)
        .await
        .expect(ERR_FETCH)
        .expect(ERR_REQ_ROW);
    assert_eq!(row, test_row);

    let rows = conn
        .fetch_all(&test_row.category, None, Some(2), true)
        .await
        .expect(ERR_FETCH_ALL);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0], test_row);

    conn.commit().await.expect(ERR_COMMIT);
}

pub async fn db_txn_contention(db: impl TestStore + 'static) {
    let test_row = Entry::new(
        "category",
        "count",
        "0",
        vec![
            EntryTag::Encrypted("t1".to_string(), "v1".to_string()),
            EntryTag::Plaintext("t2".to_string(), "v2".to_string()),
        ],
    );

    let mut conn = db.transaction(None).await.expect(ERR_TRANSACTION);

    conn.insert(
        &test_row.category,
        &test_row.name,
        &test_row.value,
        Some(test_row.tags.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    conn.commit().await.expect(ERR_COMMIT);

    const TASKS: usize = 25;
    const INC: usize = 500;

    async fn inc(db: impl TestStore, category: String, name: String) {
        for _ in 0..INC {
            let mut conn = db.transaction(None).await.expect(ERR_TRANSACTION);
            let row = conn
                .fetch(&category, &name, true)
                .await
                .expect(ERR_FETCH)
                .expect(ERR_REQ_ROW);
            let val: usize = str::parse(row.value.as_opt_str().unwrap()).unwrap();
            conn.replace(
                &category,
                &name,
                &format!("{}", val + 1).as_bytes(),
                Some(row.tags.as_slice()),
                None,
            )
            .await
            .expect(ERR_REPLACE);
            conn.commit().await.expect(ERR_COMMIT);
        }
    }

    let mut tasks = vec![];
    for _ in 0..TASKS {
        tasks.push(spawn(inc(
            db.clone(),
            test_row.category.clone(),
            test_row.name.clone(),
        )));
    }
    // JoinSet is not stable yet, just await all the tasks
    for task in tasks {
        task.await.unwrap();
    }

    // check the total
    let mut conn = db.session(None).await.expect(ERR_SESSION);
    let row = conn
        .fetch(&test_row.category, &test_row.name, false)
        .await
        .expect(ERR_FETCH)
        .expect(ERR_REQ_ROW);
    assert_eq!(row.value, format!("{}", TASKS * INC).as_bytes());
}
