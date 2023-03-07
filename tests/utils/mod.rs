use std::{fmt::Debug, future::Future, ops::Deref, pin::Pin, sync::Arc};

use aries_askar::{
    kms::{KeyAlg, LocalKey},
    Backend, Entry, EntryTag, Error, ErrorKind, Store, TagFilter,
};

use tokio::task::spawn;

const ERR_PROFILE: &str = "Error creating profile";
const ERR_SESSION: &str = "Error starting session";
const ERR_TRANSACTION: &str = "Error starting transaction";
const ERR_COMMIT: &str = "Error committing transaction";
const ERR_COUNT: &str = "Error performing count";
const ERR_FETCH: &str = "Error fetching test row";
const ERR_FETCH_ALL: &str = "Error fetching all test rows";
const ERR_REQ_ROW: &str = "Expected row";
const ERR_REQ_ERR: &str = "Expected error";
const ERR_INSERT: &str = "Error inserting test row";
const ERR_REPLACE: &str = "Error replacing test row";
const ERR_REMOVE_ALL: &str = "Error removing test rows";
const ERR_SCAN: &str = "Error starting scan";
const ERR_SCAN_NEXT: &str = "Error fetching scan rows";
const ERR_CREATE_KEYPAIR: &str = "Error creating keypair";
const ERR_INSERT_KEY: &str = "Error inserting key";
const ERR_FETCH_KEY: &str = "Error fetching key";
const ERR_LOAD_KEY: &str = "Error loading key";

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
    assert!(db
        .remove_profile(profile)
        .await
        .expect("Error removing profile"),);
    assert!(!db
        .remove_profile("not a profile".to_string())
        .await
        .expect("Error removing profile"),);
}

pub async fn db_fetch_fail(db: impl TestStore) {
    let mut conn = db.session(None).await.expect(ERR_SESSION);
    let result = conn.fetch("cat", "name", false).await.expect(ERR_FETCH);
    assert!(result.is_none());
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
            Some(TagFilter::negate(TagFilter::exist(vec![
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

pub async fn db_keypair_insert_fetch(db: impl TestStore) {
    let keypair = LocalKey::generate(KeyAlg::Ed25519, false).expect(ERR_CREATE_KEYPAIR);

    let mut conn = db.session(None).await.expect(ERR_SESSION);

    let key_name = "testkey";
    let metadata = "meta";
    conn.insert_key(key_name, &keypair, Some(metadata), None, None)
        .await
        .expect(ERR_INSERT_KEY);

    let found = conn
        .fetch_key(key_name, false)
        .await
        .expect(ERR_FETCH_KEY)
        .expect(ERR_REQ_ROW);
    assert_eq!(found.algorithm(), Some(KeyAlg::Ed25519.as_str()));
    assert_eq!(found.name(), key_name);
    assert_eq!(found.metadata(), Some(metadata));
    assert!(found.is_local());
    found.load_local_key().expect(ERR_LOAD_KEY);
}

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

    const TASKS: usize = 10;
    const INC: usize = 1000;

    async fn inc(db: impl TestStore, category: String, name: String) -> Result<(), &'static str> {
        // try to avoid panics in this section, as they will be raised on a tokio worker thread
        for _ in 0..INC {
            let mut conn = db.transaction(None).await.expect(ERR_TRANSACTION);
            let row = conn
                .fetch(&category, &name, true)
                .await
                .map_err(|e| {
                    log::error!("{:?}", e);
                    ERR_FETCH
                })?
                .ok_or(ERR_REQ_ROW)?;
            let val: usize = str::parse(row.value.as_opt_str().ok_or("Non-string counter value")?)
                .map_err(|_| "Error parsing counter value")?;
            conn.replace(
                &category,
                &name,
                format!("{}", val + 1).as_bytes(),
                Some(row.tags.as_slice()),
                None,
            )
            .await
            .map_err(|e| {
                log::error!("{:?}", e);
                ERR_REPLACE
            })?;
            conn.commit().await.map_err(|_| ERR_COMMIT)?;
        }
        Ok(())
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
        if let Err(s) = task.await.unwrap() {
            panic!("Error in concurrent update task: {}", s);
        }
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
