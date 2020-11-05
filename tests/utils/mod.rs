use aries_askar::{verify_signature, wql, Backend, Entry, EntryTag, ErrorKind, KeyAlg, Store};

const ERR_SESSION: &'static str = "Error starting session";
const ERR_TRANSACTION: &'static str = "Error starting transaction";
const ERR_COUNT: &'static str = "Error performing count";
const ERR_FETCH: &'static str = "Error fetching test row";
const ERR_FETCH_ALL: &'static str = "Error fetching all test rows";
const ERR_REQ_ROW: &'static str = "Expected row";
const ERR_REQ_ERR: &'static str = "Expected error";
const ERR_INSERT: &'static str = "Error inserting test row";
const ERR_REPLACE: &'static str = "Error replacing test row";
const ERR_SCAN: &'static str = "Error starting scan";
const ERR_SCAN_NEXT: &'static str = "Error fetching scan rows";
const ERR_CREATE_KEYPAIR: &'static str = "Error creating keypair";
const ERR_FETCH_KEY: &'static str = "Error fetching key";
const ERR_SIGN: &'static str = "Error signing message";
const ERR_VERIFY: &'static str = "Error verifying signature";
const ERR_PACK: &'static str = "Error packing message";
const ERR_UNPACK: &'static str = "Error unpacking message";

pub async fn db_fetch_fail<DB: Backend>(db: &Store<DB>) {
    let mut conn = db.session(None).await.expect(ERR_SESSION);
    let result = conn.fetch("cat", "name").await.expect(ERR_FETCH);
    assert_eq!(result.is_none(), true);
}

pub async fn db_insert_fetch<DB: Backend>(db: &Store<DB>) {
    let test_row = Entry {
        category: "cat".to_string(),
        name: "name".to_string(),
        value: b"value".to_vec(),
        tags: Some(vec![
            EntryTag::Encrypted("t1".to_string(), "v1".to_string()),
            EntryTag::Plaintext("t2".to_string(), "v2".to_string()),
        ]),
    };

    let mut conn = db.session(None).await.expect(ERR_SESSION);

    conn.insert(
        &test_row.category,
        &test_row.name,
        &test_row.value,
        test_row.tags.as_ref().map(|t| t.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    let row = conn
        .fetch(&test_row.category, &test_row.name)
        .await
        .expect(ERR_FETCH)
        .expect(ERR_REQ_ROW);
    assert_eq!(row, test_row);

    let rows = conn
        .fetch_all(&test_row.category, None, None)
        .await
        .expect(ERR_FETCH_ALL);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0], test_row);
}

pub async fn db_insert_duplicate<DB: Backend>(db: &Store<DB>) {
    let test_row = Entry {
        category: "cat".to_string(),
        name: "name".to_string(),
        value: b"value".to_vec(),
        tags: None,
    };

    let mut conn = db.session(None).await.expect(ERR_SESSION);

    conn.insert(
        &test_row.category,
        &test_row.name,
        &test_row.value,
        test_row.tags.as_ref().map(|t| t.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    let err = conn
        .insert(
            &test_row.category,
            &test_row.name,
            &test_row.value,
            test_row.tags.as_ref().map(|t| t.as_slice()),
            None,
        )
        .await
        .expect_err(ERR_REQ_ERR);
    assert_eq!(err.kind(), ErrorKind::Duplicate);
}

pub async fn db_replace_fetch<DB: Backend>(db: &Store<DB>) {
    let test_row = Entry {
        category: "cat".to_string(),
        name: "name".to_string(),
        value: b"value".to_vec(),
        tags: None,
    };

    let mut conn = db.session(None).await.expect(ERR_SESSION);

    conn.insert(
        &test_row.category,
        &test_row.name,
        &test_row.value,
        test_row.tags.as_ref().map(|t| t.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    let mut replace_row = test_row.clone();
    replace_row.value = b"new value".to_vec();
    conn.replace(
        &replace_row.category,
        &replace_row.name,
        &replace_row.value,
        replace_row.tags.as_ref().map(|t| t.as_slice()),
        None,
    )
    .await
    .expect(ERR_REPLACE);

    let row = conn
        .fetch(&replace_row.category, &replace_row.name)
        .await
        .expect(ERR_FETCH)
        .expect(ERR_REQ_ROW);
    assert_eq!(row, replace_row);
}

pub async fn db_replace_missing<DB: Backend>(db: &Store<DB>) {
    let test_row = Entry {
        category: "cat".to_string(),
        name: "name".to_string(),
        value: b"value".to_vec(),
        tags: None,
    };

    let mut conn = db.session(None).await.expect(ERR_SESSION);

    let err = conn
        .replace(
            &test_row.category,
            &test_row.name,
            &test_row.value,
            test_row.tags.as_ref().map(|t| t.as_slice()),
            None,
        )
        .await
        .expect_err(ERR_REQ_ERR);
    assert_eq!(err.kind(), ErrorKind::NotFound);
}

pub async fn db_count<DB: Backend>(db: &Store<DB>) {
    let category = "cat".to_string();
    let test_rows = vec![Entry {
        category: category.clone(),
        name: "name".to_string(),
        value: b"value".to_vec(),
        tags: None,
    }];

    let mut conn = db.session(None).await.expect(ERR_SESSION);

    for upd in test_rows.iter() {
        conn.insert(
            &upd.category,
            &upd.name,
            &upd.value,
            upd.tags.as_ref().map(|t| t.as_slice()),
            None,
        )
        .await
        .expect(ERR_INSERT);
    }

    let tag_filter = None;
    let count = conn.count(&category, tag_filter).await.expect(ERR_COUNT);
    assert_eq!(count, 1);

    let tag_filter = Some(wql::Query::Eq("sometag".to_string(), "someval".to_string()));
    let count = conn.count(&category, tag_filter).await.expect(ERR_COUNT);
    assert_eq!(count, 0);
}

pub async fn db_scan<DB: Backend>(db: &Store<DB>) {
    let category = "cat".to_string();
    let test_rows = vec![Entry {
        category: category.clone(),
        name: "name".to_string(),
        value: b"value".to_vec(),
        tags: Some(vec![
            EntryTag::Encrypted("t1".to_string(), "v1".to_string()),
            EntryTag::Plaintext("t2".to_string(), "v2".to_string()),
        ]),
    }];

    let mut conn = db.session(None).await.expect(ERR_SESSION);

    for upd in test_rows.iter() {
        conn.insert(
            &upd.category,
            &upd.name,
            &upd.value,
            upd.tags.as_ref().map(|t| t.as_slice()),
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

    let tag_filter = Some(wql::Query::Eq("sometag".to_string(), "someval".to_string()));
    let mut scan = db
        .scan(None, category.clone(), tag_filter, offset, limit)
        .await
        .expect(ERR_SCAN);
    let rows = scan.fetch_next().await.expect(ERR_SCAN_NEXT);
    assert_eq!(rows, None);
}

pub async fn db_keypair_create_fetch<DB: Backend>(db: &Store<DB>) {
    let mut conn = db.session(None).await.expect(ERR_SESSION);

    let metadata = "meta".to_owned();
    let key_info = conn
        .create_keypair(KeyAlg::ED25519, Some(&metadata), None, None)
        .await
        .expect(ERR_CREATE_KEYPAIR);
    assert_eq!(key_info.params.metadata, Some(metadata));

    let found = conn
        .fetch_key(key_info.category.clone(), &key_info.ident)
        .await
        .expect(ERR_FETCH_KEY);
    assert_eq!(Some(key_info), found);
}

pub async fn db_keypair_sign_verify<DB: Backend>(db: &Store<DB>) {
    let mut conn = db.session(None).await.expect(ERR_SESSION);

    let key_info = conn
        .create_keypair(KeyAlg::ED25519, None, None, None)
        .await
        .expect(ERR_CREATE_KEYPAIR);

    let message = b"message".to_vec();
    let sig = conn
        .sign_message(&key_info.ident, &message)
        .await
        .expect(ERR_SIGN);

    assert_eq!(
        verify_signature(&key_info.ident, &message, &sig).expect(ERR_VERIFY),
        true
    );

    assert_eq!(
        verify_signature(&key_info.ident, b"bad input", &sig).expect(ERR_VERIFY),
        false
    );

    assert_eq!(
        verify_signature(&key_info.ident, &message, b"bad sig").expect(ERR_VERIFY),
        false
    );

    let err = verify_signature("not a key", &message, &sig).expect_err(ERR_REQ_ERR);
    assert_eq!(err.kind(), ErrorKind::Input);
}

pub async fn db_keypair_pack_unpack_anon<DB: Backend>(db: &Store<DB>) {
    let mut conn = db.session(None).await.expect(ERR_SESSION);

    let recip_key = conn
        .create_keypair(KeyAlg::ED25519, None, None, None)
        .await
        .expect(ERR_CREATE_KEYPAIR);

    let msg = b"message".to_vec();

    let packed = conn
        .pack_message(vec![recip_key.ident.as_str()], None, &msg)
        .await
        .expect(ERR_PACK);

    let (unpacked, p_recip, p_send) = conn.unpack_message(&packed).await.expect(ERR_UNPACK);
    assert_eq!(unpacked, msg);
    assert_eq!(p_recip, recip_key.encoded_verkey().unwrap());
    assert_eq!(p_send, None);
}

pub async fn db_keypair_pack_unpack_auth<DB: Backend>(db: &Store<DB>) {
    let mut conn = db.session(None).await.expect(ERR_SESSION);

    let sender_key = conn
        .create_keypair(KeyAlg::ED25519, None, None, None)
        .await
        .expect(ERR_CREATE_KEYPAIR);
    let recip_key = conn
        .create_keypair(KeyAlg::ED25519, None, None, None)
        .await
        .expect(ERR_CREATE_KEYPAIR);

    let msg = b"message".to_vec();

    let packed = conn
        .pack_message(
            vec![recip_key.ident.as_str()],
            Some(&sender_key.ident),
            &msg,
        )
        .await
        .expect(ERR_PACK);

    let (unpacked, p_recip, p_send) = conn.unpack_message(&packed).await.expect(ERR_UNPACK);
    assert_eq!(unpacked, msg);
    assert_eq!(p_recip, recip_key.encoded_verkey().unwrap());
    assert_eq!(p_send, Some(sender_key.encoded_verkey().unwrap()));
}

pub async fn db_txn_rollback<DB: Backend>(db: &Store<DB>) {
    let test_row = Entry {
        category: "cat".to_string(),
        name: "name".to_string(),
        value: b"value".to_vec(),
        tags: None,
    };

    let mut conn = db.transaction(None).await.expect(ERR_TRANSACTION);

    conn.insert(
        &test_row.category,
        &test_row.name,
        &test_row.value,
        test_row.tags.as_ref().map(|t| t.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    conn.rollback()
        .await
        .expect("Error rolling back transaction");

    let mut conn = db.session(None).await.expect("Error starting new session");

    let row = conn
        .fetch(&test_row.category, &test_row.name)
        .await
        .expect("Error fetching test row");
    assert_eq!(row, None);
}

pub async fn db_txn_drop<DB: Backend>(db: &Store<DB>) {
    let test_row = Entry {
        category: "cat".to_string(),
        name: "name".to_string(),
        value: b"value".to_vec(),
        tags: None,
    };

    let mut conn = db
        .transaction(None)
        .await
        .expect("Error starting new transaction");

    conn.insert(
        &test_row.category,
        &test_row.name,
        &test_row.value,
        test_row.tags.as_ref().map(|t| t.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    drop(conn);

    let mut conn = db.session(None).await.expect("Error starting new session");

    let row = conn
        .fetch(&test_row.category, &test_row.name)
        .await
        .expect("Error fetching test row");
    assert_eq!(row, None);
}

// test that session does NOT have transaction rollback behaviour
pub async fn db_session_drop<DB: Backend>(db: &Store<DB>) {
    let test_row = Entry {
        category: "cat".to_string(),
        name: "name".to_string(),
        value: b"value".to_vec(),
        tags: None,
    };

    let mut conn = db.session(None).await.expect(ERR_SESSION);

    conn.insert(
        &test_row.category,
        &test_row.name,
        &test_row.value,
        test_row.tags.as_ref().map(|t| t.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    drop(conn);

    let mut conn = db.session(None).await.expect(ERR_SESSION);

    let row = conn
        .fetch(&test_row.category, &test_row.name)
        .await
        .expect(ERR_FETCH);
    assert_eq!(row, Some(test_row));
}

pub async fn db_txn_commit<DB: Backend>(db: &Store<DB>) {
    let test_row = Entry {
        category: "cat".to_string(),
        name: "name".to_string(),
        value: b"value".to_vec(),
        tags: None,
    };

    let mut conn = db.transaction(None).await.expect(ERR_TRANSACTION);

    conn.insert(
        &test_row.category,
        &test_row.name,
        &test_row.value,
        test_row.tags.as_ref().map(|t| t.as_slice()),
        None,
    )
    .await
    .expect(ERR_INSERT);

    conn.commit().await.expect("Error committing transaction");

    let mut conn = db.session(None).await.expect(ERR_SESSION);

    let row = conn
        .fetch(&test_row.category, &test_row.name)
        .await
        .expect(ERR_FETCH);
    assert_eq!(row, Some(test_row));
}
