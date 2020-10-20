use aries_askar::{
    wql, Entry, EntryFetchOptions, EntryTag, KeyAlg, KeyFetchOptions, RawStore, Result as KvResult,
    Store, UpdateEntry,
};

pub async fn db_fetch_fail<DB: RawStore>(db: &Store<DB>) -> KvResult<()> {
    let options = EntryFetchOptions::default();
    let result = db
        .fetch(None, "cat".to_string(), "name".to_string(), options)
        .await?;
    assert!(result.is_none());
    Ok(())
}

pub async fn db_add_fetch<DB: RawStore>(db: &Store<DB>) -> KvResult<()> {
    let test_row = Entry {
        category: "cat".to_string(),
        name: "name".to_string(),
        value: b"value".to_vec(),
        tags: None,
    };

    let options = EntryFetchOptions::new(true);

    let updates = vec![UpdateEntry {
        entry: Entry {
            category: test_row.category.clone(),
            name: test_row.name.clone(),
            value: test_row.value.clone(),
            tags: None,
        },
        expire_ms: None,
    }];
    db.update(None, updates).await?;

    let row = db
        .fetch(
            None,
            test_row.category.clone(),
            test_row.name.clone(),
            options,
        )
        .await?;

    assert!(row.is_some());
    let found = row.unwrap();
    assert_eq!(found, test_row);

    Ok(())
}

pub async fn db_add_fetch_tags<DB: RawStore>(db: &Store<DB>) -> KvResult<()> {
    let test_row = Entry {
        category: "cat".to_string(),
        name: "name".to_string(),
        value: b"value".to_vec(),
        tags: Some(vec![
            EntryTag::Encrypted("t1".to_string(), "v1".to_string()),
            EntryTag::Plaintext("t2".to_string(), "v2".to_string()),
        ]),
    };

    let options = EntryFetchOptions::new(true);

    let updates = vec![UpdateEntry {
        entry: Entry {
            category: test_row.category.clone(),
            name: test_row.name.clone(),
            value: test_row.value.clone(),
            tags: test_row.tags.clone(),
        },
        expire_ms: None,
    }];
    db.update(None, updates).await?;

    let row = db
        .fetch(
            None,
            test_row.category.clone(),
            test_row.name.clone(),
            options,
        )
        .await?;

    assert!(row.is_some());
    let found = row.unwrap();
    assert_eq!(found, test_row);

    Ok(())
}

pub async fn db_count<DB: RawStore>(db: &Store<DB>) -> KvResult<()> {
    let category = "cat".to_string();
    let test_rows = vec![Entry {
        category: category.clone(),
        name: "name".to_string(),
        value: b"value".to_vec(),
        tags: None,
    }];

    let updates = test_rows
        .iter()
        .map(|row| UpdateEntry {
            entry: Entry {
                category: row.category.clone(),
                name: row.name.clone(),
                value: row.value.clone(),
                tags: row.tags.clone(),
            },
            expire_ms: None,
        })
        .collect();
    db.update(None, updates).await?;

    let tag_filter = None;
    let count = db.count(None, category.clone(), tag_filter).await?;
    assert_eq!(count, 1);

    let tag_filter = Some(wql::Query::Eq("sometag".to_string(), "someval".to_string()));
    let count = db.count(None, category.clone(), tag_filter).await?;
    assert_eq!(count, 0);

    Ok(())
}

pub async fn db_scan<DB: RawStore>(db: &Store<DB>) -> KvResult<()> {
    let category = "cat".to_string();
    let test_rows = vec![Entry {
        category: category.clone(),
        name: "name".to_string(),
        value: b"value".to_vec(),
        tags: None,
    }];

    let updates = test_rows
        .iter()
        .map(|row| UpdateEntry {
            entry: Entry {
                category: row.category.clone(),
                name: row.name.clone(),
                value: row.value.clone(),
                tags: row.tags.clone(),
            },
            expire_ms: None,
        })
        .collect();
    db.update(None, updates).await?;

    let options = EntryFetchOptions::default();
    let tag_filter = None;
    let offset = None;
    let max_rows = None;
    let mut scan = db
        .scan(
            None,
            category.clone(),
            options,
            tag_filter,
            offset,
            max_rows,
        )
        .await?;
    let rows = scan.fetch_next().await?;
    assert_eq!(rows, Some(test_rows));
    let rows = scan.fetch_next().await?;
    assert_eq!(rows, None);

    let options = EntryFetchOptions::default();
    let tag_filter = Some(wql::Query::Eq("sometag".to_string(), "someval".to_string()));
    let mut scan = db
        .scan(
            None,
            category.clone(),
            options,
            tag_filter,
            offset,
            max_rows,
        )
        .await?;
    let rows = scan.fetch_next().await?;
    assert_eq!(rows, None);

    Ok(())
}

pub async fn db_create_lock_non_existing<DB: RawStore>(db: &Store<DB>) -> KvResult<()> {
    let update = UpdateEntry {
        entry: Entry {
            category: "cat".to_string(),
            name: "name".to_string(),
            value: b"value".to_vec(),
            tags: None,
        },
        expire_ms: None,
    };
    let lock_update = update.clone();
    let (entry, _lock) = db.create_lock(None, lock_update, None).await?;
    assert_eq!(entry, update.entry);

    Ok(())
}

pub async fn db_create_lock_timeout<DB: RawStore>(db: &Store<DB>) -> KvResult<()> {
    let update = UpdateEntry {
        entry: Entry {
            category: "cat".to_string(),
            name: "name".to_string(),
            value: b"value".to_vec(),
            tags: None,
        },
        expire_ms: None,
    };
    let (entry, _lock) = db.create_lock(None, update.clone(), Some(100)).await?;
    assert_eq!(entry, update.entry);

    let lock2 = db.create_lock(None, update.clone(), Some(100)).await;
    assert!(lock2.is_err());

    Ok(())
}

pub async fn db_create_lock_drop_expire<DB: RawStore>(db: &Store<DB>) -> KvResult<()> {
    let update = UpdateEntry {
        entry: Entry {
            category: "cat".to_string(),
            name: "name".to_string(),
            value: b"value".to_vec(),
            tags: None,
        },
        expire_ms: None,
    };
    let (entry, lock) = db.create_lock(None, update.clone(), Some(100)).await?;
    assert_eq!(entry, update.entry);
    drop(lock);

    let (entry2, _lock2) = db.create_lock(None, update.clone(), Some(100)).await?;
    assert_eq!(entry2, update.entry);

    Ok(())
}

pub async fn db_keypair_create_fetch<DB: RawStore>(db: &Store<DB>) -> KvResult<()> {
    let metadata = "meta".to_owned();
    let key_info = db
        .create_keypair(None, KeyAlg::ED25519, Some(metadata.clone()), None, None)
        .await?;
    assert_eq!(key_info.params.metadata, Some(metadata));

    let found = db
        .fetch_key(
            None,
            key_info.category.clone(),
            key_info.ident.clone(),
            KeyFetchOptions::default(),
        )
        .await?;
    assert_eq!(Some(key_info), found);

    Ok(())
}

pub async fn db_keypair_sign_verify<DB: RawStore>(db: &Store<DB>) -> KvResult<()> {
    let key_info = db
        .create_keypair(None, KeyAlg::ED25519, None, None, None)
        .await?;

    let message = b"message".to_vec();
    let sig = db
        .sign_message(None, key_info.ident.clone(), message.clone())
        .await?;

    assert_eq!(
        db.verify_signature(key_info.ident.clone(), message.clone(), sig.clone())
            .await?,
        true
    );

    assert_eq!(
        db.verify_signature(key_info.ident.clone(), b"bad input".to_vec(), sig.clone())
            .await?,
        false
    );

    assert_eq!(
        db.verify_signature(key_info.ident.clone(), message.clone(), b"bad sig".to_vec())
            .await?,
        false
    );

    assert_eq!(
        db.verify_signature("not a key".to_owned(), message.clone(), sig.clone())
            .await
            .is_err(),
        true
    );

    Ok(())
}

pub async fn db_keypair_pack_unpack_anon<DB: RawStore>(db: &Store<DB>) -> KvResult<()> {
    let recip_key = db
        .create_keypair(None, KeyAlg::ED25519, None, None, None)
        .await?;

    let msg = b"message".to_vec();

    let packed = db
        .pack_message(None, vec![recip_key.ident.clone()], None, msg.clone())
        .await?;

    let (unpacked, p_recip, p_send) = db.unpack_message(None, packed.clone()).await?;
    assert_eq!(unpacked, msg);
    assert_eq!(p_recip, recip_key.ident);
    assert_eq!(p_send, None);

    Ok(())
}

pub async fn db_keypair_pack_unpack_auth<DB: RawStore>(db: &Store<DB>) -> KvResult<()> {
    let sender_key = db
        .create_keypair(None, KeyAlg::ED25519, None, None, None)
        .await?;
    let recip_key = db
        .create_keypair(None, KeyAlg::ED25519, None, None, None)
        .await?;

    let msg = b"message".to_vec();

    let packed = db
        .pack_message(
            None,
            vec![recip_key.ident.clone()],
            Some(sender_key.ident.clone()),
            msg.clone(),
        )
        .await?;

    let (unpacked, p_recip, p_send) = db.unpack_message(None, packed.clone()).await?;
    assert_eq!(unpacked, msg);
    assert_eq!(p_recip, recip_key.ident);
    assert_eq!(p_send, Some(sender_key.ident.clone()));

    Ok(())
}
