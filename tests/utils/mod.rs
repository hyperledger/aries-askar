use aries_store_kv::{
    wql, KvEntry, KvFetchOptions, KvKeySelect, KvLockStatus, KvResult, KvStore, KvTag,
    KvUpdateEntry,
};

pub async fn db_fetch_fail<DB: KvStore>(db: &DB) -> KvResult<()> {
    let profile_key = KvKeySelect::ForProfile(1);
    let options = KvFetchOptions::default();
    let result = db.fetch(profile_key, b"cat", b"name", options).await?;
    assert!(result.is_none());
    Ok(())
}

pub async fn db_add_fetch<DB: KvStore>(db: &DB) -> KvResult<()> {
    let test_row = KvEntry {
        key_id: 1,
        category: b"cat".to_vec(),
        name: b"name".to_vec(),
        value: b"value".to_vec(),
        tags: None,
        locked: None,
    };

    let profile_key = KvKeySelect::ForProfile(1);
    let options = KvFetchOptions::new(true, true, false);

    let updates = vec![KvUpdateEntry {
        profile_key: profile_key.clone(),
        category: test_row.category.clone(),
        name: test_row.name.clone(),
        value: test_row.value.clone(),
        tags: None,
        expire_ms: None,
    }];
    db.update(updates, None).await?;

    let row = db
        .fetch(
            profile_key.clone(),
            &test_row.category,
            &test_row.name,
            options,
        )
        .await?;

    assert!(row.is_some());
    let found = row.unwrap();
    assert_eq!(found, test_row);

    Ok(())
}

pub async fn db_add_fetch_tags<DB: KvStore>(db: &DB) -> KvResult<()> {
    let test_row = KvEntry {
        key_id: 1,
        category: b"cat".to_vec(),
        name: b"name".to_vec(),
        value: b"value".to_vec(),
        tags: Some(vec![
            KvTag::Encrypted(b"t1".to_vec(), b"v1".to_vec()),
            KvTag::Plaintext(b"t2".to_vec(), b"v2".to_vec()),
        ]),
        locked: None,
    };

    let profile_key = KvKeySelect::ForProfile(1);
    let options = KvFetchOptions::new(true, true, false);

    let updates = vec![KvUpdateEntry {
        profile_key: profile_key.clone(),
        category: test_row.category.clone(),
        name: test_row.name.clone(),
        value: test_row.value.clone(),
        tags: test_row.tags.clone(),
        expire_ms: None,
    }];
    db.update(updates, None).await?;

    let row = db
        .fetch(
            profile_key.clone(),
            &test_row.category,
            &test_row.name,
            options,
        )
        .await?;

    assert!(row.is_some());
    let found = row.unwrap();
    assert_eq!(found, test_row);

    Ok(())
}

pub async fn db_count<DB: KvStore>(db: &DB) -> KvResult<()> {
    let category = b"cat".to_vec();
    let test_rows = vec![KvEntry {
        key_id: 1,
        category: category.clone(),
        name: b"name".to_vec(),
        value: b"value".to_vec(),
        tags: None,
        locked: None,
    }];

    let profile_key = KvKeySelect::ForProfile(1);
    let updates = test_rows
        .iter()
        .map(|row| KvUpdateEntry {
            profile_key: profile_key.clone(),
            category: row.category.clone(),
            name: row.name.clone(),
            value: row.value.clone(),
            tags: row.tags.clone(),
            expire_ms: None,
        })
        .collect();
    db.update(updates, None).await?;

    let tag_filter = None;
    let count = db.count(profile_key.clone(), &category, tag_filter).await?;
    assert_eq!(count, 1);

    let tag_filter = Some(wql::Query::Eq("sometag".to_string(), "someval".to_string()));
    let count = db.count(profile_key.clone(), &category, tag_filter).await?;
    assert_eq!(count, 0);

    Ok(())
}

pub async fn db_scan<DB: KvStore>(db: &DB) -> KvResult<()> {
    let category = b"cat".to_vec();
    let test_rows = vec![KvEntry {
        key_id: 1,
        category: category.clone(),
        name: b"name".to_vec(),
        value: b"value".to_vec(),
        tags: None,
        locked: None,
    }];

    let profile_key = KvKeySelect::ForProfile(1);
    let updates = test_rows
        .iter()
        .map(|row| KvUpdateEntry {
            profile_key: profile_key.clone(),
            category: row.category.clone(),
            name: row.name.clone(),
            value: row.value.clone(),
            tags: row.tags.clone(),
            expire_ms: None,
        })
        .collect();
    db.update(updates, None).await?;

    let options = KvFetchOptions::default();
    let tag_filter = None;
    let offset = None;
    let max_rows = None;
    let scan_token = db
        .scan_start(
            profile_key.clone(),
            &category,
            options,
            tag_filter,
            offset,
            max_rows,
        )
        .await?;
    let (rows, scan_next) = db.scan_next(scan_token).await?;
    assert_eq!(rows, test_rows);
    assert!(scan_next.is_none());

    let options = KvFetchOptions::default();
    let tag_filter = Some(wql::Query::Eq("sometag".to_string(), "someval".to_string()));
    let scan_token = db
        .scan_start(
            profile_key.clone(),
            &category,
            options,
            tag_filter,
            offset,
            max_rows,
        )
        .await?;
    let (rows, scan_next) = db.scan_next(scan_token).await?;
    assert_eq!(rows, vec![]);
    assert!(scan_next.is_none());

    Ok(())
}

pub async fn db_create_lock_non_existing<DB: KvStore>(db: &DB) -> KvResult<()> {
    let update = KvUpdateEntry {
        profile_key: KvKeySelect::ForProfile(1),
        category: b"cat".to_vec(),
        name: b"name".to_vec(),
        value: b"value".to_vec(),
        tags: None,
        expire_ms: None,
    };
    let lock_update = update.clone();
    let (opt_lock, entry) = db.create_lock(lock_update, None).await?;
    assert!(opt_lock.is_some());
    assert_eq!(entry.category, update.category);
    assert_eq!(entry.name, update.name);
    assert_eq!(entry.value, update.value);
    assert_eq!(entry.locked, Some(KvLockStatus::Locked));

    Ok(())
}
