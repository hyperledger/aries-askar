use aries_store_kv::{
    wql, KvEntry, KvFetchOptions, KvStore, KvTag, KvUpdateEntry, Result as KvResult,
};

pub async fn db_fetch_fail<DB: KvStore>(db: &DB) -> KvResult<()> {
    let options = KvFetchOptions::default();
    let result = db.fetch(None, "cat", "name", options).await?;
    assert!(result.is_none());
    Ok(())
}

pub async fn db_add_fetch<DB: KvStore>(db: &DB) -> KvResult<()> {
    let test_row = KvEntry {
        category: "cat".to_owned(),
        name: "name".to_owned(),
        value: b"value".to_vec(),
        tags: None,
    };

    let options = KvFetchOptions::new(true, true);

    let updates = vec![KvUpdateEntry {
        entry: KvEntry {
            category: test_row.category.clone(),
            name: test_row.name.clone(),
            value: test_row.value.clone(),
            tags: None,
        },
        expire_ms: None,
        profile_id: None,
    }];
    db.update(updates, None).await?;

    let row = db
        .fetch(None, &test_row.category, &test_row.name, options)
        .await?;

    assert!(row.is_some());
    let found = row.unwrap();
    assert_eq!(found, test_row);

    Ok(())
}

pub async fn db_add_fetch_tags<DB: KvStore>(db: &DB) -> KvResult<()> {
    let test_row = KvEntry {
        category: "cat".to_owned(),
        name: "name".to_owned(),
        value: b"value".to_vec(),
        tags: Some(vec![
            KvTag::Encrypted("t1".to_owned(), "v1".to_owned()),
            KvTag::Plaintext("t2".to_owned(), "v2".to_owned()),
        ]),
    };

    let options = KvFetchOptions::new(true, true);

    let updates = vec![KvUpdateEntry {
        entry: KvEntry {
            category: test_row.category.clone(),
            name: test_row.name.clone(),
            value: test_row.value.clone(),
            tags: test_row.tags.clone(),
        },
        expire_ms: None,
        profile_id: None,
    }];
    db.update(updates, None).await?;

    let row = db
        .fetch(None, &test_row.category, &test_row.name, options)
        .await?;

    assert!(row.is_some());
    let found = row.unwrap();
    assert_eq!(found, test_row);

    Ok(())
}

pub async fn db_count<DB: KvStore>(db: &DB) -> KvResult<()> {
    let category = "cat".to_owned();
    let test_rows = vec![KvEntry {
        category: category.clone(),
        name: "name".to_owned(),
        value: b"value".to_vec(),
        tags: None,
    }];

    let updates = test_rows
        .iter()
        .map(|row| KvUpdateEntry {
            entry: KvEntry {
                category: row.category.clone(),
                name: row.name.clone(),
                value: row.value.clone(),
                tags: row.tags.clone(),
            },
            expire_ms: None,
            profile_id: None,
        })
        .collect();
    db.update(updates, None).await?;

    let tag_filter = None;
    let count = db.count(None, &category, tag_filter).await?;
    assert_eq!(count, 1);

    let tag_filter = Some(wql::Query::Eq("sometag".to_string(), "someval".to_string()));
    let count = db.count(None, &category, tag_filter).await?;
    assert_eq!(count, 0);

    Ok(())
}

pub async fn db_scan<DB: KvStore>(db: &DB) -> KvResult<()> {
    let category = "cat".to_owned();
    let test_rows = vec![KvEntry {
        category: category.clone(),
        name: "name".to_owned(),
        value: b"value".to_vec(),
        tags: None,
    }];

    let updates = test_rows
        .iter()
        .map(|row| KvUpdateEntry {
            entry: KvEntry {
                category: row.category.clone(),
                name: row.name.clone(),
                value: row.value.clone(),
                tags: row.tags.clone(),
            },
            expire_ms: None,
            profile_id: None,
        })
        .collect();
    db.update(updates, None).await?;

    let options = KvFetchOptions::default();
    let tag_filter = None;
    let offset = None;
    let max_rows = None;
    let scan_token = db
        .scan_start(None, &category, options, tag_filter, offset, max_rows)
        .await?;
    let (rows, scan_next) = db.scan_next(scan_token).await?;
    assert_eq!(rows, test_rows);
    assert!(scan_next.is_none());

    let options = KvFetchOptions::default();
    let tag_filter = Some(wql::Query::Eq("sometag".to_string(), "someval".to_string()));
    let scan_token = db
        .scan_start(None, &category, options, tag_filter, offset, max_rows)
        .await?;
    let (rows, scan_next) = db.scan_next(scan_token).await?;
    assert_eq!(rows, vec![]);
    assert!(scan_next.is_none());

    Ok(())
}

pub async fn db_create_lock_non_existing<DB: KvStore>(db: &DB) -> KvResult<()> {
    let update = KvUpdateEntry {
        entry: KvEntry {
            category: "cat".to_owned(),
            name: "name".to_owned(),
            value: b"value".to_vec(),
            tags: None,
        },
        expire_ms: None,
        profile_id: None,
    };
    let lock_update = update.clone();
    let opt_lock = db
        .create_lock(lock_update, KvFetchOptions::default(), None)
        .await?;
    assert!(opt_lock.is_some());
    let (_lock_info, entry) = opt_lock.unwrap();
    assert_eq!(entry, update.entry);

    Ok(())
}

pub async fn db_create_lock_timeout<DB: KvStore>(db: &DB) -> KvResult<()> {
    let update = KvUpdateEntry {
        entry: KvEntry {
            category: "cat".to_owned(),
            name: "name".to_owned(),
            value: b"value".to_vec(),
            tags: None,
        },
        expire_ms: None,
        profile_id: None,
    };
    let opt_lock = db
        .create_lock(update.clone(), KvFetchOptions::default(), Some(100))
        .await?;
    assert!(opt_lock.is_some());
    let (_lock_token, entry) = opt_lock.unwrap();
    assert_eq!(entry, update.entry);

    let opt_lock2 = db
        .create_lock(update.clone(), KvFetchOptions::default(), Some(100))
        .await?;
    assert!(opt_lock2.is_none());

    Ok(())
}
