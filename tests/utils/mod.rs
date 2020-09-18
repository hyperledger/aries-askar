use aries_store_kv::{
    wql, Entry, EntryFetchOptions, EntryTag, Result as KvResult, Store, UpdateEntry,
};

pub async fn db_fetch_fail<DB: Store>(db: &DB) -> KvResult<()> {
    let options = EntryFetchOptions::default();
    let result = db.fetch(None, "cat", "name", options).await?;
    assert!(result.is_none());
    Ok(())
}

pub async fn db_add_fetch<DB: Store>(db: &DB) -> KvResult<()> {
    let test_row = Entry {
        category: "cat".to_owned(),
        name: "name".to_owned(),
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
        profile_id: None,
    }];
    db.update(updates).await?;

    let row = db
        .fetch(None, &test_row.category, &test_row.name, options)
        .await?;

    assert!(row.is_some());
    let found = row.unwrap();
    assert_eq!(found, test_row);

    Ok(())
}

pub async fn db_add_fetch_tags<DB: Store>(db: &DB) -> KvResult<()> {
    let test_row = Entry {
        category: "cat".to_owned(),
        name: "name".to_owned(),
        value: b"value".to_vec(),
        tags: Some(vec![
            EntryTag::Encrypted("t1".to_owned(), "v1".to_owned()),
            EntryTag::Plaintext("t2".to_owned(), "v2".to_owned()),
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
        profile_id: None,
    }];
    db.update(updates).await?;

    let row = db
        .fetch(None, &test_row.category, &test_row.name, options)
        .await?;

    assert!(row.is_some());
    let found = row.unwrap();
    assert_eq!(found, test_row);

    Ok(())
}

pub async fn db_count<DB: Store>(db: &DB) -> KvResult<()> {
    let category = "cat".to_owned();
    let test_rows = vec![Entry {
        category: category.clone(),
        name: "name".to_owned(),
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
            profile_id: None,
        })
        .collect();
    db.update(updates).await?;

    let tag_filter = None;
    let count = db.count(None, &category, tag_filter).await?;
    assert_eq!(count, 1);

    let tag_filter = Some(wql::Query::Eq("sometag".to_string(), "someval".to_string()));
    let count = db.count(None, &category, tag_filter).await?;
    assert_eq!(count, 0);

    Ok(())
}

pub async fn db_scan<DB: Store>(db: &DB) -> KvResult<()> {
    let category = "cat".to_owned();
    let test_rows = vec![Entry {
        category: category.clone(),
        name: "name".to_owned(),
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
            profile_id: None,
        })
        .collect();
    db.update(updates).await?;

    let options = EntryFetchOptions::default();
    let tag_filter = None;
    let offset = None;
    let max_rows = None;
    let mut scan = db
        .scan(None, &category, options, tag_filter, offset, max_rows)
        .await?;
    let rows = scan.fetch_next().await?;
    assert_eq!(rows, Some(test_rows));
    let rows = scan.fetch_next().await?;
    assert_eq!(rows, None);

    let options = EntryFetchOptions::default();
    let tag_filter = Some(wql::Query::Eq("sometag".to_string(), "someval".to_string()));
    let mut scan = db
        .scan(None, &category, options, tag_filter, offset, max_rows)
        .await?;
    let rows = scan.fetch_next().await?;
    assert_eq!(rows, None);

    Ok(())
}

pub async fn db_create_lock_non_existing<DB: Store>(db: &DB) -> KvResult<()> {
    let update = UpdateEntry {
        entry: Entry {
            category: "cat".to_owned(),
            name: "name".to_owned(),
            value: b"value".to_vec(),
            tags: None,
        },
        expire_ms: None,
        profile_id: None,
    };
    let lock_update = update.clone();
    let (entry, _lock) = db
        .create_lock(lock_update, EntryFetchOptions::default(), None)
        .await?;
    assert_eq!(entry, update.entry);

    Ok(())
}

pub async fn db_create_lock_timeout<DB: Store>(db: &DB) -> KvResult<()> {
    let update = UpdateEntry {
        entry: Entry {
            category: "cat".to_owned(),
            name: "name".to_owned(),
            value: b"value".to_vec(),
            tags: None,
        },
        expire_ms: None,
        profile_id: None,
    };
    let (entry, _lock) = db
        .create_lock(update.clone(), EntryFetchOptions::default(), Some(100))
        .await?;
    assert_eq!(entry, update.entry);

    let lock2 = db
        .create_lock(update.clone(), EntryFetchOptions::default(), Some(100))
        .await;
    assert!(lock2.is_err());

    Ok(())
}
