use async_std;
use async_trait::async_trait;

use r2d2;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection};

use std::thread;

use super::error::{KvError, KvResult};
use super::types::{
    ClientId, Enclave, EnclaveHandle, KeyId, KvFetchOptions, KvKeySelect, KvLockOperation,
    KvLockToken, KvRecord, KvScanToken, KvTag, KvUpdateRecord,
};
use super::wql;
use super::{KvProvisionStore, KvStore};

pub struct KvSqlite {
    conn_pool: r2d2::Pool<SqliteConnectionManager>,
    enclave: EnclaveHandle,
}

impl KvSqlite {
    pub fn open_in_memory(enclave: EnclaveHandle) -> KvResult<Self> {
        let mgr = SqliteConnectionManager::memory();
        let conn_pool = r2d2::Pool::new(mgr).expect("Error creating connection pool");
        Ok(Self { conn_pool, enclave })
    }
}

impl From<rusqlite::Error> for KvError {
    fn from(err: rusqlite::Error) -> Self {
        KvError::BackendError(err.to_string())
    }
}

impl KvProvisionStore for KvSqlite {
    fn provision(&self) -> KvResult<()> {
        let conn = self.conn_pool.get().expect("Error getting pool instance");
        conn.execute_batch(
            r#"
            PRAGMA locking_mode=EXCLUSIVE;
            PRAGMA foreign_keys=ON;
            BEGIN EXCLUSIVE TRANSACTION;

            CREATE TABLE items(
                id INTEGER NOT NULL,
                key_id INTEGER NOT NULL,
                category NOT NULL,
                name NOT NULL,
                value NOT NULL,
                value_key NULL,
                expiry NULL,
                PRIMARY KEY(id)
            );
            CREATE UNIQUE INDEX ux_items_uniq ON items(key_id, category, name);

            CREATE TABLE tags_encrypted(
                name NOT NULL,
                value NOT NULL,
                item_id INTEGER NOT NULL,
                PRIMARY KEY(name, item_id),
                FOREIGN KEY(item_id)
                    REFERENCES items(id)
                    ON DELETE CASCADE
                    ON UPDATE CASCADE
            );
            CREATE INDEX ix_tags_encrypted_item_id ON tags_encrypted(item_id);
    
            CREATE TABLE tags_plaintext(
                name NOT NULL,
                value NOT NULL,
                item_id INTEGER NOT NULL,
                PRIMARY KEY(name, item_id),
                FOREIGN KEY(item_id)
                    REFERENCES items(id)
                    ON DELETE CASCADE
                    ON UPDATE CASCADE
            );
            CREATE INDEX ix_tags_plaintext_value ON tags_plaintext(value);
            CREATE INDEX ix_tags_plaintext_item_id ON tags_plaintext(item_id);
            END TRANSACTION;
        "#,
        )?;
        Ok(())
    }
}

async fn get_key_id(k: KvKeySelect) -> KeyId {
    b"1".to_vec()
}

#[derive(Clone, Debug)]
pub struct Scan {}
impl KvScanToken for Scan {}

#[derive(Clone, Debug)]
pub struct Lock {}
impl KvLockToken for Lock {}

#[async_trait]
impl KvStore for KvSqlite {
    type ScanToken = Scan;
    type LockToken = Lock;

    async fn count(
        &self,
        client_key: KvKeySelect,
        category: &[u8],
        tag_filter: Option<wql::Query>,
    ) -> KvResult<u64> {
        let pool = self.conn_pool.clone();
        let key_id = get_key_id(client_key).await;
        let category = category.to_vec();
        let count: i64 = async_std::task::spawn_blocking(move || {
            let conn = pool.get().expect("Error getting pool instance");
            conn.query_row(
                "SELECT COUNT(*) FROM items where key_id = ?1 AND category = ?2 AND (expiry IS NULL OR expiry > CURRENT_TIME())",
                &[&key_id, &category],
                |row| {
                    Ok(row.get(0)?)
                },
            )
        }).await?;
        Ok(count as u64)
    }

    async fn fetch(
        &self,
        client_key: KvKeySelect,
        category: &[u8],
        name: &[u8],
        options: KvFetchOptions,
    ) -> KvResult<Option<KvRecord>> {
        let pool = self.conn_pool.clone();
        let key_id = get_key_id(client_key).await;
        let category = category.to_vec();
        let name = name.to_vec();
        let q_category = category.clone();
        let q_name = name.clone();
        let result: rusqlite::Result<(i64, Vec<u8>, Vec<u8>)> =
            async_std::task::spawn_blocking(move || {
                let conn = pool.get().expect("Error getting pool instance");
                let mut stmt = conn.prepare_cached(
                    "SELECT id, value, value_key FROM items
                    WHERE key_id = ?1 AND category = ?2 AND name = ?3
                    AND (expiry IS NULL OR expiry > CURRENT_TIME)",
                )?;
                stmt.query_row(&[&key_id, &q_category, &q_name], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })
            })
            .await;
        match result {
            Ok((row_id, value, value_key)) => {
                let tags = if options.retrieve_tags {
                    let pool = self.conn_pool.clone();
                    async_std::task::spawn_blocking(move || {
                        let conn = pool.get().expect("Error getting pool instance");
                        let mut stmt = conn.prepare_cached(
                            "SELECT 0 as encrypted, name, value FROM tags_plaintext WHERE item_id = ?1
                            UNION ALL
                            SELECT 1 as encrypted, name, value FROM tags_encrypted WHERE item_id = ?1")?;
                        let rows = stmt
                            .query_map(&[&row_id], |row| {
                                let enc: i32 = row.get(0)?;
                                if enc == 1 {
                                    Ok(KvTag::Encrypted(row.get(1)?, row.get(2)?))
                                } else {
                                    Ok(KvTag::Plaintext(row.get(1)?, row.get(2)?))
                                }
                            })?
                            .try_fold(vec![], |mut v, tag| {
                                v.push(tag?);
                                KvResult::Ok(v)
                            })?;
                        KvResult::Ok(Some(rows))
                    }).await?
                } else {
                    None
                };
                Ok(Some(KvRecord {
                    category,
                    name,
                    value,
                    tags,
                }))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    async fn scan_start(
        &self,
        client_key: KvKeySelect,
        category: &[u8],
        options: KvFetchOptions,
        tag_filter: Option<wql::Query>,
        max_rows: Option<u64>,
    ) -> KvResult<Self::ScanToken> {
        /*let key_id = get_key_id(client_key).await;
        let result = self.conn.query_row(
            "SELECT id, value, value_key FROM items where key_id = ?1 AND category = ?2 AND name = ?3 AND (expiry IS NULL OR expiry > CURRENT_TIME())",
            &[&key_id, &category, &name],
            |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            },
        );*/
        Ok(Scan {})
    }

    async fn scan_next(
        &self,
        scan_token: Self::ScanToken,
    ) -> KvResult<(Vec<KvRecord>, Option<Self::ScanToken>)> {
        Ok((vec![], None))
    }

    async fn update(
        &self,
        entries: &[KvUpdateRecord],
        with_lock: KvLockOperation<Self::LockToken>,
    ) -> KvResult<()> {
        Ok(())
    }

    async fn create_lock(
        &self,
        client_id: ClientId,
        category: &[u8],
        name: &[u8],
        max_duration_ms: Option<u64>,
        acquire_timeout_ms: Option<u64>,
    ) -> KvResult<(Self::LockToken, Option<KvRecord>)> {
        Ok((Lock {}, None))
    }

    async fn refresh_lock(
        &self,
        token: Self::LockToken,
        max_duration_ms: Option<u64>,
    ) -> KvResult<Self::LockToken> {
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_std::task::block_on;

    #[test]
    fn test_init() {
        let db = KvSqlite::open_in_memory(EnclaveHandle {}).unwrap();
        db.provision().unwrap();

        let client_key = KvKeySelect::ForClient(vec![]);
        let options = KvFetchOptions::default();
        let row = db.fetch(client_key, b"cat", b"name", options);
        let result = block_on(row).unwrap();
        assert!(result.is_none())
    }
}
