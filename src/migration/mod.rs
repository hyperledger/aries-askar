use self::strategy::{Strategy, UpdatedIndyItem};
use crate::crypto::generic_array::typenum::U32;
use crate::protect::hmac_key::HmacKey;
use crate::protect::ProfileKey;
use crate::{Argon2Level, Error};
use askar_crypto::alg::chacha20::{Chacha20Key, C20P};
use askar_crypto::kdf::argon2::{Argon2, PARAMS_INTERACTIVE, PARAMS_MODERATE};
use askar_crypto::kdf::KeyDerivation;
use askar_crypto::repr::KeySecretBytes;
use sha2::Sha256;
use sqlx::sqlite::SqliteRow;
use sqlx::{Connection, Row, SqliteConnection};

mod strategy;

const CHACHAPOLY_KEY_LEN: u8 = 32;
const CHACHAPOLY_NONCE_LEN: u8 = 12;

#[derive(Serialize, Deserialize, Debug, Default)]
pub(crate) struct IndyKeyMetadata {
    keys: Vec<u8>,
    master_key_salt: Vec<u8>,
}

/// Copies: https://github.com/hyperledger/indy-sdk/blob/83547c4c01162f6323cf138f8b071da2e15f0c90/libindy/indy-wallet/src/wallet.rs#L18
#[derive(Serialize, Deserialize)]
pub(crate) struct IndyKey {
    type_key: Chacha20Key<C20P>,
    name_key: Chacha20Key<C20P>,
    value_key: Chacha20Key<C20P>,
    item_hmac_key: HmacKey<Sha256, U32>,
    tag_name_key: Chacha20Key<C20P>,
    tag_value_key: Chacha20Key<C20P>,
    tag_hmac_key: HmacKey<Sha256, U32>,
}

pub(crate) struct IndyKeyWithMasterAndSalt {
    indy_key: IndyKey,
    master: Chacha20Key<C20P>,
    salt: Vec<u8>,
}

pub(crate) struct IndySdkToAriesAskarMigration {
    conn: SqliteConnection,
    wallet_key: String,
    wallet_name: String,
    kdf_method: KdfMethod,
}

pub enum KdfMethod {
    Argon2i(Argon2Level),
    Raw,
}

impl KdfMethod {
    fn to_prefix(&self) -> String {
        match self {
            Self::Raw => "raw:".to_owned(),
            Self::Argon2i(method) => match method {
                Argon2Level::Interactive => "kdf:argon2i:13:int".to_owned(),
                Argon2Level::Moderate => "kdf:argon2i:13:mod".to_owned(),
            },
        }
    }

    fn derive(&self, key: &[u8], salt: Option<&[u8]>) -> Result<Chacha20Key<C20P>, Error> {
        match self {
            Self::Argon2i(method) => {
                let params = match method {
                    Argon2Level::Interactive => PARAMS_INTERACTIVE,
                    Argon2Level::Moderate => PARAMS_MODERATE,
                };
                let salt = salt.ok_or(err_msg!("Deriving key with argon2i requires salt"))?;
                let mut kdf = Argon2::new(key, salt, params)?;
                let mut key = [0u8; CHACHAPOLY_KEY_LEN as usize];
                kdf.derive_key_bytes(&mut key)?;
                Ok(Chacha20Key::<C20P>::from_secret_bytes(&key)?)
            }
            Self::Raw => Ok(Chacha20Key::<C20P>::from_secret_bytes(&key)?),
        }
    }

    fn to_storable_pass_key(
        &self,
        key: Option<&[u8]>,
        salt: Option<&[u8]>,
    ) -> Result<String, Error> {
        let prefix = self.to_prefix();
        match self {
            Self::Raw => {
                let key = key.ok_or(err_msg!("raw kdf method needs a key"))?;
                let key = bs58::encode(key).into_string();
                let key = format!("{prefix}{key}");
                Ok(key)
            }
            Self::Argon2i(_) => {
                let salt = salt.ok_or(err_msg!("Salt must be provided for argon2i kdf method"))?;
                let salt_hex = hex::encode(salt);
                Ok(format!("{prefix}?salt={salt_hex}"))
            }
        }
    }
}

impl From<&str> for KdfMethod {
    fn from(s: &str) -> Self {
        match s {
            "ARGON2I_MOD" => Self::Argon2i(Argon2Level::Moderate),
            "ARGON2I_INT" => Self::Argon2i(Argon2Level::Interactive),
            "RAW" => Self::Raw,
            _ => Self::Argon2i(Argon2Level::Moderate),
        }
    }
}

impl IndySdkToAriesAskarMigration {
    pub async fn new(
        spec_uri: &str,
        wallet_name: &str,
        wallet_key: &str,
        kdf_method: &str,
    ) -> Result<Self, Error> {
        let conn = SqliteConnection::connect(spec_uri).await?;
        Ok(Self {
            conn,
            wallet_key: wallet_key.to_owned(),
            wallet_name: wallet_name.to_owned(),
            kdf_method: kdf_method.into(),
        })
    }

    pub async fn migrate(&mut self) -> Result<(), Error> {
        if self.is_migrated().await? {
            return Err(err_msg!(Backend, "Database is already migrated",));
        }

        self.pre_upgrade().await?;
        let indy_key = self.fetch_indy_key().await?;
        self.create_config(&indy_key).await?;
        let profile_key = self.init_profile(&indy_key).await?;
        self.update_items(&indy_key, &profile_key).await?;
        self.finish_upgrade().await?;
        Ok(())
    }

    #[inline]
    async fn is_migrated(&mut self) -> Result<bool, Error> {
        let res: Option<SqliteRow> =
            sqlx::query("SELECT name FROM sqlite_master WHERE type='table' AND name=?1")
                .bind("metadata")
                .fetch_optional(&mut self.conn)
                .await?;
        Ok(res.is_none())
    }

    async fn pre_upgrade(&mut self) -> Result<(), Error> {
        sqlx::query(
            "
            BEGIN EXCLUSIVE TRANSACTION;
                CREATE TABLE config (
                    name TEXT NOT NULL,
                    value TEXT,
                    PRIMARY KEY (name)
                );
                 CREATE TABLE profiles (
                    id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    reference TEXT NULL,
                    profile_key BLOB NULL,
                    PRIMARY KEY (id)
                 );
                 CREATE UNIQUE INDEX ix_profile_name ON profiles (name);
                 ALTER TABLE items RENAME TO items_old;
                 CREATE TABLE items (
                    id INTEGER NOT NULL,
                    profile_id INTEGER NOT NULL,
                    kind INTEGER NOT NULL,
                    category BLOB NOT NULL,
                    name BLOB NOT NULL,
                    value BLOB NOT NULL,
                    expiry DATETIME NULL,
                    PRIMARY KEY (id),
                    FOREIGN KEY (profile_id) REFERENCES profiles (id)
                        ON DELETE CASCADE ON UPDATE CASCADE
                 );
                 CREATE UNIQUE INDEX ix_items_uniq ON items
                     (profile_id, kind, category, name);
                 CREATE TABLE items_tags (
                     id INTEGER NOT NULL,
                     item_id INTEGER NOT NULL,
                     name BLOB NOT NULL,
                     value BLOB NOT NULL,
                     plaintext BOOLEAN NOT NULL,
                     PRIMARY KEY (id),
                     FOREIGN KEY (item_id) REFERENCES items (id)
                         ON DELETE CASCADE ON UPDATE CASCADE
                 );
                 CREATE INDEX ix_items_tags_item_id ON items_tags (item_id);
                 CREATE INDEX ix_items_tags_name_enc ON items_tags
                     (name, SUBSTR(value, 1, 12)) WHERE plaintext=0;
                 CREATE INDEX ix_items_tags_name_plain ON items_tags
                     (name, value) WHERE plaintext=1;
                 COMMIT;
                 ",
        )
        .execute(&mut self.conn)
        .await?;
        Ok(())
    }

    async fn fetch_indy_key(&mut self) -> Result<IndyKeyWithMasterAndSalt, Error> {
        let metadata_row: Vec<u8> = sqlx::query("SELECT value FROM metadata")
            .fetch_one(&mut self.conn)
            .await?
            .try_get(0)?;
        let metadata_json = String::from_utf8_lossy(&metadata_row);
        let metadata: IndyKeyMetadata = serde_json::from_str(&metadata_json).map_err(err_map!(
            Input,
            "Could not convert value from metadata to IndyKey",
        ))?;
        let keys_enc = metadata.keys;
        let salt = &metadata.master_key_salt[..16];

        let key = self
            .kdf_method
            .derive(self.wallet_key.as_bytes(), Some(salt))?;

        let keys_mpk = Strategy::decrypt_merged(keys_enc.as_slice(), &key)?;
        let keys_lst: IndyKey = rmp_serde::from_slice(&keys_mpk)
            .map_err(err_map!(Input, "indy key not valid msgpack",))?;

        let indy_key_with_master_and_salt = IndyKeyWithMasterAndSalt {
            indy_key: keys_lst,
            master: key,
            salt: salt.to_vec(),
        };

        Ok(indy_key_with_master_and_salt)
    }

    async fn init_profile(
        &mut self,
        indy_key: &IndyKeyWithMasterAndSalt,
    ) -> Result<ProfileKey, Error> {
        let IndyKeyWithMasterAndSalt {
            indy_key,
            master,
            salt: _salt,
        } = indy_key;
        let profile_row: Option<SqliteRow> = sqlx::query("SELECT profile_key FROM profiles")
            .fetch_optional(&mut self.conn)
            .await?;
        let profile_row: Option<Vec<u8>> = match profile_row {
            Some(row) => row.try_get(0).ok(),
            None => None,
        };

        let profile_key = match profile_row {
            Some(profile_row) => serde_cbor::from_slice(&profile_row)
                .map_err(err_map!(Input, "Invalid cbor encoding for profile_key"))?,
            None => ProfileKey {
                category_key: indy_key.type_key.clone(),
                name_key: indy_key.name_key.clone(),
                item_hmac_key: indy_key.item_hmac_key.clone(),
                tag_name_key: indy_key.tag_name_key.clone(),
                tag_value_key: indy_key.tag_value_key.clone(),
                tags_hmac_key: indy_key.tag_hmac_key.clone(),
            },
        };

        let enc_pk = Strategy::encrypt_merged(&profile_key.to_bytes()?, master, None)?;
        self.insert_profile(enc_pk.as_slice()).await?;
        Ok(profile_key)
    }

    async fn update_items(
        &mut self,
        indy_key: &IndyKeyWithMasterAndSalt,
        profile_key: &ProfileKey,
    ) -> Result<(), Error> {
        Strategy::update_items(self, &indy_key.indy_key, profile_key).await?;
        Ok(())
    }

    async fn finish_upgrade(&mut self) -> Result<(), Error> {
        sqlx::query(
            r#"
        BEGIN EXCLUSIVE TRANSACTION;
        DROP TABLE items_old;
        DROP TABLE metadata;
        DROP TABLE tags_encrypted;
        DROP TABLE tags_plaintext;
        INSERT INTO config (name, value) VALUES ("version", "1");
        COMMIT;"#,
        )
        .execute(&mut self.conn)
        .await?;
        Ok(())
    }

    async fn update_items_in_db(&mut self, items: Vec<UpdatedIndyItem>) -> Result<(), Error> {
        let mut del_ids = vec![];

        for item in items {
            del_ids.push(item.id);
            let ins = sqlx::query(
                "INSERT INTO items (profile_id, kind, category, name, value)
            VALUES (1, 2, ?1, ?2, ?3)",
            )
            .bind(item.category)
            .bind(item.name)
            .bind(item.value)
            .execute(&mut self.conn)
            .await?;
            let item_id = ins.last_insert_rowid();
            for (plain, name, value) in item.tags {
                sqlx::query("INSERT INTO items_tags (item_id, plaintext, name, value) VALUES (?1, ?2, ?3, ?4)")
                .bind(item_id)
                .bind(plain)
                .bind(name)
                .bind(value)
                .execute(&mut self.conn)
                .await?;
            }
        }
        sqlx::query("DELETE FROM items_old WHERE id IN (?1)")
            .bind(
                del_ids
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<String>>()
                    .join(","),
            )
            .execute(&mut self.conn)
            .await?;
        Ok(())
    }

    async fn create_config(&mut self, indy_key: &IndyKeyWithMasterAndSalt) -> Result<(), Error> {
        let pass_key = self
            .kdf_method
            .to_storable_pass_key(Some(self.wallet_key.as_bytes()), Some(&indy_key.salt))?;

        sqlx::query("INSERT INTO config (name, value) VALUES (?1, ?2)")
            .bind("default_profile")
            .bind(&self.wallet_name)
            .execute(&mut self.conn)
            .await?;

        sqlx::query("INSERT INTO config (name, value) VALUES (?1, ?2)")
            .bind("key")
            .bind(pass_key)
            .execute(&mut self.conn)
            .await?;

        Ok(())
    }

    async fn insert_profile(&mut self, key: &[u8]) -> Result<(), Error> {
        sqlx::query("INSERT INTO profiles (name, profile_key) VALUES (?1, ?2)")
            .bind(&self.wallet_name)
            .bind(key.to_vec())
            .execute(&mut self.conn)
            .await?;

        Ok(())
    }

    async fn fetch_pending_items<
        T: Send + Unpin + for<'r> sqlx::FromRow<'r, sqlx::sqlite::SqliteRow>,
    >(
        &mut self,
        limit: u8,
    ) -> Result<Option<Vec<T>>, Error> {
        let res = sqlx::query_as(
            "SELECT i.id, i.type, i.name, i.value, i.key,
        (SELECT GROUP_CONCAT(HEX(te.name) || ':' || HEX(te.value))
            FROM tags_encrypted te WHERE te.item_id = i.id) AS tags_enc,
        (SELECT GROUP_CONCAT(HEX(tp.name) || ':' || HEX(tp.value))
            FROM tags_plaintext tp WHERE tp.item_id = i.id) AS tags_plain
        FROM items_old i LIMIT ?1",
        )
        .bind(limit)
        .fetch_all(&mut self.conn)
        .await?;

        match res.len() {
            0 => Ok(None),
            _ => Ok(Some(res)),
        }
    }
}

#[cfg(test)]
mod test_migration {
    use crate::{future::block_on, Error};

    use super::IndySdkToAriesAskarMigration;

    const DB_PATH: &str = "./tests/indy_wallet_sqlite.db";
    const DB_BACKUP_PATH: &str = "./tests/indy_wallet_sqlite.bak.db";


    /// Backup the database by creating a copy
    fn backup_db() {
        std::fs::copy(DB_PATH, DB_BACKUP_PATH).unwrap();
    }

    /// Reverting the database by overwriting the transformed db
    fn revert_db() {
        std::fs::rename(DB_BACKUP_PATH, DB_PATH).unwrap();
    }

    #[test]
    fn test_migration() {
        backup_db();
        let res = block_on::<Result<(), Error>>(async {
            let wallet_name = "walletwallet.0";
            let wallet_key = "keykey0";
            let mut migrator =
                IndySdkToAriesAskarMigration::new(DB_PATH, wallet_name, wallet_key, "ARGON2I_MOD")
                    .await?;
            migrator.migrate().await?;
            Ok(())
        });
        revert_db();

        // We still need some indication if something returned with an error
        res.unwrap();
    }
}
