use suspend::iter_stream;

use super::sqlite::context::{
    Connection, ConnectionContext, ResultProcessor, Row, Rows, SqlParams,
};
use super::{KvEntry, KvResult};
use crate::keys::indy_key::{decode_wallet_key, decrypt, EncKey, IndyWalletKey};

// test method for dumping the contents of the wallet
pub fn print_records<'a>(path: String, password: String) -> KvResult<()> {
    let mut db = ConnectionContext::new(path.to_string(), None, None)?;

    let dec = KeyDecoder { password };
    let params = SqlParams::new();
    let results = db.process_query("SELECT id, value from metadata".to_string(), params, dec);
    let wallet_key = iter_stream(results).wait_next().unwrap().unwrap();

    let dec = RowDecoder { wallet_key };
    let params = SqlParams::new();
    let results = db.process_query(
        "SELECT id, type, name, value, key FROM items".to_string(),
        params,
        dec,
    );
    for row in iter_stream(results) {
        println!("{:?}", row?);
    }
    Ok(())
}

struct KeyDecoder {
    password: String,
}

impl KeyDecoder {
    fn decode(&self, row: &Row) -> KvResult<IndyWalletKey> {
        decode_wallet_key(col_bytes(row, 1)?, &self.password)
    }
}

impl ResultProcessor for KeyDecoder {
    type Item = IndyWalletKey;

    fn next(&mut self, rows: &mut Rows, _conn: &Connection) -> Option<KvResult<Self::Item>> {
        match rows.next() {
            Ok(Some(row)) => {
                let key = self.decode(row);
                println!(".");
                Some(key)
            }
            Ok(None) => {
                println!("!");
                None
            }
            Err(err) => Some(Err(err.into())),
        }
    }

    fn completed(&self) -> bool {
        false
    }
}

fn col_bytes<'r>(row: &'r Row, index: usize) -> KvResult<&'r [u8]> {
    Ok(row.get_raw(index).as_blob().unwrap())
}

struct RowDecoder {
    wallet_key: IndyWalletKey,
}

impl RowDecoder {
    fn decode(&self, row: &Row) -> KvResult<KvEntry> {
        let value_key_enc = col_bytes(row, 4)?;
        let value_key = EncKey::from_slice(decrypt(&self.wallet_key.value_key, value_key_enc)?);
        let value = decrypt(&value_key, col_bytes(row, 3)?)?;

        let entry = KvEntry {
            key_id: vec![],
            category: self.wallet_key.decrypt_category(col_bytes(row, 1)?)?,
            name: self.wallet_key.decrypt_name(col_bytes(row, 2)?)?,
            value,
            tags: None,
            locked: None,
        };
        Ok(entry)
    }
}

impl ResultProcessor for RowDecoder {
    type Item = KvEntry;
    fn next(&mut self, rows: &mut Rows, _conn: &Connection) -> Option<KvResult<Self::Item>> {
        match rows.next() {
            Ok(Some(row)) => {
                let row = self.decode(row);
                Some(row)
            }
            Ok(None) => None,
            Err(err) => Some(Err(err.into())),
        }
    }

    fn completed(&self) -> bool {
        false
    }
}
