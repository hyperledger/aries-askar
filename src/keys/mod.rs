use super::error::Result;
use super::types::{EncEntryTag, EntryTag};

pub mod kdf;

pub mod store;

mod types;
pub use self::types::{KeyAlg, KeyCategory, KeyEntry, KeyParams};

pub mod wrap;

use indy_utils::keys::{EncodedVerKey, PrivateKey};

// #[cfg(target_os = "macos")]
// mod keychain;

pub fn derive_verkey(alg: KeyAlg, seed: &[u8]) -> Result<String> {
    match alg {
        KeyAlg::ED25519 => (),
        _ => return Err(err_msg!("Unsupported key algorithm")),
    }

    let sk =
        PrivateKey::from_seed(seed).map_err(err_map!(Unexpected, "Error generating keypair"))?;
    let pk = sk
        .public_key()
        .map_err(err_map!(Unexpected, "Error generating public key"))?
        .as_base58()
        .map_err(err_map!(Unexpected, "Error encoding public key"))?
        .long_form();
    Ok(pk)
}

pub fn verify_signature(signer_vk: &str, data: &[u8], signature: &[u8]) -> Result<bool> {
    let vk = EncodedVerKey::from_str(&signer_vk).map_err(err_map!("Invalid verkey"))?;
    Ok(vk
        .decode()
        .map_err(err_map!("Unsupported verkey"))?
        .verify_signature(&data, &signature)
        .unwrap_or(false))
}

pub trait EntryEncryptor {
    fn encrypt_entry_category(&self, category: &str) -> Result<Vec<u8>>;
    fn encrypt_entry_name(&self, name: &str) -> Result<Vec<u8>>;
    fn encrypt_entry_value(&self, value: &[u8]) -> Result<Vec<u8>>;
    fn encrypt_entry_tags(&self, tags: &[EntryTag]) -> Result<Vec<EncEntryTag>>;

    fn decrypt_entry_category(&self, enc_category: &[u8]) -> Result<String>;
    fn decrypt_entry_name(&self, enc_name: &[u8]) -> Result<String>;
    fn decrypt_entry_value(&self, enc_value: &[u8]) -> Result<Vec<u8>>;
    fn decrypt_entry_tags(&self, enc_tags: &[EncEntryTag]) -> Result<Vec<EntryTag>>;
}

pub struct NullEncryptor;

impl EntryEncryptor for NullEncryptor {
    fn encrypt_entry_category(&self, category: &str) -> Result<Vec<u8>> {
        Ok(category.as_bytes().to_vec())
    }
    fn encrypt_entry_name(&self, name: &str) -> Result<Vec<u8>> {
        Ok(name.as_bytes().to_vec())
    }
    fn encrypt_entry_value(&self, value: &[u8]) -> Result<Vec<u8>> {
        Ok(value.to_vec())
    }
    fn encrypt_entry_tags(&self, tags: &[EntryTag]) -> Result<Vec<EncEntryTag>> {
        Ok(tags
            .into_iter()
            .map(|tag| match tag {
                EntryTag::Encrypted(name, value) => EncEntryTag {
                    name: name.as_bytes().to_vec(),
                    value: value.as_bytes().to_vec(),
                    plaintext: false,
                },
                EntryTag::Plaintext(name, value) => EncEntryTag {
                    name: name.as_bytes().to_vec(),
                    value: value.as_bytes().to_vec(),
                    plaintext: true,
                },
            })
            .collect())
    }

    fn decrypt_entry_category(&self, enc_category: &[u8]) -> Result<String> {
        Ok(String::from_utf8(enc_category.to_vec()).map_err(err_map!(Encryption))?)
    }
    fn decrypt_entry_name(&self, enc_name: &[u8]) -> Result<String> {
        Ok(String::from_utf8(enc_name.to_vec()).map_err(err_map!(Encryption))?)
    }
    fn decrypt_entry_value(&self, enc_value: &[u8]) -> Result<Vec<u8>> {
        Ok(enc_value.to_vec())
    }
    fn decrypt_entry_tags(&self, enc_tags: &[EncEntryTag]) -> Result<Vec<EntryTag>> {
        Ok(enc_tags.into_iter().try_fold(vec![], |mut acc, tag| {
            let name = String::from_utf8(tag.name.to_vec()).map_err(err_map!(Encryption))?;
            let value = String::from_utf8(tag.value.to_vec()).map_err(err_map!(Encryption))?;
            acc.push(if tag.plaintext {
                EntryTag::Plaintext(name, value)
            } else {
                EntryTag::Encrypted(name, value)
            });
            Result::Ok(acc)
        })?)
    }
}
