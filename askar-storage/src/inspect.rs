//! Read-only decryption of raw storage records for diagnostic tools.

use crate::{
    crypto::buffer::SecretBytes,
    entry::EntryTag,
    protect::{EntryEncryptor, PassKey, ProfileKey, StoreKey, StoreKeyReference},
    Error,
};

#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "postgres")]
pub mod postgres;

/// A profile with its wrapped key, including profiles with a missing key.
#[derive(Debug)]
pub struct RawProfile {
    /// Database row identifier.
    pub id: i64,
    /// Profile name.
    pub name: String,
    /// Serialized, possibly wrapped profile key.
    pub profile_key: Option<Vec<u8>>,
}

/// A tag as stored in `items_tags`.
#[derive(Debug)]
pub struct RawTag {
    /// Encrypted tag name.
    pub name: Vec<u8>,
    /// Encrypted value, or UTF-8 bytes for a plaintext tag.
    pub value: Vec<u8>,
    /// Whether the value is stored as plaintext.
    pub plaintext: bool,
}

/// Encrypted fields of an item, including rows excluded by regular scans.
#[derive(Debug)]
pub struct RawItem {
    /// Database row identifier.
    pub id: i64,
    /// Stored kind discriminator (including unknown values).
    pub kind: i64,
    /// Encrypted category.
    pub category: Vec<u8>,
    /// Encrypted name.
    pub name: Vec<u8>,
    /// Encrypted value.
    pub value: Vec<u8>,
    /// Expiry timestamp, if present.
    pub expiry: Option<chrono::NaiveDateTime>,
    /// Tags belonging to the row.
    pub tags: Vec<RawTag>,
}

/// Decrypted fields, each with its own error so damaged rows remain inspectable.
#[derive(Debug)]
pub struct InspectedItem {
    /// Database row identifier.
    pub id: i64,
    /// Stored kind discriminator.
    pub kind: i64,
    /// Decrypted category.
    pub category: Result<String, Error>,
    /// Decrypted name.
    pub name: Result<String, Error>,
    /// Decrypted value.
    pub value: Result<SecretBytes, Error>,
    /// Expiry timestamp, if present.
    pub expiry: Option<chrono::NaiveDateTime>,
    /// Independently decrypted tags.
    pub tags: Vec<Result<EntryTag, Error>>,
}

/// A profile key unlocked using the store's recorded key method.
pub struct Inspector {
    key: ProfileKey,
}

/// A resolved store key that can unlock multiple profiles without repeating key derivation.
pub struct InspectionKey {
    store_key: StoreKey,
}

impl std::fmt::Debug for InspectionKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("InspectionKey(<redacted>)")
    }
}

impl InspectionKey {
    /// Resolve the store's recorded key reference once.
    pub fn resolve(key_reference: &str, pass_key: PassKey<'_>) -> Result<Self, Error> {
        Ok(Self {
            store_key: StoreKeyReference::parse_uri(key_reference)?.resolve(pass_key)?,
        })
    }

    /// Unlock a profile key with this store key.
    pub fn unlock(&self, wrapped_profile_key: Vec<u8>) -> Result<Inspector, Error> {
        let profile_key = self.store_key.unwrap_data(wrapped_profile_key)?;
        Ok(Inspector {
            key: ProfileKey::from_slice(profile_key.as_ref())?,
        })
    }
}

impl std::fmt::Debug for Inspector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Inspector(<redacted>)")
    }
}

impl Inspector {
    /// Unlock a profile key with the key reference stored in `config.key`.
    pub fn unlock(
        key_reference: &str,
        pass_key: PassKey<'_>,
        wrapped_profile_key: Vec<u8>,
    ) -> Result<Self, Error> {
        InspectionKey::resolve(key_reference, pass_key)?.unlock(wrapped_profile_key)
    }

    /// Decrypt one raw row without losing other fields when a field is damaged.
    pub fn decrypt(&self, raw: RawItem) -> InspectedItem {
        let category = self.key.decrypt_entry_category(raw.category);
        let name = self.key.decrypt_entry_name(raw.name);
        let value = match (&category, &name) {
            (Ok(category), Ok(name)) => {
                self.key
                    .decrypt_entry_value(category.as_bytes(), name.as_bytes(), raw.value)
            }
            _ => Err(err_msg!(
                Encryption,
                "Cannot decrypt value without category and name"
            )),
        };
        let tags = raw
            .tags
            .into_iter()
            .map(|tag| {
                let name = self.key.decrypt_tag_name(tag.name)?;
                let name = String::from_utf8(name.into_vec())
                    .map_err(err_map!(Encryption, "Invalid tag name"))?;
                let value = if tag.plaintext {
                    tag.value
                } else {
                    self.key.decrypt_tag_value(tag.value)?.into_vec()
                };
                let value =
                    String::from_utf8(value).map_err(err_map!(Encryption, "Invalid tag value"))?;
                Ok(if tag.plaintext {
                    EntryTag::Plaintext(name, value)
                } else {
                    EntryTag::Encrypted(name, value)
                })
            })
            .collect();
        InspectedItem {
            id: raw.id,
            kind: raw.kind,
            category,
            name,
            value,
            expiry: raw.expiry,
            tags,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protect::EntryEncryptor;

    #[test]
    fn decrypts_fields_independently() {
        let profile = ProfileKey::new().unwrap();
        let inspector = Inspector::unlock(
            "none",
            PassKey::empty(),
            profile.to_bytes().unwrap().into_vec(),
        )
        .unwrap();
        let mut value = profile
            .encrypt_entry_value(b"records", b"first", SecretBytes::from(b"hello".as_slice()))
            .unwrap();
        value[12] ^= 1;
        let raw = RawItem {
            id: 3,
            kind: 2,
            category: profile
                .encrypt_entry_category(b"records".as_slice().into())
                .unwrap(),
            name: profile
                .encrypt_entry_name(b"first".as_slice().into())
                .unwrap(),
            value,
            expiry: Some(chrono::DateTime::from_timestamp(12, 0).unwrap().naive_utc()),
            tags: vec![RawTag {
                name: profile
                    .encrypt_tag_name(b"status".as_slice().into())
                    .unwrap(),
                value: b"active".to_vec(),
                plaintext: true,
            }],
        };
        let item = inspector.decrypt(raw);
        assert_eq!(item.category.unwrap(), "records");
        assert_eq!(item.name.unwrap(), "first");
        assert!(item.value.is_err());
        assert_eq!(
            item.tags[0].as_ref().unwrap(),
            &EntryTag::Plaintext("status".into(), "active".into())
        );
        assert_eq!(
            item.expiry,
            Some(chrono::DateTime::from_timestamp(12, 0).unwrap().naive_utc())
        );
    }
}
