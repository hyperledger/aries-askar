use std::borrow::Cow;

use indy_utils::base58;
pub use indy_utils::keys::wallet::{decrypt, encrypt_non_searchable, EncKey as WrapKey};
use indy_utils::ursa::encryption::random_bytes;

use super::kdf::KdfMethod;
use crate::error::{ErrorKind, Result};

pub const PREFIX_KDF: &'static str = "kdf";
pub const PREFIX_RAW: &'static str = "raw";
pub const PREFIX_NONE: &'static str = "none";

pub const RAW_KEY_SIZE: usize = 32;

pub fn generate_raw_wrap_key() -> Result<String> {
    let key = WrapKey::from(random_bytes().unwrap());
    Ok(base58::encode(key.as_slice()))
}

fn parse_raw_key(raw_key: &str) -> Result<WrapKey> {
    let key =
        base58::decode(raw_key).map_err(|_| err_msg!("Error parsing raw key as base58 value"))?;
    if key.len() != RAW_KEY_SIZE {
        Err(err_msg!("Incorrect length for encoded raw key"))
    } else {
        Ok(WrapKey::from_slice(key))
    }
}

fn wrap_data(key: &WrapKey, input: &[u8]) -> Result<Vec<u8>> {
    Ok(encrypt_non_searchable(key, input)?)
}

fn unwrap_data(key: &WrapKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
    Ok(decrypt(key, ciphertext)?)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum WrapKeyMethod {
    CreateManagedKey(String),
    // ExistingManagedKey(String),
    DeriveKey(KdfMethod),
    RawKey,
    Unprotected,
}

impl WrapKeyMethod {
    pub fn parse_uri(uri: &str) -> Result<Self> {
        let mut prefix_and_detail = uri.splitn(2, ':');
        let prefix = prefix_and_detail.next().unwrap_or_default();
        // let detail = prefix_and_detail.next().unwrap_or_default();
        match prefix {
            PREFIX_RAW => Ok(Self::RawKey),
            PREFIX_KDF => match KdfMethod::from_str(uri) {
                Some((method, _)) => Ok(Self::DeriveKey(method)),
                None => Err(ErrorKind::Unsupported.into()),
            },
            PREFIX_NONE => Ok(Self::Unprotected),
            _ => Err(ErrorKind::Unsupported.into()),
        }
    }

    // FIXME: do not perform key derivation, encryption on current thread
    pub async fn wrap_data<'a>(
        &self,
        data: &'a [u8],
        pass_key: Option<&str>,
    ) -> Result<(Cow<'a, [u8]>, Option<WrapKey>, WrapKeyReference)> {
        match self {
            Self::CreateManagedKey(_mgr_ref) => unimplemented!(),
            // Self::ExistingManagedKey(String),
            Self::DeriveKey(method) => {
                if let Some(password) = pass_key {
                    let (key, detail) = method.derive_new_key(password)?;
                    let key_ref = WrapKeyReference::DeriveKey(*method, detail);
                    Ok((Cow::Owned(wrap_data(&key, data)?), Some(key), key_ref))
                } else {
                    Err(err_msg!("Key derivation password not provided"))
                }
            }
            Self::RawKey => {
                if let Some(raw_key) = pass_key {
                    let key = parse_raw_key(raw_key)?;
                    let key_ref = WrapKeyReference::RawKey;
                    Ok((Cow::Owned(wrap_data(&key, data)?), Some(key), key_ref))
                } else {
                    Err(err_msg!("Encoded raw key not provided"))
                }
            }
            Self::Unprotected => Ok((Cow::Borrowed(data), None, WrapKeyReference::Unprotected)),
        }
    }
}

impl Default for WrapKeyMethod {
    fn default() -> Self {
        Self::DeriveKey(KdfMethod::Argon2i(Default::default()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum WrapKeyReference {
    ManagedKey(String),
    DeriveKey(KdfMethod, String),
    RawKey,
    Unprotected,
}

impl WrapKeyReference {
    pub fn parse_uri(uri: &str) -> Result<Self> {
        let mut prefix_and_detail = uri.splitn(2, ':');
        let prefix = prefix_and_detail.next().unwrap_or_default();
        match prefix {
            PREFIX_RAW => Ok(Self::RawKey),
            PREFIX_KDF => match KdfMethod::from_str(uri) {
                Some((method, detail)) => Ok(Self::DeriveKey(method, detail)),
                None => Err(ErrorKind::Unsupported.into()),
            },
            PREFIX_NONE => Ok(Self::Unprotected),
            _ => Err(ErrorKind::Unsupported.into()),
        }
    }

    pub fn into_uri(self) -> String {
        match self {
            Self::ManagedKey(keyref) => keyref,
            Self::DeriveKey(method, detail) => method.to_string(Some(detail.as_str())),
            Self::RawKey => PREFIX_RAW.to_string(),
            Self::Unprotected => PREFIX_NONE.to_string(),
        }
    }

    pub async fn unwrap_data<'a>(
        &self,
        ciphertext: &'a [u8],
        pass_key: Option<&str>,
    ) -> Result<Cow<'a, [u8]>> {
        match self {
            Self::ManagedKey(_key_ref) => unimplemented!(),
            Self::DeriveKey(method, detail) => {
                if let Some(password) = pass_key {
                    let key = method.derive_key(password, detail)?;
                    Ok(Cow::Owned(unwrap_data(&key, ciphertext)?))
                } else {
                    Err(err_msg!("Key derivation password not provided"))
                }
            }
            Self::RawKey => {
                if let Some(raw_key) = pass_key {
                    let key = parse_raw_key(raw_key)?;
                    Ok(Cow::Owned(unwrap_data(&key, ciphertext)?))
                } else {
                    Err(err_msg!("Encoded raw key not provided"))
                }
            }
            Self::Unprotected => Ok(Cow::Borrowed(ciphertext)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::future::block_on;

    #[test]
    fn protection_method_parse() {
        let parse = WrapKeyMethod::parse_uri;
        assert_eq!(parse("none"), Ok(WrapKeyMethod::Unprotected));
        assert_eq!(parse("raw"), Ok(WrapKeyMethod::RawKey));
        assert_eq!(
            parse("kdf:argon2i"),
            Ok(WrapKeyMethod::DeriveKey(KdfMethod::Argon2i(
                Default::default()
            )))
        );
        assert_eq!(
            parse("other:method:etc"),
            Err(ErrorKind::Unsupported.into())
        );
    }

    #[test]
    fn derived_key_wrap() {
        let input = b"test data";
        let pass = "pass";
        let (wrapped, key, key_ref) = block_on(
            WrapKeyMethod::DeriveKey(KdfMethod::Argon2i(Default::default()))
                .wrap_data(input, Some(pass)),
        )
        .unwrap();
        let wrapped = wrapped.into_owned();
        assert!(key.is_some());
        assert_ne!(wrapped, input);

        // round trip the key reference
        let key_uri = key_ref.into_uri();
        let key_ref = WrapKeyReference::parse_uri(&key_uri).unwrap();

        let unwrapped = block_on(key_ref.unwrap_data(&wrapped, Some(pass)))
            .unwrap()
            .into_owned();
        assert_eq!(unwrapped, input);

        let check_bad_pass = block_on(key_ref.unwrap_data(&wrapped, Some("not my pass")));
        assert!(check_bad_pass.is_err());
    }

    #[test]
    fn raw_key_wrap() {
        let input = b"test data";
        let raw_key = generate_raw_wrap_key().unwrap();
        let (wrapped, key, key_ref) =
            block_on(WrapKeyMethod::RawKey.wrap_data(input, Some(raw_key.as_str()))).unwrap();
        let wrapped = wrapped.into_owned();
        assert!(key.is_some());
        assert_ne!(wrapped, input);

        // round trip the key reference
        let key_uri = key_ref.into_uri();
        let key_ref = WrapKeyReference::parse_uri(&key_uri).unwrap();

        let unwrapped = block_on(key_ref.unwrap_data(&wrapped, Some(raw_key.as_str())))
            .unwrap()
            .into_owned();
        assert_eq!(unwrapped, input);

        let check_bad_key = block_on(key_ref.unwrap_data(&wrapped, Some("not the key")));
        assert!(check_bad_key.is_err());
    }

    #[test]
    fn unprotected_wrap() {
        let input = b"test data";
        let (wrapped, key, key_ref) =
            block_on(WrapKeyMethod::Unprotected.wrap_data(input, None)).unwrap();
        let wrapped = wrapped.into_owned();
        assert!(key.is_none());
        assert_eq!(wrapped, input);

        // round trip the key reference
        let key_uri = key_ref.into_uri();
        let key_ref = WrapKeyReference::parse_uri(&key_uri).unwrap();

        let unwrapped = block_on(key_ref.unwrap_data(&wrapped, None))
            .unwrap()
            .into_owned();
        assert_eq!(unwrapped, input);
    }
}
