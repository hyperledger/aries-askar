use chacha20poly1305::aead::generic_array::typenum::U32;
use indy_utils::{base58, keys::ArrayKey, random::random_deterministic};

use super::kdf::KdfMethod;
use super::store::{decrypt, encrypt_non_searchable, EncKey};
use super::types::PassKey;
use crate::error::Result;

pub const PREFIX_KDF: &'static str = "kdf";
pub const PREFIX_RAW: &'static str = "raw";
pub const PREFIX_NONE: &'static str = "none";

pub const RAW_KEY_SIZE: usize = 32;

pub fn generate_raw_wrap_key(seed: Option<&[u8]>) -> Result<PassKey<'static>> {
    if let Some(seed) = seed {
        if seed.len() != RAW_KEY_SIZE {
            return Err(err_msg!(Encryption, "Invalid length for wrap key seed"));
        }
        let enc_key = EncKey::from_slice(seed);
        let raw_key = EncKey::from_slice(&random_deterministic(&enc_key, RAW_KEY_SIZE));
        Ok(WrapKey::from(raw_key).to_opt_string().unwrap().into())
    } else {
        Ok(WrapKey::random()?.to_opt_string().unwrap().into())
    }
}

pub fn parse_raw_key(raw_key: &str) -> Result<WrapKey> {
    let key = base58::decode(raw_key)
        .map_err(|_| err_msg!(Input, "Error parsing raw key as base58 value"))?;
    if key.len() != RAW_KEY_SIZE {
        Err(err_msg!(Input, "Incorrect length for encoded raw key"))
    } else {
        Ok(WrapKey::from(WrapKeyData::from_slice(key)))
    }
}

pub type WrapKeyData = ArrayKey<U32>;

#[derive(Clone, Debug)]
pub struct WrapKey(pub Option<WrapKeyData>);

impl WrapKey {
    pub const fn empty() -> Self {
        Self(None)
    }

    pub fn random() -> Result<Self> {
        Ok(Self(Some(WrapKeyData::random())))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    pub fn wrap_data<'a>(&self, data: &[u8]) -> Result<Vec<u8>> {
        match &self.0 {
            Some(key) => Ok(encrypt_non_searchable(key, data)?),
            None => Ok(data.to_vec()),
        }
    }

    pub fn unwrap_data<'a>(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        match &self.0 {
            Some(key) => Ok(decrypt(key, ciphertext)?),
            None => Ok(ciphertext.to_vec()),
        }
    }

    pub fn to_opt_string(&self) -> Option<String> {
        self.0.as_ref().map(|key| base58::encode(key.as_slice()))
    }
}

impl From<WrapKeyData> for WrapKey {
    fn from(data: WrapKeyData) -> Self {
        Self(Some(data))
    }
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
                None => Err(err_msg!(Unsupported, "Invalid key derivation method")),
            },
            PREFIX_NONE => Ok(Self::Unprotected),
            _ => Err(err_msg!(Unsupported, "Invalid wrap key method")),
        }
    }

    pub fn resolve(&self, pass_key: PassKey<'_>) -> Result<(WrapKey, WrapKeyReference)> {
        match self {
            Self::CreateManagedKey(_mgr_ref) => unimplemented!(),
            // Self::ExistingManagedKey(String),
            Self::DeriveKey(method) => {
                if !pass_key.is_none() {
                    let (key, detail) = method.derive_new_key(&*pass_key)?;
                    let key_ref = WrapKeyReference::DeriveKey(*method, detail);
                    Ok((key, key_ref))
                } else {
                    Err(err_msg!(Input, "Key derivation password not provided"))
                }
            }
            Self::RawKey => {
                let key = if !pass_key.is_empty() {
                    parse_raw_key(&*pass_key)?
                } else {
                    WrapKey::random()?
                };
                Ok((key, WrapKeyReference::RawKey))
            }
            Self::Unprotected => Ok((WrapKey::empty(), WrapKeyReference::Unprotected)),
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
                None => Err(err_msg!(
                    Unsupported,
                    "Invalid key derivation method for reference"
                )),
            },
            PREFIX_NONE => Ok(Self::Unprotected),
            _ => Err(err_msg!(
                Unsupported,
                "Invalid wrap key method for reference"
            )),
        }
    }

    pub fn compare_method(&self, method: &WrapKeyMethod) -> bool {
        match self {
            Self::ManagedKey(_keyref) => matches!(method, WrapKeyMethod::CreateManagedKey(..)),
            Self::DeriveKey(kdf_method, _detail) => match method {
                WrapKeyMethod::DeriveKey(m) if m == kdf_method => true,
                _ => false,
            },
            Self::RawKey => *method == WrapKeyMethod::RawKey,
            Self::Unprotected => *method == WrapKeyMethod::Unprotected,
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

    pub fn resolve(&self, pass_key: PassKey<'_>) -> Result<WrapKey> {
        match self {
            Self::ManagedKey(_key_ref) => unimplemented!(),
            Self::DeriveKey(method, detail) => {
                if !pass_key.is_none() {
                    method.derive_key(&*pass_key, detail)
                } else {
                    Err(err_msg!(Input, "Key derivation password not provided"))
                }
            }
            Self::RawKey => {
                if !pass_key.is_empty() {
                    parse_raw_key(&*pass_key)
                } else {
                    Err(err_msg!(Input, "Encoded raw key not provided"))
                }
            }
            Self::Unprotected => Ok(WrapKey::empty()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;

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
            parse("other:method:etc").unwrap_err().kind(),
            ErrorKind::Unsupported
        );
    }

    #[test]
    fn derived_key_wrap() {
        let input = b"test data";
        let pass = PassKey::from("pass");
        let (key, key_ref) = WrapKeyMethod::DeriveKey(KdfMethod::Argon2i(Default::default()))
            .resolve(pass.as_ref())
            .expect("Error deriving new key");
        assert!(!key.is_empty());
        let wrapped = key.wrap_data(input).expect("Error wrapping input");
        assert_ne!(wrapped, input);

        // round trip the key reference
        let key_uri = key_ref.into_uri();
        let key_ref = WrapKeyReference::parse_uri(&key_uri).expect("Error parsing key ref");
        let key = key_ref.resolve(pass).expect("Error deriving existing key");

        let unwrapped = key.unwrap_data(&wrapped).expect("Error unwrapping data");
        assert_eq!(unwrapped, input);

        let check_bad_pass = key_ref
            .resolve("not my pass".into())
            .expect("Error deriving comparison key");
        let unwrapped_err = check_bad_pass.unwrap_data(&wrapped);
        assert_eq!(unwrapped_err.is_err(), true);
    }

    #[test]
    fn raw_key_wrap() {
        let input = b"test data";
        let raw_key = generate_raw_wrap_key(None).unwrap();

        let (key, key_ref) = WrapKeyMethod::RawKey
            .resolve(raw_key.as_ref())
            .expect("Error resolving raw key");
        assert_eq!(key.is_empty(), false);
        let wrapped = key.wrap_data(input).expect("Error wrapping input");
        assert_ne!(wrapped, input);

        // round trip the key reference
        let key_uri = key_ref.into_uri();
        let key_ref = WrapKeyReference::parse_uri(&key_uri).expect("Error parsing raw key URI");
        let key = key_ref.resolve(raw_key).expect("Error resolving raw key");

        let unwrapped = key.unwrap_data(&wrapped).expect("Error unwrapping data");
        assert_eq!(unwrapped, input);

        let check_no_key = key_ref.resolve(None.into());
        assert_eq!(check_no_key.is_err(), true);

        let check_bad_key = key_ref.resolve("not the key".into());
        assert_eq!(check_bad_key.is_err(), true);
    }

    #[test]
    fn unprotected_wrap() {
        let input = b"test data";
        let (key, key_ref) = WrapKeyMethod::Unprotected
            .resolve(None.into())
            .expect("Error resolving unprotected");
        assert_eq!(key.is_empty(), true);
        let wrapped = key.wrap_data(input).expect("Error wrapping unprotected");
        assert_eq!(wrapped, input);

        // round trip the key reference
        let key_uri = key_ref.into_uri();
        let key_ref =
            WrapKeyReference::parse_uri(&key_uri).expect("Error parsing unprotected key ref");
        let key = key_ref
            .resolve(None.into())
            .expect("Error resolving unprotected key ref");

        let unwrapped = key
            .unwrap_data(&wrapped)
            .expect("Error unwrapping unprotected");
        assert_eq!(unwrapped, input);
    }
}
