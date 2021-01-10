use aead::generic_array::typenum::Unsigned;

use indy_utils::{base58, keys::ArrayKey, random::random_deterministic};

use super::encrypt::{chacha::ChaChaEncrypt, SymEncrypt};
use super::kdf::KdfMethod;
use super::store::EncKey;
use super::types::PassKey;
use crate::{error::Result, SecretBytes};

pub const PREFIX_KDF: &'static str = "kdf";
pub const PREFIX_RAW: &'static str = "raw";
pub const PREFIX_NONE: &'static str = "none";

/// Create a new raw wrap key for a store
pub fn generate_raw_wrap_key(seed: Option<&[u8]>) -> Result<PassKey<'static>> {
    let key = if let Some(seed) = seed {
        if seed.len() != WRAP_KEY_SIZE {
            return Err(err_msg!(Encryption, "Invalid length for wrap key seed"));
        }
        let enc_key = EncKey::<WrapKeyAlg>::from_slice(seed);
        let raw_key =
            EncKey::<WrapKeyAlg>::from_slice(&random_deterministic(&enc_key, WRAP_KEY_SIZE));
        WrapKey::from(raw_key)
    } else {
        WrapKey::random()?
    };
    Ok(key.to_opt_string().unwrap().into())
}

pub fn parse_raw_key(raw_key: &str) -> Result<WrapKey> {
    let key = base58::decode(raw_key)
        .map_err(|_| err_msg!(Input, "Error parsing raw key as base58 value"))?;
    if key.len() != WRAP_KEY_SIZE {
        Err(err_msg!(Input, "Incorrect length for encoded raw key"))
    } else {
        Ok(WrapKey::from(WrapKeyData::from_slice(key)))
    }
}

pub type WrapKeyAlg = ChaChaEncrypt;
pub type WrapKeyData = ArrayKey<<WrapKeyAlg as SymEncrypt>::KeySize>;
pub const WRAP_KEY_SIZE: usize = <WrapKeyAlg as SymEncrypt>::KeySize::USIZE;

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

    pub fn prepare_input(&self, input: &[u8]) -> SecretBytes {
        WrapKeyAlg::prepare_input(input)
    }

    pub fn wrap_data(&self, data: SecretBytes) -> Result<Vec<u8>> {
        match &self.0 {
            Some(key) => Ok(WrapKeyAlg::encrypt(data, key, None)?),
            None => Ok(data.into_vec()),
        }
    }

    pub fn unwrap_data(&self, ciphertext: Vec<u8>) -> Result<SecretBytes> {
        match &self.0 {
            Some(key) => Ok(WrapKeyAlg::decrypt(ciphertext, key)?),
            None => Ok(ciphertext.into()),
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

/// Supported methods for generating or referencing a new wrap key
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
        let wrapped = key
            .wrap_data(key.prepare_input(input))
            .expect("Error wrapping input");
        assert_ne!(wrapped, input);
        let unwrapped = key.unwrap_data(wrapped).expect("Error unwrapping data");
        assert_eq!(unwrapped, &input[..]);
        let key_uri = key_ref.into_uri();
        assert_eq!(key_uri.starts_with("kdf:argon2i:13:mod?salt="), true);
    }

    #[test]
    fn derived_key_unwrap_expected() {
        let input = b"test data";
        let wrapped: &[u8] = &[
            194, 156, 102, 253, 229, 11, 48, 184, 160, 119, 218, 30, 169, 188, 244, 223, 235, 95,
            171, 234, 18, 5, 9, 115, 174, 208, 232, 37, 31, 32, 250, 216, 32, 92, 253, 45, 236,
        ];
        let pass = PassKey::from("pass");
        let key_ref = WrapKeyReference::parse_uri("kdf:argon2i:13:mod?salt=MR6B1jrReV2JioaizEaRo6")
            .expect("Error parsing derived key ref");
        let key = key_ref.resolve(pass).expect("Error deriving existing key");
        let unwrapped = key
            .unwrap_data(wrapped.to_vec())
            .expect("Error unwrapping data");
        assert_eq!(unwrapped, &input[..]);
    }

    #[test]
    fn derived_key_check_bad_password() {
        let wrapped: &[u8] = &[
            194, 156, 102, 253, 229, 11, 48, 184, 160, 119, 218, 30, 169, 188, 244, 223, 235, 95,
            171, 234, 18, 5, 9, 115, 174, 208, 232, 37, 31, 32, 250, 216, 32, 92, 253, 45, 236,
        ];
        let key_ref = WrapKeyReference::parse_uri("kdf:argon2i:13:mod?salt=MR6B1jrReV2JioaizEaRo6")
            .expect("Error parsing derived key ref");
        let check_bad_pass = key_ref
            .resolve("not my pass".into())
            .expect("Error deriving comparison key");
        let unwrapped_err = check_bad_pass.unwrap_data(wrapped.to_vec());
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
        let wrapped = key
            .wrap_data(key.prepare_input(input))
            .expect("Error wrapping input");
        assert_ne!(wrapped, input);

        // round trip the key reference
        let key_uri = key_ref.into_uri();
        let key_ref = WrapKeyReference::parse_uri(&key_uri).expect("Error parsing raw key URI");
        let key = key_ref.resolve(raw_key).expect("Error resolving raw key");

        let unwrapped = key.unwrap_data(wrapped).expect("Error unwrapping data");
        assert_eq!(unwrapped, &input[..]);

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
        let wrapped = key
            .wrap_data(key.prepare_input(input))
            .expect("Error wrapping unprotected");
        assert_eq!(wrapped, input);

        // round trip the key reference
        let key_uri = key_ref.into_uri();
        let key_ref =
            WrapKeyReference::parse_uri(&key_uri).expect("Error parsing unprotected key ref");
        let key = key_ref
            .resolve(None.into())
            .expect("Error resolving unprotected key ref");

        let unwrapped = key
            .unwrap_data(wrapped)
            .expect("Error unwrapping unprotected");
        assert_eq!(unwrapped, &input[..]);
    }
}
