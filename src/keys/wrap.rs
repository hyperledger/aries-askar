use indy_utils::{aead::generic_array::typenum::U32, base58, keys::ArrayKey};
use ursa::encryption::random_bytes;

use super::kdf::KdfMethod;
use crate::error::Result;
use crate::future::blocking;
use crate::keys::store::{decrypt, encrypt_non_searchable, random_deterministic, EncKey};

pub const PREFIX_KDF: &'static str = "kdf";
pub const PREFIX_RAW: &'static str = "raw";
pub const PREFIX_NONE: &'static str = "none";

pub const RAW_KEY_SIZE: usize = 32;

pub fn generate_raw_wrap_key(seed: Option<&[u8]>) -> Result<String> {
    if let Some(seed) = seed {
        if seed.len() != RAW_KEY_SIZE {
            return Err(err_msg!(Encryption, "Invalid length for wrap key seed"));
        }
        let enc_key = EncKey::from_slice(seed);
        let raw_key = EncKey::from_slice(&random_deterministic(&enc_key, RAW_KEY_SIZE));
        Ok(WrapKey::from(raw_key).to_opt_string().unwrap())
    } else {
        Ok(WrapKey::random()?.to_opt_string().unwrap())
    }
}

// pub fn generate_raw_wrap_key(seed: Option<&[u8]>) -> Result<String> {
//     if let Some(seed) = seed {
//         let data = [0; RAW_KEY_SIZE];

//     } else {
//         Ok(WrapKey::random()?.to_opt_string().unwrap())
//     }
// }

fn parse_raw_key(raw_key: &str) -> Result<WrapKey> {
    let key =
        base58::decode(raw_key).map_err(|_| err_msg!("Error parsing raw key as base58 value"))?;
    if key.len() != RAW_KEY_SIZE {
        Err(err_msg!("Incorrect length for encoded raw key"))
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
        Ok(Self(Some(WrapKeyData::from(random_bytes().map_err(
            |e| err_msg!(Encryption, "Error generating new key: {}", e),
        )?))))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    pub async fn wrap_data<'a>(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        match &self.0 {
            Some(key_data) => {
                let key = key_data.clone();
                let data = zeroize::Zeroizing::new(data);
                blocking(move || Ok(encrypt_non_searchable(&key, &data)?)).await
            }
            None => Ok(data),
        }
    }

    pub async fn unwrap_data<'a>(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>> {
        match &self.0 {
            Some(key_data) => {
                let key = key_data.clone();
                blocking(move || Ok(decrypt(&key, &ciphertext)?)).await
            }
            None => Ok(ciphertext),
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

    pub async fn resolve(&self, pass_key: Option<&str>) -> Result<(WrapKey, WrapKeyReference)> {
        match self {
            Self::CreateManagedKey(_mgr_ref) => unimplemented!(),
            // Self::ExistingManagedKey(String),
            Self::DeriveKey(method) => {
                if let Some(password) = pass_key {
                    let method = *method;
                    let password = zeroize::Zeroizing::new(password.to_owned());
                    blocking(move || {
                        let (key, detail) = method.derive_new_key(&password)?;
                        let key_ref = WrapKeyReference::DeriveKey(method, detail);
                        Ok((key, key_ref))
                    })
                    .await
                } else {
                    Err(err_msg!("Key derivation password not provided"))
                }
            }
            Self::RawKey => {
                let key = if let Some(raw_key) = pass_key {
                    parse_raw_key(raw_key)?
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

    pub async fn resolve(&self, pass_key: Option<&str>) -> Result<WrapKey> {
        match self {
            Self::ManagedKey(_key_ref) => unimplemented!(),
            Self::DeriveKey(method, detail) => {
                if let Some(password) = pass_key {
                    let method = *method;
                    let password = zeroize::Zeroizing::new(password.to_string());
                    let detail = detail.to_owned();
                    blocking(move || method.derive_key(&password, &detail)).await
                } else {
                    Err(err_msg!("Key derivation password not provided"))
                }
            }
            Self::RawKey => {
                if let Some(raw_key) = pass_key {
                    parse_raw_key(raw_key)
                } else {
                    Err(err_msg!("Encoded raw key not provided"))
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
            parse("other:method:etc").unwrap_err().kind(),
            ErrorKind::Unsupported
        );
    }

    #[test]
    fn derived_key_wrap() {
        let input = b"test data";
        let pass = "pass";
        let (wrapped, key_ref) = block_on(async {
            let (key, key_ref) = WrapKeyMethod::DeriveKey(KdfMethod::Argon2i(Default::default()))
                .resolve(Some(pass))
                .await?;
            assert!(!key.is_empty());
            let wrapped = key.wrap_data(input.to_vec()).await?;
            Result::Ok((wrapped, key_ref))
        })
        .unwrap();
        assert_ne!(wrapped, input);

        // round trip the key reference
        let key_uri = key_ref.into_uri();
        let key_ref = WrapKeyReference::parse_uri(&key_uri).unwrap();
        let key = block_on(key_ref.resolve(Some(pass))).unwrap();

        let unwrapped = block_on(key.unwrap_data(wrapped.clone())).unwrap();
        assert_eq!(unwrapped, input);

        let check_bad_pass = block_on(key_ref.resolve(Some("not my pass"))).unwrap();
        let unwrapped_err = block_on(check_bad_pass.unwrap_data(wrapped));
        assert!(unwrapped_err.is_err());
    }

    #[test]
    fn raw_key_wrap() {
        let input = b"test data";
        let raw_key = generate_raw_wrap_key(None).unwrap();

        let (wrapped, key_ref) = block_on(async {
            let (key, key_ref) = WrapKeyMethod::RawKey.resolve(Some(&raw_key)).await?;
            assert!(!key.is_empty());
            let wrapped = key.wrap_data(input.to_vec()).await?;
            Result::Ok((wrapped, key_ref))
        })
        .unwrap();
        assert_ne!(wrapped, input);

        // round trip the key reference
        let key_uri = key_ref.into_uri();
        let key_ref = WrapKeyReference::parse_uri(&key_uri).unwrap();
        let key = block_on(key_ref.resolve(Some(&raw_key))).unwrap();

        let unwrapped = block_on(key.unwrap_data(wrapped)).unwrap();
        assert_eq!(unwrapped, input);

        let check_no_key = block_on(key_ref.resolve(None));
        assert!(check_no_key.is_err());

        let check_bad_key = block_on(key_ref.resolve(Some("not the key")));
        assert!(check_bad_key.is_err());
    }

    #[test]
    fn unprotected_wrap() {
        let input = b"test data";
        let (wrapped, key_ref) = block_on(async {
            let (key, key_ref) = WrapKeyMethod::Unprotected.resolve(None).await?;
            assert!(key.is_empty());
            let wrapped = key.unwrap_data(input.to_vec()).await?;
            Result::Ok((wrapped, key_ref))
        })
        .unwrap();
        assert_eq!(wrapped, input);

        // round trip the key reference
        let key_uri = key_ref.into_uri();
        let key_ref = WrapKeyReference::parse_uri(&key_uri).unwrap();
        let key = block_on(key_ref.resolve(None)).unwrap();

        let unwrapped = block_on(key.unwrap_data(wrapped)).unwrap();
        assert_eq!(unwrapped, input);
    }
}
