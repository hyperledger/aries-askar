use super::kdf::KdfMethod;

use super::pass_key::PassKey;
use crate::{
    crypto::{
        alg::chacha20::{Chacha20Key, C20P},
        buffer::{ArrayKey, ResizeBuffer, SecretBytes},
        encrypt::{KeyAeadInPlace, KeyAeadMeta},
        repr::{KeyGen, KeyMeta, KeySecretBytes},
    },
    error::Error,
};

pub const PREFIX_KDF: &'static str = "kdf";
pub const PREFIX_RAW: &'static str = "raw";
pub const PREFIX_NONE: &'static str = "none";

pub type WrapKeyType = Chacha20Key<C20P>;

type WrapKeyNonce = ArrayKey<<WrapKeyType as KeyAeadMeta>::NonceSize>;

/// Create a new raw wrap key for a store
pub fn generate_raw_wrap_key(seed: Option<&[u8]>) -> Result<PassKey<'static>, Error> {
    let key = if let Some(seed) = seed {
        WrapKey::from(WrapKeyType::from_seed(seed)?)
    } else {
        WrapKey::from(WrapKeyType::generate()?)
    };
    Ok(key.to_passkey())
}

pub fn parse_raw_key(raw_key: &str) -> Result<WrapKey, Error> {
    let mut key = ArrayKey::<<WrapKeyType as KeyMeta>::KeySize>::default();
    let key_len = bs58::decode(raw_key)
        .into(key.as_mut())
        .map_err(|_| err_msg!(Input, "Error parsing raw key as base58 value"))?;
    if key_len != key.len() {
        Err(err_msg!(Input, "Incorrect length for encoded raw key"))
    } else {
        Ok(WrapKey::from(WrapKeyType::from_secret_bytes(key.as_ref())?))
    }
}

#[derive(Clone, Debug)]
pub struct WrapKey(pub Option<WrapKeyType>);

impl WrapKey {
    pub const fn empty() -> Self {
        Self(None)
    }

    pub fn random() -> Result<Self, Error> {
        Ok(Self(Some(WrapKeyType::generate()?)))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_none()
    }

    pub fn wrap_data(&self, mut data: SecretBytes) -> Result<SecretBytes, Error> {
        match &self.0 {
            Some(key) => {
                let nonce = WrapKeyNonce::random();
                key.encrypt_in_place(&mut data, nonce.as_ref(), &[])?;
                data.buffer_insert_slice(0, nonce.as_ref())?;
                Ok(data)
            }
            None => Ok(data),
        }
    }

    pub fn unwrap_data(&self, mut ciphertext: SecretBytes) -> Result<SecretBytes, Error> {
        match &self.0 {
            Some(key) => {
                let nonce = WrapKeyNonce::from_slice(&ciphertext.as_ref()[..WrapKeyNonce::SIZE]);
                ciphertext.buffer_remove(0..WrapKeyNonce::SIZE)?;
                key.decrypt_in_place(&mut ciphertext, nonce.as_ref(), &[])?;
                Ok(ciphertext)
            }
            None => Ok(ciphertext),
        }
    }

    pub fn to_passkey(&self) -> PassKey<'static> {
        if let Some(key) = self.0.as_ref() {
            PassKey::from(key.with_secret_bytes(|sk| bs58::encode(sk.unwrap()).into_string()))
        } else {
            PassKey::empty()
        }
    }
}

impl From<WrapKeyType> for WrapKey {
    fn from(data: WrapKeyType) -> Self {
        Self(Some(data))
    }
}

/// Supported methods for generating or referencing a new wrap key
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum WrapKeyMethod {
    // CreateManagedKey(String),
    // ExistingManagedKey(String),
    /// Derive a new wrapping key using a key derivation function
    DeriveKey(KdfMethod),
    /// Wrap using an externally-managed raw key
    RawKey,
    /// No wrapping key in effect
    Unprotected,
}

impl WrapKeyMethod {
    pub(crate) fn parse_uri(uri: &str) -> Result<Self, Error> {
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

    pub(crate) fn resolve(
        &self,
        pass_key: PassKey<'_>,
    ) -> Result<(WrapKey, WrapKeyReference), Error> {
        match self {
            // Self::CreateManagedKey(_mgr_ref) => unimplemented!(),
            // Self::ExistingManagedKey(String) => unimplemented!(),
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
    // ManagedKey(String),
    DeriveKey(KdfMethod, String),
    RawKey,
    Unprotected,
}

impl WrapKeyReference {
    pub fn parse_uri(uri: &str) -> Result<Self, Error> {
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
            // Self::ManagedKey(_keyref) => matches!(method, WrapKeyMethod::CreateManagedKey(..)),
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
            // Self::ManagedKey(keyref) => keyref,
            Self::DeriveKey(method, detail) => method.to_string(Some(detail.as_str())),
            Self::RawKey => PREFIX_RAW.to_string(),
            Self::Unprotected => PREFIX_NONE.to_string(),
        }
    }

    pub fn resolve(&self, pass_key: PassKey<'_>) -> Result<WrapKey, Error> {
        match self {
            // Self::ManagedKey(_key_ref) => unimplemented!(),
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
            .wrap_data((&input[..]).into())
            .expect("Error wrapping input");
        assert_ne!(wrapped, &input[..]);
        let unwrapped = key.unwrap_data(wrapped).expect("Error unwrapping data");
        assert_eq!(unwrapped, &input[..]);
        let key_uri = key_ref.into_uri();
        assert_eq!(key_uri.starts_with("kdf:argon2i:13:mod?salt="), true);
    }

    #[test]
    fn derived_key_unwrap_expected() {
        let input = b"test data";
        let wrapped = SecretBytes::from_slice(
            &[
                194, 156, 102, 253, 229, 11, 48, 184, 160, 119, 218, 30, 169, 188, 244, 223, 235,
                95, 171, 234, 18, 5, 9, 115, 174, 208, 232, 37, 31, 32, 250, 216, 32, 92, 253, 45,
                236,
            ][..],
        );
        let pass = PassKey::from("pass");
        let key_ref = WrapKeyReference::parse_uri("kdf:argon2i:13:mod?salt=MR6B1jrReV2JioaizEaRo6")
            .expect("Error parsing derived key ref");
        let key = key_ref.resolve(pass).expect("Error deriving existing key");
        let unwrapped = key.unwrap_data(wrapped).expect("Error unwrapping data");
        assert_eq!(unwrapped, &input[..]);
    }

    #[test]
    fn derived_key_check_bad_password() {
        let wrapped = SecretBytes::from_slice(
            &[
                194, 156, 102, 253, 229, 11, 48, 184, 160, 119, 218, 30, 169, 188, 244, 223, 235,
                95, 171, 234, 18, 5, 9, 115, 174, 208, 232, 37, 31, 32, 250, 216, 32, 92, 253, 45,
                236,
            ][..],
        );
        let key_ref = WrapKeyReference::parse_uri("kdf:argon2i:13:mod?salt=MR6B1jrReV2JioaizEaRo6")
            .expect("Error parsing derived key ref");
        let check_bad_pass = key_ref
            .resolve("not my pass".into())
            .expect("Error deriving comparison key");
        let unwrapped_err = check_bad_pass.unwrap_data(wrapped);
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
            .wrap_data((&input[..]).into())
            .expect("Error wrapping input");
        assert_ne!(wrapped, &input[..]);

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
            .wrap_data((&input[..]).into())
            .expect("Error wrapping unprotected");
        assert_eq!(wrapped, &input[..]);

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
