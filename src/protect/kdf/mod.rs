use super::store_key::{StoreKey, PREFIX_KDF};
use crate::{
    crypto::{
        buffer::{ArrayKey, HexRepr},
        generic_array::ArrayLength,
    },
    error::Error,
    storage::options::Options,
};
// use crate::keys::wrap::WrapKey;
// use crate::options::Options;

mod argon2;
use self::argon2::{Level as Argon2Level, SaltSize as Argon2Salt};

pub const METHOD_ARGON2I: &'static str = "argon2i";

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum KdfMethod {
    Argon2i(Argon2Level),
}

impl KdfMethod {
    pub fn from_str(method: &str) -> Option<(Self, String)> {
        let mut method_and_detail = method.splitn(3, ':');
        let prefix = method_and_detail.next();
        if prefix != Some(PREFIX_KDF) {
            return None;
        }
        let method = method_and_detail.next().unwrap_or_default();
        let mut level_and_detail = method_and_detail.next().unwrap_or_default().splitn(2, '?');
        let level = level_and_detail.next().unwrap_or_default();
        let detail = level_and_detail.next().unwrap_or_default();
        match method {
            METHOD_ARGON2I => {
                if let Some(level) = Argon2Level::from_str(level) {
                    Some((
                        Self::Argon2i(level),
                        if detail.is_empty() {
                            "".to_owned()
                        } else {
                            format!("?{}", detail)
                        },
                    ))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn to_string(&self, detail: Option<&str>) -> String {
        match self {
            Self::Argon2i(level) => format!(
                "{}:{}:{}{}",
                PREFIX_KDF,
                METHOD_ARGON2I,
                level.as_str(),
                detail.unwrap_or_default()
            ),
        }
    }

    pub fn derive_new_key(&self, password: &str) -> Result<(StoreKey, String), Error> {
        match self {
            Self::Argon2i(level) => {
                let salt = level.generate_salt();
                let key = level.derive_key(password.as_bytes(), salt.as_ref())?;
                let detail = format!("?salt={}", HexRepr(salt.as_ref()));
                Ok((key.into(), detail))
            }
        }
    }

    pub fn derive_key(&self, password: &str, detail: &str) -> Result<StoreKey, Error> {
        match self {
            Self::Argon2i(level) => {
                let salt = parse_salt::<Argon2Salt>(detail)?;
                let key = level.derive_key(password.as_bytes(), salt.as_ref())?;
                Ok(key.into())
            }
        }
    }
}

fn parse_salt<L: ArrayLength<u8>>(detail: &str) -> Result<ArrayKey<L>, Error> {
    let opts = Options::parse_uri(detail)?;
    if let Some(salt) = opts.query.get("salt") {
        let mut salt_arr = ArrayKey::<L>::default();
        if hex::decode_to_slice(salt, salt_arr.as_mut()).is_ok() {
            Ok(salt_arr)
        } else {
            Err(err_msg!(Input, "Invalid salt"))
        }
    } else {
        Err(err_msg!(Input, "Missing salt"))
    }
}
