use indy_utils::base58;

use super::wrap::PREFIX_KDF;
use crate::error::Result;
use crate::keys::wrap::WrapKey;
use crate::options::Options;

pub mod argon2;
use self::argon2::{generate_salt, Level as Argon2Level, SALT_SIZE};

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

    pub fn derive_new_key(&self, password: &str) -> Result<(WrapKey, String)> {
        match self {
            Self::Argon2i(level) => {
                let salt = generate_salt();
                let key = level.derive_key(&salt, password)?;
                let detail = format!("?salt={}", base58::encode(&salt));
                Ok((WrapKey::from_slice(&key), detail))
            }
        }
    }

    pub fn derive_key(&self, password: &str, detail: &str) -> Result<WrapKey> {
        match self {
            Self::Argon2i(level) => {
                let salt = parse_salt(detail)?;
                let key = level.derive_key(&salt, password)?;
                Ok(WrapKey::from_slice(&key))
            }
        }
    }
}

fn parse_salt(detail: &str) -> Result<Vec<u8>> {
    let opts = Options::parse_uri(detail)?;
    if let Some(salt) = opts.query.get("salt") {
        if let Ok(salt) = base58::decode(salt) {
            if salt.len() >= SALT_SIZE {
                Ok(salt)
            } else {
                Err(err_msg!("Invalid salt length"))
            }
        } else {
            Err(err_msg!("Invalid salt"))
        }
    } else {
        Err(err_msg!("Missing salt"))
    }
}
