use ursa::encryption::random_vec;

use crate::error::Result;

pub const LEVEL_INTERACTIVE: &'static str = "13:int";
pub const LEVEL_MODERATE: &'static str = "13:mod";

pub const HASH_SIZE: usize = 32;
pub const SALT_SIZE: usize = 16;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Level {
    Interactive,
    Moderate,
}

impl Default for Level {
    fn default() -> Self {
        Self::Moderate
    }
}

impl Level {
    pub fn from_str(level: &str) -> Option<Self> {
        match level {
            "int" | LEVEL_INTERACTIVE => Some(Self::Interactive),
            "mod" | LEVEL_MODERATE => Some(Self::Moderate),
            "" => Some(Self::default()),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Interactive => LEVEL_INTERACTIVE,
            Self::Moderate => LEVEL_MODERATE,
        }
    }

    pub fn derive_key(&self, salt: &[u8], password: &str) -> Result<Vec<u8>> {
        let (mem_cost, time_cost) = match self {
            Self::Interactive => (32768, 4),
            Self::Moderate => (131072, 6),
        };
        derive_key(password, salt, mem_cost, time_cost)
    }
}

fn derive_key(password: &str, salt: &[u8], mem_cost: u32, time_cost: u32) -> Result<Vec<u8>> {
    if salt.len() < SALT_SIZE {
        return Err(err_msg!(Encryption, "Invalid salt for argon2i hash"));
    }
    let config = argon2::Config {
        variant: argon2::Variant::Argon2i,
        version: argon2::Version::Version13,
        mem_cost,
        time_cost,
        lanes: 1,
        thread_mode: argon2::ThreadMode::Sequential,
        secret: &[],
        ad: &[],
        hash_length: HASH_SIZE as u32,
    };
    argon2::hash_raw(password.as_bytes(), &salt[..SALT_SIZE], &config)
        .map_err(|e| err_msg!(Encryption, "Error deriving key: {}", e))
}

pub fn generate_salt() -> Vec<u8> {
    random_vec(SALT_SIZE).unwrap()
}
