use crate::{buffer::SecretBytes, error::Error, random::random_secret};

pub use argon2::{Algorithm, Version};

pub const HASH_SIZE: usize = 32;
pub const SALT_SIZE: usize = 16;

pub const PARAMS_INTERACTIVE: Params = Params {
    alg: Algorithm::Argon2i,
    version: Version::V0x13,
    mem_cost: 32768,
    time_cost: 4,
};
pub const PARAMS_MODERATE: Params = Params {
    alg: Algorithm::Argon2i,
    version: Version::V0x13,
    mem_cost: 131072,
    time_cost: 6,
};

pub struct Params {
    alg: Algorithm,
    version: Version,
    mem_cost: u32,
    time_cost: u32,
}

// pub const LEVEL_INTERACTIVE: &'static str = "13:int";
// pub const LEVEL_MODERATE: &'static str = "13:mod";

// #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
// pub enum Level {
//     Interactive,
//     Moderate,
// }

// impl Default for Level {
//     fn default() -> Self {
//         Self::Moderate
//     }
// }

// impl Level {
//     pub fn from_str(level: &str) -> Option<Self> {
//         match level {
//             "int" | LEVEL_INTERACTIVE => Some(Self::Interactive),
//             "mod" | LEVEL_MODERATE => Some(Self::Moderate),
//             "" => Some(Self::default()),
//             _ => None,
//         }
//     }

//     pub fn as_str(&self) -> &'static str {
//         match self {
//             Self::Interactive => LEVEL_INTERACTIVE,
//             Self::Moderate => LEVEL_MODERATE,
//         }
//     }

//     // pub fn derive_key(&self, salt: &[u8], password: &str) -> Result<EncKey<ChaChaEncrypt>> {
//     //     let (mem_cost, time_cost) = match self {
//     //         Self::Interactive => (32768, 4),
//     //         Self::Moderate => (131072, 6),
//     //     };
//     //     derive_key(password, salt, mem_cost, time_cost)
//     // }
// }

pub struct Argon2;

impl Argon2 {
    pub fn derive_key(
        password: &[u8],
        salt: &[u8],
        params: Params,
        output: &mut [u8],
    ) -> Result<(), Error> {
        if salt.len() < SALT_SIZE {
            return Err(err_msg!("invalid salt for argon2i hash"));
        }
        if output.len() > u32::MAX as usize {
            return Err(err_msg!("output length exceeds max for argon2i hash"));
        }
        let context =
            argon2::Argon2::new(None, params.time_cost, params.mem_cost, 1, params.version)
                .map_err(|e| err_msg!("Error creating hasher: {}", e))?;
        context
            .hash_password_into(params.alg, password, salt, &[], output)
            .map_err(|e| err_msg!("Error deriving key: {}", e))
    }
}

// FIXME generate into buffer
pub fn generate_salt() -> SecretBytes {
    random_secret(SALT_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected() {
        let pass = b"my password";
        let salt = b"long enough salt";
        let mut output = [0u8; 32];
        Argon2::derive_key(pass, salt, PARAMS_INTERACTIVE, &mut output).unwrap();
        assert_eq!(
            output,
            hex!("9ef87bcf828c46c0136a0d1d9e391d713f75b327c6dc190455bd36c1bae33259")
        );
    }
}
