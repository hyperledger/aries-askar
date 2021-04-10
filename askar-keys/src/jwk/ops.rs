use core::{
    fmt::{self, Debug, Display, Formatter},
    ops::{BitAnd, BitOr},
};

static OPS: &[KeyOps] = &[
    KeyOps::Encrypt,
    KeyOps::Decrypt,
    KeyOps::Sign,
    KeyOps::Verify,
    KeyOps::WrapKey,
    KeyOps::UnwrapKey,
    KeyOps::DeriveKey,
    KeyOps::DeriveBits,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(usize)]
pub enum KeyOps {
    Encrypt = 1 << 0,
    Decrypt = 1 << 1,
    Sign = 1 << 2,
    Verify = 1 << 3,
    WrapKey = 1 << 4,
    UnwrapKey = 1 << 5,
    DeriveKey = 1 << 6,
    DeriveBits = 1 << 7,
}

impl Display for KeyOps {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl KeyOps {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Encrypt => "encrypt",
            Self::Decrypt => "decrypt",
            Self::Sign => "sign",
            Self::Verify => "verify",
            Self::WrapKey => "wrapKey",
            Self::UnwrapKey => "unwrapKey",
            Self::DeriveKey => "deriveKey",
            Self::DeriveBits => "deriveBits",
        }
    }

    pub fn from_str(key: &str) -> Option<Self> {
        match key {
            "sign" => Some(Self::Sign),
            "verify" => Some(Self::Verify),
            "encrypt" => Some(Self::Encrypt),
            "decrypt" => Some(Self::Decrypt),
            "wrapKey" => Some(Self::WrapKey),
            "unwrapKey" => Some(Self::UnwrapKey),
            "deriveKey" => Some(Self::DeriveKey),
            "deriveBits" => Some(Self::DeriveBits),
            _ => None,
        }
    }
}

impl BitOr<Self> for KeyOps {
    type Output = KeyOpsSet;

    fn bitor(self, rhs: Self) -> Self::Output {
        KeyOpsSet {
            value: self as usize | rhs as usize,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct KeyOpsSet {
    value: usize,
}

impl KeyOpsSet {
    pub const fn new() -> Self {
        Self { value: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.value == 0
    }
}

impl Default for KeyOpsSet {
    fn default() -> Self {
        Self::new()
    }
}

impl BitOr<Self> for KeyOpsSet {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        KeyOpsSet {
            value: self.value | rhs.value,
        }
    }
}

impl BitOr<KeyOps> for KeyOpsSet {
    type Output = KeyOpsSet;

    fn bitor(self, rhs: KeyOps) -> Self::Output {
        KeyOpsSet {
            value: self.value | rhs as usize,
        }
    }
}

impl BitAnd<KeyOps> for KeyOpsSet {
    type Output = bool;

    fn bitand(self, rhs: KeyOps) -> Self::Output {
        self.value & rhs as usize != 0
    }
}

impl BitAnd<Self> for KeyOpsSet {
    type Output = bool;

    fn bitand(self, rhs: Self) -> Self::Output {
        self.value & rhs.value != 0
    }
}

impl Debug for KeyOpsSet {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut vals = &mut f.debug_set();
        for op in self {
            vals = vals.entry(&op.as_str());
        }
        vals.finish()
    }
}

impl From<KeyOps> for KeyOpsSet {
    fn from(op: KeyOps) -> Self {
        Self { value: op as usize }
    }
}

impl IntoIterator for &KeyOpsSet {
    type IntoIter = KeyOpsIter;
    type Item = KeyOps;

    fn into_iter(self) -> Self::IntoIter {
        KeyOpsIter {
            index: 0,
            value: *self,
        }
    }
}

pub struct KeyOpsIter {
    index: usize,
    value: KeyOpsSet,
}

impl Iterator for KeyOpsIter {
    type Item = KeyOps;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < OPS.len() {
            let op = OPS[self.index];
            self.index += 1;
            if self.value & op {
                return Some(op);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invariants() {
        assert_eq!(KeyOpsSet::new().is_empty(), true);
        assert_eq!(KeyOpsSet::from(KeyOps::Decrypt).is_empty(), false);
        assert_eq!(KeyOpsSet::new(), KeyOpsSet::new());
        assert_ne!(KeyOpsSet::from(KeyOps::Decrypt), KeyOpsSet::new());
        assert_ne!(KeyOps::Decrypt, KeyOps::Encrypt);
        assert_ne!(
            KeyOpsSet::from(KeyOps::Decrypt),
            KeyOpsSet::from(KeyOps::Encrypt)
        );
        assert_eq!(
            KeyOps::Decrypt | KeyOps::Encrypt,
            KeyOps::Encrypt | KeyOps::Decrypt
        );
    }

    #[test]
    fn debug_format() {
        assert_eq!(
            format!("{:?}", KeyOps::Decrypt | KeyOps::Encrypt),
            "{\"encrypt\", \"decrypt\"}"
        );
    }
}
