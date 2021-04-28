//! Supported key algorithms

use core::{
    fmt::{self, Debug, Display, Formatter},
    str::FromStr,
};

use zeroize::Zeroize;

use crate::error::Error;

#[cfg(any(test, feature = "any_key"))]
mod any;
#[cfg(any(test, feature = "any_key"))]
#[cfg_attr(docsrs, doc(cfg(feature = "any_key")))]
pub use any::{AnyKey, AnyKeyCreate};

// pub mod bls;

pub mod aesgcm;

pub mod chacha20;

pub mod ed25519;
pub mod x25519;

pub mod k256;

pub mod p256;

/// Supported key algorithms
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
pub enum KeyAlg {
    /// AES
    Aes(AesTypes),
    /// (X)ChaCha20-Poly1305
    Chacha20(Chacha20Types),
    /// Curve25519 signing key
    Ed25519,
    /// Curve25519 diffie-hellman key exchange key
    X25519,
    /// Elliptic Curve key for signing or key exchange
    EcCurve(EcCurves),
    // /// BLS12-1381 signing key in group G1 or G2
    // BLS12_1381(BlsGroup),
}

impl KeyAlg {
    /// Get a reference to a string representing the `KeyAlg`
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Aes(AesTypes::A128GCM) => "a128gcm",
            Self::Aes(AesTypes::A256GCM) => "a256gcm",
            Self::Chacha20(Chacha20Types::C20P) => "c20p",
            Self::Chacha20(Chacha20Types::XC20P) => "xc20p",
            Self::Ed25519 => "ed25519",
            Self::X25519 => "x25519",
            Self::EcCurve(EcCurves::Secp256k1) => "k256",
            Self::EcCurve(EcCurves::Secp256r1) => "p256",
        }
    }
}

impl AsRef<str> for KeyAlg {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for KeyAlg {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if match_alg(s, &["a128gcm", "aes128gcm"]) {
            return Ok(Self::Aes(AesTypes::A128GCM));
        }
        if match_alg(s, &["a256gcm", "aes256gcm"]) {
            return Ok(Self::Aes(AesTypes::A256GCM));
        }
        if match_alg(s, &["c20p", "chacha20poly1305"]) {
            return Ok(Self::Chacha20(Chacha20Types::C20P));
        }
        if match_alg(s, &["xc20p", "xchacha20poly1305"]) {
            return Ok(Self::Chacha20(Chacha20Types::XC20P));
        }
        if match_alg(s, &["ed25519"]) {
            return Ok(Self::Ed25519);
        }
        if match_alg(s, &["x25519"]) {
            return Ok(Self::X25519);
        }
        if match_alg(s, &["k256", "secp256k1"]) {
            return Ok(Self::EcCurve(EcCurves::Secp256k1));
        }
        if match_alg(s, &["p256", "secp256r1"]) {
            return Ok(Self::EcCurve(EcCurves::Secp256r1));
        }
        Err(err_msg!(Unsupported, "Unknown key algorithm"))
    }
}

struct NormalizeAlg<'a> {
    chars: core::str::Chars<'a>,
}

fn normalize_alg(alg: &str) -> NormalizeAlg<'_> {
    NormalizeAlg { chars: alg.chars() }
}

impl Iterator for NormalizeAlg<'_> {
    type Item = char;
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(c) = self.chars.next() {
            if c != '-' && c != '_' {
                return Some(c.to_ascii_lowercase());
            }
        }
        None
    }
}

fn match_alg(alg: &str, pats: &[&str]) -> bool {
    'pats: for pat in pats {
        for (a, b) in pat.chars().zip(normalize_alg(alg)) {
            if a != b {
                continue 'pats;
            }
        }
        return true;
    }
    false
}

impl Display for KeyAlg {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Supported BLS12-381 groups
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
pub enum BlsGroups {
    /// A key or signature represented by an element from the BLS12-381 G1 group
    G1,
    /// A key or signature represented by an element from the BLS12-381 G2 group
    G2,
}

/// Supported algorithms for AES
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
pub enum AesTypes {
    /// AES 128-bit GCM
    A128GCM,
    /// AES 256-bit GCM
    A256GCM,
}

/// Supported algorithms for (X)ChaCha20-Poly1305
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
pub enum Chacha20Types {
    /// ChaCha20-Poly1305
    C20P,
    /// XChaCha20-Poly1305
    XC20P,
}

/// Supported curves for ECC operations
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
pub enum EcCurves {
    /// NIST P-256 curve
    Secp256r1,
    /// Koblitz 256 curve
    Secp256k1,
}

/// A common trait for accessing the algorithm of a key,
/// used when converting to generic `AnyKey` instances.
pub trait HasKeyAlg: Debug {
    /// Get the corresponding key algorithm.
    fn algorithm(&self) -> KeyAlg;
}
