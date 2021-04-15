use core::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use zeroize::Zeroize;

use crate::error::Error;

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
    Aes(AesSizes),
    /// (X)ChaCha20-Poly1305
    Chacha20(Chacha20Sizes),
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
    pub fn as_str(&self) -> &str {
        match self {
            Self::Aes(AesSizes::A128GCM) => "a128gcm",
            Self::Aes(AesSizes::A192GCM) => "a192gcm",
            Self::Aes(AesSizes::A256GCM) => "a256gcm",
            Self::Chacha20(Chacha20Sizes::C20P) => "c20p",
            Self::Chacha20(Chacha20Sizes::XC20P) => "xc20p",
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
        Ok(match s {
            "aes128gcm" => Self::Aes(AesSizes::A128GCM),
            "aes192gcm" => Self::Aes(AesSizes::A192GCM),
            "aes256gcm" => Self::Aes(AesSizes::A256GCM),
            "chacha20poly1305" => Self::Chacha20(Chacha20Sizes::C20P),
            "xchacha20poly1305" => Self::Chacha20(Chacha20Sizes::XC20P),
            "c20p" => Self::Chacha20(Chacha20Sizes::C20P),
            "xc20p" => Self::Chacha20(Chacha20Sizes::XC20P),
            "ed25519" => Self::Ed25519,
            "x25519" => Self::X25519,
            "k256" => Self::EcCurve(EcCurves::Secp256k1),
            "p256" => Self::EcCurve(EcCurves::Secp256r1),
            "secp256k1" => Self::EcCurve(EcCurves::Secp256k1),
            "secp256r1" => Self::EcCurve(EcCurves::Secp256r1),
            _ => return Err(err_msg!("Unknown key algorithm: {}", s)),
        })
    }
}

impl Display for KeyAlg {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
pub enum BlsGroups {
    /// A key or signature represented by an element from the BLS12-381 G1 group
    G1,
    /// A key or signature represented by an element from the BLS12-381 G2 group
    G2,
}

/// Supported algorithms for AES
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
pub enum AesSizes {
    /// AES 128-bit GCM
    A128GCM,
    /// AES 192-bit GCM
    A192GCM,
    /// AES 256-bit GCM
    A256GCM,
}

/// Supported algorithms for (X)ChaCha20-Poly1305
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
pub enum Chacha20Sizes {
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
