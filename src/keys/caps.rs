use std::convert::Infallible;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use zeroize::Zeroize;

use super::any::AnyPublicKey;
use crate::error::Error;

/// Supported key algorithms
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
pub enum KeyAlg {
    /// Curve25519 signing key
    ED25519,
    /// Curve25519 diffie-hellman key exchange key
    X25519,
    // /// Elliptic Curve diffie-hellman key exchange key
    // Ecdh(EcCurves),
    // /// Elliptic Curve signing key
    // Ecdsa(EcCurves),
    /// BLS12-1381 signing key in group G1 or G2
    // BLS12_1381(BlsGroup),
    /// Unrecognized algorithm
    Other(String),
}

serde_as_str_impl!(KeyAlg);

impl KeyAlg {
    /// Get a reference to a string representing the `KeyAlg`
    pub fn as_str(&self) -> &str {
        match self {
            Self::ED25519 => "ed25519",
            Self::X25519 => "x25519",
            Self::Other(other) => other.as_str(),
        }
    }
}

impl AsRef<str> for KeyAlg {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for KeyAlg {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "ed25519" => Self::ED25519,
            "x25519" => Self::X25519,
            other => Self::Other(other.to_owned()),
        })
    }
}

impl Display for KeyAlg {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Categories of keys supported by the default KMS
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
pub enum KeyCategory {
    /// A private key or keypair
    PrivateKey,
    /// A public key
    PublicKey,
    /// An unrecognized key category
    Other(String),
}

impl KeyCategory {
    /// Get a reference to a string representing the `KeyCategory`
    pub fn as_str(&self) -> &str {
        match self {
            Self::PrivateKey => "private",
            Self::PublicKey => "public",
            Self::Other(other) => other.as_str(),
        }
    }

    /// Convert the `KeyCategory` into an owned string
    pub fn into_string(self) -> String {
        match self {
            Self::Other(other) => other,
            _ => self.as_str().to_owned(),
        }
    }
}

serde_as_str_impl!(KeyCategory);

impl AsRef<str> for KeyCategory {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for KeyCategory {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "private" => Self::PrivateKey,
            "public" => Self::PublicKey,
            other => Self::Other(other.to_owned()),
        })
    }
}

impl Display for KeyCategory {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub trait KeyCapGetPublic {
    fn key_get_public(&self, alg: Option<KeyAlg>) -> Result<AnyPublicKey, Error>;
}

pub trait KeyCapSign {
    fn key_sign(
        &self,
        data: &[u8],
        sig_type: Option<SignatureType>,
        sig_format: Option<SignatureFormat>,
    ) -> Result<Vec<u8>, Error>;
}

pub trait KeyCapVerify {
    fn key_verify(
        &self,
        data: &[u8],
        signature: &[u8],
        sig_type: Option<SignatureType>,
        sig_format: Option<SignatureFormat>,
    ) -> Result<bool, Error>;
}

pub enum SignatureFormat {
    /// Base58-encoded binary signature
    Base58,
}

pub enum SignatureType {
    // Bls12_1381(BlsGroup),
    /// Standard signature output for ed25519
    Ed25519,
    // Ecdsa(EcdsaMethod),
}

impl SignatureType {
    pub const fn signature_size(&self) -> usize {
        match self {
            // Self::Bls12_1381(BlsGroup::G1) => 48,
            // Self::Bls12_1381(BlsGroup::G2) => 96,
            Self::Ed25519 => 64,
            // Self::Ecdsa(_) => ,
        }
    }
}

// pub enum BlsGroup {
//     /// A key or signature represented by an element from the G1 group
//     G1,
//     /// A key or signature represented by an element from the G2 group
//     G2,
// }

// pub enum EcdsaMethod {
//     /// Sign/verify ECC signatures using SHA2-256
//     Sha256,
//     /// Sign/verify ECC signatures using SHA2-384
//     Sha384,
//     /// Sign/verify ECC signatures using SHA2-512
//     Sha512,
// }

// /// Possibly supported curves for ECC operations
// #[derive(Clone, Copy, Debug)]
// pub enum EcCurves {
//     /// NIST P-256 curve
//     Secp256r1,
//     /// NIST P-384 curve
//     Secp384r1,
//     /// NIST P-512 curve
//     Secp512r1,
//     /// Koblitz 256 curve
//     Secp256k1,
// }
