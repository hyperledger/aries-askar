use alloc::string::{String, ToString};
use core::{
    fmt::{self, Display, Formatter},
    str::FromStr,
};

use zeroize::Zeroize;

use crate::{
    buffer::{SecretBytes, WriteBuffer},
    error::Error,
};

// #[cfg(feature = "any")]
// use crate::any::AnyKey;

/// Generate a new random key.
pub trait KeyGen: Sized {
    fn generate() -> Result<Self, Error>;
}

/// Allows a key to be created uninitialized and populated later,
/// for instance when nested inside another struct.
pub trait KeyGenInPlace {
    fn generate_in_place(&mut self) -> Result<(), Error>;
}

/// Initialize a key from an array of bytes.
pub trait KeySecretBytes: Sized {
    fn from_key_secret_bytes(key: &[u8]) -> Result<Self, Error>;

    fn to_key_secret_buffer<B: WriteBuffer>(&self, out: &mut B) -> Result<(), Error>;

    fn to_key_secret_bytes(&self) -> Result<SecretBytes, Error> {
        let mut buf = SecretBytes::with_capacity(128);
        self.to_key_secret_buffer(&mut buf)?;
        Ok(buf)
    }
}

pub trait KeyCapSign {
    fn key_sign_buffer<B: WriteBuffer>(
        &self,
        data: &[u8],
        sig_type: Option<SignatureType>,
        out: &mut B,
    ) -> Result<(), Error>;

    fn key_sign(&self, data: &[u8], sig_type: Option<SignatureType>) -> Result<SecretBytes, Error> {
        let mut buf = SecretBytes::with_capacity(128);
        self.key_sign_buffer(data, sig_type, &mut buf)?;
        Ok(buf)
    }
}

pub trait KeyCapVerify {
    fn key_verify(
        &self,
        data: &[u8],
        signature: &[u8],
        sig_type: Option<SignatureType>,
    ) -> Result<bool, Error>;
}

/// Supported key algorithms
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
pub enum KeyAlg {
    /// Curve25519 signing key
    Ed25519,
    /// Curve25519 diffie-hellman key exchange key
    X25519,
    /// Elliptic Curve diffie-hellman key exchange key
    Ecdh(EcCurves),
    /// Elliptic Curve signing key
    Ecdsa(EcCurves),
    // /// BLS12-1381 signing key in group G1 or G2
    // BLS12_1381(BlsGroup),
}

serde_as_str_impl!(KeyAlg);

impl KeyAlg {
    /// Get a reference to a string representing the `KeyAlg`
    pub fn as_str(&self) -> &str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::X25519 => "X25519",
            Self::Ecdh(EcCurves::Secp256r1) => "P-256/ecdh",
            Self::Ecdsa(EcCurves::Secp256r1) => "P-256/ecdsa",
            Self::Ecdh(EcCurves::Secp256k1) => "secp256k1/ecdh",
            Self::Ecdsa(EcCurves::Secp256k1) => "secp256k1/ecdsa",
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
            "Ed25519" => Self::Ed25519,
            "X25519" => Self::X25519,
            _ => return Err(err_msg!("Unknown key algorithm: {}", s)),
        })
    }
}

impl Display for KeyAlg {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Categories of keys supported by the default KMS
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
pub enum KeyCategory {
    /// A private key or keypair
    PrivateKey,
    /// A public key
    PublicKey,
}

impl KeyCategory {
    /// Get a reference to a string representing the `KeyCategory`
    pub fn as_str(&self) -> &str {
        match self {
            Self::PrivateKey => "private",
            Self::PublicKey => "public",
        }
    }

    /// Convert the `KeyCategory` into an owned string
    pub fn to_string(&self) -> String {
        self.as_str().to_string()
    }
}

serde_as_str_impl!(KeyCategory);

impl AsRef<str> for KeyCategory {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for KeyCategory {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "private" => Self::PrivateKey,
            "public" => Self::PublicKey,
            _ => return Err(err_msg!("Unknown key category: {}", s)),
        })
    }
}

impl Display for KeyCategory {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignatureFormat {
    /// Base58-encoded binary signature
    Base58,
    /// Base64-encoded binary signature
    Base64,
    /// Base64-URL-encoded binary signature
    Base64Url,
    /// Hex-encoded binary signature
    Hex,
    /// Raw binary signature (method dependent)
    Raw,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignatureType {
    Bls12_1381(BlsGroup),
    /// Standard signature output for ed25519
    EdDSA,
    // Elliptic curve DSA using P-256 and SHA-256
    ES256,
    // Elliptic curve DSA using K-256 and SHA-256
    ES256K,
}

impl SignatureType {
    pub const fn signature_size(&self) -> usize {
        match self {
            Self::Bls12_1381(BlsGroup::G1) => 48,
            Self::Bls12_1381(BlsGroup::G2) => 96,
            Self::EdDSA => 64,
            Self::ES256 => 64,
            Self::ES256K => 64,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
pub enum BlsGroup {
    /// A key or signature represented by an element from the BLS12-381 G1 group
    G1,
    /// A key or signature represented by an element from the BLS12-381 G2 group
    G2,
}

/// Supported curves for ECC operations
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Zeroize)]
pub enum EcCurves {
    /// NIST P-256 curve
    Secp256r1,
    /// Koblitz 256 curve
    Secp256k1,
}
