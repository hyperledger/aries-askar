#[cfg(feature = "alloc")]
use alloc::{boxed::Box, sync::Arc};
#[cfg(feature = "ed25519")]
use core::convert::TryFrom;
use core::{any::TypeId, fmt::Debug};

#[cfg(feature = "aes")]
use super::{
    aes::{A128CbcHs256, A128Gcm, A128Kw, A256CbcHs512, A256Gcm, A256Kw, AesKey},
    AesTypes,
};

#[cfg(feature = "bls")]
use super::{
    bls::{BlsKeyPair, BlsPublicKeyType, G1, G1G2, G2},
    BlsCurves,
};

#[cfg(feature = "chacha")]
use super::{
    chacha20::{Chacha20Key, C20P, XC20P},
    Chacha20Types,
};

#[cfg(feature = "ed25519")]
use super::ed25519::{self, Ed25519KeyPair};
#[cfg(feature = "ed25519")]
use super::x25519::{self, X25519KeyPair};

#[cfg(feature = "k256")]
use super::k256::{self, K256KeyPair};

#[cfg(feature = "p256")]
use super::p256::{self, P256KeyPair};

#[cfg(feature = "p384")]
use super::p384::{self, P384KeyPair};

use super::KeyAlg;
use crate::{
    encrypt::KeyAeadInPlace,
    error::Error,
    jwk::{FromJwk, JwkParts, ToJwk},
    kdf::{DynKeyExchange, KeyDerivation},
    random::KeyMaterial,
    repr::{DynPublicBytes, DynSecretBytes, KeyGen, KeyPublicBytes, KeySecretBytes},
    sign::{KeySign, SignatureType},
};

#[cfg(any(feature = "k256", feature = "p256"))]
use super::EcCurves;

#[cfg(any(feature = "aes", feature = "chacha"))]
use crate::kdf::{FromKeyDerivation, FromKeyExchange};

/// A trait for accessing the algorithm of a key, used when
/// converting to generic `AnyKey` instances.
pub trait AnyKey:
    Debug
    + DynKeyExchange
    + DynSecretBytes
    + DynPublicBytes
    + KeyAeadInPlace
    + KeySign
    + Send
    + Sync
    + ToJwk
    + 'static
{
    /// Get the corresponding key algorithm.
    fn algorithm(&self) -> KeyAlg;

    /// Get a reference to the concrete key instance.
    fn key_ptr(&self) -> *const () {
        // type-erased to make AnyKey object-safe
        self as *const Self as *const ()
    }

    /// Get the TypeId of the concrete key type.
    fn key_type_id(&self) -> TypeId {
        TypeId::of::<Self>()
    }
}

impl dyn AnyKey {
    /// Check the concrete key type
    #[inline]
    pub fn is<K: 'static>(&self) -> bool {
        self.key_type_id() == TypeId::of::<K>()
    }

    /// Convert an AnyKey reference to a concrete key type, panicing on failure
    #[inline]
    pub fn assume<K: AnyKey>(&self) -> &K {
        if let Some(key) = self.downcast_ref() {
            key
        } else {
            panic!("Invalid key conversion");
        }
    }

    /// Try to convert an AnyKey reference to a concrete key type
    #[inline]
    pub fn downcast_ref<K: 'static>(&self) -> Option<&K> {
        if self.is::<K>() {
            Some(unsafe { &*(self.key_ptr() as *const K) })
        } else {
            None
        }
    }
}

/// Create `AnyKey` instances from various sources
pub trait AnyKeyCreate: Sized {
    /// Generate a new key from a key material generator for the given key algorithm.
    fn generate(alg: KeyAlg, rng: impl KeyMaterial) -> Result<Self, Error>;

    /// Generate a new random key for the given key algorithm.
    #[cfg(feature = "getrandom")]
    fn random(alg: KeyAlg) -> Result<Self, Error> {
        Self::generate(alg, crate::random::default_rng())
    }

    /// Generate a new random key for the given key algorithm.
    fn random_det(alg: KeyAlg, seed: &[u8]) -> Result<Self, Error> {
        Self::generate(alg, crate::random::RandomDet::new(seed))
    }

    /// Load a public key from its byte representation
    fn from_public_bytes(alg: KeyAlg, public: &[u8]) -> Result<Self, Error>;

    /// Load a secret key or keypair from its byte representation
    fn from_secret_bytes(alg: KeyAlg, secret: &[u8]) -> Result<Self, Error>;

    /// Convert from a concrete key instance
    fn from_key<K: AnyKey>(key: K) -> Self;

    /// Create a new key instance from a key exchange
    fn from_key_exchange(
        alg: KeyAlg,
        secret: &dyn AnyKey,
        public: &dyn AnyKey,
    ) -> Result<Self, Error>;

    /// Create a new key instance from a key derivation
    fn from_key_derivation(alg: KeyAlg, derive: impl KeyDerivation) -> Result<Self, Error>;

    /// Derive the corresponding key for the provided key algorithm
    fn convert_key(&self, alg: KeyAlg) -> Result<Self, Error>;
}

impl<R: AllocKey> AnyKeyCreate for R {
    fn generate(alg: KeyAlg, rng: impl KeyMaterial) -> Result<Self, Error> {
        generate_any(alg, rng)
    }

    fn from_public_bytes(alg: KeyAlg, public: &[u8]) -> Result<Self, Error> {
        from_public_bytes_any(alg, public)
    }

    fn from_secret_bytes(alg: KeyAlg, secret: &[u8]) -> Result<Self, Error> {
        from_secret_bytes_any(alg, secret)
    }

    #[inline(always)]
    fn from_key<K: AnyKey>(key: K) -> Self {
        R::alloc_key(key)
    }

    fn from_key_exchange(
        alg: KeyAlg,
        secret: &dyn AnyKey,
        public: &dyn AnyKey,
    ) -> Result<Self, Error> {
        from_key_exchange_any(alg, secret, public)
    }

    fn from_key_derivation(alg: KeyAlg, derive: impl KeyDerivation) -> Result<Self, Error> {
        from_key_derivation_any(alg, derive)
    }

    fn convert_key(&self, alg: KeyAlg) -> Result<Self, Error> {
        convert_key_any(self.as_ref(), alg)
    }
}

#[inline]
fn generate_any<R: AllocKey>(
    alg: KeyAlg,
    #[allow(unused)] rng: impl KeyMaterial,
) -> Result<R, Error> {
    match alg {
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A128Gcm) => AesKey::<A128Gcm>::generate(rng).map(R::alloc_key),
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A256Gcm) => AesKey::<A256Gcm>::generate(rng).map(R::alloc_key),
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A128CbcHs256) => {
            AesKey::<A128CbcHs256>::generate(rng).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A256CbcHs512) => {
            AesKey::<A256CbcHs512>::generate(rng).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A128Kw) => AesKey::<A128Kw>::generate(rng).map(R::alloc_key),
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A256Kw) => AesKey::<A256Kw>::generate(rng).map(R::alloc_key),
        #[cfg(feature = "bls")]
        KeyAlg::Bls12_381(BlsCurves::G1) => BlsKeyPair::<G1>::generate(rng).map(R::alloc_key),
        #[cfg(feature = "bls")]
        KeyAlg::Bls12_381(BlsCurves::G2) => BlsKeyPair::<G2>::generate(rng).map(R::alloc_key),
        #[cfg(feature = "bls")]
        KeyAlg::Bls12_381(BlsCurves::G1G2) => BlsKeyPair::<G1G2>::generate(rng).map(R::alloc_key),
        #[cfg(feature = "chacha")]
        KeyAlg::Chacha20(Chacha20Types::C20P) => {
            Chacha20Key::<C20P>::generate(rng).map(R::alloc_key)
        }
        #[cfg(feature = "chacha")]
        KeyAlg::Chacha20(Chacha20Types::XC20P) => {
            Chacha20Key::<XC20P>::generate(rng).map(R::alloc_key)
        }
        #[cfg(feature = "ed25519")]
        KeyAlg::Ed25519 => Ed25519KeyPair::generate(rng).map(R::alloc_key),
        #[cfg(feature = "ed25519")]
        KeyAlg::X25519 => X25519KeyPair::generate(rng).map(R::alloc_key),
        #[cfg(feature = "k256")]
        KeyAlg::EcCurve(EcCurves::Secp256k1) => K256KeyPair::generate(rng).map(R::alloc_key),
        #[cfg(feature = "p256")]
        KeyAlg::EcCurve(EcCurves::Secp256r1) => P256KeyPair::generate(rng).map(R::alloc_key),
        #[cfg(feature = "p384")]
        KeyAlg::EcCurve(EcCurves::Secp384r1) => P384KeyPair::generate(rng).map(R::alloc_key),
        #[allow(unreachable_patterns)]
        _ => {
            return Err(err_msg!(
                Unsupported,
                "Unsupported algorithm for key generation"
            ))
        }
    }
}

#[inline]
fn from_public_bytes_any<R: AllocKey>(
    alg: KeyAlg,
    #[allow(unused)] public: &[u8],
) -> Result<R, Error> {
    match alg {
        #[cfg(feature = "bls")]
        KeyAlg::Bls12_381(BlsCurves::G1) => {
            BlsKeyPair::<G1>::from_public_bytes(public).map(R::alloc_key)
        }
        #[cfg(feature = "bls")]
        KeyAlg::Bls12_381(BlsCurves::G2) => {
            BlsKeyPair::<G2>::from_public_bytes(public).map(R::alloc_key)
        }
        #[cfg(feature = "bls")]
        KeyAlg::Bls12_381(BlsCurves::G1G2) => {
            BlsKeyPair::<G1G2>::from_public_bytes(public).map(R::alloc_key)
        }
        #[cfg(feature = "ed25519")]
        KeyAlg::Ed25519 => Ed25519KeyPair::from_public_bytes(public).map(R::alloc_key),
        #[cfg(feature = "ed25519")]
        KeyAlg::X25519 => X25519KeyPair::from_public_bytes(public).map(R::alloc_key),
        #[cfg(feature = "k256")]
        KeyAlg::EcCurve(EcCurves::Secp256k1) => {
            K256KeyPair::from_public_bytes(public).map(R::alloc_key)
        }
        #[cfg(feature = "p256")]
        KeyAlg::EcCurve(EcCurves::Secp256r1) => {
            P256KeyPair::from_public_bytes(public).map(R::alloc_key)
        }
        #[cfg(feature = "p384")]
        KeyAlg::EcCurve(EcCurves::Secp384r1) => {
            P384KeyPair::from_public_bytes(public).map(R::alloc_key)
        }
        #[allow(unreachable_patterns)]
        _ => {
            return Err(err_msg!(
                Unsupported,
                "Unsupported algorithm for public key import"
            ))
        }
    }
}

#[inline]
fn from_secret_bytes_any<R: AllocKey>(
    alg: KeyAlg,
    #[allow(unused)] secret: &[u8],
) -> Result<R, Error> {
    match alg {
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A128Gcm) => {
            AesKey::<A128Gcm>::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A256Gcm) => {
            AesKey::<A256Gcm>::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A128CbcHs256) => {
            AesKey::<A128CbcHs256>::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A256CbcHs512) => {
            AesKey::<A256CbcHs512>::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A128Kw) => {
            AesKey::<A128Kw>::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A256Kw) => {
            AesKey::<A256Kw>::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[cfg(feature = "bls")]
        KeyAlg::Bls12_381(BlsCurves::G1) => {
            BlsKeyPair::<G1>::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[cfg(feature = "bls")]
        KeyAlg::Bls12_381(BlsCurves::G2) => {
            BlsKeyPair::<G2>::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[cfg(feature = "bls")]
        KeyAlg::Bls12_381(BlsCurves::G1G2) => {
            BlsKeyPair::<G1G2>::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[cfg(feature = "chacha")]
        KeyAlg::Chacha20(Chacha20Types::C20P) => {
            Chacha20Key::<C20P>::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[cfg(feature = "chacha")]
        KeyAlg::Chacha20(Chacha20Types::XC20P) => {
            Chacha20Key::<XC20P>::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[cfg(feature = "ed25519")]
        KeyAlg::Ed25519 => Ed25519KeyPair::from_secret_bytes(secret).map(R::alloc_key),
        #[cfg(feature = "ed25519")]
        KeyAlg::X25519 => X25519KeyPair::from_secret_bytes(secret).map(R::alloc_key),
        #[cfg(feature = "k256")]
        KeyAlg::EcCurve(EcCurves::Secp256k1) => {
            K256KeyPair::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[cfg(feature = "p256")]
        KeyAlg::EcCurve(EcCurves::Secp256r1) => {
            P256KeyPair::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[cfg(feature = "p384")]
        KeyAlg::EcCurve(EcCurves::Secp384r1) => {
            P384KeyPair::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[allow(unreachable_patterns)]
        _ => {
            return Err(err_msg!(
                Unsupported,
                "Unsupported algorithm for secret key import"
            ))
        }
    }
}

#[inline]
fn from_key_exchange_any<R>(
    alg: KeyAlg,
    #[allow(unused)] secret: &dyn AnyKey,
    #[allow(unused)] public: &dyn AnyKey,
) -> Result<R, Error>
where
    R: AllocKey,
{
    match alg {
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A128Gcm) => {
            AesKey::<A128Gcm>::from_key_exchange(secret, public).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A256Gcm) => {
            AesKey::<A256Gcm>::from_key_exchange(secret, public).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A128CbcHs256) => {
            AesKey::<A128CbcHs256>::from_key_exchange(secret, public).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A256CbcHs512) => {
            AesKey::<A256CbcHs512>::from_key_exchange(secret, public).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A128Kw) => {
            AesKey::<A128Kw>::from_key_exchange(secret, public).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A256Kw) => {
            AesKey::<A256Kw>::from_key_exchange(secret, public).map(R::alloc_key)
        }
        #[cfg(feature = "chacha")]
        KeyAlg::Chacha20(Chacha20Types::C20P) => {
            Chacha20Key::<C20P>::from_key_exchange(secret, public).map(R::alloc_key)
        }
        #[cfg(feature = "chacha")]
        KeyAlg::Chacha20(Chacha20Types::XC20P) => {
            Chacha20Key::<XC20P>::from_key_exchange(secret, public).map(R::alloc_key)
        }
        #[allow(unreachable_patterns)]
        _ => {
            return Err(err_msg!(
                Unsupported,
                "Unsupported algorithm for key exchange"
            ));
        }
    }
}

#[inline]
fn from_key_derivation_any<R: AllocKey>(
    alg: KeyAlg,
    #[allow(unused)] derive: impl KeyDerivation,
) -> Result<R, Error> {
    match alg {
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A128Gcm) => {
            AesKey::<A128Gcm>::from_key_derivation(derive).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A256Gcm) => {
            AesKey::<A256Gcm>::from_key_derivation(derive).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A128CbcHs256) => {
            AesKey::<A128CbcHs256>::from_key_derivation(derive).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A256CbcHs512) => {
            AesKey::<A256CbcHs512>::from_key_derivation(derive).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A128Kw) => {
            AesKey::<A128Kw>::from_key_derivation(derive).map(R::alloc_key)
        }
        #[cfg(feature = "aes")]
        KeyAlg::Aes(AesTypes::A256Kw) => {
            AesKey::<A256Kw>::from_key_derivation(derive).map(R::alloc_key)
        }
        #[cfg(feature = "chacha")]
        KeyAlg::Chacha20(Chacha20Types::C20P) => {
            Chacha20Key::<C20P>::from_key_derivation(derive).map(R::alloc_key)
        }
        #[cfg(feature = "chacha")]
        KeyAlg::Chacha20(Chacha20Types::XC20P) => {
            Chacha20Key::<XC20P>::from_key_derivation(derive).map(R::alloc_key)
        }
        #[allow(unreachable_patterns)]
        _ => {
            return Err(err_msg!(
                Unsupported,
                "Unsupported algorithm for key derivation"
            ));
        }
    }
}

#[inline]
fn convert_key_any<R: AllocKey>(key: &dyn AnyKey, alg: KeyAlg) -> Result<R, Error> {
    match (key.algorithm(), alg) {
        #[cfg(feature = "bls")]
        (KeyAlg::Bls12_381(BlsCurves::G1G2), KeyAlg::Bls12_381(BlsCurves::G1)) => Ok(R::alloc_key(
            BlsKeyPair::<G1>::from(key.assume::<BlsKeyPair<G1G2>>()),
        )),
        #[cfg(feature = "bls")]
        (KeyAlg::Bls12_381(BlsCurves::G1G2), KeyAlg::Bls12_381(BlsCurves::G2)) => Ok(R::alloc_key(
            BlsKeyPair::<G2>::from(key.assume::<BlsKeyPair<G1G2>>()),
        )),
        #[cfg(feature = "ed25519")]
        (KeyAlg::Ed25519, KeyAlg::X25519) => Ok(<X25519KeyPair as TryFrom<_>>::try_from(
            key.assume::<Ed25519KeyPair>(),
        )
        .map(R::alloc_key)?),
        #[allow(unreachable_patterns)]
        _ => {
            return Err(err_msg!(
                Unsupported,
                "Unsupported key conversion operation"
            ))
        }
    }
}

impl<R: AllocKey> FromJwk for R {
    fn from_jwk_parts(jwk: JwkParts<'_>) -> Result<Self, Error> {
        from_jwk_any(jwk)
    }
}

#[inline]
fn from_jwk_any<R: AllocKey>(jwk: JwkParts<'_>) -> Result<R, Error> {
    match (jwk.kty, jwk.crv.as_ref()) {
        #[cfg(feature = "ed25519")]
        ("OKP", c) if c == ed25519::JWK_CURVE => {
            Ed25519KeyPair::from_jwk_parts(jwk).map(R::alloc_key)
        }
        #[cfg(feature = "ed25519")]
        ("OKP", c) if c == x25519::JWK_CURVE => {
            X25519KeyPair::from_jwk_parts(jwk).map(R::alloc_key)
        }
        #[cfg(feature = "bls")]
        ("OKP" | "EC", c) if c == G1::JWK_CURVE => {
            BlsKeyPair::<G1>::from_jwk_parts(jwk).map(R::alloc_key)
        }
        #[cfg(feature = "bls")]
        ("OKP" | "EC", c) if c == G2::JWK_CURVE => {
            BlsKeyPair::<G2>::from_jwk_parts(jwk).map(R::alloc_key)
        }
        #[cfg(feature = "bls")]
        ("OKP" | "EC", c) if c == G1G2::JWK_CURVE => {
            BlsKeyPair::<G1G2>::from_jwk_parts(jwk).map(R::alloc_key)
        }
        #[cfg(feature = "k256")]
        ("EC", c) if c == k256::JWK_CURVE => K256KeyPair::from_jwk_parts(jwk).map(R::alloc_key),
        #[cfg(feature = "p256")]
        ("EC", c) if c == p256::JWK_CURVE => P256KeyPair::from_jwk_parts(jwk).map(R::alloc_key),
        #[cfg(feature = "p384")]
        ("EC", c) if c == p384::JWK_CURVE => P384KeyPair::from_jwk_parts(jwk).map(R::alloc_key),
        // FIXME implement symmetric keys?
        _ => Err(err_msg!(Unsupported, "Unsupported JWK for key import")),
    }
}

/// Trait for allocated key containers
pub trait AllocKey: AsRef<dyn AnyKey> {
    /// Construct a new container from a key instance
    fn alloc_key<K: AnyKey>(key: K) -> Self;
}

#[cfg(feature = "alloc")]
impl AllocKey for Box<dyn AnyKey> {
    #[inline(always)]
    fn alloc_key<K: AnyKey>(key: K) -> Self {
        Box::new(key)
    }
}

#[cfg(feature = "alloc")]
impl AllocKey for Arc<dyn AnyKey> {
    #[inline(always)]
    fn alloc_key<K: AnyKey>(key: K) -> Self {
        Arc::new(key)
    }
}

#[macro_export]
/// Implement AnyKey for a key container type
macro_rules! impl_anykey_as_ref {
    ($name:path) => {
        impl $crate::alg::AnyKey for $name {
            #[inline]
            fn algorithm(&self) -> $crate::alg::KeyAlg {
                self.as_ref().algorithm()
            }

            #[inline]
            fn key_ptr(&self) -> *const () {
                self.as_ref().key_ptr()
            }

            #[inline]
            fn key_type_id(&self) -> ::core::any::TypeId {
                self.as_ref().key_type_id()
            }
        }

        impl $crate::repr::DynPublicBytes for $name {
            #[inline]
            fn public_bytes_length(&self) -> Option<usize> {
                self.as_ref().public_bytes_length()
            }

            #[inline]
            fn write_public_bytes(
                &self,
                out: &mut dyn $crate::buffer::WriteBuffer,
            ) -> Result<(), $crate::Error> {
                self.as_ref().write_public_bytes(out)
            }
        }

        impl $crate::repr::DynSecretBytes for $name {
            #[inline]
            fn secret_bytes_length(&self) -> Option<usize> {
                self.as_ref().secret_bytes_length()
            }

            #[inline]
            fn write_secret_bytes(
                &self,
                out: &mut dyn $crate::buffer::WriteBuffer,
            ) -> Result<(), $crate::Error> {
                self.as_ref().write_secret_bytes(out)
            }
        }

        impl $crate::kdf::DynKeyExchange for $name {
            #[inline]
            fn exchange_key_length(&self, public: &dyn AnyKey) -> Option<usize> {
                self.as_ref().exchange_key_length(public)
            }

            #[inline]
            fn write_key_exchange(
                &self,
                public: &dyn $crate::alg::AnyKey,
                out: &mut dyn $crate::buffer::WriteBuffer,
            ) -> Result<(), $crate::Error> {
                self.as_ref().write_key_exchange(public, out)
            }
        }

        impl $crate::encrypt::KeyAeadInPlace for $name {
            #[inline]
            fn aead_padding(&self, msg_len: usize) -> usize {
                self.as_ref().aead_padding(msg_len)
            }

            #[inline]
            fn aead_params(&self) -> $crate::encrypt::KeyAeadParams {
                self.as_ref().aead_params()
            }

            #[inline]
            fn encrypt_in_place(
                &self,
                buffer: &mut dyn $crate::buffer::ResizeBuffer,
                nonce: &[u8],
                aad: &[u8],
            ) -> Result<usize, $crate::Error> {
                self.as_ref().encrypt_in_place(buffer, nonce, aad)
            }

            #[inline]
            fn decrypt_in_place(
                &self,
                buffer: &mut dyn $crate::buffer::ResizeBuffer,
                nonce: &[u8],
                aad: &[u8],
            ) -> Result<(), $crate::Error> {
                self.as_ref().decrypt_in_place(buffer, nonce, aad)
            }
        }

        impl $crate::sign::KeySign for $name {
            #[inline]
            fn signature_length(&self, sig_type: Option<SignatureType>) -> Option<usize> {
                self.as_ref().signature_length(sig_type)
            }

            #[inline]
            fn write_signature(
                &self,
                message: &[u8],
                sig_type: Option<SignatureType>,
                out: &mut dyn $crate::buffer::WriteBuffer,
            ) -> Result<(), $crate::Error> {
                self.as_ref().write_signature(message, sig_type, out)
            }
        }

        impl $crate::sign::KeySigVerify for $name {
            #[inline]
            fn verify_signature(
                &self,
                message: &[u8],
                signature: &[u8],
                sig_type: Option<$crate::sign::SignatureType>,
            ) -> Result<bool, $crate::Error> {
                self.as_ref().verify_signature(message, signature, sig_type)
            }
        }

        impl $crate::jwk::ToJwk for $name {
            #[inline]
            fn encode_jwk(
                &self,
                enc: &mut dyn $crate::jwk::JwkEncoder,
            ) -> Result<(), $crate::Error> {
                self.as_ref().encode_jwk(enc)
            }
        }
    };
}

#[cfg(feature = "alloc")]
impl_anykey_as_ref!(Box<dyn AnyKey>);
#[cfg(feature = "alloc")]
impl_anykey_as_ref!(Arc<dyn AnyKey>);

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    // FIXME - add a custom key type for testing, to allow feature independence

    #[cfg(feature = "ed25519")]
    #[test]
    fn generate_any() {
        let key = Box::<dyn AnyKey>::random(KeyAlg::Ed25519).unwrap();
        assert_eq!(key.algorithm(), KeyAlg::Ed25519);
        assert_eq!(key.key_type_id(), TypeId::of::<Ed25519KeyPair>());
        assert!(key.is::<Ed25519KeyPair>());
        let _ = key.to_jwk_public(None).unwrap();
    }

    #[cfg(all(feature = "aes", feature = "ed25519"))]
    #[test]
    fn key_exchange_any() {
        let alice = Box::<dyn AnyKey>::random(KeyAlg::X25519).unwrap();
        let bob = Box::<dyn AnyKey>::random(KeyAlg::X25519).unwrap();
        let exch_a = alice.key_exchange_bytes(&*bob).unwrap();
        let exch_b = bob.key_exchange_bytes(&*alice).unwrap();
        assert_eq!(exch_a, exch_b);

        let _aes_key =
            Box::<dyn AnyKey>::from_key_exchange(KeyAlg::Aes(AesTypes::A256Gcm), &*alice, &*bob)
                .unwrap();
    }

    #[cfg(feature = "chacha")]
    #[test]
    fn key_encrypt_any() {
        use crate::buffer::SecretBytes;
        let message = b"test message";
        let mut data = SecretBytes::from(&message[..]);

        let key = Box::<dyn AnyKey>::random(KeyAlg::Chacha20(Chacha20Types::XC20P)).unwrap();
        let nonce = [0u8; 24]; // size varies by algorithm
        key.encrypt_in_place(&mut data, &nonce, &[])
            .expect("Error performing encryption");
        assert_ne!(data, &message[..]);
        key.decrypt_in_place(&mut data, &nonce, &[])
            .expect("Error performing decrypytion");
        assert_eq!(data, &message[..]);
    }

    #[cfg(all(feature = "ed25519"))]
    #[test]
    fn key_sign_any() {
        let key = Box::<dyn AnyKey>::random(KeyAlg::Ed25519).unwrap();
        let message = b"test message";
        let sig = key
            .create_signature(message, None)
            .expect("Error performing signing");
        assert!(key
            .verify_signature(message, &sig, None)
            .expect("Error performing signature verification"),);
    }
}
