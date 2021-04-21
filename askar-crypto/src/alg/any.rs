use alloc::{boxed::Box, sync::Arc};
use core::{
    any::{Any, TypeId},
    convert::TryFrom,
    fmt::Debug,
};

use super::aesgcm::{AesGcmKey, A128, A256};
use super::chacha20::{Chacha20Key, C20P, XC20P};
use super::ed25519::{self, Ed25519KeyPair};
use super::k256::{self, K256KeyPair};
use super::p256::{self, P256KeyPair};
use super::x25519::{self, X25519KeyPair};
use super::{AesTypes, Chacha20Types, EcCurves, HasKeyAlg, KeyAlg};
use crate::{
    buffer::{ResizeBuffer, WriteBuffer},
    encrypt::{KeyAeadInPlace, KeyAeadParams},
    error::Error,
    jwk::{FromJwk, JwkEncoder, JwkParts, ToJwk},
    kdf::{FromKeyDerivation, FromKeyExchange, KeyDerivation, KeyExchange},
    repr::{KeyGen, KeyPublicBytes, KeySecretBytes},
    sign::{KeySigVerify, KeySign, SignatureType},
};

#[derive(Debug)]
pub struct KeyT<T: KeyAsAny + Send + Sync + ?Sized>(T);

pub type AnyKey = KeyT<dyn KeyAsAny + Send + Sync>;

impl AnyKey {
    pub fn algorithm(&self) -> KeyAlg {
        self.0.algorithm()
    }

    fn assume<K: KeyAsAny>(&self) -> &K {
        self.downcast_ref().expect("Error assuming key type")
    }

    #[inline]
    pub fn downcast_ref<K: KeyAsAny>(&self) -> Option<&K> {
        self.0.as_any().downcast_ref()
    }

    #[inline]
    fn key_type_id(&self) -> TypeId {
        self.0.as_any().type_id()
    }
}

// key instances are immutable
#[cfg(feature = "std")]
impl std::panic::UnwindSafe for AnyKey {}
#[cfg(feature = "std")]
impl std::panic::RefUnwindSafe for AnyKey {}

pub trait AnyKeyCreate: Sized {
    fn generate(alg: KeyAlg) -> Result<Self, Error>;

    fn from_public_bytes(alg: KeyAlg, public: &[u8]) -> Result<Self, Error>;

    fn from_secret_bytes(alg: KeyAlg, secret: &[u8]) -> Result<Self, Error>;

    fn from_key<K: HasKeyAlg + Send + Sync + 'static>(key: K) -> Self;

    fn from_key_exchange<Sk, Pk>(alg: KeyAlg, secret: &Sk, public: &Pk) -> Result<Self, Error>
    where
        Sk: KeyExchange<Pk> + ?Sized,
        Pk: ?Sized;

    fn from_key_derivation(alg: KeyAlg, derive: impl KeyDerivation) -> Result<Self, Error>;

    fn convert_key(&self, alg: KeyAlg) -> Result<Self, Error>;
}

impl AnyKeyCreate for Box<AnyKey> {
    fn generate(alg: KeyAlg) -> Result<Self, Error> {
        generate_any(alg)
    }

    fn from_public_bytes(alg: KeyAlg, public: &[u8]) -> Result<Self, Error> {
        from_public_any(alg, public)
    }

    fn from_secret_bytes(alg: KeyAlg, secret: &[u8]) -> Result<Self, Error> {
        from_secret_any(alg, secret)
    }

    #[inline(always)]
    fn from_key<K: HasKeyAlg + Send + Sync + 'static>(key: K) -> Self {
        Box::new(KeyT(key))
    }

    fn from_key_exchange<Sk, Pk>(alg: KeyAlg, secret: &Sk, public: &Pk) -> Result<Self, Error>
    where
        Sk: KeyExchange<Pk> + ?Sized,
        Pk: ?Sized,
    {
        from_key_exchange_any(alg, secret, public)
    }

    fn from_key_derivation(alg: KeyAlg, derive: impl KeyDerivation) -> Result<Self, Error> {
        from_key_derivation_any(alg, derive)
    }

    fn convert_key(&self, alg: KeyAlg) -> Result<Self, Error> {
        convert_key_any(self, alg)
    }
}

impl AnyKeyCreate for Arc<AnyKey> {
    fn generate(alg: KeyAlg) -> Result<Self, Error> {
        generate_any(alg)
    }

    fn from_public_bytes(alg: KeyAlg, public: &[u8]) -> Result<Self, Error> {
        from_public_any(alg, public)
    }

    fn from_secret_bytes(alg: KeyAlg, secret: &[u8]) -> Result<Self, Error> {
        from_secret_any(alg, secret)
    }

    #[inline(always)]
    fn from_key<K: HasKeyAlg + Send + Sync + 'static>(key: K) -> Self {
        Arc::new(KeyT(key))
    }

    fn from_key_exchange<Sk, Pk>(alg: KeyAlg, secret: &Sk, public: &Pk) -> Result<Self, Error>
    where
        Sk: KeyExchange<Pk> + ?Sized,
        Pk: ?Sized,
    {
        from_key_exchange_any(alg, secret, public)
    }

    fn from_key_derivation(alg: KeyAlg, derive: impl KeyDerivation) -> Result<Self, Error> {
        from_key_derivation_any(alg, derive)
    }

    fn convert_key(&self, alg: KeyAlg) -> Result<Self, Error> {
        convert_key_any(self, alg)
    }
}

#[inline]
fn generate_any<R: AllocKey>(alg: KeyAlg) -> Result<R, Error> {
    match alg {
        KeyAlg::Aes(AesTypes::A128GCM) => AesGcmKey::<A128>::generate().map(R::alloc_key),
        KeyAlg::Aes(AesTypes::A256GCM) => AesGcmKey::<A256>::generate().map(R::alloc_key),
        KeyAlg::Chacha20(Chacha20Types::C20P) => Chacha20Key::<C20P>::generate().map(R::alloc_key),
        KeyAlg::Chacha20(Chacha20Types::XC20P) => {
            Chacha20Key::<XC20P>::generate().map(R::alloc_key)
        }
        KeyAlg::Ed25519 => Ed25519KeyPair::generate().map(R::alloc_key),
        KeyAlg::X25519 => X25519KeyPair::generate().map(R::alloc_key),
        KeyAlg::EcCurve(EcCurves::Secp256k1) => K256KeyPair::generate().map(R::alloc_key),
        KeyAlg::EcCurve(EcCurves::Secp256r1) => P256KeyPair::generate().map(R::alloc_key),
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
fn from_public_any<R: AllocKey>(alg: KeyAlg, public: &[u8]) -> Result<R, Error> {
    match alg {
        KeyAlg::Ed25519 => Ed25519KeyPair::from_public_bytes(public).map(R::alloc_key),
        KeyAlg::X25519 => X25519KeyPair::from_public_bytes(public).map(R::alloc_key),
        KeyAlg::EcCurve(EcCurves::Secp256k1) => {
            K256KeyPair::from_public_bytes(public).map(R::alloc_key)
        }
        KeyAlg::EcCurve(EcCurves::Secp256r1) => {
            P256KeyPair::from_public_bytes(public).map(R::alloc_key)
        }
        #[allow(unreachable_patterns)]
        _ => {
            return Err(err_msg!(
                Unsupported,
                "Unsupported algorithm for key import"
            ))
        }
    }
}

#[inline]
fn from_secret_any<R: AllocKey>(alg: KeyAlg, secret: &[u8]) -> Result<R, Error> {
    match alg {
        KeyAlg::Aes(AesTypes::A128GCM) => {
            AesGcmKey::<A128>::from_secret_bytes(secret).map(R::alloc_key)
        }
        KeyAlg::Aes(AesTypes::A256GCM) => {
            AesGcmKey::<A256>::from_secret_bytes(secret).map(R::alloc_key)
        }
        KeyAlg::Chacha20(Chacha20Types::C20P) => {
            Chacha20Key::<C20P>::from_secret_bytes(secret).map(R::alloc_key)
        }
        KeyAlg::Chacha20(Chacha20Types::XC20P) => {
            Chacha20Key::<XC20P>::from_secret_bytes(secret).map(R::alloc_key)
        }
        KeyAlg::Ed25519 => Ed25519KeyPair::from_secret_bytes(secret).map(R::alloc_key),
        KeyAlg::X25519 => X25519KeyPair::from_secret_bytes(secret).map(R::alloc_key),
        KeyAlg::EcCurve(EcCurves::Secp256k1) => {
            K256KeyPair::from_secret_bytes(secret).map(R::alloc_key)
        }
        KeyAlg::EcCurve(EcCurves::Secp256r1) => {
            P256KeyPair::from_secret_bytes(secret).map(R::alloc_key)
        }
        #[allow(unreachable_patterns)]
        _ => {
            return Err(err_msg!(
                Unsupported,
                "Unsupported algorithm for key import"
            ))
        }
    }
}

#[inline]
fn from_key_exchange_any<R, Sk, Pk>(alg: KeyAlg, secret: &Sk, public: &Pk) -> Result<R, Error>
where
    R: AllocKey,
    Sk: KeyExchange<Pk> + ?Sized,
    Pk: ?Sized,
{
    match alg {
        KeyAlg::Aes(AesTypes::A128GCM) => {
            AesGcmKey::<A128>::from_key_exchange(secret, public).map(R::alloc_key)
        }
        KeyAlg::Aes(AesTypes::A256GCM) => {
            AesGcmKey::<A256>::from_key_exchange(secret, public).map(R::alloc_key)
        }
        KeyAlg::Chacha20(Chacha20Types::C20P) => {
            Chacha20Key::<C20P>::from_key_exchange(secret, public).map(R::alloc_key)
        }
        KeyAlg::Chacha20(Chacha20Types::XC20P) => {
            Chacha20Key::<XC20P>::from_key_exchange(secret, public).map(R::alloc_key)
        }
        #[allow(unreachable_patterns)]
        _ => {
            return Err(err_msg!(
                Unsupported,
                "Unsupported algorithm for key import"
            ))
        }
    }
}

#[inline]
fn from_key_derivation_any<R: AllocKey>(
    alg: KeyAlg,
    derive: impl KeyDerivation,
) -> Result<R, Error> {
    match alg {
        KeyAlg::Aes(AesTypes::A128GCM) => {
            AesGcmKey::<A128>::from_key_derivation(derive).map(R::alloc_key)
        }
        KeyAlg::Aes(AesTypes::A256GCM) => {
            AesGcmKey::<A256>::from_key_derivation(derive).map(R::alloc_key)
        }
        KeyAlg::Chacha20(Chacha20Types::C20P) => {
            Chacha20Key::<C20P>::from_key_derivation(derive).map(R::alloc_key)
        }
        KeyAlg::Chacha20(Chacha20Types::XC20P) => {
            Chacha20Key::<XC20P>::from_key_derivation(derive).map(R::alloc_key)
        }
        #[allow(unreachable_patterns)]
        _ => {
            return Err(err_msg!(
                Unsupported,
                "Unsupported algorithm for key import"
            ))
        }
    }
}

#[inline]
fn convert_key_any<R: AllocKey>(key: &AnyKey, alg: KeyAlg) -> Result<R, Error> {
    match (key.algorithm(), alg) {
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

impl KeyExchange for AnyKey {
    fn key_exchange_buffer(&self, other: &AnyKey, out: &mut dyn WriteBuffer) -> Result<(), Error> {
        match self.key_type_id() {
            s if s != other.key_type_id() => Err(err_msg!(Unsupported, "Unsupported key exchange")),
            s if s == TypeId::of::<X25519KeyPair>() => Ok(self
                .assume::<X25519KeyPair>()
                .key_exchange_buffer(other.assume::<X25519KeyPair>(), out)?),
            s if s == TypeId::of::<K256KeyPair>() => Ok(self
                .assume::<K256KeyPair>()
                .key_exchange_buffer(other.assume::<K256KeyPair>(), out)?),
            s if s == TypeId::of::<P256KeyPair>() => Ok(self
                .assume::<P256KeyPair>()
                .key_exchange_buffer(other.assume::<P256KeyPair>(), out)?),
            #[allow(unreachable_patterns)]
            _ => return Err(err_msg!(Unsupported, "Unsupported key exchange")),
        }
    }
}

impl FromJwk for Box<AnyKey> {
    fn from_jwk_parts(jwk: JwkParts<'_>) -> Result<Self, Error> {
        from_jwk_any(jwk)
    }
}

impl FromJwk for Arc<AnyKey> {
    fn from_jwk_parts(jwk: JwkParts<'_>) -> Result<Self, Error> {
        from_jwk_any(jwk)
    }
}

#[inline]
fn from_jwk_any<R: AllocKey>(jwk: JwkParts<'_>) -> Result<R, Error> {
    match (jwk.kty, jwk.crv.as_ref()) {
        ("OKP", c) if c == ed25519::JWK_CURVE => {
            Ed25519KeyPair::from_jwk_parts(jwk).map(R::alloc_key)
        }
        ("OKP", c) if c == x25519::JWK_CURVE => {
            X25519KeyPair::from_jwk_parts(jwk).map(R::alloc_key)
        }
        ("EC", c) if c == k256::JWK_CURVE => K256KeyPair::from_jwk_parts(jwk).map(R::alloc_key),
        ("EC", c) if c == p256::JWK_CURVE => P256KeyPair::from_jwk_parts(jwk).map(R::alloc_key),
        // "oct"
        _ => Err(err_msg!(Unsupported, "Unsupported JWK for key import")),
    }
}

macro_rules! match_key_types {
    ($slf:expr, $( $t:ty ),+; $errmsg:expr) => {
        match $slf.key_type_id() {
            $(
                t if t == TypeId::of::<$t>() => $slf.assume::<$t>(),
            )+
            #[allow(unreachable_patterns)]
            _ => {
                return Err(err_msg!(
                    Unsupported,
                    $errmsg
                ))
            }
        }
    };
}

impl AnyKey {
    fn key_as_aead(&self) -> Result<&dyn KeyAeadInPlace, Error> {
        Ok(match_key_types! {
            self,
            AesGcmKey<A128>,
            AesGcmKey<A256>,
            Chacha20Key<C20P>,
            Chacha20Key<XC20P>;
            "AEAD is not supported for this key type"
        })
    }
}

impl KeyAeadInPlace for AnyKey {
    fn encrypt_in_place(
        &self,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(), Error> {
        self.key_as_aead()?.encrypt_in_place(buffer, nonce, aad)
    }

    fn decrypt_in_place(
        &self,
        buffer: &mut dyn ResizeBuffer,
        nonce: &[u8],
        aad: &[u8],
    ) -> Result<(), Error> {
        self.key_as_aead()?.decrypt_in_place(buffer, nonce, aad)
    }

    fn aead_params(&self) -> KeyAeadParams {
        if let Ok(key) = self.key_as_aead() {
            key.aead_params()
        } else {
            KeyAeadParams::default()
        }
    }
}

impl ToJwk for AnyKey {
    fn to_jwk_encoder(&self, enc: &mut JwkEncoder<'_>) -> Result<(), Error> {
        let key: &dyn ToJwk = match_key_types! {
            self,
            AesGcmKey<A128>,
            AesGcmKey<A256>,
            Chacha20Key<C20P>,
            Chacha20Key<XC20P>,
            Ed25519KeyPair,
            X25519KeyPair,
            K256KeyPair,
            P256KeyPair;
            "JWK export is not supported for this key type"
        };
        key.to_jwk_encoder(enc)
    }
}

impl KeySign for AnyKey {
    fn write_signature(
        &self,
        message: &[u8],
        sig_type: Option<SignatureType>,
        out: &mut dyn WriteBuffer,
    ) -> Result<(), Error> {
        let key: &dyn KeySign = match_key_types! {
            self,
            Ed25519KeyPair,
            K256KeyPair,
            P256KeyPair;
            "Signing is not supported for this key type"
        };
        key.write_signature(message, sig_type, out)
    }
}

impl KeySigVerify for AnyKey {
    fn verify_signature(
        &self,
        message: &[u8],
        signature: &[u8],
        sig_type: Option<SignatureType>,
    ) -> Result<bool, Error> {
        let key: &dyn KeySigVerify = match_key_types! {
            self,
            Ed25519KeyPair,
            K256KeyPair,
            P256KeyPair;
            "Signature verification is not supported for this key type"
        };
        key.verify_signature(message, signature, sig_type)
    }
}

// may want to implement in-place initialization to avoid copies
trait AllocKey {
    fn alloc_key<K: KeyAsAny + Send + Sync>(key: K) -> Self;
}

impl AllocKey for Arc<AnyKey> {
    #[inline(always)]
    fn alloc_key<K: KeyAsAny + Send + Sync>(key: K) -> Self {
        Self::from_key(key)
    }
}

impl AllocKey for Box<AnyKey> {
    #[inline(always)]
    fn alloc_key<K: KeyAsAny + Send + Sync>(key: K) -> Self {
        Self::from_key(key)
    }
}

pub trait KeyAsAny: HasKeyAlg + 'static {
    fn as_any(&self) -> &dyn Any;
}

// implement for all concrete key types
impl<K: HasKeyAlg + Sized + 'static> KeyAsAny for K {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIXME - add a custom key type for testing, to allow feature independence

    #[test]
    fn ed25519_as_any() {
        let key = Box::<AnyKey>::generate(KeyAlg::Ed25519).unwrap();
        assert_eq!(key.algorithm(), KeyAlg::Ed25519);
        assert_eq!(key.key_type_id(), TypeId::of::<Ed25519KeyPair>());
        let _ = key.to_jwk_public().unwrap();
    }

    #[test]
    fn key_exchange_any() {
        let alice = Box::<AnyKey>::generate(KeyAlg::X25519).unwrap();
        let bob = Box::<AnyKey>::generate(KeyAlg::X25519).unwrap();
        let exch_a = alice.key_exchange_bytes(&bob).unwrap();
        let exch_b = bob.key_exchange_bytes(&alice).unwrap();
        assert_eq!(exch_a, exch_b);

        let _aes_key =
            Box::<AnyKey>::from_key_exchange(KeyAlg::Aes(AesTypes::A256GCM), &*alice, &*bob)
                .unwrap();
    }

    #[test]
    fn key_encrypt_any() {
        use crate::buffer::SecretBytes;
        let message = b"test message";
        let mut data = SecretBytes::from(&message[..]);

        let key = Box::<AnyKey>::generate(KeyAlg::Chacha20(Chacha20Types::XC20P)).unwrap();
        let nonce = [0u8; 24]; // size varies by algorithm
        key.encrypt_in_place(&mut data, &nonce, &[]).unwrap();
        assert_ne!(data, &message[..]);
        key.decrypt_in_place(&mut data, &nonce, &[]).unwrap();
        assert_eq!(data, &message[..]);
    }
}
