#[cfg(not(any(test, feature = "std")))]
use alloc::boxed::Box;
#[cfg(any(test, feature = "std"))]
use std::boxed::Box;

use core::any::Any;

use super::aesgcm::{AesGcmKey, A128, A256};
use super::chacha20::{Chacha20Key, C20P, XC20P};
use super::ed25519::{self, Ed25519KeyPair};
use super::k256::{self, K256KeyPair};
use super::p256::{self, P256KeyPair};
use super::x25519::{self, X25519KeyPair};
use super::{AesTypes, Chacha20Types, EcCurves, KeyAlg};
use crate::{
    buffer::WriteBuffer,
    error::Error,
    jwk::{FromJwk, JwkEncoder, JwkParts, ToJwk},
    repr::KeyMeta,
    sign::{KeySigVerify, KeySign, SignatureType},
};

type BoxKey = Box<dyn Any + Send + 'static>;

#[derive(Debug)]
pub struct AnyKey {
    pub(crate) alg: KeyAlg,
    pub(crate) inst: BoxKey,
}

impl AnyKey {
    pub fn key_alg(&self) -> KeyAlg {
        self.alg
    }

    pub fn downcast<T: 'static>(self) -> Result<Box<T>, Self> {
        match BoxKey::downcast(self.inst) {
            Ok(key) => Ok(key),
            Err(inst) => Err(Self {
                alg: self.alg,
                inst,
            }),
        }
    }

    pub fn downcast_ref<T: 'static>(&self) -> Option<&T> {
        self.inst.downcast_ref()
    }

    pub fn from_key<K>(key: K) -> Self
    where
        K: KeyMeta + Send + 'static,
    {
        Self {
            alg: K::ALG,
            inst: Box::new(key) as BoxKey,
        }
    }

    pub fn from_boxed_key<K>(key: Box<K>) -> Self
    where
        K: KeyMeta + Send + 'static,
    {
        Self {
            alg: K::ALG,
            inst: Box::new(key) as BoxKey,
        }
    }
}

fn assume<'r, T: 'static>(inst: &'r (dyn Any + Send + 'static)) -> &'r T {
    if let Some(t) = inst.downcast_ref::<T>() {
        t
    } else {
        panic!("Invalid any key state");
    }
}

impl FromJwk for AnyKey {
    fn from_jwk_parts(jwk: JwkParts<'_>) -> Result<Self, Error> {
        let (alg, inst) = match (jwk.kty, jwk.crv.as_ref()) {
            ("EC", c) if c == k256::JWK_CURVE => (
                KeyAlg::EcCurve(EcCurves::Secp256k1),
                Box::new(K256KeyPair::from_jwk_parts(jwk)?) as BoxKey,
            ),
            ("EC", c) if c == p256::JWK_CURVE => (
                KeyAlg::EcCurve(EcCurves::Secp256r1),
                Box::new(P256KeyPair::from_jwk_parts(jwk)?) as BoxKey,
            ),
            ("OKP", c) if c == ed25519::JWK_CURVE => (
                KeyAlg::Ed25519,
                Box::new(Ed25519KeyPair::from_jwk_parts(jwk)?) as BoxKey,
            ),
            ("OKP", c) if c == x25519::JWK_CURVE => (
                KeyAlg::X25519,
                Box::new(X25519KeyPair::from_jwk_parts(jwk)?) as BoxKey,
            ),
            // "oct"
            _ => return Err(err_msg!(Unsupported, "Unsupported JWK for key import")),
        };
        Ok(Self { alg, inst })
    }
}

impl ToJwk for AnyKey {
    fn to_jwk_encoder(&self, enc: &mut JwkEncoder<'_>) -> Result<(), Error> {
        let key: &dyn ToJwk = match self.alg {
            KeyAlg::Aes(AesTypes::A128GCM) => assume::<AesGcmKey<A128>>(&self.inst),
            KeyAlg::Aes(AesTypes::A256GCM) => assume::<AesGcmKey<A256>>(&self.inst),
            KeyAlg::Chacha20(Chacha20Types::C20P) => assume::<Chacha20Key<C20P>>(&self.inst),
            KeyAlg::Chacha20(Chacha20Types::XC20P) => assume::<Chacha20Key<XC20P>>(&self.inst),
            KeyAlg::Ed25519 => assume::<Ed25519KeyPair>(&self.inst),
            KeyAlg::X25519 => assume::<X25519KeyPair>(&self.inst),
            KeyAlg::EcCurve(EcCurves::Secp256k1) => assume::<K256KeyPair>(&self.inst),
            KeyAlg::EcCurve(EcCurves::Secp256r1) => assume::<P256KeyPair>(&self.inst),
            #[allow(unreachable_patterns)]
            _ => {
                return Err(err_msg!(
                    Unsupported,
                    "JWK export is not supported for this key type"
                ))
            }
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
        let key: &dyn KeySign = match self.alg {
            KeyAlg::Ed25519 => assume::<Ed25519KeyPair>(&self.inst),
            KeyAlg::EcCurve(EcCurves::Secp256k1) => assume::<K256KeyPair>(&self.inst),
            KeyAlg::EcCurve(EcCurves::Secp256r1) => assume::<P256KeyPair>(&self.inst),
            _ => {
                return Err(err_msg!(
                    Unsupported,
                    "Signing is not supported for this key type"
                ))
            }
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
        let key: &dyn KeySigVerify = match self.alg {
            KeyAlg::Ed25519 => assume::<Ed25519KeyPair>(&self.inst),
            KeyAlg::EcCurve(EcCurves::Secp256k1) => assume::<K256KeyPair>(&self.inst),
            KeyAlg::EcCurve(EcCurves::Secp256r1) => assume::<P256KeyPair>(&self.inst),
            _ => {
                return Err(err_msg!(
                    Unsupported,
                    "Signature verification not supported for this key type"
                ))
            }
        };
        key.verify_signature(message, signature, sig_type)
    }
}
