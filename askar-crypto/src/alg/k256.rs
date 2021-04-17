use core::convert::{TryFrom, TryInto};

use k256::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    elliptic_curve::{ecdh::diffie_hellman, sec1::Coordinates, Curve},
    EncodedPoint, PublicKey, SecretKey,
};

use crate::{
    buffer::{ArrayKey, WriteBuffer},
    error::Error,
    generic_array::typenum::{U32, U33, U65},
    jwk::{FromJwk, JwkEncoder, JwkParts, ToJwk},
    kdf::KeyExchange,
    random::with_rng,
    repr::{KeyGen, KeyMeta, KeyPublicBytes, KeySecretBytes, KeypairBytes, KeypairMeta},
    sign::{KeySigVerify, KeySign, SignatureType},
};

pub const ES256K_SIGNATURE_LENGTH: usize = 64;

pub const PUBLIC_KEY_LENGTH: usize = 33; // compressed size
pub const SECRET_KEY_LENGTH: usize = 32;
pub const KEYPAIR_LENGTH: usize = SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH;

pub static JWK_KEY_TYPE: &'static str = "EC";
pub static JWK_CURVE: &'static str = "secp256k1";

type FieldSize = <k256::Secp256k1 as Curve>::FieldSize;

#[derive(Clone, Debug)]
pub struct K256KeyPair {
    // SECURITY: SecretKey zeroizes on drop
    secret: Option<SecretKey>,
    public: PublicKey,
}

impl K256KeyPair {
    #[inline]
    pub(crate) fn from_secret_key(sk: SecretKey) -> Self {
        let pk = sk.public_key();
        Self {
            secret: Some(sk),
            public: pk,
        }
    }

    pub(crate) fn to_signing_key(&self) -> Option<SigningKey> {
        self.secret.as_ref().map(SigningKey::from)
    }

    pub fn sign(&self, message: &[u8]) -> Option<[u8; ES256K_SIGNATURE_LENGTH]> {
        if let Some(skey) = self.to_signing_key() {
            let sig: Signature = skey.sign(message);
            let sigb: [u8; 64] = sig.as_ref().try_into().unwrap();
            Some(sigb)
        } else {
            None
        }
    }

    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        if let Ok(sig) = Signature::try_from(signature) {
            let vk = VerifyingKey::from(self.public.as_affine());
            vk.verify(message, &sig).is_ok()
        } else {
            false
        }
    }
}

impl KeyGen for K256KeyPair {
    fn generate() -> Result<Self, Error> {
        Ok(Self::from_secret_key(with_rng(|r| SecretKey::random(r))))
    }
}

impl KeyMeta for K256KeyPair {
    type KeySize = U32;
}

impl KeySecretBytes for K256KeyPair {
    fn from_secret_bytes(key: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_secret_key(
            SecretKey::from_bytes(key).map_err(|_| err_msg!(InvalidKeyData))?,
        ))
    }

    fn with_secret_bytes<O>(&self, f: impl FnOnce(Option<&[u8]>) -> O) -> O {
        if let Some(sk) = self.secret.as_ref() {
            let b = k256::SecretBytes::from(sk.to_bytes());
            f(Some(&b[..]))
        } else {
            f(None)
        }
    }
}

impl KeypairMeta for K256KeyPair {
    type PublicKeySize = U33;
    type KeypairSize = U65;
}

impl KeypairBytes for K256KeyPair {
    fn from_keypair_bytes(kp: &[u8]) -> Result<Self, Error> {
        if kp.len() != KEYPAIR_LENGTH {
            return Err(err_msg!(InvalidKeyData));
        }
        let sk = SecretKey::from_bytes(&kp[..SECRET_KEY_LENGTH])
            .map_err(|_| err_msg!(InvalidKeyData))?;
        let pk = EncodedPoint::from_bytes(&kp[SECRET_KEY_LENGTH..])
            .and_then(|pt| pt.decode())
            .map_err(|_| err_msg!(InvalidKeyData))?;
        // FIXME: derive pk from sk and check value?

        Ok(Self {
            secret: Some(sk),
            public: pk,
        })
    }

    fn with_keypair_bytes<O>(&self, f: impl FnOnce(Option<&[u8]>) -> O) -> O {
        if let Some(sk) = self.secret.as_ref() {
            let mut buf = ArrayKey::<<Self as KeypairMeta>::KeypairSize>::default();
            let sk_b = k256::SecretBytes::from(sk.to_bytes());
            let pk_enc = EncodedPoint::encode(self.public, true);
            buf.as_mut()[..SECRET_KEY_LENGTH].copy_from_slice(&sk_b[..]);
            buf.as_mut()[SECRET_KEY_LENGTH..].copy_from_slice(pk_enc.as_ref());
            f(Some(buf.as_ref()))
        } else {
            f(None)
        }
    }
}

impl KeyPublicBytes for K256KeyPair {
    fn from_public_bytes(key: &[u8]) -> Result<Self, Error> {
        let pk = EncodedPoint::from_bytes(key)
            .and_then(|pt| pt.decode())
            .map_err(|_| err_msg!(InvalidKeyData))?;
        Ok(Self {
            secret: None,
            public: pk,
        })
    }

    fn with_public_bytes<O>(&self, f: impl FnOnce(&[u8]) -> O) -> O {
        let pt = EncodedPoint::encode(self.public, true);
        f(pt.as_ref())
    }
}

impl KeySign for K256KeyPair {
    fn key_sign_buffer<B: WriteBuffer>(
        &self,
        message: &[u8],
        sig_type: Option<SignatureType>,
        out: &mut B,
    ) -> Result<(), Error> {
        match sig_type {
            None | Some(SignatureType::ES256K) => {
                if let Some(sig) = self.sign(message) {
                    out.write_slice(&sig[..])?;
                    Ok(())
                } else {
                    Err(err_msg!(Unsupported, "Undefined secret key"))
                }
            }
            #[allow(unreachable_patterns)]
            _ => Err(err_msg!(Unsupported, "Unsupported signature type")),
        }
    }
}

impl KeySigVerify for K256KeyPair {
    fn key_verify(
        &self,
        message: &[u8],
        signature: &[u8],
        sig_type: Option<SignatureType>,
    ) -> Result<bool, Error> {
        match sig_type {
            None | Some(SignatureType::ES256K) => Ok(self.verify_signature(message, signature)),
            #[allow(unreachable_patterns)]
            _ => Err(err_msg!(Unsupported, "Unsupported signature type")),
        }
    }
}

impl ToJwk for K256KeyPair {
    fn to_jwk_encoder<B: WriteBuffer>(&self, enc: &mut JwkEncoder<B>) -> Result<(), Error> {
        let pk_enc = EncodedPoint::encode(self.public, false);
        let (x, y) = match pk_enc.coordinates() {
            Coordinates::Identity => {
                return Err(err_msg!(
                    Unsupported,
                    "Cannot convert identity point to JWK"
                ))
            }
            Coordinates::Uncompressed { x, y } => (x, y),
            Coordinates::Compressed { .. } => unreachable!(),
        };

        enc.add_str("crv", JWK_CURVE)?;
        enc.add_str("kty", JWK_KEY_TYPE)?;
        enc.add_as_base64("x", &x[..])?;
        enc.add_as_base64("y", &y[..])?;
        if enc.is_secret() {
            self.with_secret_bytes(|buf| {
                if let Some(sk) = buf {
                    enc.add_as_base64("d", sk)
                } else {
                    Ok(())
                }
            })?;
        }
        Ok(())
    }
}

impl FromJwk for K256KeyPair {
    fn from_jwk_parts(jwk: JwkParts<'_>) -> Result<Self, Error> {
        // SECURITY: ArrayKey zeroizes on drop
        let mut pk_x = ArrayKey::<FieldSize>::default();
        let mut pk_y = ArrayKey::<FieldSize>::default();
        if jwk.x.decode_base64(pk_x.as_mut())? != pk_x.len() {
            return Err(err_msg!(InvalidKeyData));
        }
        if jwk.y.decode_base64(pk_y.as_mut())? != pk_y.len() {
            return Err(err_msg!(InvalidKeyData));
        }
        let pk = EncodedPoint::from_affine_coordinates(pk_x.as_ref(), pk_y.as_ref(), false)
            .decode()
            .map_err(|_| err_msg!(InvalidKeyData))?;
        let sk = if jwk.d.is_some() {
            let mut sk = ArrayKey::<FieldSize>::default();
            if jwk.d.decode_base64(sk.as_mut())? != sk.len() {
                return Err(err_msg!(InvalidKeyData));
            }
            Some(SecretKey::from_bytes(sk.as_ref()).map_err(|_| err_msg!(InvalidKeyData))?)
        } else {
            None
        };
        Ok(Self {
            secret: sk,
            public: pk,
        })
    }
}

impl KeyExchange for K256KeyPair {
    fn key_exchange_buffer<B: WriteBuffer>(&self, other: &Self, out: &mut B) -> Result<(), Error> {
        match self.secret.as_ref() {
            Some(sk) => {
                let xk = diffie_hellman(sk.secret_scalar(), other.public.as_affine());
                out.write_slice(xk.as_bytes())?;
                Ok(())
            }
            None => Err(err_msg!(MissingSecretKey)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwk_expected() {
        // from https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/
        // {"kty":"EC",
        // "crv":"secp256k1",
        // "d": "rhYFsBPF9q3-uZThy7B3c4LDF_8wnozFUAEm5LLC4Zw",
        // "kid": "JUvpllMEYUZ2joO59UNui_XYDqxVqiFLLAJ8klWuPBw",
        // "kty": "EC",
        // "x": "dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A",
        // "y": "36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA"
        // }
        let test_pvt_b64 = "rhYFsBPF9q3-uZThy7B3c4LDF_8wnozFUAEm5LLC4Zw";
        let test_pub_b64 = (
            "dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A",
            "36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA",
        );
        let test_pvt = base64::decode_config(test_pvt_b64, base64::URL_SAFE).unwrap();
        let sk = K256KeyPair::from_secret_bytes(&test_pvt).expect("Error creating signing key");

        let jwk = sk.to_jwk_public().expect("Error converting key to JWK");
        let jwk = jwk.to_parts().expect("Error parsing JWK");
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, JWK_CURVE);
        assert_eq!(jwk.x, test_pub_b64.0);
        assert_eq!(jwk.y, test_pub_b64.1);
        assert_eq!(jwk.d, None);
        let pk_load = K256KeyPair::from_jwk_parts(jwk).unwrap();
        assert_eq!(sk.to_public_bytes(), pk_load.to_public_bytes());

        let jwk = sk.to_jwk_secret().expect("Error converting key to JWK");
        let jwk = jwk.to_parts().expect("Error parsing JWK");
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, JWK_CURVE);
        assert_eq!(jwk.x, test_pub_b64.0);
        assert_eq!(jwk.y, test_pub_b64.1);
        assert_eq!(jwk.d, test_pvt_b64);
        let sk_load = K256KeyPair::from_jwk_parts(jwk).unwrap();
        assert_eq!(
            sk.to_keypair_bytes().unwrap(),
            sk_load.to_keypair_bytes().unwrap()
        );
    }

    #[test]
    fn sign_verify_expected() {
        let test_msg = b"This is a dummy message for use with tests";
        let test_sig = &hex!(
            "a2a3affbe18cda8c5a7b6375f05b304c2303ab8beb21428709a43a519f8f946f
            6ffa7966afdb337e9b1f70bb575282e71d4fe5bbe6bfa97b229d6bd7e97df1e5"
        );
        let test_pvt = base64::decode_config(
            "jv_VrhPomm6_WOzb74xF4eMI0hu9p0W1Zlxi0nz8AFs",
            base64::URL_SAFE_NO_PAD,
        )
        .unwrap();
        let kp = K256KeyPair::from_secret_bytes(&test_pvt).unwrap();
        let sig = kp.sign(&test_msg[..]).unwrap();
        assert_eq!(sig, &test_sig[..]);
        assert_eq!(kp.verify_signature(&test_msg[..], &sig[..]), true);
        assert_eq!(kp.verify_signature(b"Not the message", &sig[..]), false);
        assert_eq!(kp.verify_signature(&test_msg[..], &[0u8; 64]), false);
    }

    #[test]
    fn key_exchange_random() {
        let kp1 = K256KeyPair::generate().unwrap();
        let kp2 = K256KeyPair::generate().unwrap();
        assert_ne!(
            kp1.to_keypair_bytes().unwrap(),
            kp2.to_keypair_bytes().unwrap()
        );

        let xch1 = kp1.key_exchange_bytes(&kp2).unwrap();
        let xch2 = kp2.key_exchange_bytes(&kp1).unwrap();
        assert_eq!(xch1.len(), 32);
        assert_eq!(xch1, xch2);
    }

    #[test]
    fn round_trip_bytes() {
        let kp = K256KeyPair::generate().unwrap();
        let cmp = K256KeyPair::from_keypair_bytes(&kp.to_keypair_bytes().unwrap()).unwrap();
        assert_eq!(
            kp.to_keypair_bytes().unwrap(),
            cmp.to_keypair_bytes().unwrap()
        );
    }
}
