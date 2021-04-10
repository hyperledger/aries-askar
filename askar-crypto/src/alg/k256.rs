use alloc::boxed::Box;
use core::convert::{TryFrom, TryInto};

use k256::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    elliptic_curve::{ecdh::diffie_hellman, sec1::Coordinates},
    EncodedPoint, PublicKey, SecretKey,
};
use rand::rngs::OsRng;

use crate::{
    // any::{AnyPrivateKey, AnyPublicKey},
    buffer::{SecretBytes, WriteBuffer},
    caps::{KeyCapSign, KeyCapVerify, SignatureType},
    error::Error,
    jwk::{JwkEncoder, KeyToJwk, KeyToJwkSecret},
};

pub const ES256K_SIGNATURE_LENGTH: usize = 64;

pub const PUBLIC_KEY_LENGTH: usize = 33; // compressed size
pub const SECRET_KEY_LENGTH: usize = 32;
pub const KEYPAIR_LENGTH: usize = SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH;

#[derive(Clone, Debug)]
pub struct K256KeyPair(Box<Keypair>);

impl K256KeyPair {
    pub fn generate() -> Result<Self, Error> {
        Ok(Self::from_secret_key(SecretKey::random(OsRng)))
    }

    pub fn from_keypair_bytes(kp: &[u8]) -> Result<Self, Error> {
        if kp.len() != KEYPAIR_LENGTH {
            return Err(err_msg!("Invalid keypair bytes"));
        }
        let sk = SecretKey::from_bytes(&kp[..SECRET_KEY_LENGTH])
            .map_err(|_| err_msg!("Invalid k-256 secret key bytes"))?;
        let pk = EncodedPoint::from_bytes(&kp[SECRET_KEY_LENGTH..])
            .and_then(|pt| pt.decode())
            .map_err(|_| err_msg!("Invalid k-256 public key bytes"))?;
        // FIXME: derive pk from sk and check value?

        Ok(Self(Box::new(Keypair {
            secret: Some(sk),
            public: pk,
        })))
    }

    pub fn from_public_key_bytes(key: &[u8]) -> Result<Self, Error> {
        let pk = EncodedPoint::from_bytes(key)
            .and_then(|pt| pt.decode())
            .map_err(|_| err_msg!("Invalid k-256 public key bytes"))?;
        Ok(Self(Box::new(Keypair {
            secret: None,
            public: pk,
        })))
    }

    pub fn from_secret_key_bytes(key: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_secret_key(
            SecretKey::from_bytes(key).map_err(|_| err_msg!("Invalid k-256 secret key bytes"))?,
        ))
    }

    #[inline]
    pub(crate) fn from_secret_key(sk: SecretKey) -> Self {
        let pk = sk.public_key();
        Self(Box::new(Keypair {
            secret: Some(sk),
            public: pk,
        }))
    }

    pub fn key_exchange_with(&self, other: &Self) -> Option<SecretBytes> {
        match self.0.secret.as_ref() {
            Some(sk) => {
                let xk = diffie_hellman(sk.secret_scalar(), other.0.public.as_affine());
                Some(SecretBytes::from(xk.as_bytes().to_vec()))
            }
            None => None,
        }
    }

    pub fn to_keypair_bytes(&self) -> Option<SecretBytes> {
        if let Some(secret) = self.0.secret.as_ref() {
            let encp = EncodedPoint::encode(self.0.public.clone(), true);
            let output = SecretBytes::new_with(KEYPAIR_LENGTH, |buf| {
                buf[..SECRET_KEY_LENGTH].copy_from_slice(&secret.to_bytes()[..]);
                buf[SECRET_KEY_LENGTH..].copy_from_slice(encp.as_ref());
            });
            Some(output)
        } else {
            None
        }
    }

    pub(crate) fn to_signing_key(&self) -> Option<SigningKey> {
        self.0.secret.as_ref().map(SigningKey::from)
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
            let vk = VerifyingKey::from(self.0.public.as_affine());
            vk.verify(message, &sig).is_ok()
        } else {
            false
        }
    }
}

impl KeyCapSign for K256KeyPair {
    fn key_sign<B: WriteBuffer>(
        &self,
        message: &[u8],
        sig_type: Option<SignatureType>,
        out: &mut B,
    ) -> Result<usize, Error> {
        match sig_type {
            None | Some(SignatureType::ES256K) => {
                if let Some(sig) = self.sign(message) {
                    out.extend_from_slice(&sig[..])?;
                    Ok(ES256K_SIGNATURE_LENGTH)
                } else {
                    Err(err_msg!(Unsupported, "Undefined secret key"))
                }
            }
            #[allow(unreachable_patterns)]
            _ => Err(err_msg!(Unsupported, "Unsupported signature type")),
        }
    }
}

impl KeyCapVerify for K256KeyPair {
    fn key_verify(
        &self,
        message: &[u8],
        signature: &[u8],
        sig_type: Option<SignatureType>,
    ) -> Result<bool, Error> {
        match sig_type {
            None | Some(SignatureType::ES256K) => {
                if let Ok(sig) = TryInto::<&[u8; ES256K_SIGNATURE_LENGTH]>::try_into(signature) {
                    Ok(self.verify_signature(message, sig))
                } else {
                    Ok(false)
                }
            }
            #[allow(unreachable_patterns)]
            _ => Err(err_msg!(Unsupported, "Unsupported signature type")),
        }
    }
}

impl KeyToJwk for K256KeyPair {
    const KTY: &'static str = "EC";

    fn to_jwk_buffer<B: WriteBuffer>(&self, buffer: &mut JwkEncoder<B>) -> Result<(), Error> {
        let encp = EncodedPoint::encode(self.0.public.clone(), false);
        let (x, y) = match encp.coordinates() {
            Coordinates::Identity => return Err(err_msg!("Cannot convert identity point to JWK")),
            Coordinates::Uncompressed { x, y } => (x, y),
            Coordinates::Compressed { .. } => unreachable!(),
        };

        buffer.add_str("crv", "secp256k1")?;
        buffer.add_as_base64("x", &x[..])?;
        buffer.add_as_base64("y", &y[..])?;
        // buffer.add_str("use", "enc")?;
        Ok(())
    }
}

impl KeyToJwkSecret for K256KeyPair {
    fn to_jwk_buffer_secret<B: WriteBuffer>(
        &self,
        buffer: &mut JwkEncoder<B>,
    ) -> Result<(), Error> {
        self.to_jwk_buffer(buffer)?;
        if let Some(sk) = self.0.secret.as_ref() {
            buffer.add_as_base64("d", &sk.to_bytes()[..])?;
            Ok(())
        } else {
            self.to_jwk_buffer(buffer)
        }
    }
}

// impl TryFrom<&AnyPrivateKey> for K256SigningKey {
//     type Error = Error;

//     fn try_from(value: &AnyPrivateKey) -> Result<Self, Self::Error> {
//         if value.alg == KeyAlg::Ecdsa(EcCurves::Secp256k1) {
//             Self::from_bytes(value.data.as_ref())
//         } else {
//             Err(err_msg!(Unsupported, "Expected k-256 key type"))
//         }
//     }
// }

#[derive(Clone, Debug)]
struct Keypair {
    // SECURITY: SecretKey zeroizes on drop
    secret: Option<SecretKey>,
    public: PublicKey,
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
        let test_pvt = base64::decode_config(test_pvt_b64, base64::URL_SAFE).unwrap();
        let sk = K256KeyPair::from_secret_key_bytes(&test_pvt).expect("Error creating signing key");
        let jwk = sk.to_jwk_secret().expect("Error converting key to JWK");
        let jwk = jwk.to_parts().expect("Error parsing JWK");
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, "secp256k1");
        assert_eq!(jwk.x, "dWCvM4fTdeM0KmloF57zxtBPXTOythHPMm1HCLrdd3A");
        assert_eq!(jwk.y, "36uMVGM7hnw-N6GnjFcihWE3SkrhMLzzLCdPMXPEXlA");
        assert_eq!(jwk.d, test_pvt_b64);
    }

    #[test]
    fn sign_verify_expected() {
        let test_msg = b"This is a dummy message for use with tests";
        let test_sig = hex!("a2a3affbe18cda8c5a7b6375f05b304c2303ab8beb21428709a43a519f8f946f6ffa7966afdb337e9b1f70bb575282e71d4fe5bbe6bfa97b229d6bd7e97df1e5");
        let test_pvt = base64::decode_config(
            "jv_VrhPomm6_WOzb74xF4eMI0hu9p0W1Zlxi0nz8AFs",
            base64::URL_SAFE_NO_PAD,
        )
        .unwrap();
        let kp = K256KeyPair::from_secret_key_bytes(&test_pvt).unwrap();
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

        let xch1 = kp1.key_exchange_with(&kp2);
        let xch2 = kp2.key_exchange_with(&kp1);
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
