use core::convert::TryInto;

use k256::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    elliptic_curve::{
        ecdh::diffie_hellman,
        sec1::{Coordinates, FromEncodedPoint},
    },
    EncodedPoint, PublicKey, SecretKey,
};
use rand::rngs::OsRng;
use serde_json::json;

use crate::{
    // any::{AnyPrivateKey, AnyPublicKey},
    buffer::{SecretBytes, WriteBuffer},
    caps::{EcCurves, KeyAlg, KeyCapSign, KeyCapVerify, SignatureFormat, SignatureType},
    error::Error,
};

pub const ES256K_SIGNATURE_LENGTH: usize = 64;

#[derive(Clone, Debug)]
pub struct K256SigningKey(SecretKey);

impl K256SigningKey {
    pub fn generate() -> Result<Self, Error> {
        Ok(Self(SecretKey::random(OsRng)))
    }

    pub fn from_bytes(pt: &[u8]) -> Result<Self, Error> {
        let kp = SecretKey::from_bytes(pt).map_err(|_| err_msg!("Invalid signing key bytes"))?;
        Ok(Self(kp))
    }

    pub fn to_bytes(&self) -> SecretBytes {
        SecretBytes::from(self.0.to_bytes().to_vec())
    }

    pub fn public_key(&self) -> K256VerifyingKey {
        K256VerifyingKey(SigningKey::from(&self.0).verify_key())
    }

    pub fn sign(&self, message: &[u8]) -> [u8; ES256K_SIGNATURE_LENGTH] {
        let skey = SigningKey::from(self.0.clone());
        let sig: Signature = skey.sign(message);
        let mut sigb = [0u8; 64];
        sigb[0..32].copy_from_slice(&sig.r().to_bytes());
        sigb[32..].copy_from_slice(&sig.s().to_bytes());
        sigb
    }

    pub fn verify(&self, message: &[u8], signature: &[u8; ES256K_SIGNATURE_LENGTH]) -> bool {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&signature[..32]);
        s.copy_from_slice(&signature[32..]);
        if let Ok(sig) = Signature::from_scalars(r, s) {
            let vk = VerifyingKey::from(SigningKey::from(&self.0));
            vk.verify(message, &sig).is_ok()
        } else {
            false
        }
    }
}

impl KeyCapSign for K256SigningKey {
    fn key_sign<B: WriteBuffer>(
        &self,
        data: &[u8],
        sig_type: Option<SignatureType>,
        out: &mut B,
    ) -> Result<usize, Error> {
        match sig_type {
            None | Some(SignatureType::ES256K) => {
                let sig = self.sign(data);
                out.extend_from_slice(&sig[..]);
                Ok(ES256K_SIGNATURE_LENGTH)
            }
            #[allow(unreachable_patterns)]
            _ => Err(err_msg!(Unsupported, "Unsupported signature type")),
        }
    }
}

impl KeyCapVerify for K256SigningKey {
    fn key_verify(
        &self,
        message: &[u8],
        signature: &[u8],
        sig_type: Option<SignatureType>,
    ) -> Result<bool, Error> {
        match sig_type {
            None | Some(SignatureType::ES256K) => {
                if let Ok(sig) = TryInto::<&[u8; ES256K_SIGNATURE_LENGTH]>::try_into(signature) {
                    Ok(self.verify(message, sig))
                } else {
                    Ok(false)
                }
            }
            #[allow(unreachable_patterns)]
            _ => Err(err_msg!(Unsupported, "Unsupported signature type")),
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct K256VerifyingKey(VerifyingKey);

impl K256VerifyingKey {
    pub fn from_str(key: impl AsRef<str>) -> Result<Self, Error> {
        let key = key.as_ref();
        let key = key.strip_suffix(":k256/ecdsa").unwrap_or(key);
        let mut bval = [0u8; 32];
        bs58::decode(key)
            .into(&mut bval)
            .map_err(|_| err_msg!("Invalid base58 public key"))?;
        Self::from_bytes(bval)
    }

    pub fn from_bytes(pk: impl AsRef<[u8]>) -> Result<Self, Error> {
        let encp = EncodedPoint::from_bytes(pk.as_ref())
            .map_err(|_| err_msg!("Invalid public key bytes"))?;
        if encp.is_identity() {
            return Err(err_msg!("Invalid public key: identity point"));
        }
        Ok(Self(
            VerifyingKey::from_encoded_point(&encp).map_err(|_| err_msg!("Invalid public key"))?,
        ))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut k = [0u8; 32];
        let encp = EncodedPoint::from(&self.0);
        k.copy_from_slice(encp.as_bytes());
        k
    }

    // pub fn to_string(&self) -> String {
    //     let mut sval = String::with_capacity(64);
    //     bs58::encode(self.to_bytes()).into(&mut sval).unwrap();
    //     sval.push_str(":k256/ecdsa");
    //     sval
    // }

    pub fn to_jwk(&self) -> Result<serde_json::Value, Error> {
        let encp = EncodedPoint::encode(self.0.clone(), false);
        let (x, y) = match encp.coordinates() {
            Coordinates::Identity => return Err(err_msg!("Cannot convert identity point to JWK")),
            Coordinates::Uncompressed { x, y } => (
                base64::encode_config(x, base64::URL_SAFE_NO_PAD),
                base64::encode_config(y, base64::URL_SAFE_NO_PAD),
            ),
            Coordinates::Compressed { .. } => unreachable!(),
        };
        Ok(json!({
            "kty": "EC",
            "crv": "secp256k1",
            "x": x,
            "y": y,
            "key_ops": ["verify"]
        }))
    }

    pub fn verify(&self, message: &[u8], signature: [u8; 64]) -> bool {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&signature[..32]);
        s.copy_from_slice(&signature[32..]);
        if let Ok(sig) = Signature::from_scalars(r, s) {
            self.0.verify(message, &sig).is_ok()
        } else {
            false
        }
    }
}

impl KeyCapVerify for K256VerifyingKey {
    fn key_verify(
        &self,
        data: &[u8],
        signature: &[u8],
        sig_type: Option<SignatureType>,
    ) -> Result<bool, Error> {
        match sig_type {
            None | Some(SignatureType::ES256K) => {
                let mut sig = [0u8; ES256K_SIGNATURE_LENGTH];
                if data.len() != ES256K_SIGNATURE_LENGTH {
                    return Err(err_msg!("Invalid ES256K signature"));
                }
                Ok(self.verify(data, sig))
            }
            #[allow(unreachable_patterns)]
            _ => Err(err_msg!(Unsupported, "Unsupported signature type")),
        }
    }
}

// impl TryFrom<&AnyPublicKey> for K256VerifyingKey {
//     type Error = Error;

//     fn try_from(value: &AnyPublicKey) -> Result<Self, Self::Error> {
//         if value.alg == KeyAlg::Ecdsa(EcCurves::Secp256k1) {
//             Self::from_bytes(&value.data)
//         } else {
//             Err(err_msg!(Unsupported, "Expected k-256 key type"))
//         }
//     }
// }

#[derive(Clone, Debug)]
pub struct K256ExchPrivateKey(SecretKey);

impl K256ExchPrivateKey {
    pub fn generate() -> Result<Self, Error> {
        Ok(Self(SecretKey::random(OsRng)))
    }

    pub fn from_bytes(pt: &[u8]) -> Result<Self, Error> {
        let kp = SecretKey::from_bytes(pt).map_err(|_| err_msg!("Invalid signing key bytes"))?;
        Ok(Self(kp))
    }

    pub fn to_bytes(&self) -> SecretBytes {
        SecretBytes::from(self.0.to_bytes().to_vec())
    }

    pub fn key_exchange_with(&self, pk: &K256ExchPublicKey) -> SecretBytes {
        let xk = diffie_hellman(self.0.secret_scalar(), pk.0.as_affine());
        SecretBytes::from(xk.as_bytes().to_vec())
    }

    pub fn public_key(&self) -> K256ExchPublicKey {
        K256ExchPublicKey(self.0.public_key())
    }
}

// impl TryFrom<&AnyPrivateKey> for K256ExchPrivateKey {
//     type Error = Error;

//     fn try_from(value: &AnyPrivateKey) -> Result<Self, Self::Error> {
//         if value.alg == KeyAlg::Ecdh(EcCurves::Secp256k1) {
//             Self::from_bytes(value.data.as_ref())
//         } else {
//             Err(err_msg!(Unsupported, "Expected k-256 key type"))
//         }
//     }
// }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct K256ExchPublicKey(PublicKey);

impl K256ExchPublicKey {
    pub fn from_str(key: impl AsRef<str>) -> Result<Self, Error> {
        let key = key.as_ref();
        let key = key.strip_suffix(":k256/ecdh").unwrap_or(key);
        let mut bval = [0u8; 32];
        bs58::decode(key)
            .into(&mut bval)
            .map_err(|_| err_msg!("Invalid base58 public key"))?;
        Self::from_bytes(bval)
    }

    pub fn from_bytes(pk: impl AsRef<[u8]>) -> Result<Self, Error> {
        let encp = EncodedPoint::from_bytes(pk.as_ref())
            .map_err(|_| err_msg!("Invalid public key bytes"))?;
        if encp.is_identity() {
            return Err(err_msg!("Invalid public key: identity point"));
        }
        Ok(Self(
            PublicKey::from_encoded_point(&encp).ok_or_else(|| err_msg!("Invalid public key"))?,
        ))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut k = [0u8; 32];
        let encp = EncodedPoint::from(&self.0);
        k.copy_from_slice(encp.as_bytes());
        k
    }

    pub fn to_jwk(&self) -> Result<serde_json::Value, Error> {
        let encp = EncodedPoint::encode(self.0, false);
        let (x, y) = match encp.coordinates() {
            Coordinates::Identity => return Err(err_msg!("Cannot convert identity point to JWK")),
            Coordinates::Uncompressed { x, y } => (
                base64::encode_config(x, base64::URL_SAFE_NO_PAD),
                base64::encode_config(y, base64::URL_SAFE_NO_PAD),
            ),
            Coordinates::Compressed { .. } => unreachable!(),
        };
        Ok(json!({
            "kty": "EC",
            "crv": "K-256",
            "x": x,
            "y": y,
            "key_ops": ["deriveKey"]
        }))
    }
}

// impl TryFrom<&AnyPublicKey> for K256ExchPublicKey {
//     type Error = Error;

//     fn try_from(value: &AnyPublicKey) -> Result<Self, Self::Error> {
//         if value.alg == KeyAlg::Ecdh(EcCurves::Secp256k1) {
//             Self::from_bytes(&value.data)
//         } else {
//             Err(err_msg!(Unsupported, "Expected k-256 key type"))
//         }
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_keypair_random() {
        let sk = K256SigningKey::generate().expect("Error creating signing key");
        let _vk = sk.public_key();
    }

    #[test]
    fn jwk_expected() {
        // {"kty":"EC",
        // "crv":"secp256k1",
        // "x":"Hr99bGFN0HWT3ZgNNAXvmz-6Wk1HIxwsyFqUZH8PBFc",
        // "y":"bonc3DRZe51NzuWetY336VmTYdUFvPK7DivSPHeu_CA",
        // "d":"jv_VrhPomm6_WOzb74xF4eMI0hu9p0W1Zlxi0nz8AFs"
        // }
        let test_pvt = base64::decode_config(
            "jv_VrhPomm6_WOzb74xF4eMI0hu9p0W1Zlxi0nz8AFs",
            base64::URL_SAFE,
        )
        .unwrap();
        let sk = K256SigningKey::from_bytes(&test_pvt).expect("Error creating signing key");
        let vk = sk.public_key();
        let jwk = vk.to_jwk().expect("Error converting public key to JWK");
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "secp256k1");
        assert_eq!(jwk["x"], "Hr99bGFN0HWT3ZgNNAXvmz-6Wk1HIxwsyFqUZH8PBFc");
        assert_eq!(jwk["y"], "bonc3DRZe51NzuWetY336VmTYdUFvPK7DivSPHeu_CA");
    }

    #[test]
    fn sign_verify_expected() {
        let test_msg = b"This is a dummy message for use with tests";
        let test_sig =  hex::decode("a2a3affbe18cda8c5a7b6375f05b304c2303ab8beb21428709a43a519f8f946f6ffa7966afdb337e9b1f70bb575282e71d4fe5bbe6bfa97b229d6bd7e97df1e5").unwrap();
        let test_pvt = base64::decode_config(
            "jv_VrhPomm6_WOzb74xF4eMI0hu9p0W1Zlxi0nz8AFs",
            base64::URL_SAFE_NO_PAD,
        )
        .unwrap();
        let kp = K256SigningKey::from_bytes(&&test_pvt).unwrap();
        let sig = kp.sign(&test_msg[..]);
        assert_eq!(sig, test_sig.as_slice());
        assert_eq!(kp.public_key().verify(&test_msg[..], sig), true);
        assert_eq!(kp.public_key().verify(b"Not the message", sig), false);
        assert_eq!(kp.public_key().verify(&test_msg[..], [0u8; 64]), false);
    }

    #[test]
    fn key_exchange_random() {
        let kp1 = K256ExchPrivateKey::generate().unwrap();
        let kp2 = K256ExchPrivateKey::generate().unwrap();
        assert_ne!(kp1.to_bytes(), kp2.to_bytes());

        let xch1 = kp1.key_exchange_with(&kp2.public_key());
        let xch2 = kp2.key_exchange_with(&kp1.public_key());
        assert_eq!(xch1, xch2);

        // test round trip
        let xch3 = K256ExchPrivateKey::from_bytes(&kp1.to_bytes())
            .unwrap()
            .key_exchange_with(&kp2.public_key());
        assert_eq!(xch3, xch1);
    }
}
