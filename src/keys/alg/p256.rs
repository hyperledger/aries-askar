use std::convert::TryFrom;

use p256::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    elliptic_curve::{ecdh::diffie_hellman, sec1::FromEncodedPoint},
    EncodedPoint, PublicKey, SecretKey,
};
use rand::rngs::OsRng;
use serde_json::json;

use super::edwards::{decode_signature, encode_signature};
use crate::{
    error::Error,
    keys::any::{AnyPrivateKey, AnyPublicKey},
    keys::caps::{EcCurves, KeyAlg, KeyCapSign, KeyCapVerify, SignatureFormat, SignatureType},
    types::SecretBytes,
};

#[derive(Clone, Debug)]
pub struct P256SigningKey(SecretKey);

impl P256SigningKey {
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

    pub fn public_key(&self) -> P256VerifyingKey {
        P256VerifyingKey(self.0.public_key())
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let skey = SigningKey::from(self.0.clone());
        let sig = skey.sign(message);
        let mut sigb = [0u8; 64];
        sigb[0..32].copy_from_slice(&sig.r().to_bytes());
        sigb[32..].copy_from_slice(&sig.s().to_bytes());
        sigb
    }

    pub fn verify(&self, message: &[u8], signature: [u8; 64]) -> bool {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&signature[..32]);
        s.copy_from_slice(&signature[32..]);
        if let Ok(sig) = Signature::from_scalars(r, s) {
            let vk = VerifyingKey::from(self.0.public_key());
            vk.verify(message, &sig).is_ok()
        } else {
            false
        }
    }
}

impl KeyCapSign for P256SigningKey {
    fn key_sign(
        &self,
        data: &[u8],
        sig_type: Option<SignatureType>,
        sig_format: Option<SignatureFormat>,
    ) -> Result<Vec<u8>, Error> {
        match sig_type {
            None | Some(SignatureType::ES256) => {
                let sig = self.sign(data);
                encode_signature(&sig, sig_format)
            }
            #[allow(unreachable_patterns)]
            _ => Err(err_msg!(Unsupported, "Unsupported signature type")),
        }
    }
}

impl KeyCapVerify for P256SigningKey {
    fn key_verify(
        &self,
        data: &[u8],
        signature: &[u8],
        sig_type: Option<SignatureType>,
        sig_format: Option<SignatureFormat>,
    ) -> Result<bool, Error> {
        match sig_type {
            None | Some(SignatureType::ES256) => {
                let mut sig = [0u8; 64];
                decode_signature(signature, &mut sig, sig_format)?;
                Ok(self.verify(data, sig))
            }
            #[allow(unreachable_patterns)]
            _ => Err(err_msg!(Unsupported, "Unsupported signature type")),
        }
    }
}

impl TryFrom<&AnyPrivateKey> for P256SigningKey {
    type Error = Error;

    fn try_from(value: &AnyPrivateKey) -> Result<Self, Self::Error> {
        if value.alg == KeyAlg::Ecdsa(EcCurves::Secp256r1) {
            Self::from_bytes(value.data.as_ref())
        } else {
            Err(err_msg!(Unsupported, "Expected p-256 key type"))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P256VerifyingKey(PublicKey);

impl P256VerifyingKey {
    pub fn from_str(key: impl AsRef<str>) -> Result<Self, Error> {
        let key = key.as_ref();
        let key = key.strip_suffix(":p256/ecdsa").unwrap_or(key);
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

    pub fn to_base58(&self) -> String {
        bs58::encode(self.to_bytes()).into_string()
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut k = [0u8; 32];
        let encp = EncodedPoint::from(&self.0);
        k.copy_from_slice(encp.as_bytes());
        k
    }

    pub fn to_string(&self) -> String {
        let mut sval = String::with_capacity(64);
        bs58::encode(self.to_bytes()).into(&mut sval).unwrap();
        sval.push_str(":p256/ecdsa");
        sval
    }

    pub fn to_jwk(&self) -> Result<serde_json::Value, Error> {
        let encp = EncodedPoint::from(&self.0);
        if encp.is_identity() {
            return Err(err_msg!("Cannot convert identity point to JWK"));
        }
        let x = base64::encode_config(encp.x().unwrap(), base64::URL_SAFE_NO_PAD);
        let y = base64::encode_config(encp.y().unwrap(), base64::URL_SAFE_NO_PAD);
        Ok(json!({
            "kty": "EC",
            "crv": "P-256",
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
            let vk = VerifyingKey::from(self.0.clone());
            vk.verify(message, &sig).is_ok()
        } else {
            false
        }
    }
}

impl KeyCapVerify for P256VerifyingKey {
    fn key_verify(
        &self,
        data: &[u8],
        signature: &[u8],
        sig_type: Option<SignatureType>,
        sig_format: Option<SignatureFormat>,
    ) -> Result<bool, Error> {
        match sig_type {
            None | Some(SignatureType::ES256) => {
                let mut sig = [0u8; 64];
                decode_signature(signature, &mut sig, sig_format)?;
                Ok(self.verify(data, sig))
            }
            #[allow(unreachable_patterns)]
            _ => Err(err_msg!(Unsupported, "Unsupported signature type")),
        }
    }
}

impl TryFrom<&AnyPublicKey> for P256VerifyingKey {
    type Error = Error;

    fn try_from(value: &AnyPublicKey) -> Result<Self, Self::Error> {
        if value.alg == KeyAlg::Ecdsa(EcCurves::Secp256r1) {
            Self::from_bytes(&value.data)
        } else {
            Err(err_msg!(Unsupported, "Expected p-256 key type"))
        }
    }
}

#[derive(Clone, Debug)]
pub struct P256ExchPrivateKey(SecretKey);

impl P256ExchPrivateKey {
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

    pub fn key_exchange_with(&self, pk: &P256ExchPublicKey) -> SecretBytes {
        let xk = diffie_hellman(self.0.secret_scalar(), pk.0.as_affine());
        SecretBytes::from(xk.as_bytes().to_vec())
    }

    pub fn public_key(&self) -> P256ExchPublicKey {
        P256ExchPublicKey(self.0.public_key())
    }
}

impl TryFrom<&AnyPrivateKey> for P256ExchPrivateKey {
    type Error = Error;

    fn try_from(value: &AnyPrivateKey) -> Result<Self, Self::Error> {
        if value.alg == KeyAlg::Ecdh(EcCurves::Secp256r1) {
            Self::from_bytes(value.data.as_ref())
        } else {
            Err(err_msg!(Unsupported, "Expected p-256 key type"))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P256ExchPublicKey(PublicKey);

impl P256ExchPublicKey {
    pub fn from_str(key: impl AsRef<str>) -> Result<Self, Error> {
        let key = key.as_ref();
        let key = key.strip_suffix(":p256/ecdh").unwrap_or(key);
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

    pub fn to_base58(&self) -> String {
        bs58::encode(self.to_bytes()).into_string()
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut k = [0u8; 32];
        let encp = EncodedPoint::from(&self.0);
        k.copy_from_slice(encp.as_bytes());
        k
    }

    pub fn to_string(&self) -> String {
        let mut sval = String::with_capacity(64);
        bs58::encode(self.to_bytes()).into(&mut sval).unwrap();
        sval.push_str(":p256/ecdh");
        sval
    }

    pub fn to_jwk(&self) -> Result<serde_json::Value, Error> {
        let encp = EncodedPoint::from(&self.0);
        if encp.is_identity() {
            return Err(err_msg!("Cannot convert identity point to JWK"));
        }
        let x = base64::encode_config(encp.x().unwrap(), base64::URL_SAFE_NO_PAD);
        let y = base64::encode_config(encp.y().unwrap(), base64::URL_SAFE_NO_PAD);
        Ok(json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y,
            "key_ops": ["deriveKey"]
        }))
    }
}

impl TryFrom<&AnyPublicKey> for P256ExchPublicKey {
    type Error = Error;

    fn try_from(value: &AnyPublicKey) -> Result<Self, Self::Error> {
        if value.alg == KeyAlg::Ecdh(EcCurves::Secp256r1) {
            Self::from_bytes(&value.data)
        } else {
            Err(err_msg!(Unsupported, "Expected p-256 key type"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_keypair_random() {
        let sk = P256SigningKey::generate().expect("Error creating signing key");
        let _vk = sk.public_key();
    }

    #[test]
    fn jwk_expected() {
        // from JWS RFC https://tools.ietf.org/html/rfc7515
        // {"kty":"EC",
        // "crv":"P-256",
        // "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        // "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        // "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
        // }
        let test_pvt = base64::decode_config(
            "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
            base64::URL_SAFE,
        )
        .unwrap();
        let sk = P256SigningKey::from_bytes(&test_pvt).expect("Error creating signing key");
        let vk = sk.public_key();
        let jwk = vk.to_jwk().expect("Error converting public key to JWK");
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert_eq!(jwk["x"], "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU");
        assert_eq!(jwk["y"], "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0");
    }

    #[test]
    fn sign_verify_expected() {
        let test_msg = b"This is a dummy message for use with tests";
        let test_sig =  hex::decode("241f765f19d4e6148452f2249d2fa69882244a6ad6e70aadb8848a6409d207124e85faf9587100247de7bdace13a3073b47ec8a531ca91c1375b2b6134344413").unwrap();
        let test_pvt = base64::decode_config(
            "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI",
            base64::URL_SAFE_NO_PAD,
        )
        .unwrap();
        let kp = P256SigningKey::from_bytes(&&test_pvt).unwrap();
        let sig = kp.sign(&test_msg[..]);
        assert_eq!(sig, test_sig.as_slice());
        assert_eq!(kp.public_key().verify(&test_msg[..], sig), true);
        assert_eq!(kp.public_key().verify(b"Not the message", sig), false);
        assert_eq!(kp.public_key().verify(&test_msg[..], [0u8; 64]), false);
    }

    #[test]
    fn key_exchange_random() {
        let kp1 = P256ExchPrivateKey::generate().unwrap();
        let kp2 = P256ExchPrivateKey::generate().unwrap();
        assert_ne!(kp1.to_bytes(), kp2.to_bytes());

        let xch1 = kp1.key_exchange_with(&kp2.public_key());
        let xch2 = kp2.key_exchange_with(&kp1.public_key());
        assert_eq!(xch1, xch2);

        // test round trip
        let xch3 = P256ExchPrivateKey::from_bytes(&kp1.to_bytes())
            .unwrap()
            .key_exchange_with(&kp2.public_key());
        assert_eq!(xch3, xch1);
    }
}
