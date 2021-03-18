use std::convert::{TryFrom, TryInto};

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer, KEYPAIR_LENGTH};
use rand::rngs::OsRng;
use sha2::{self, Digest};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XSecretKey};

use crate::{
    error::Error,
    keys::any::{AnyPrivateKey, AnyPublicKey},
    keys::caps::{KeyAlg, KeyCapSign, KeyCapVerify, SignatureFormat, SignatureType},
    types::SecretBytes,
};

// FIXME - check for low-order points when loading public keys?
// https://github.com/tendermint/tmkms/pull/279

#[derive(Debug)]
pub struct Ed25519KeyPair(Keypair);

impl Ed25519KeyPair {
    pub fn generate() -> Result<Self, Error> {
        let mut rng = OsRng;
        Ok(Self(Keypair::generate(&mut rng)))
    }

    pub fn from_seed(ikm: &[u8]) -> Result<Self, Error> {
        let secret = SecretKey::from_bytes(ikm).map_err(|_| err_msg!("Invalid key material"))?;
        let public = PublicKey::from(&secret);
        Ok(Self(Keypair { secret, public }))
    }

    pub fn from_bytes(kp: &[u8]) -> Result<Self, Error> {
        let kp = Keypair::from_bytes(kp).map_err(|_| err_msg!("Invalid keypair bytes"))?;
        Ok(Self(kp))
    }

    pub fn to_bytes(&self) -> SecretBytes {
        SecretBytes::from(self.0.to_bytes().to_vec())
    }

    pub fn to_x25519(&self) -> X25519KeyPair {
        let hash = sha2::Sha512::digest(&self.0.secret.to_bytes()[..]);
        let output: [u8; 32] = (&hash[..32]).try_into().unwrap();
        // clamp result
        let secret = XSecretKey::from(output);
        let public = XPublicKey::from(&secret);
        X25519KeyPair(secret, public)
    }

    pub fn private_key(&self) -> SecretBytes {
        SecretBytes::from(self.0.secret.to_bytes().to_vec())
    }

    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey(self.0.public.clone())
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.0.sign(&message).to_bytes()
    }

    pub fn verify(&self, message: &[u8], signature: [u8; 64]) -> bool {
        self.0.verify_strict(message, &signature.into()).is_ok()
    }
}

impl Clone for Ed25519KeyPair {
    fn clone(&self) -> Self {
        Self(Keypair {
            secret: SecretKey::from_bytes(&self.0.secret.as_bytes()[..]).unwrap(),
            public: self.0.public.clone(),
        })
    }
}

impl KeyCapSign for Ed25519KeyPair {
    fn key_sign(
        &self,
        data: &[u8],
        sig_type: Option<SignatureType>,
        sig_format: Option<SignatureFormat>,
    ) -> Result<Vec<u8>, Error> {
        match sig_type {
            None | Some(SignatureType::Ed25519) => match sig_format {
                None | Some(SignatureFormat::Base58) => {
                    Ok(bs58::encode(self.sign(data)).into_vec())
                }
                #[allow(unreachable_patterns)]
                _ => Err(err_msg!(Unsupported, "Unsupported signature format")),
            },
            #[allow(unreachable_patterns)]
            _ => Err(err_msg!(Unsupported, "Unsupported signature type")),
        }
    }
}

impl KeyCapVerify for Ed25519KeyPair {
    fn key_verify(
        &self,
        data: &[u8],
        signature: &[u8],
        sig_type: Option<SignatureType>,
        sig_format: Option<SignatureFormat>,
    ) -> Result<bool, Error> {
        match sig_type {
            None | Some(SignatureType::Ed25519) => match sig_format {
                None | Some(SignatureFormat::Base58) => {
                    let mut sig = [0u8; 64];
                    bs58::decode(signature)
                        .into(&mut sig)
                        .map_err(|_| err_msg!("Invalid base58 signature"))?;
                    Ok(self.verify(data, sig))
                }
                #[allow(unreachable_patterns)]
                _ => Err(err_msg!(Unsupported, "Unsupported signature format")),
            },
            #[allow(unreachable_patterns)]
            _ => Err(err_msg!(Unsupported, "Unsupported signature type")),
        }
    }
}

impl TryFrom<&AnyPrivateKey> for Ed25519KeyPair {
    type Error = Error;

    fn try_from(value: &AnyPrivateKey) -> Result<Self, Self::Error> {
        if value.alg == KeyAlg::ED25519 {
            Self::from_bytes(value.data.as_ref())
        } else {
            Err(err_msg!(Unsupported, "Expected ed25519 key type"))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed25519PublicKey(PublicKey);

impl Ed25519PublicKey {
    pub fn from_str(key: impl AsRef<str>) -> Result<Self, Error> {
        let key = key.as_ref();
        let key = key.strip_suffix(":ed25519").unwrap_or(key);
        let mut bval = [0u8; 32];
        bs58::decode(key)
            .into(&mut bval)
            .map_err(|_| err_msg!("Invalid base58 public key"))?;
        Self::from_bytes(bval)
    }

    pub fn from_bytes(pk: impl AsRef<[u8]>) -> Result<Self, Error> {
        let pk =
            PublicKey::from_bytes(pk.as_ref()).map_err(|_| err_msg!("Invalid public key bytes"))?;
        Ok(Self(pk))
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(self.to_bytes()).into_string()
    }

    pub fn to_string(&self) -> String {
        let mut sval = String::with_capacity(64);
        bs58::encode(self.to_bytes()).into(&mut sval).unwrap();
        sval.push_str(":ed25519");
        sval
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn to_jwk(&self) -> Result<String, Error> {
        unimplemented!();
    }

    pub fn to_x25519(&self) -> X25519PublicKey {
        let public = XPublicKey::from(
            CompressedEdwardsY(self.0.to_bytes())
                .decompress()
                .unwrap()
                .to_montgomery()
                .to_bytes(),
        );
        X25519PublicKey(public)
    }

    pub fn verify(&self, message: &[u8], signature: [u8; 64]) -> bool {
        self.0.verify_strict(message, &signature.into()).is_ok()
    }
}

impl KeyCapVerify for Ed25519PublicKey {
    fn key_verify(
        &self,
        data: &[u8],
        signature: &[u8],
        sig_type: Option<SignatureType>,
        sig_format: Option<SignatureFormat>,
    ) -> Result<bool, Error> {
        match sig_type {
            None | Some(SignatureType::Ed25519) => match sig_format {
                None | Some(SignatureFormat::Base58) => {
                    let mut sig = [0u8; 64];
                    bs58::decode(signature)
                        .into(&mut sig)
                        .map_err(|_| err_msg!("Invalid base58 signature"))?;
                    Ok(self.verify(data, sig))
                }
                #[allow(unreachable_patterns)]
                _ => Err(err_msg!(Unsupported, "Unsupported signature format")),
            },
            #[allow(unreachable_patterns)]
            _ => Err(err_msg!(Unsupported, "Unsupported signature type")),
        }
    }
}

impl TryFrom<&AnyPublicKey> for Ed25519PublicKey {
    type Error = Error;

    fn try_from(value: &AnyPublicKey) -> Result<Self, Self::Error> {
        if value.alg == KeyAlg::ED25519 {
            Self::from_bytes(&value.data)
        } else {
            Err(err_msg!(Unsupported, "Expected ed25519 key type"))
        }
    }
}

#[derive(Clone)]
pub struct X25519KeyPair(XSecretKey, XPublicKey);

impl X25519KeyPair {
    pub fn generate() -> Result<Self, Error> {
        let sk = XSecretKey::new(OsRng);
        let pk = XPublicKey::from(&sk);
        Ok(Self(sk, pk))
    }

    pub fn private_key(&self) -> SecretBytes {
        SecretBytes::from(self.0.to_bytes().to_vec())
    }

    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey(self.1.clone())
    }

    pub fn key_exchange_with(&self, pk: &X25519PublicKey) -> SecretBytes {
        let xk = self.0.diffie_hellman(&pk.0);
        SecretBytes::from(xk.as_bytes().to_vec())
    }

    pub fn from_bytes(pair: &[u8]) -> Result<Self, Error> {
        if pair.len() != KEYPAIR_LENGTH {
            return Err(err_msg!("Invalid keypair bytes"));
        }
        let sk: [u8; 32] = pair[..32].try_into().unwrap();
        let pk: [u8; 32] = pair[32..].try_into().unwrap();
        Ok(Self(XSecretKey::from(sk), XPublicKey::from(pk)))
    }

    pub fn to_bytes(&self) -> SecretBytes {
        let mut bytes = Vec::with_capacity(KEYPAIR_LENGTH);
        bytes.extend_from_slice(&self.0.to_bytes());
        bytes.extend_from_slice(self.1.as_bytes());
        SecretBytes::from(bytes)
    }
}

impl TryFrom<&AnyPrivateKey> for X25519KeyPair {
    type Error = Error;

    fn try_from(value: &AnyPrivateKey) -> Result<Self, Self::Error> {
        if value.alg == KeyAlg::X25519 {
            Self::from_bytes(value.data.as_ref())
        } else {
            Err(err_msg!(Unsupported, "Expected x25519 key type"))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X25519PublicKey(XPublicKey);

impl X25519PublicKey {
    pub fn from_str(key: impl AsRef<str>) -> Result<Self, Error> {
        let key = key.as_ref();
        let key = key.strip_suffix(":x25519").unwrap_or(key);
        let mut bval = [0u8; 32];
        bs58::decode(key)
            .into(&mut bval)
            .map_err(|_| err_msg!("Invalid base58 public key"))?;
        Self::from_bytes(bval)
    }

    pub fn from_bytes(pk: impl AsRef<[u8]>) -> Result<Self, Error> {
        let pk: [u8; 32] = pk
            .as_ref()
            .try_into()
            .map_err(|_| err_msg!("Invalid public key bytes"))?;
        Ok(Self(XPublicKey::from(pk)))
    }

    pub fn to_base58(&self) -> String {
        bs58::encode(self.to_bytes()).into_string()
    }

    pub fn to_string(&self) -> String {
        let mut sval = String::with_capacity(64);
        bs58::encode(self.to_bytes()).into(&mut sval).unwrap();
        sval.push_str(":x25519");
        sval
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl TryFrom<&AnyPublicKey> for X25519PublicKey {
    type Error = Error;

    fn try_from(value: &AnyPublicKey) -> Result<Self, Self::Error> {
        if value.alg == KeyAlg::X25519 {
            Self::from_bytes(&value.data)
        } else {
            Err(err_msg!(Unsupported, "Expected x25519 key type"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_keypair() {
        let seed = b"000000000000000000000000Trustee1";
        let test_sk = hex::decode("3030303030303030303030303030303030303030303030305472757374656531e33aaf381fffa6109ad591fdc38717945f8fabf7abf02086ae401c63e9913097").unwrap();

        let kp = Ed25519KeyPair::from_seed(seed).unwrap();
        assert_eq!(kp.to_bytes(), test_sk);

        // test round trip
        let cmp = Ed25519KeyPair::from_bytes(&test_sk).unwrap();
        assert_eq!(cmp.to_bytes(), test_sk);
    }

    #[test]
    fn ed25519_to_x25519() {
        let test_keypair = hex::decode("1c1179a560d092b90458fe6ab8291215a427fcd6b3927cb240701778ef55201927c96646f2d4632d4fc241f84cbc427fbc3ecaa95becba55088d6c7b81fc5bbf").unwrap();
        let x_sk = hex::decode("08e7286c232ec71b37918533ea0229bf0c75d3db4731df1c5c03c45bc909475f")
            .unwrap();
        let x_pk = hex::decode("9b4260484c889158c128796103dc8d8b883977f2ef7efb0facb12b6ca9b2ae3d")
            .unwrap();
        let x_pair = Ed25519KeyPair::from_bytes(&test_keypair)
            .unwrap()
            .to_x25519()
            .to_bytes();
        assert_eq!(&x_pair[..32], x_sk);
        assert_eq!(&x_pair[32..], x_pk);
    }

    #[test]
    fn test_sign() {
        let test_msg = b"This is a dummy message for use with tests";
        let test_sig =  hex::decode("451b5b8e8725321541954997781de51f4142e4a56bab68d24f6a6b92615de5eefb74134138315859a32c7cf5fe5a488bc545e2e08e5eedfd1fb10188d532d808").unwrap();

        let test_keypair = hex::decode("1c1179a560d092b90458fe6ab8291215a427fcd6b3927cb240701778ef55201927c96646f2d4632d4fc241f84cbc427fbc3ecaa95becba55088d6c7b81fc5bbf").unwrap();
        let kp = Ed25519KeyPair::from_bytes(&test_keypair).unwrap();
        let sig = kp.sign(&test_msg[..]);
        assert_eq!(sig, test_sig.as_slice());
        assert_eq!(kp.public_key().verify(&test_msg[..], sig), true);
        assert_eq!(kp.public_key().verify(b"Not the message", sig), false);
        assert_eq!(kp.public_key().verify(&test_msg[..], [0u8; 64]), false);
    }

    #[test]
    fn key_exchange_random() {
        let kp1 = X25519KeyPair::generate().unwrap();
        let kp2 = X25519KeyPair::generate().unwrap();
        assert_ne!(kp1.to_bytes(), kp2.to_bytes());

        let xch1 = kp1.key_exchange_with(&kp2.public_key());
        let xch2 = kp2.key_exchange_with(&kp1.public_key());
        assert_eq!(xch1, xch2);

        // test round trip
        let xch3 = X25519KeyPair::from_bytes(&kp1.to_bytes())
            .unwrap()
            .key_exchange_with(&kp2.public_key());
        assert_eq!(xch3, xch1);
    }
}
