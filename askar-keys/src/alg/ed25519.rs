use alloc::boxed::Box;
use core::convert::{TryFrom, TryInto};

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{ExpandedSecretKey, PublicKey, SecretKey, Signature, Signer};
use rand::rngs::OsRng;
use serde_json::json;
use sha2::{self, Digest};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XSecretKey};
use zeroize::Zeroize;

use super::x25519::X25519KeyPair;
use crate::{
    // any::{AnyPrivateKey, AnyPublicKey},
    buffer::{SecretBytes, WriteBuffer},
    caps::{KeyAlg, KeyCapSign, KeyCapVerify, SignatureType},
    error::Error,
};

// FIXME - check for low-order points when loading public keys?
// https://github.com/tendermint/tmkms/pull/279

pub const EDDSA_SIGNATURE_LENGTH: usize = 64;

pub const PUBLIC_KEY_LENGTH: usize = 32;
pub const SECRET_KEY_LENGTH: usize = 32;
pub const KEYPAIR_LENGTH: usize = 64;

// FIXME implement debug
pub struct Ed25519KeyPair(Box<Keypair>);

impl Ed25519KeyPair {
    pub fn generate() -> Result<Self, Error> {
        Ok(Self::from_secret_key(SecretKey::generate(&mut OsRng)))
    }

    pub fn from_seed(ikm: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_secret_key(
            SecretKey::from_bytes(ikm).map_err(|_| err_msg!("Invalid key material"))?,
        ))
    }

    pub fn from_keypair_bytes(kp: &[u8]) -> Result<Self, Error> {
        let kp = if kp.len() == 32 {
            Self::from_secret_key(
                SecretKey::from_bytes(kp).map_err(|_| err_msg!("Invalid keypair bytes"))?,
            )
        } else if kp.len() == KEYPAIR_LENGTH {
            let sk = SecretKey::from_bytes(kp).map_err(|_| err_msg!("Invalid keypair bytes"))?;
            let pk = PublicKey::from_bytes(kp).map_err(|_| err_msg!("Invalid keypair bytes"))?;
            Self(Box::new(Keypair {
                secret: Some(sk),
                public: pk,
            }))
        } else {
            return Err(err_msg!("Invalid keypair bytes"));
        };
        Ok(kp)
    }

    pub(crate) fn from_secret_key(sk: SecretKey) -> Self {
        let public = PublicKey::from(&sk);
        Self(Box::new(Keypair {
            secret: Some(sk),
            public,
        }))
    }

    pub fn keypair_bytes(&self) -> Option<SecretBytes> {
        SecretBytes::from(self.0.to_bytes().to_vec())
    }

    pub fn to_x25519(&self) -> X25519KeyPair {
        let hash = sha2::Sha512::digest(&self.0.secret.to_bytes()[..]);
        let output: [u8; 32] = (&hash[..32]).try_into().unwrap();
        // clamp result
        let secret = XSecretKey::from(output);
        let public = XPublicKey::from(&secret);
        X25519KeyPair::new(Some(secret), public)

        //     pub fn to_x25519(&self) -> X25519PublicKey {
        //         let public = XPublicKey::from(
        //             CompressedEdwardsY(self.0.to_bytes())
        //                 .decompress()
        //                 .unwrap()
        //                 .to_montgomery()
        //                 .to_bytes(),
        //         );
        //         X25519PublicKey(public)
        //     }
    }

    pub fn private_key_bytes(&self) -> Option<SecretBytes> {
        SecretBytes::from(self.0.secret.to_bytes().to_vec())
    }

    pub fn signing_key(&self) -> Option<Ed25519SigningKey<'_>> {
        self.0
            .secret
            .as_ref()
            .map(|sk| Ed25519SigningKey(ExpandedSecretKey::from(sk), &self.0.public))
    }

    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        if let Ok(sig) = Signature::try_from(signature) {
            self.0.public.verify_strict(message, &sig).is_ok()
        } else {
            false
        }
    }
}

impl Clone for Ed25519KeyPair {
    fn clone(&self) -> Self {
        Self(Box::new(Keypair {
            secret: self
                .0
                .secret
                .as_ref()
                .map(|sk| SecretKey::from_bytes(&sk.as_bytes()[..]).unwrap()),
            public: self.0.public.clone(),
        }))
    }
}

impl KeyCapSign for Ed25519KeyPair {
    fn key_sign<B: WriteBuffer>(
        &self,
        data: &[u8],
        sig_type: Option<SignatureType>,
        out: &mut B,
    ) -> Result<usize, Error> {
        match sig_type {
            None | Some(SignatureType::EdDSA) => {
                if let Some(signer) = self.signing_key() {
                    let sig = signer.sign(data);
                    out.extend_from_slice(&sig[..]);
                    Ok(EDDSA_SIGNATURE_LENGTH)
                } else {
                    Err(err_msg!(Unsupported, "Undefined private key"))
                }
            }
            #[allow(unreachable_patterns)]
            _ => Err(err_msg!(Unsupported, "Unsupported signature type")),
        }
    }
}

impl KeyCapVerify for Ed25519KeyPair {
    fn key_verify(
        &self,
        message: &[u8],
        signature: &[u8],
        sig_type: Option<SignatureType>,
    ) -> Result<bool, Error> {
        match sig_type {
            None | Some(SignatureType::EdDSA) => Ok(self.verify_signature(message, signature)),
            #[allow(unreachable_patterns)]
            _ => Err(err_msg!(Unsupported, "Unsupported signature type")),
        }
    }
}

struct Keypair {
    // SECURITY: SecretKey zeroizes on drop
    secret: Option<SecretKey>,
    public: PublicKey,
}

/// FIXME implement debug
// SECURITY: ExpandedSecretKey zeroizes on drop
pub struct Ed25519SigningKey<'p>(ExpandedSecretKey, &'p PublicKey);

impl Ed25519SigningKey<'_> {
    pub fn sign(&self, message: &[u8]) -> [u8; EDDSA_SIGNATURE_LENGTH] {
        self.0.sign(message, &self.1).to_bytes()
    }
}

// impl TryFrom<&AnyPrivateKey> for Ed25519KeyPair {
//     type Error = Error;

//     fn try_from(value: &AnyPrivateKey) -> Result<Self, Self::Error> {
//         if value.alg == KeyAlg::Ed25519 {
//             Self::from_bytes(value.data.as_ref())
//         } else {
//             Err(err_msg!(Unsupported, "Expected ed25519 key type"))
//         }
//     }
// }

// #[derive(Clone, Debug, PartialEq, Eq)]
// pub struct Ed25519PublicKey(PublicKey);

// impl Ed25519PublicKey {
//     pub fn from_str(key: impl AsRef<str>) -> Result<Self, Error> {
//         let key = key.as_ref();
//         let key = key.strip_suffix(":ed25519").unwrap_or(key);
//         let mut bval = [0u8; 32];
//         bs58::decode(key)
//             .into(&mut bval)
//             .map_err(|_| err_msg!("Invalid base58 public key"))?;
//         Self::from_bytes(bval)
//     }

//     pub fn from_bytes(pk: impl AsRef<[u8]>) -> Result<Self, Error> {
//         let pk =
//             PublicKey::from_bytes(pk.as_ref()).map_err(|_| err_msg!("Invalid public key bytes"))?;
//         Ok(Self(pk))
//     }

//     pub fn to_base58(&self) -> String {
//         bs58::encode(self.to_bytes()).into_string()
//     }

//     pub fn to_string(&self) -> String {
//         let mut sval = String::with_capacity(64);
//         bs58::encode(self.to_bytes()).into(&mut sval).unwrap();
//         sval.push_str(":ed25519");
//         sval
//     }

//     pub fn to_bytes(&self) -> [u8; 32] {
//         self.0.to_bytes()
//     }

//     pub fn to_jwk(&self) -> Result<serde_json::Value, Error> {
//         let x = base64::encode_config(self.to_bytes(), base64::URL_SAFE_NO_PAD);
//         Ok(json!({
//             "kty": "OKP",
//             "crv": "Ed25519",
//             "x": x,
//             "key_ops": ["verify"]
//         }))
//     }

//     pub fn to_x25519(&self) -> X25519PublicKey {
//         let public = XPublicKey::from(
//             CompressedEdwardsY(self.0.to_bytes())
//                 .decompress()
//                 .unwrap()
//                 .to_montgomery()
//                 .to_bytes(),
//         );
//         X25519PublicKey(public)
//     }

//     pub fn verify(&self, message: &[u8], signature: &[u8; EDDSA_SIGNATURE_LENGTH]) -> bool {
//         self.0.verify_strict(message, &signature.into()).is_ok()
//     }
// }

// impl KeyCapVerify for Ed25519PublicKey {
//     fn key_verify(
//         &self,
//         data: &[u8],
//         signature: &[u8],
//         sig_type: Option<SignatureType>,
//     ) -> Result<bool, Error> {
//         match sig_type {
//             None | Some(SignatureType::EdDSA) => {
//                 if let Ok(sig) = TryInto::<&[u8; EDDSA_SIGNATURE_LENGTH]>::try_into(signature) {
//                     Ok(self.verify(data, sig))
//                 } else {
//                     Ok(false)
//                 }
//             }
//             #[allow(unreachable_patterns)]
//             _ => Err(err_msg!(Unsupported, "Unsupported signature type")),
//         }
//     }
// }

// impl TryFrom<&AnyPublicKey> for Ed25519PublicKey {
//     type Error = Error;

//     fn try_from(value: &AnyPublicKey) -> Result<Self, Self::Error> {
//         if value.alg == KeyAlg::Ed25519 {
//             Self::from_bytes(&value.data)
//         } else {
//             Err(err_msg!(Unsupported, "Expected ed25519 key type"))
//         }
//     }
// }

// pub(super) fn encode_signature(
//     signature: &[u8],
//     sig_format: Option<SignatureFormat>,
// ) -> Result<Vec<u8>, Error> {
//     match sig_format {
//         None | Some(SignatureFormat::Base58) => Ok(bs58::encode(signature).into_vec()),
//         Some(SignatureFormat::Raw) => Ok(signature.to_vec()),
//         #[allow(unreachable_patterns)]
//         _ => Err(err_msg!(Unsupported, "Unsupported signature format")),
//     }
// }

// pub(super) fn decode_signature(
//     sig_input: &[u8],
//     sig_output: &mut impl AsMut<[u8]>,
//     sig_format: Option<SignatureFormat>,
// ) -> Result<(), Error> {
//     match sig_format {
//         None | Some(SignatureFormat::Base58) => {
//             bs58::decode(sig_input)
//                 .into(sig_output)
//                 .map_err(|_| err_msg!("Invalid base58 signature"))?;
//             Ok(())
//         }
//         Some(SignatureFormat::Raw) => {
//             if sig_input.len() != sig_output.as_mut().len() {
//                 return Err(err_msg!("Invalid raw signature"));
//             }
//             sig_output.as_mut().copy_from_slice(sig_input);
//             Ok(())
//         }
//         #[allow(unreachable_patterns)]
//         _ => Err(err_msg!(Unsupported, "Unsupported signature format")),
//     }
// }

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
    fn jwk_expected() {
        // from https://www.connect2id.com/blog/nimbus-jose-jwt-6
        // {
        //     "kty" : "OKP",
        //     "crv" : "Ed25519",
        //     "x"   : "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        //     "d"   : "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
        //     "use" : "sig",
        //     "kid" : "FdFYFzERwC2uCBB46pZQi4GG85LujR8obt-KWRBICVQ"
        //   }
        let test_pvt_b64 = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
        let test_pvt = base64::decode_config(test_pvt_b64, base64::URL_SAFE).unwrap();
        let sk = Ed25519KeyPair::from_bytes(&test_pvt).expect("Error creating signing key");
        let vk = sk.public_key();
        let jwk = vk.to_jwk().expect("Error converting public key to JWK");
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");
        assert_eq!(jwk["x"], "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
        assert_eq!(
            base64::encode_config(sk.private_key(), base64::URL_SAFE_NO_PAD),
            test_pvt_b64
        );
    }

    #[test]
    fn sign_verify_expected() {
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
