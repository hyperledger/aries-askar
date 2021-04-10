use alloc::boxed::Box;
use core::{
    convert::{TryFrom, TryInto},
    fmt::{self, Debug, Formatter},
};

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{ExpandedSecretKey, PublicKey, SecretKey, Signature};
use rand::rngs::OsRng;
use sha2::{self, Digest};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XSecretKey};

use super::x25519::X25519KeyPair;
use crate::{
    // any::{AnyPrivateKey, AnyPublicKey},
    buffer::{SecretBytes, WriteBuffer},
    caps::{KeyCapSign, KeyCapVerify, SignatureType},
    error::Error,
    jwk::{JwkEncoder, KeyToJwk},
};

// FIXME - check for low-order points when loading public keys?
// https://github.com/tendermint/tmkms/pull/279

pub const EDDSA_SIGNATURE_LENGTH: usize = 64;

pub const PUBLIC_KEY_LENGTH: usize = 32;
pub const SECRET_KEY_LENGTH: usize = 32;
pub const KEYPAIR_LENGTH: usize = SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH;

pub static JWK_CURVE: &'static str = "Ed25519";

pub struct Ed25519KeyPair(Box<Keypair>);

impl Ed25519KeyPair {
    pub fn generate() -> Result<Self, Error> {
        Ok(Self::from_secret_key(SecretKey::generate(&mut OsRng)))
    }

    pub fn from_seed(ikm: &[u8]) -> Result<Self, Error> {
        Self::from_secret_key_bytes(ikm)
    }

    pub fn from_keypair_bytes(kp: &[u8]) -> Result<Self, Error> {
        if kp.len() != KEYPAIR_LENGTH {
            return Err(err_msg!("Invalid keypair bytes"));
        }
        let sk = SecretKey::from_bytes(&kp[..SECRET_KEY_LENGTH])
            .map_err(|_| err_msg!("Invalid ed25519 secret key bytes"))?;
        let pk = PublicKey::from_bytes(&kp[SECRET_KEY_LENGTH..])
            .map_err(|_| err_msg!("Invalid ed25519 public key bytes"))?;
        // FIXME: derive pk from sk and check value?

        Ok(Self(Box::new(Keypair {
            secret: Some(sk),
            public: pk,
        })))
    }

    pub fn from_public_key_bytes(key: &[u8]) -> Result<Self, Error> {
        if key.len() != PUBLIC_KEY_LENGTH {
            return Err(err_msg!("Invalid ed25519 public key length"));
        }
        Ok(Self(Box::new(Keypair {
            secret: None,
            public: PublicKey::from_bytes(key).map_err(|_| err_msg!("Invalid keypair bytes"))?,
        })))
    }

    pub fn from_secret_key_bytes(key: &[u8]) -> Result<Self, Error> {
        if key.len() != SECRET_KEY_LENGTH {
            return Err(err_msg!("Invalid ed25519 secret key length"));
        }
        let sk = SecretKey::from_bytes(key).expect("Error loading ed25519 key");
        Ok(Self::from_secret_key(sk))
    }

    #[inline]
    pub(crate) fn from_secret_key(sk: SecretKey) -> Self {
        let public = PublicKey::from(&sk);
        Self(Box::new(Keypair {
            secret: Some(sk),
            public,
        }))
    }

    pub fn to_keypair_bytes(&self) -> Option<SecretBytes> {
        if let Some(secret) = self.0.secret.as_ref() {
            let output = SecretBytes::new_with(KEYPAIR_LENGTH, |buf| {
                buf[..SECRET_KEY_LENGTH].copy_from_slice(secret.as_bytes());
                buf[SECRET_KEY_LENGTH..].copy_from_slice(self.0.public.as_bytes());
            });
            Some(output)
        } else {
            None
        }
    }

    pub fn to_public_key_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0.public.to_bytes()
    }

    pub fn to_secret_key_bytes(&self) -> Option<SecretBytes> {
        self.0
            .secret
            .as_ref()
            .map(|sk| SecretBytes::from_slice(sk.as_bytes()))
    }

    pub fn to_signing_key(&self) -> Option<Ed25519SigningKey<'_>> {
        self.0
            .secret
            .as_ref()
            .map(|sk| Ed25519SigningKey(ExpandedSecretKey::from(sk), &self.0.public))
    }

    pub fn to_x25519_keypair(&self) -> X25519KeyPair {
        if let Some(secret) = self.0.secret.as_ref() {
            let hash = sha2::Sha512::digest(secret.as_bytes());
            // clamp result
            let secret = XSecretKey::from(TryInto::<[u8; 32]>::try_into(&hash[..32]).unwrap());
            let public = XPublicKey::from(&secret);
            X25519KeyPair::new(Some(secret), public)
        } else {
            let public = XPublicKey::from(
                CompressedEdwardsY(self.0.public.to_bytes())
                    .decompress()
                    .unwrap()
                    .to_montgomery()
                    .to_bytes(),
            );
            X25519KeyPair::new(None, public)
        }
    }

    pub fn sign(&self, message: &[u8]) -> Option<[u8; EDDSA_SIGNATURE_LENGTH]> {
        self.to_signing_key().map(|sk| sk.sign(message))
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

impl Debug for Ed25519KeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519KeyPair")
            .field(
                "secret",
                if self.0.secret.is_some() {
                    &"<secret>"
                } else {
                    &"None"
                },
            )
            .field("public", &self.0.public)
            .finish()
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
                if let Some(signer) = self.to_signing_key() {
                    let sig = signer.sign(data);
                    out.extend_from_slice(&sig[..])?;
                    Ok(EDDSA_SIGNATURE_LENGTH)
                } else {
                    Err(err_msg!(Unsupported, "Undefined secret key"))
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

impl KeyToJwk for Ed25519KeyPair {
    const KTY: &'static str = "OKP";

    fn to_jwk_buffer<B: WriteBuffer>(&self, buffer: &mut JwkEncoder<B>) -> Result<(), Error> {
        buffer.add_str("crv", JWK_CURVE)?;
        buffer.add_as_base64("x", &self.to_public_key_bytes()[..])?;
        if buffer.is_secret() {
            if let Some(sk) = self.0.secret.as_ref() {
                buffer.add_as_base64("d", sk.as_bytes())?;
            }
        }
        buffer.add_str("use", "sig")?;
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_keypair() {
        let seed = b"000000000000000000000000Trustee1";
        let test_sk = &hex!("3030303030303030303030303030303030303030303030305472757374656531e33aaf381fffa6109ad591fdc38717945f8fabf7abf02086ae401c63e9913097");

        let kp = Ed25519KeyPair::from_seed(seed).unwrap();
        assert_eq!(kp.to_keypair_bytes().unwrap(), &test_sk[..]);

        // test round trip
        let cmp = Ed25519KeyPair::from_keypair_bytes(test_sk).unwrap();
        assert_eq!(cmp.to_keypair_bytes().unwrap(), &test_sk[..]);
    }

    #[test]
    fn ed25519_to_x25519() {
        let test_keypair = &hex!("1c1179a560d092b90458fe6ab8291215a427fcd6b3927cb240701778ef55201927c96646f2d4632d4fc241f84cbc427fbc3ecaa95becba55088d6c7b81fc5bbf");
        let x_sk = &hex!("08e7286c232ec71b37918533ea0229bf0c75d3db4731df1c5c03c45bc909475f");
        let x_pk = &hex!("9b4260484c889158c128796103dc8d8b883977f2ef7efb0facb12b6ca9b2ae3d");
        let x_pair = Ed25519KeyPair::from_keypair_bytes(test_keypair)
            .unwrap()
            .to_x25519_keypair()
            .to_keypair_bytes()
            .unwrap();
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
        let test_pub_b64 = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
        let test_pvt = base64::decode_config(test_pvt_b64, base64::URL_SAFE).unwrap();
        let kp =
            Ed25519KeyPair::from_secret_key_bytes(&test_pvt).expect("Error creating signing key");
        let jwk = kp.to_jwk().expect("Error converting public key to JWK");
        let jwk = jwk.to_parts().expect("Error parsing JWK output");
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv, JWK_CURVE);
        assert_eq!(jwk.x, "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");

        let jwk = kp
            .to_jwk_secret()
            .expect("Error converting private key to JWK");
        let jwk = jwk.to_parts().expect("Error parsing JWK output");
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv, JWK_CURVE);
        assert_eq!(jwk.x, test_pub_b64);
        assert_eq!(jwk.d, test_pvt_b64);
    }

    #[test]
    fn sign_verify_expected() {
        let test_msg = b"This is a dummy message for use with tests";
        let test_sig = &hex!(
            "451b5b8e8725321541954997781de51f4142e4a56bab68d24f6a6b92615de5ee
            fb74134138315859a32c7cf5fe5a488bc545e2e08e5eedfd1fb10188d532d808"
        );
        let test_keypair = &hex!(
            "1c1179a560d092b90458fe6ab8291215a427fcd6b3927cb240701778ef552019
            27c96646f2d4632d4fc241f84cbc427fbc3ecaa95becba55088d6c7b81fc5bbf"
        );
        let kp = Ed25519KeyPair::from_keypair_bytes(test_keypair).unwrap();
        let sig = &kp.sign(test_msg).unwrap();
        assert_eq!(sig, test_sig);
        assert_eq!(kp.verify_signature(test_msg, &sig[..]), true);
        assert_eq!(kp.verify_signature(b"Not the message", &sig[..]), false);
        assert_eq!(kp.verify_signature(test_msg, &[0u8; 64]), false);
    }

    #[test]
    fn round_trip_bytes() {
        let kp = Ed25519KeyPair::generate().unwrap();
        let cmp = Ed25519KeyPair::from_keypair_bytes(&kp.to_keypair_bytes().unwrap()).unwrap();
        assert_eq!(
            kp.to_keypair_bytes().unwrap(),
            cmp.to_keypair_bytes().unwrap()
        );
    }
}
