//! Ed25519 signature and verification key support

use core::fmt::{self, Debug, Formatter};

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{ExpandedSecretKey, PublicKey, SecretKey, Signature};
use sha2::Digest;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XSecretKey};

use super::{x25519::X25519KeyPair, AnyKey, KeyAlg};
use crate::{
    buffer::{ArrayKey, WriteBuffer},
    encrypt::KeyAeadInPlace,
    error::Error,
    generic_array::typenum::{U32, U64},
    jwk::{FromJwk, JwkEncoder, JwkParts, ToJwk},
    kdf::DynKeyExchange,
    random::KeyMaterial,
    repr::{KeyGen, KeyMeta, KeyPublicBytes, KeySecretBytes, KeypairBytes, KeypairMeta},
    sign::{KeySigVerify, KeySign, SignatureType},
};

/// The length of an EdDSA signature
pub const EDDSA_SIGNATURE_LENGTH: usize = 64;

/// The length of a public key in bytes
pub const PUBLIC_KEY_LENGTH: usize = 32;
/// The length of a secret key in bytes
pub const SECRET_KEY_LENGTH: usize = 32;
/// The length of a keypair in bytes
pub const KEYPAIR_LENGTH: usize = SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH;

/// The 'kty' value of an Ed25519 JWK
pub const JWK_KEY_TYPE: &str = "OKP";
/// The 'crv' value of an Ed25519 JWK
pub const JWK_CURVE: &str = "Ed25519";

/// An Ed25519 public key or keypair
pub struct Ed25519KeyPair {
    // SECURITY: SecretKey zeroizes on drop
    secret: Option<SecretKey>,
    public: PublicKey,
}

impl Ed25519KeyPair {
    #[inline]
    pub(crate) fn from_secret_key(sk: SecretKey) -> Self {
        let public = PublicKey::from(&sk);
        Self {
            secret: Some(sk),
            public,
        }
    }

    pub(crate) fn check_public_bytes(&self, pk: &[u8]) -> Result<(), Error> {
        if self.public.as_bytes().ct_eq(pk).into() {
            Ok(())
        } else {
            Err(err_msg!(InvalidKeyData, "invalid ed25519 keypair"))
        }
    }

    /// Create a signing key from the secret key
    pub fn to_signing_key(&self) -> Option<Ed25519SigningKey<'_>> {
        self.secret
            .as_ref()
            .map(|sk| Ed25519SigningKey(ExpandedSecretKey::from(sk), &self.public))
    }

    /// Convert this keypair to an X25519 keypair
    pub fn to_x25519_keypair(&self) -> X25519KeyPair {
        if let Some(secret) = self.secret.as_ref() {
            let hash = sha2::Sha512::digest(secret.as_bytes());
            // clamp result
            let secret = XSecretKey::from(TryInto::<[u8; 32]>::try_into(&hash[..32]).unwrap());
            let public = XPublicKey::from(&secret);
            X25519KeyPair::new(Some(secret), public)
        } else {
            let public = XPublicKey::from(
                CompressedEdwardsY(self.public.to_bytes())
                    .decompress()
                    .unwrap()
                    .to_montgomery()
                    .to_bytes(),
            );
            X25519KeyPair::new(None, public)
        }
    }

    /// Sign a message with the secret key
    pub fn sign(&self, message: &[u8]) -> Option<[u8; EDDSA_SIGNATURE_LENGTH]> {
        self.to_signing_key().map(|sk| sk.sign(message))
    }

    /// Verify a signature against the public key
    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        if let Ok(sig) = Signature::try_from(signature) {
            self.public.verify_strict(message, &sig).is_ok()
        } else {
            false
        }
    }
}

impl Clone for Ed25519KeyPair {
    fn clone(&self) -> Self {
        Self {
            secret: self
                .secret
                .as_ref()
                .map(|sk| SecretKey::from_bytes(&sk.as_bytes()[..]).unwrap()),
            public: self.public,
        }
    }
}

impl Debug for Ed25519KeyPair {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519KeyPair")
            .field(
                "secret",
                if self.secret.is_some() {
                    &"<secret>"
                } else {
                    &"None"
                },
            )
            .field("public", &self.public)
            .finish()
    }
}

impl KeyGen for Ed25519KeyPair {
    fn generate(rng: impl KeyMaterial) -> Result<Self, Error> {
        let sk = ArrayKey::<U32>::generate(rng);
        // NB: from_bytes is infallible if the slice is the right length
        Ok(Self::from_secret_key(
            SecretKey::from_bytes(sk.as_ref()).unwrap(),
        ))
    }
}

impl AnyKey for Ed25519KeyPair {
    fn algorithm(&self) -> KeyAlg {
        KeyAlg::Ed25519
    }
}

impl DynKeyExchange for Ed25519KeyPair {
    // default implementation
}

impl KeyMeta for Ed25519KeyPair {
    type KeySize = U32;
}

impl KeySecretBytes for Ed25519KeyPair {
    fn from_secret_bytes(key: &[u8]) -> Result<Self, Error> {
        if key.len() != SECRET_KEY_LENGTH {
            return Err(err_msg!(InvalidKeyData));
        }
        let sk = SecretKey::from_bytes(key).expect("Error loading ed25519 key");
        Ok(Self::from_secret_key(sk))
    }

    fn with_secret_bytes<O>(&self, f: impl FnOnce(Option<&[u8]>) -> O) -> O {
        f(self.secret.as_ref().map(|sk| &sk.as_bytes()[..]))
    }
}

impl KeypairMeta for Ed25519KeyPair {
    type PublicKeySize = U32;
    type KeypairSize = U64;
}

impl KeypairBytes for Ed25519KeyPair {
    fn from_keypair_bytes(kp: &[u8]) -> Result<Self, Error> {
        if kp.len() != KEYPAIR_LENGTH {
            return Err(err_msg!(InvalidKeyData));
        }
        // NB: this is infallible if the slice is the right length
        let result = Ed25519KeyPair::from_secret_bytes(&kp[..SECRET_KEY_LENGTH])?;
        result.check_public_bytes(&kp[SECRET_KEY_LENGTH..])?;
        Ok(result)
    }

    fn with_keypair_bytes<O>(&self, f: impl FnOnce(Option<&[u8]>) -> O) -> O {
        if let Some(secret) = self.secret.as_ref() {
            ArrayKey::<<Self as KeypairMeta>::KeypairSize>::temp(|arr| {
                arr[..SECRET_KEY_LENGTH].copy_from_slice(secret.as_bytes());
                arr[SECRET_KEY_LENGTH..].copy_from_slice(self.public.as_bytes());
                f(Some(&*arr))
            })
        } else {
            f(None)
        }
    }
}

impl KeyPublicBytes for Ed25519KeyPair {
    fn from_public_bytes(key: &[u8]) -> Result<Self, Error> {
        if key.len() != PUBLIC_KEY_LENGTH {
            return Err(err_msg!(InvalidKeyData));
        }
        Ok(Self {
            secret: None,
            public: PublicKey::from_bytes(key).map_err(|_| err_msg!(InvalidKeyData))?,
        })
    }

    fn with_public_bytes<O>(&self, f: impl FnOnce(&[u8]) -> O) -> O {
        f(&self.public.to_bytes()[..])
    }
}

impl KeyAeadInPlace for Ed25519KeyPair {
    // null impl
}

impl KeySign for Ed25519KeyPair {
    fn signature_length(&self, sig_type: Option<SignatureType>) -> Option<usize> {
        match sig_type {
            None | Some(SignatureType::EdDSA) => Some(EDDSA_SIGNATURE_LENGTH),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    fn write_signature(
        &self,
        message: &[u8],
        sig_type: Option<SignatureType>,
        out: &mut dyn WriteBuffer,
    ) -> Result<(), Error> {
        match sig_type {
            None | Some(SignatureType::EdDSA) => {
                if let Some(signer) = self.to_signing_key() {
                    let sig = signer.sign(message);
                    out.buffer_write(&sig[..])?;
                    Ok(())
                } else {
                    Err(err_msg!(MissingSecretKey))
                }
            }
            #[allow(unreachable_patterns)]
            _ => Err(err_msg!(Unsupported, "Unsupported signature type")),
        }
    }
}

impl KeySigVerify for Ed25519KeyPair {
    fn verify_signature(
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

impl ToJwk for Ed25519KeyPair {
    fn encode_jwk(&self, enc: &mut dyn JwkEncoder) -> Result<(), Error> {
        enc.add_str("crv", JWK_CURVE)?;
        enc.add_str("kty", JWK_KEY_TYPE)?;
        self.with_public_bytes(|buf| enc.add_as_base64("x", buf))?;
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

impl FromJwk for Ed25519KeyPair {
    fn from_jwk_parts(jwk: JwkParts<'_>) -> Result<Self, Error> {
        if jwk.kty != JWK_KEY_TYPE {
            return Err(err_msg!(InvalidKeyData, "Unsupported key type"));
        }
        if jwk.crv != JWK_CURVE {
            return Err(err_msg!(InvalidKeyData, "Unsupported key algorithm"));
        }
        ArrayKey::<U32>::temp(|pk_arr| {
            if jwk.x.decode_base64(pk_arr)? != pk_arr.len() {
                Err(err_msg!(InvalidKeyData))
            } else if jwk.d.is_some() {
                ArrayKey::<U32>::temp(|sk_arr| {
                    if jwk.d.decode_base64(sk_arr)? != sk_arr.len() {
                        Err(err_msg!(InvalidKeyData))
                    } else {
                        let kp = Ed25519KeyPair::from_secret_bytes(sk_arr)?;
                        kp.check_public_bytes(pk_arr)?;
                        Ok(kp)
                    }
                })
            } else {
                Ed25519KeyPair::from_public_bytes(pk_arr)
            }
        })
    }
}

/// An Ed25519 expanded secret key used for signing
// SECURITY: ExpandedSecretKey zeroizes on drop
pub struct Ed25519SigningKey<'p>(ExpandedSecretKey, &'p PublicKey);

impl Ed25519SigningKey<'_> {
    /// Sign a message with the secret key
    pub fn sign(&self, message: &[u8]) -> [u8; EDDSA_SIGNATURE_LENGTH] {
        self.0.sign(message, self.1).to_bytes()
    }
}

impl Debug for Ed25519SigningKey<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519SigningKey")
            .field("secret", &"<secret>")
            .field("public", &self.1)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repr::{DynPublicBytes, DynSecretBytes};

    #[test]
    fn expand_keypair() {
        let seed = b"000000000000000000000000Trustee1";
        let test_sk = &hex!("3030303030303030303030303030303030303030303030305472757374656531e33aaf381fffa6109ad591fdc38717945f8fabf7abf02086ae401c63e9913097");

        let kp = Ed25519KeyPair::from_secret_bytes(seed).unwrap();
        assert_eq!(kp.to_keypair_bytes().unwrap(), &test_sk[..]);
        assert_eq!(kp.to_secret_bytes().unwrap(), &seed[..]);

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
        let kp = Ed25519KeyPair::from_secret_bytes(&test_pvt).expect("Error creating signing key");
        let jwk = kp
            .to_jwk_public(None)
            .expect("Error converting public key to JWK");
        let jwk = JwkParts::from_str(&jwk).expect("Error parsing JWK output");
        assert_eq!(jwk.kty, JWK_KEY_TYPE);
        assert_eq!(jwk.crv, JWK_CURVE);
        assert_eq!(jwk.x, "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
        let pk_load = Ed25519KeyPair::from_jwk_parts(jwk).unwrap();
        assert_eq!(kp.to_public_bytes(), pk_load.to_public_bytes());

        let jwk = kp
            .to_jwk_secret(None)
            .expect("Error converting private key to JWK");
        let jwk = JwkParts::from_slice(&jwk).expect("Error parsing JWK output");
        assert_eq!(jwk.kty, JWK_KEY_TYPE);
        assert_eq!(jwk.crv, JWK_CURVE);
        assert_eq!(jwk.x, test_pub_b64);
        assert_eq!(jwk.d, test_pvt_b64);
        let sk_load = Ed25519KeyPair::from_jwk_parts(jwk).unwrap();
        assert_eq!(
            kp.to_keypair_bytes().unwrap(),
            sk_load.to_keypair_bytes().unwrap()
        );
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
        assert!(kp.verify_signature(test_msg, &sig[..]));
        assert!(!kp.verify_signature(b"Not the message", &sig[..]));
        assert!(!kp.verify_signature(test_msg, &[0u8; 64]));
    }

    #[test]
    fn round_trip_bytes() {
        let kp = Ed25519KeyPair::random().unwrap();
        let cmp = Ed25519KeyPair::from_keypair_bytes(&kp.to_keypair_bytes().unwrap()).unwrap();
        assert_eq!(
            kp.to_keypair_bytes().unwrap(),
            cmp.to_keypair_bytes().unwrap()
        );
    }
}
