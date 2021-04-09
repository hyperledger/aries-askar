use alloc::boxed::Box;
use core::convert::TryInto;

use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret as SecretKey};
use zeroize::Zeroize;

use crate::{
    buffer::{SecretBytes, WriteBuffer},
    error::Error,
    jwk::{JwkEncoder, KeyToJwk, KeyToJwkPrivate},
};

pub const PUBLIC_KEY_LENGTH: usize = 32;
pub const SECRET_KEY_LENGTH: usize = 32;

#[derive(Clone)]
// FIXME implement zeroize
pub struct X25519KeyPair(Box<Keypair>);

impl X25519KeyPair {
    #[inline(always)]
    pub(crate) fn new(sk: Option<SecretKey>, pk: PublicKey) -> Self {
        Self(Box::new(Keypair { sk, pk }))
    }

    pub fn generate() -> Result<Self, Error> {
        let sk = SecretKey::new(OsRng);
        let pk = PublicKey::from(&sk);
        Ok(Self::new(Some(sk), pk))
    }

    pub fn key_exchange_with(&self, other: &Self) -> Option<SecretBytes> {
        match &self.0.sk {
            Some(sk) => {
                let xk = sk.diffie_hellman(&other.0.pk);
                Some(SecretBytes::from(xk.as_bytes().to_vec()))
            }
            None => None,
        }
    }

    pub fn from_public_key_bytes(key: &[u8]) -> Result<Self, Error> {
        if key.len() != PUBLIC_KEY_LENGTH {
            return Err(err_msg!("Invalid x25519 key length"));
        }
        Ok(Self::new(
            None,
            PublicKey::from(TryInto::<[u8; PUBLIC_KEY_LENGTH]>::try_into(key).unwrap()),
        ))
    }

    pub fn from_secret_key_bytes(key: &[u8]) -> Result<Self, Error> {
        if key.len() != SECRET_KEY_LENGTH {
            return Err(err_msg!("Invalid x25519 key length"));
        }
        let sk = SecretKey::from(TryInto::<[u8; SECRET_KEY_LENGTH]>::try_into(key).unwrap());
        let pk = PublicKey::from(&sk);
        Ok(Self::new(Some(sk), pk))
    }

    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0.pk.to_bytes()
    }

    pub fn secret_key_bytes(&self) -> Option<SecretBytes> {
        self.0
            .sk
            .as_ref()
            .map(|sk| SecretBytes::from_slice(&sk.to_bytes()[..]))
    }
}

impl KeyToJwk for X25519KeyPair {
    const KTY: &'static str = "OKP";

    fn to_jwk_buffer<B: WriteBuffer>(&self, buffer: &mut JwkEncoder<B>) -> Result<(), Error> {
        buffer.add_str("crv", "X25519")?;
        buffer.add_as_base58("x", &self.public_key_bytes()[..])?;
        buffer.add_str("use", "enc");
        Ok(())
    }
}

impl KeyToJwkPrivate for X25519KeyPair {
    fn to_jwk_buffer_private<B: WriteBuffer>(
        &self,
        buffer: &mut JwkEncoder<B>,
    ) -> Result<(), Error> {
        if let Some(sk) = self.0.sk.as_ref() {
            let mut sk = sk.to_bytes();
            buffer.add_str("crv", "X25519")?;
            buffer.add_as_base58("x", &self.public_key_bytes()[..])?;
            buffer.add_as_base58("d", &sk[..])?;
            sk.zeroize();
            Ok(())
        } else {
            self.to_jwk_buffer(buffer)
        }
    }
}

#[derive(Clone)]
struct Keypair {
    sk: Option<SecretKey>,
    pk: PublicKey,
}

// impl TryFrom<&AnyPrivateKey> for X25519KeyPair {
//     type Error = Error;

//     fn try_from(value: &AnyPrivateKey) -> Result<Self, Self::Error> {
//         if value.alg == KeyAlg::X25519 {
//             Self::from_bytes(value.data.as_ref())
//         } else {
//             Err(err_msg!(Unsupported, "Expected x25519 key type"))
//         }
//     }
// }

// #[derive(Clone, Debug, PartialEq, Eq)]
// pub struct X25519PublicKey(PublicKey);

// impl X25519PublicKey {
//     pub fn from_str(key: impl AsRef<str>) -> Result<Self, Error> {
//         let key = key.as_ref();
//         let key = key.strip_suffix(":x25519").unwrap_or(key);
//         let mut bval = [0u8; 32];
//         bs58::decode(key)
//             .into(&mut bval)
//             .map_err(|_| err_msg!("Invalid base58 public key"))?;
//         Self::from_bytes(bval)
//     }

//     pub fn from_bytes(pk: impl AsRef<[u8]>) -> Result<Self, Error> {
//         let pk: [u8; 32] = pk
//             .as_ref()
//             .try_into()
//             .map_err(|_| err_msg!("Invalid public key bytes"))?;
//         Ok(Self(XPublicKey::from(pk)))
//     }

//     pub fn to_base58(&self) -> String {
//         bs58::encode(self.to_bytes()).into_string()
//     }

//     pub fn to_jwk(&self) -> Result<serde_json::Value, Error> {
//         let x = base64::encode_config(self.to_bytes(), base64::URL_SAFE_NO_PAD);
//         Ok(json!({
//             "kty": "OKP",
//             "crv": "X25519",
//             "x": x,
//             "key_ops": ["deriveKey"]
//         }))
//     }

//     pub fn to_string(&self) -> String {
//         let mut sval = String::with_capacity(64);
//         bs58::encode(self.to_bytes()).into(&mut sval).unwrap();
//         sval.push_str(":x25519");
//         sval
//     }

//     pub fn to_bytes(&self) -> [u8; 32] {
//         self.0.to_bytes()
//     }
// }

// impl TryFrom<&AnyPublicKey> for X25519PublicKey {
//     type Error = Error;

//     fn try_from(value: &AnyPublicKey) -> Result<Self, Self::Error> {
//         if value.alg == KeyAlg::X25519 {
//             Self::from_bytes(&value.data)
//         } else {
//             Err(err_msg!(Unsupported, "Expected x25519 key type"))
//         }
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;

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
        let kp =
            X25519KeyPair::from_secret_key_bytes(&test_pvt).expect("Error creating signing key");
        let jwk = kp.to_jwk().expect("Error converting public key to JWK");
        let jwk = serde_json::to_value(&jwk).expect("Error parsing JWK output");
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "X25519");
        assert_eq!(jwk["x"], "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
        assert_eq!(jwk["d"].is_null(), true);

        let jwk = kp
            .to_jwk_private()
            .expect("Error converting private key to JWK");
        let jwk = serde_json::to_value(&jwk).expect("Error parsing JWK output");
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "X25519");
        assert_eq!(jwk["x"], "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
        assert_eq!(jwk["d"], test_pvt_b64);
    }

    #[test]
    fn key_exchange_random() {
        let kp1 = X25519KeyPair::generate().unwrap();
        let kp2 = X25519KeyPair::generate().unwrap();
        assert_ne!(kp1.to_jwk(), kp2.to_jwk());

        let xch1 = kp1.key_exchange_with(&kp2);
        let xch2 = kp2.key_exchange_with(&kp1);
        assert_eq!(xch1, xch2);

        // // test round trip
        // let xch3 = X25519KeyPair::from_bytes(&kp1.to_bytes())
        //     .unwrap()
        //     .key_exchange_with(&kp2.public_key());
        // assert_eq!(xch3, xch1);
    }
}
