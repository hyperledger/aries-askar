//! BLS12-381 key support

use core::{
    convert::TryInto,
    fmt::{self, Debug, Formatter},
    ops::Add,
};

use blake2::Digest;
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use group::GroupEncoding;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::generic_array::{
    typenum::{self, Unsigned, U144, U32, U48, U96},
    ArrayLength,
};

use super::{BlsCurves, HasKeyAlg, KeyAlg};
use crate::{
    buffer::ArrayKey,
    error::Error,
    jwk::{FromJwk, JwkEncoder, JwkParts, ToJwk},
    random::fill_random,
    repr::{KeyGen, KeyMeta, KeyPublicBytes, KeySecretBytes, KeypairMeta, Seed, SeedMethod},
};

/// The 'kty' value of a BLS key JWK
pub const JWK_KEY_TYPE: &'static str = "EC";

/// A BLS12-381 key pair
#[derive(Clone)]
pub struct BlsKeyPair<Pk: BlsPublicKeyType> {
    secret: Option<BlsSecretKey>,
    public: Pk::Buffer,
}

impl<Pk: BlsPublicKeyType> BlsKeyPair<Pk> {
    #[inline]
    fn from_secret_key(sk: BlsSecretKey) -> Self {
        let public = Pk::from_secret_scalar(&sk.0);
        Self {
            secret: Some(sk),
            public,
        }
    }
}

impl<Pk: BlsPublicKeyType> Debug for BlsKeyPair<Pk> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlsKeyPair")
            .field("crv", &Pk::JWK_CURVE)
            .field("secret", &self.secret)
            .field("public", &self.public)
            .finish()
    }
}

impl<Pk: BlsPublicKeyType> PartialEq for BlsKeyPair<Pk> {
    fn eq(&self, other: &Self) -> bool {
        other.secret == self.secret && other.public == self.public
    }
}

impl<Pk: BlsPublicKeyType> Eq for BlsKeyPair<Pk> {}

impl<Pk: BlsPublicKeyType> HasKeyAlg for BlsKeyPair<Pk> {
    fn algorithm(&self) -> KeyAlg {
        KeyAlg::Bls12_381(Pk::ALG_TYPE)
    }
}

impl<Pk: BlsPublicKeyType> KeyMeta for BlsKeyPair<Pk> {
    type KeySize = U32;
}

impl<Pk> KeypairMeta for BlsKeyPair<Pk>
where
    Pk: BlsPublicKeyType,
    U32: Add<Pk::BufferSize>,
    <U32 as Add<Pk::BufferSize>>::Output: ArrayLength<u8>,
{
    type PublicKeySize = Pk::BufferSize;
    type KeypairSize = typenum::Sum<Self::KeySize, Pk::BufferSize>;
}

impl<Pk: BlsPublicKeyType> KeyGen for BlsKeyPair<Pk> {
    fn generate() -> Result<Self, Error> {
        let secret = BlsSecretKey::generate()?;
        Ok(Self::from_secret_key(secret))
    }

    fn from_seed(seed: Seed<'_>) -> Result<Self, Error>
    where
        Self: Sized,
    {
        match seed {
            Seed::Bytes(ikm, SeedMethod::Preferred)
            | Seed::Bytes(ikm, SeedMethod::BlsKeyGenDraft4) => {
                Ok(Self::from_secret_key(BlsSecretKey::from_seed(ikm)?))
            }
            #[allow(unreachable_patterns)]
            _ => Err(err_msg!(Unsupported, "Unsupported seed method for BLS key")),
        }
    }
}

impl<Pk: BlsPublicKeyType> KeySecretBytes for BlsKeyPair<Pk> {
    fn from_secret_bytes(key: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let sk = BlsSecretKey::from_bytes(key)?;
        Ok(Self::from_secret_key(sk))
    }

    fn with_secret_bytes<O>(&self, f: impl FnOnce(Option<&[u8]>) -> O) -> O {
        if let Some(sk) = self.secret.as_ref() {
            let mut skb = Zeroizing::new(sk.0.to_bytes());
            skb.reverse(); // into big-endian
            f(Some(&*skb))
        } else {
            f(None)
        }
    }
}

impl<Pk: BlsPublicKeyType> KeyPublicBytes for BlsKeyPair<Pk> {
    fn from_public_bytes(key: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            secret: None,
            public: Pk::from_public_bytes(key)?,
        })
    }

    fn with_public_bytes<O>(&self, f: impl FnOnce(&[u8]) -> O) -> O {
        Pk::with_bytes(&self.public, None, f)
    }
}

impl<Pk: BlsPublicKeyType> ToJwk for BlsKeyPair<Pk> {
    fn encode_jwk(&self, enc: &mut JwkEncoder<'_>) -> Result<(), Error> {
        enc.add_str("crv", Pk::get_jwk_curve(enc.alg()))?;
        enc.add_str("kty", JWK_KEY_TYPE)?;
        Pk::with_bytes(&self.public, enc.alg(), |buf| enc.add_as_base64("x", buf))?;
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

impl<Pk: BlsPublicKeyType> FromJwk for BlsKeyPair<Pk> {
    fn from_jwk_parts(jwk: JwkParts<'_>) -> Result<Self, Error> {
        let pk = ArrayKey::<Pk::BufferSize>::temp(|arr| {
            if jwk.x.decode_base64(arr)? != arr.len() {
                Err(err_msg!(InvalidKeyData))
            } else {
                Pk::from_public_bytes(arr)
            }
        })?;
        let sk = if jwk.d.is_some() {
            Some(ArrayKey::<U32>::temp(|arr| {
                if jwk.d.decode_base64(arr)? != arr.len() {
                    Err(err_msg!(InvalidKeyData))
                } else {
                    BlsSecretKey::from_bytes(arr)
                }
            })?)
        } else {
            None
        };
        Ok(Self {
            secret: sk,
            public: pk,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
struct BlsSecretKey(Scalar);

impl BlsSecretKey {
    pub fn generate() -> Result<Self, Error> {
        let mut secret = Zeroizing::new([0u8; 64]);
        fill_random(&mut secret[..]);
        Ok(Self(Scalar::from_bytes_wide(&secret)))
    }

    // bls-signatures draft 4 version (incompatible with earlier)
    pub fn from_seed(ikm: &[u8]) -> Result<Self, Error> {
        const SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";
        if ikm.len() < 32 {
            return Err(err_msg!(Usage, "Insufficient length for seed"));
        }

        let mut salt = Sha256::digest(SALT);
        Ok(Self(loop {
            let mut okm = Zeroizing::new([0u8; 64]);
            let mut extract = hkdf::HkdfExtract::<Sha256>::new(Some(salt.as_ref()));
            extract.input_ikm(ikm);
            extract.input_ikm(&[0u8]);
            let (_, hkdf) = extract.finalize();
            hkdf.expand(&(48 as u16).to_be_bytes(), &mut okm[16..])
                .expect("HDKF extract failure");
            okm.reverse(); // into little endian
            let scalar = Scalar::from_bytes_wide(&okm);
            if scalar != Scalar::zero() {
                break scalar;
            }
            salt = Sha256::digest(salt.as_ref());
        }))
    }

    pub fn from_bytes(sk: &[u8]) -> Result<Self, Error> {
        if sk.len() != 32 {
            return Err(err_msg!(InvalidKeyData));
        }
        let mut skb = Zeroizing::new([0u8; 32]);
        skb.copy_from_slice(sk);
        skb.reverse(); // into little endian
        let result: Option<Scalar> = Scalar::from_bytes(&skb).into();
        Ok(Self(result.ok_or_else(|| err_msg!(InvalidKeyData))?))
    }
}

/// Trait implemented by supported BLS public key types
pub trait BlsPublicKeyType: 'static {
    /// The concrete key representation
    type Buffer: Clone + Debug + PartialEq + Sized;

    /// The size of the serialized public key
    type BufferSize: ArrayLength<u8>;

    /// The associated algorithm type
    const ALG_TYPE: BlsCurves;
    /// The associated JWK curve name
    const JWK_CURVE: &'static str;

    /// Get the JWK curve for a specific key algorithm
    fn get_jwk_curve(_alg: Option<KeyAlg>) -> &'static str {
        Self::JWK_CURVE
    }

    /// Initialize from the secret scalar
    fn from_secret_scalar(secret: &Scalar) -> Self::Buffer;

    /// Initialize from the compressed bytes
    fn from_public_bytes(key: &[u8]) -> Result<Self::Buffer, Error>;

    /// Access the bytes of the public key
    fn with_bytes<O>(buf: &Self::Buffer, alg: Option<KeyAlg>, f: impl FnOnce(&[u8]) -> O) -> O;
}

/// G1 curve
#[derive(Debug)]
pub struct G1;

impl BlsPublicKeyType for G1 {
    type Buffer = G1Affine;
    type BufferSize = U48;

    const ALG_TYPE: BlsCurves = BlsCurves::G1;
    const JWK_CURVE: &'static str = "BLS12381_G1";

    #[inline]
    fn from_secret_scalar(secret: &Scalar) -> Self::Buffer {
        G1Affine::from(G1Projective::generator() * secret)
    }

    fn from_public_bytes(key: &[u8]) -> Result<Self::Buffer, Error> {
        let buf: Option<G1Affine> = G1Affine::from_compressed(
            TryInto::<&[u8; 48]>::try_into(key).map_err(|_| err_msg!(InvalidKeyData))?,
        )
        .into();
        buf.ok_or_else(|| err_msg!(InvalidKeyData))
    }

    fn with_bytes<O>(buf: &Self::Buffer, _alg: Option<KeyAlg>, f: impl FnOnce(&[u8]) -> O) -> O {
        f(buf.to_bytes().as_ref())
    }
}

/// G2 curve
#[derive(Debug)]
pub struct G2;

impl BlsPublicKeyType for G2 {
    type Buffer = G2Affine;
    type BufferSize = U96;

    const ALG_TYPE: BlsCurves = BlsCurves::G2;
    const JWK_CURVE: &'static str = "BLS12381_G2";

    #[inline]
    fn from_secret_scalar(secret: &Scalar) -> Self::Buffer {
        G2Affine::from(G2Projective::generator() * secret)
    }

    fn from_public_bytes(key: &[u8]) -> Result<Self::Buffer, Error> {
        let buf: Option<G2Affine> = G2Affine::from_compressed(
            TryInto::<&[u8; 96]>::try_into(key).map_err(|_| err_msg!(InvalidKeyData))?,
        )
        .into();
        buf.ok_or_else(|| err_msg!(InvalidKeyData))
    }

    fn with_bytes<O>(buf: &Self::Buffer, _alg: Option<KeyAlg>, f: impl FnOnce(&[u8]) -> O) -> O {
        f(buf.to_bytes().as_ref())
    }
}

/// G1 + G2 curves
#[derive(Debug)]
pub struct G1G2;

impl BlsPublicKeyType for G1G2 {
    type Buffer = (G1Affine, G2Affine);
    type BufferSize = U144;

    const ALG_TYPE: BlsCurves = BlsCurves::G1G2;
    const JWK_CURVE: &'static str = "BLS12381_G1G2";

    fn get_jwk_curve(alg: Option<KeyAlg>) -> &'static str {
        if alg == Some(KeyAlg::Bls12_381(BlsCurves::G1)) {
            G1::JWK_CURVE
        } else if alg == Some(KeyAlg::Bls12_381(BlsCurves::G2)) {
            G2::JWK_CURVE
        } else {
            Self::JWK_CURVE
        }
    }

    #[inline]
    fn from_secret_scalar(secret: &Scalar) -> Self::Buffer {
        (
            G1Affine::from(G1Projective::generator() * secret),
            G2Affine::from(G2Projective::generator() * secret),
        )
    }

    fn from_public_bytes(key: &[u8]) -> Result<Self::Buffer, Error> {
        if key.len() != Self::BufferSize::USIZE {
            return Err(err_msg!(InvalidKeyData));
        }
        let g1: Option<G1Affine> =
            G1Affine::from_compressed(TryInto::<&[u8; 48]>::try_into(&key[..48]).unwrap()).into();
        let g2: Option<G2Affine> =
            G2Affine::from_compressed(TryInto::<&[u8; 96]>::try_into(&key[48..]).unwrap()).into();
        if let (Some(g1), Some(g2)) = (g1, g2) {
            Ok((g1, g2))
        } else {
            Err(err_msg!(InvalidKeyData))
        }
    }

    fn with_bytes<O>(buf: &Self::Buffer, alg: Option<KeyAlg>, f: impl FnOnce(&[u8]) -> O) -> O {
        if alg == Some(KeyAlg::Bls12_381(BlsCurves::G1)) {
            ArrayKey::<U48>::temp(|arr| {
                arr.copy_from_slice(buf.0.to_bytes().as_ref());
                f(&arr[..])
            })
        } else if alg == Some(KeyAlg::Bls12_381(BlsCurves::G2)) {
            ArrayKey::<U96>::temp(|arr| {
                arr.copy_from_slice(buf.1.to_bytes().as_ref());
                f(&arr[..])
            })
        } else {
            ArrayKey::<U144>::temp(|arr| {
                arr[0..48].copy_from_slice(buf.0.to_bytes().as_ref());
                arr[48..].copy_from_slice(buf.1.to_bytes().as_ref());
                f(&arr[..])
            })
        }
    }
}

impl From<&BlsKeyPair<G1G2>> for BlsKeyPair<G1> {
    fn from(kp: &BlsKeyPair<G1G2>) -> Self {
        BlsKeyPair {
            secret: kp.secret.clone(),
            public: kp.public.0.clone(),
        }
    }
}

impl From<&BlsKeyPair<G1G2>> for BlsKeyPair<G2> {
    fn from(kp: &BlsKeyPair<G1G2>) -> Self {
        BlsKeyPair {
            secret: kp.secret.clone(),
            public: kp.public.1.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repr::{ToPublicBytes, ToSecretBytes};
    use std::string::ToString;

    // test against EIP-2333 (as updated for signatures draft 4)
    #[test]
    fn key_gen_expected() {
        let seed = &hex!(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553
            1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
        let sk = BlsSecretKey::from_seed(&seed[..]).unwrap();
        let kp = BlsKeyPair::<G1>::from_secret_key(sk);
        let sk = kp.to_secret_bytes().unwrap();
        assert_eq!(
            sk.as_hex().to_string(),
            "0d7359d57963ab8fbbde1852dcf553fedbc31f464d80ee7d40ae683122b45070"
        );
    }

    #[test]
    fn g1_key_expected() {
        let sk = hex!("0d7359d57963ab8fbbde1852dcf553fedbc31f464d80ee7d40ae683122b45070");
        let kp = BlsKeyPair::<G1>::from_secret_bytes(&sk[..]).unwrap();
        let pk = kp.to_public_bytes().unwrap();
        assert_eq!(
            pk.as_hex().to_string(),
            "a2c975348667926acf12f3eecb005044e08a7a9b7d95f30bd281b55445107367a2e5d0558be7943c8bd13f9a1a7036fb"
        );
        assert_eq!(
            BlsKeyPair::<G1>::from_public_bytes(pk.as_ref())
                .unwrap()
                .to_public_bytes()
                .unwrap(),
            pk
        );
    }

    #[test]
    fn g2_key_expected() {
        let sk = hex!("0d7359d57963ab8fbbde1852dcf553fedbc31f464d80ee7d40ae683122b45070");
        let kp = BlsKeyPair::<G2>::from_secret_bytes(&sk[..]).unwrap();
        let pk = kp.to_public_bytes().unwrap();
        assert_eq!(
            pk.as_hex().to_string(),
            "a5e43d5ecb7b8c01ceb3b91f7413b628ef02c6859dc42a4354b21f9195531988a648655037faafd1bac2fd2d7d9466180baa3705a45a6c597853db51eaf431616057fd8049c6bee8764292f9a104200a45a63ceae9d3c368643ab9e5ff0f8810"
        );
        assert_eq!(
            BlsKeyPair::<G2>::from_public_bytes(pk.as_ref())
                .unwrap()
                .to_public_bytes()
                .unwrap(),
            pk
        );
    }

    #[test]
    fn g1g2_key_expected() {
        let sk = hex!("0d7359d57963ab8fbbde1852dcf553fedbc31f464d80ee7d40ae683122b45070");
        let kp = BlsKeyPair::<G1G2>::from_secret_bytes(&sk[..]).unwrap();
        let pk = kp.to_public_bytes().unwrap();
        assert_eq!(
            pk.as_hex().to_string(),
            "a2c975348667926acf12f3eecb005044e08a7a9b7d95f30bd281b55445107367a2e5d0558be7943c8bd13f9a1a7036fb\
            a5e43d5ecb7b8c01ceb3b91f7413b628ef02c6859dc42a4354b21f9195531988a648655037faafd1bac2fd2d7d9466180baa3705a45a6c597853db51eaf431616057fd8049c6bee8764292f9a104200a45a63ceae9d3c368643ab9e5ff0f8810"
        );
        assert_eq!(
            BlsKeyPair::<G1G2>::from_public_bytes(pk.as_ref())
                .unwrap()
                .to_public_bytes()
                .unwrap(),
            pk
        );
    }

    #[test]
    fn jwk_expected() {
        let test_pvt = &hex!("0d7359d57963ab8fbbde1852dcf553fedbc31f464d80ee7d40ae683122b45070");
        let test_pub_g1 = &hex!("a2c975348667926acf12f3eecb005044e08a7a9b7d95f30bd281b55445107367a2e5d0558be7943c8bd13f9a1a7036fb");
        let kp = BlsKeyPair::<G1>::from_secret_bytes(&test_pvt[..]).expect("Error creating key");

        let jwk = kp.to_jwk_public(None).expect("Error converting key to JWK");
        let jwk = JwkParts::from_str(&jwk).expect("Error parsing JWK");
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, G1::JWK_CURVE);
        assert_eq!(
            jwk.x,
            base64::encode_config(test_pub_g1, base64::URL_SAFE_NO_PAD).as_str()
        );
        assert_eq!(jwk.d, None);
        let pk_load = BlsKeyPair::<G1>::from_jwk_parts(jwk).unwrap();
        assert_eq!(kp.to_public_bytes(), pk_load.to_public_bytes());

        let jwk = kp.to_jwk_secret().expect("Error converting key to JWK");
        let jwk = JwkParts::from_slice(&jwk).expect("Error parsing JWK");
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, G1::JWK_CURVE);
        assert_eq!(
            jwk.x,
            base64::encode_config(test_pub_g1, base64::URL_SAFE_NO_PAD).as_str()
        );
        assert_eq!(
            jwk.d,
            base64::encode_config(test_pvt, base64::URL_SAFE_NO_PAD).as_str()
        );
        let _sk_load = BlsKeyPair::<G1>::from_jwk_parts(jwk).unwrap();
        // assert_eq!(
        //     kp.to_keypair_bytes().unwrap(),
        //     sk_load.to_keypair_bytes().unwrap()
        // );
    }
}
