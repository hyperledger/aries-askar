use std::convert::TryFrom;

use digest::{
    generic_array::{typenum::U48, GenericArray},
    BlockInput, Digest,
};
use group::{
    prime::{PrimeCurveAffine, PrimeGroup},
    GroupEncoding,
};
use std::{convert::TryInto, iter::FromIterator, marker::PhantomData, ops::Mul};

use bls12_381::{
    hash_to_curve::{ExpandMessage, ExpandMsgXmd, HashToCurve, HashToField},
    pairing, G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar,
};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroize;

use crate::{
    error::Error,
    keys::any::{AnyPrivateKey, AnyPublicKey},
    keys::caps::{KeyAlg, KeyCapSign, KeyCapVerify, SignatureFormat, SignatureType},
    types::SecretBytes,
};

const SIG_SUITE_G1_SSWU_NUL: &'static [u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
const SIG_SUITE_G2_SSWU_NUL: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
const SIG_SUITE_G1_SSWU_AUG: &'static [u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_AUG_";
const SIG_SUITE_G2_SSWU_AUG: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_";
const SIG_SUITE_G1_SSWU_POP: &'static [u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
const SIG_SUITE_G2_SSWU_POP: &'static [u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

#[derive(Clone, Debug)]
pub struct Bls12PrivateKey(Scalar);

impl Bls12PrivateKey {
    pub fn generate() -> Result<Self, Error> {
        let mut secret = [0u8; 64];
        OsRng.fill_bytes(&mut secret);
        let inner = Scalar::from_bytes_wide(&secret);
        secret.zeroize();
        Ok(Self(inner))
    }

    // FIXME - this is the draft 7 version,
    // draft 10 hashes the salt and loops until a non-zero SK is found
    pub fn from_seed(ikm: &[u8]) -> Result<Self, Error> {
        const SALT: &[u8] = b"BLS-SIG-KEYGEN-SALT-";
        let mut okm = GenericArray::<u8, U48>::default();
        let mut extract = hkdf::HkdfExtract::<sha2::Sha256>::new(Some(SALT));
        extract.input_ikm(ikm);
        extract.input_ikm(&[0u8]);
        let (_, hkdf) = extract.finalize();
        hkdf.expand(&(48 as u16).to_be_bytes(), &mut okm)
            .expect("HDKF extract failure");
        let inner = Scalar::from_okm(&okm);
        Ok(Self(inner))
    }

    pub fn from_bytes(sk: &[u8]) -> Result<Self, Error> {
        if sk.len() != 32 {
            return Err(err_msg!("Invalid key length"));
        }
        let mut skb = [0u8; 32];
        skb.copy_from_slice(sk);
        skb.reverse();
        let result: Option<Scalar> = Scalar::from_bytes(&skb).into();
        // turn into little-endian format
        skb.zeroize();
        Ok(Self(
            result.ok_or_else(|| err_msg!("Invalid keypair bytes"))?,
        ))
    }

    pub fn to_bytes(&self) -> SecretBytes {
        let mut skb = self.0.to_bytes();
        // turn into big-endian format
        skb.reverse();
        let v = skb.to_vec();
        skb.zeroize();
        SecretBytes::from(v)
    }

    pub fn g1_public_key(&self) -> Bls12G1PublicKey {
        Bls12G1PublicKey(G1Affine::from(G1Projective::generator() * self.0))
    }

    pub fn g2_public_key(&self) -> Bls12G2PublicKey {
        Bls12G2PublicKey(G2Affine::from(G2Projective::generator() * self.0))
    }

    pub fn g1_sign_basic<H: BlockInput + Digest>(
        &self,
        message: &[u8],
        domain: Option<&[u8]>,
    ) -> Vec<u8> {
        <G2Affine as BlsSignBasic<ExpandMsgXmd<H>>>::sign(
            &self.0,
            message,
            domain.unwrap_or(SIG_SUITE_G1_SSWU_NUL),
        )
    }

    pub fn g2_sign_basic<H: BlockInput + Digest>(
        &self,
        message: &[u8],
        domain: Option<&[u8]>,
    ) -> Vec<u8> {
        <G1Affine as BlsSignBasic<ExpandMsgXmd<H>>>::sign(
            &self.0,
            message,
            domain.unwrap_or(SIG_SUITE_G2_SSWU_NUL),
        )
    }

    pub fn g1_sign_aug<H: BlockInput + Digest>(
        &self,
        message: &[u8],
        domain: Option<&[u8]>,
    ) -> Vec<u8> {
        <G2Affine as BlsSignAug<ExpandMsgXmd<H>>>::sign(
            &self.0,
            message,
            domain.unwrap_or(SIG_SUITE_G1_SSWU_AUG),
        )
    }

    pub fn g2_sign_aug<H: BlockInput + Digest>(
        &self,
        message: &[u8],
        domain: Option<&[u8]>,
    ) -> Vec<u8> {
        <G1Affine as BlsSignAug<ExpandMsgXmd<H>>>::sign(
            &self.0,
            message,
            domain.unwrap_or(SIG_SUITE_G2_SSWU_AUG),
        )
    }

    // pub fn verify(&self, message: &[u8], signature: [u8; 64]) -> bool {
    //     self.0.verify_strict(message, &signature.into()).is_ok()
    // }
}

trait HasSignature<X: ExpandMessage> {
    type SigPt;
    type Repr: AsRef<[u8]>;

    fn public_key(sk: &Scalar) -> Self;

    fn hash_to_point(message: &[u8], domain: &[u8]) -> Self::SigPt;

    fn create_signature(sk: &Scalar, pt: &Self::SigPt) -> Self::Repr;

    fn verify_signature(&self, sig: &[u8], pt: &Self::SigPt) -> bool;
}

impl<X: ExpandMessage> HasSignature<X> for G1Affine
where
    G2Projective: HashToCurve<X>,
{
    type SigPt = G2Projective;
    type Repr = <G2Affine as GroupEncoding>::Repr;

    fn public_key(sk: &Scalar) -> Self {
        G1Affine::from(G1Projective::generator() * sk)
    }

    fn hash_to_point(message: &[u8], domain: &[u8]) -> Self::SigPt {
        G2Projective::hash_to_curve(message, domain)
    }

    fn create_signature(sk: &Scalar, pt: &Self::SigPt) -> Self::Repr {
        G2Affine::from(pt * sk).to_bytes()
    }

    fn verify_signature(&self, sig: &[u8], pt: &G2Projective) -> bool {
        if let Some(sig) = <&[u8; 96]>::try_from(sig)
            .ok()
            .and_then(|arr| Option::<G2Affine>::from(G2Affine::from_compressed(arr)))
        {
            pairing(self, &G2Affine::from(pt)) == pairing(&G1Affine::generator(), &sig)
        } else {
            false
        }
    }
}

impl<X: ExpandMessage> HasSignature<X> for G2Affine
where
    G1Projective: HashToCurve<X>,
{
    type SigPt = G1Projective;
    type Repr = <G1Affine as GroupEncoding>::Repr;

    fn public_key(sk: &Scalar) -> Self {
        G2Affine::from(G2Projective::generator() * sk)
    }

    fn hash_to_point(message: &[u8], domain: &[u8]) -> Self::SigPt {
        G1Projective::hash_to_curve(message, domain)
    }

    fn create_signature(sk: &Scalar, pt: &Self::SigPt) -> Self::Repr {
        G1Affine::from(pt * sk).to_bytes()
    }

    fn verify_signature(&self, sig: &[u8], pt: &G1Projective) -> bool {
        if let Some(sig) = <&[u8; 48]>::try_from(sig)
            .ok()
            .and_then(|arr| Option::<G1Affine>::from(G1Affine::from_compressed(arr)))
        {
            pairing(&G1Affine::from(pt), self) == pairing(&sig, &G2Affine::generator())
        } else {
            false
        }
    }
}

trait BlsSignBasic<X: ExpandMessage> {
    type Pk: HasSignature<X> + GroupEncoding;

    fn sign(sk: &Scalar, message: &[u8], domain: &[u8]) -> Vec<u8> {
        let pt = Self::Pk::hash_to_point(message, domain);
        <Self::Pk as HasSignature<X>>::create_signature(sk, &pt)
            .as_ref()
            .to_vec()
    }

    fn verify(pk: &Self::Pk, sig: &[u8], message: &[u8], domain: &[u8]) -> bool {
        let q = Self::Pk::hash_to_point(&message, domain);
        pk.verify_signature(&sig, &q)
    }
}

impl<X: ExpandMessage, T> BlsSignBasic<X> for T
where
    T: HasSignature<X> + GroupEncoding,
{
    type Pk = Self;
}

fn augment_message(pk: &impl GroupEncoding, message: &[u8]) -> Vec<u8> {
    let pk = pk.to_bytes();
    let mut ext_msg = Vec::with_capacity(pk.as_ref().len() + message.len());
    ext_msg.extend_from_slice(&pk.as_ref());
    ext_msg.extend_from_slice(&message);
    ext_msg
}

trait BlsSignAug<X: ExpandMessage>: BlsSignBasic<X> {
    fn sign(sk: &Scalar, message: &[u8], domain: &[u8]) -> Vec<u8> {
        let pk = Self::Pk::public_key(sk);
        let ext_msg = augment_message(&pk, message);
        <Self as BlsSignBasic<X>>::sign(sk, &ext_msg, domain)
    }

    fn verify(pk: &Self::Pk, sig: &[u8], message: &[u8], domain: &[u8]) -> bool {
        let ext_msg = augment_message(pk, message);
        <Self as BlsSignBasic<X>>::verify(pk, sig, &ext_msg, domain)
    }
}

impl<X: ExpandMessage, T> BlsSignAug<X> for T where
    T: BlsSignBasic<X> + PrimeCurveAffine<Scalar = Scalar>
{
}

// impl KeyCapSign for Bls12PrivateKey {
//     fn key_sign(
//         &self,
//         data: &[u8],
//         sig_type: Option<SignatureType>,
//         sig_format: Option<SignatureFormat>,
//     ) -> Result<Vec<u8>, Error> {
//         match sig_type {
//             None | Some(SignatureType::Bls12_1381(G1)) => {
//                 let sig = self.sign(data);
//                 encode_signature(&sig, sig_format)
//             }
//             #[allow(unreachable_patterns)]
//             _ => Err(err_msg!(Unsupported, "Unsupported signature type")),
//         }
//     }
// }

// impl KeyCapVerify for Ed25519KeyPair {
//     fn key_verify(
//         &self,
//         data: &[u8],
//         signature: &[u8],
//         sig_type: Option<SignatureType>,
//         sig_format: Option<SignatureFormat>,
//     ) -> Result<bool, Error> {
//         match sig_type {
//             None | Some(SignatureType::EdDSA) => {
//                 let mut sig = [0u8; 64];
//                 decode_signature(signature, &mut sig, sig_format)?;
//                 Ok(self.verify(data, sig))
//             }
//             #[allow(unreachable_patterns)]
//             _ => Err(err_msg!(Unsupported, "Unsupported signature type")),
//         }
//     }
// }

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bls12G1PublicKey(G1Affine);

impl Bls12G1PublicKey {
    // pub fn from_str(key: impl AsRef<str>) -> Result<Self, Error> {
    //     let key = key.as_ref();
    //     let key = key.strip_suffix(":ed25519").unwrap_or(key);
    //     let mut bval = [0u8; 32];
    //     bs58::decode(key)
    //         .into(&mut bval)
    //         .map_err(|_| err_msg!("Invalid base58 public key"))?;
    //     Self::from_bytes(bval)
    // }

    // pub fn from_bytes(pk: impl AsRef<[u8]>) -> Result<Self, Error> {
    //     let pk =
    //         PublicKey::from_bytes(pk.as_ref()).map_err(|_| err_msg!("Invalid public key bytes"))?;
    //     Ok(Self(pk))
    // }

    // pub fn to_base58(&self) -> String {
    //     bs58::encode(self.to_bytes()).into_string()
    // }

    // pub fn to_string(&self) -> String {
    //     let mut sval = String::with_capacity(64);
    //     bs58::encode(self.to_bytes()).into(&mut sval).unwrap();
    //     sval.push_str(":ed25519");
    //     sval
    // }

    // pub fn to_bytes(&self) -> [u8; 32] {
    //     self.0.to_bytes()
    // }

    // pub fn to_jwk(&self) -> Result<serde_json::Value, Error> {
    //     let x = base64::encode_config(self.to_bytes(), base64::URL_SAFE_NO_PAD);
    //     Ok(json!({
    //         "kty": "OKP",
    //         "crv": "Ed25519",
    //         "x": x,
    //         "key_ops": ["verify"]
    //     }))
    // }

    pub fn verify_basic<H: BlockInput + Digest>(
        &self,
        signature: &[u8],
        message: &[u8],
        domain: Option<&[u8]>,
    ) -> bool {
        <G1Affine as BlsSignBasic<ExpandMsgXmd<H>>>::verify(
            &self.0,
            signature,
            message,
            domain.unwrap_or(SIG_SUITE_G2_SSWU_NUL),
        )
    }

    pub fn verify_aug<H: BlockInput + Digest>(
        &self,
        signature: &[u8],
        message: &[u8],
        domain: Option<&[u8]>,
    ) -> bool {
        <G1Affine as BlsSignAug<ExpandMsgXmd<H>>>::verify(
            &self.0,
            signature,
            message,
            domain.unwrap_or(SIG_SUITE_G2_SSWU_AUG),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bls12G2PublicKey(G2Affine);

impl Bls12G2PublicKey {
    pub fn verify_basic<H: BlockInput + Digest>(
        &self,
        signature: &[u8],
        message: &[u8],
        domain: Option<&[u8]>,
    ) -> bool {
        <G2Affine as BlsSignBasic<ExpandMsgXmd<H>>>::verify(
            &self.0,
            signature,
            message,
            domain.unwrap_or(SIG_SUITE_G1_SSWU_NUL),
        )
    }

    pub fn verify_aug<H: BlockInput + Digest>(
        &self,
        signature: &[u8],
        message: &[u8],
        domain: Option<&[u8]>,
    ) -> bool {
        <G2Affine as BlsSignAug<ExpandMsgXmd<H>>>::verify(
            &self.0,
            signature,
            message,
            domain.unwrap_or(SIG_SUITE_G1_SSWU_AUG),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint() {
        let mut secret = [0u8; 64];
        OsRng.fill_bytes(&mut secret);

        let sk = Scalar::from_bytes_wide(&secret);
        let pk_g1 = G1Affine::from(G1Affine::generator() * sk);
        let pk_g2 = G2Affine::from(G2Affine::generator() * sk);
        println!(
            "sk {}\ng1 {}\ng2: {}",
            hex::encode(sk.to_bytes()),
            hex::encode(pk_g1.to_compressed()),
            hex::encode(pk_g2.to_compressed())
        );

        let cross_0 = pairing(&G1Affine::generator(), &pk_g2);
        let cross_1 = pairing(&pk_g1, &G2Affine::generator());
        println!("gt_0 {:?}", cross_0);
        println!("gt_1 {:?}", cross_1);
        println!("eq {:?}", cross_0 == cross_1);

        assert!(false);
    }

    #[test]
    fn sig_basic_g1() {
        // test vectors from https://github.com/algorand/bls_sigs_ref/pull/7/files
        // First lines of test-vectors/sig_g1_basic/fips_186_3_B283
        let tests: &[(&str,&str,&str)] = &[
            ("067f27bbcecbad85277fa3629da11a24b2f19ba1e65a69d827fad430346c9d102e1b4452d04147c8133acc1e268490cd342a54065a1bd6470aabbad42fbddc54a9a76c68aceba397cb350327c5e6f5a6df0b5b5560f04700d536b384dd4b412e74fd1b8f782611e9426bf8ca77b2448d9a9f415bcfee30dda1ccb49737994f2d","0299ff06e019b5f78a1aec39706b22213abb601bd62b9979bf9bc89fb702e724e3ada994","89a67d9ba659d37eec881d172e04ae25b667dc5b98ab7967f889294e116be9089ded2b3b074ed80450735d3b2a3f237f"),
            ("44adcb7e2462247b44c59608cbe228ada574ecb9f6f38baf30e42b589fb9b157bb0560e5a2aa5523b71cc0d7f583b502bec45d9b8352f29ee1842f42a17a5b16136feaa2efa4a0ae306402940ecd6b71e57d1467c98e7960de2a97f88b43487e4f4016af1292381d70c18c7e6eed99a14cdeb5b3caf73688658e4c5b54c81e08","009c2804f8cab768248fb3fff8a055b3f4585c00de5c1615a19f9425b9432ea09afba8f2","978d59bb5a235726c7fef7823130729b1d638d1d8094d45b76b8f25437d09a79c07fd41b249f046ef55bb96ef6436ddb"),
            ("cffee6252c7eb6d91d8fe100a1e62f0ad9f862d78ca2b747a6c17b8c9ea8980dc239b3b673310e6e7483582399163e39d889abc1a613fe77849ebc09b4f7f4fe0688b8a9869ae918a88294c7ee199be50ee9460db14725ae70b449d0cb48f30e7d817ec02c0cd586119341dba0b74f0279330807cfccc99c8c340b72c1764a45","02e625a6bc6d0ce7c06231de827068bdb0abc8ffb57c82b35ee3a0f873b9473905974d34","8ee9e81799098380f1bb22ff1b9d625df88257033161463faa5a02fb42362d44deba1b76082f4be7e0bbefc68ff1f0e0"),
            ("d058ab5dc07228253707ef224897ea0fcd09c3d5cc91fdce9e03c1c59c53fb4596be2ed929c7455e67ac7f4891aed3eb06ad88f2c4aaaabff045b959f900d1019d706b60526375851bb891494e99995928e4cd51c9616aa651ec77bd7e398916bb9ed3156391bf7fb1e29181e2b011dae2edaf803607def2ac6b194929a57f45","0376ac24e1b86f8a55c052d92a0bdc6472fa03acdcdbccbf7c321ec0ccd97aa0a66b4181","8af01de91658881604f3f759f8fe6770c315beaa84ee5b3d05242dacdad44a2b6e1008455d44f91e5ca8222aea5b10e3"),
            ("c86f2cc7ab5df5cf1a236fd83792769474cef464032800ffe98a44cf29dbfb6f24088160eb31a11a382ff2a49f3e05e983462f5304272f96c0a002b69af3d233aebe867ee63fa46666760a6889d022c18645b491f8d71b6a3b6b4ef058e280cf625198715b64b025bf0449445d3dd7e1f27153926e617bd2c96638345431d1ed","02b50a6395fc02b9ac1841323de4520292f913519bc0d6a471aa28021322fc4dbcd7b802","a065875d636cb557fae8adb2b4e149f9670a9a76406d21912e73362a6d2b8e1c37078cda48555597a5348e4b952e6d3d"),
        ];
        for (message, sk_hex, expect_hex) in tests {
            let message = hex::decode(message).unwrap();
            let seed = hex::decode(sk_hex).unwrap();
            let sk = Bls12PrivateKey::from_seed(&seed).unwrap();
            let sig = sk.g1_sign_basic::<sha2::Sha256>(&message, None);
            assert!(sk
                .g2_public_key()
                .verify_basic::<sha2::Sha256>(&sig, &message, None));
            assert_eq!(&hex::encode(sig), expect_hex);
        }
    }

    #[test]
    fn sig_g2_basic() {
        // test vectors from https://github.com/algorand/bls_sigs_ref/pull/7/files
        // First lines of test-vectors/sig_g2_basic/fips_186_3_B283
        let tests: &[(&str,&str,&str)] = &[
            ("067f27bbcecbad85277fa3629da11a24b2f19ba1e65a69d827fad430346c9d102e1b4452d04147c8133acc1e268490cd342a54065a1bd6470aabbad42fbddc54a9a76c68aceba397cb350327c5e6f5a6df0b5b5560f04700d536b384dd4b412e74fd1b8f782611e9426bf8ca77b2448d9a9f415bcfee30dda1ccb49737994f2d","0299ff06e019b5f78a1aec39706b22213abb601bd62b9979bf9bc89fb702e724e3ada994","a9285367fc83373703663146c2a533c2ebcfdb71dda9f031bb20ca3b168908ff12fe5ae086e4e1e0f74e85cacf4f3ef20ed98849c4c8d45d0536d1759cd6208a5ba3d1966422a908ef344af4d4742b8b09fa88711b7d2c957bc073c0072ebdf7"),
            ("44adcb7e2462247b44c59608cbe228ada574ecb9f6f38baf30e42b589fb9b157bb0560e5a2aa5523b71cc0d7f583b502bec45d9b8352f29ee1842f42a17a5b16136feaa2efa4a0ae306402940ecd6b71e57d1467c98e7960de2a97f88b43487e4f4016af1292381d70c18c7e6eed99a14cdeb5b3caf73688658e4c5b54c81e08","009c2804f8cab768248fb3fff8a055b3f4585c00de5c1615a19f9425b9432ea09afba8f2","a287aa25075030d5741ad7707f68ea61fe0b965bebc7bf6bff49be60c104a7abdf2de75cd53b9beb64f90acf667851a007d0547a0e25068afd3c52a45e5bebe7a4ab1a4de9dbed8a25bee03468265169512d6755bf6cc8e53b90d2bafd10934d"),
            ("cffee6252c7eb6d91d8fe100a1e62f0ad9f862d78ca2b747a6c17b8c9ea8980dc239b3b673310e6e7483582399163e39d889abc1a613fe77849ebc09b4f7f4fe0688b8a9869ae918a88294c7ee199be50ee9460db14725ae70b449d0cb48f30e7d817ec02c0cd586119341dba0b74f0279330807cfccc99c8c340b72c1764a45","02e625a6bc6d0ce7c06231de827068bdb0abc8ffb57c82b35ee3a0f873b9473905974d34","b90b74be15b24343c7b0d8647ea4625bdba477fdee5b28e847ab451f19bba7b93abfb14a6fa3394dadc055e59bcb1fba056f721c4af27b6870371dde1750646e1a29194956b41a711c363a0fdc66609cdf812ec1e2a8723fe87acd1bae751704"),
            ("d058ab5dc07228253707ef224897ea0fcd09c3d5cc91fdce9e03c1c59c53fb4596be2ed929c7455e67ac7f4891aed3eb06ad88f2c4aaaabff045b959f900d1019d706b60526375851bb891494e99995928e4cd51c9616aa651ec77bd7e398916bb9ed3156391bf7fb1e29181e2b011dae2edaf803607def2ac6b194929a57f45","0376ac24e1b86f8a55c052d92a0bdc6472fa03acdcdbccbf7c321ec0ccd97aa0a66b4181","803e8f4be33388a272ff3a0f80986f7edd9ef35505d6754c2a63ca6a9296e0576f0b069b6761e9ae95006262f847e33b0cc660a0f0a05d19032e1a15d61c524da28869aa7aee963b4c35eaa8b2d4d3e4eeaa361619e8be911f97c5ef8c69df27"),
            ("c86f2cc7ab5df5cf1a236fd83792769474cef464032800ffe98a44cf29dbfb6f24088160eb31a11a382ff2a49f3e05e983462f5304272f96c0a002b69af3d233aebe867ee63fa46666760a6889d022c18645b491f8d71b6a3b6b4ef058e280cf625198715b64b025bf0449445d3dd7e1f27153926e617bd2c96638345431d1ed","02b50a6395fc02b9ac1841323de4520292f913519bc0d6a471aa28021322fc4dbcd7b802","8f8b7a649bb0eb1341eb9de65e94d9b3eade5173604a6b538771308d28d55d05615eb9dfd34a9e70dcf7f92c672854fa062d66edd7cb8b5391b799f2d4cf5cbd9555b61f26f4ab62b3589a0c4d9ee050597798cf7d6403a63403729de1b82e58"),
        ];
        for (message, sk_hex, expect_hex) in tests {
            let message = hex::decode(message).unwrap();
            let seed = hex::decode(sk_hex).unwrap();
            let sk = Bls12PrivateKey::from_seed(&seed).unwrap();
            let sig = sk.g2_sign_basic::<sha2::Sha256>(&message, None);
            assert!(sk
                .g1_public_key()
                .verify_basic::<sha2::Sha256>(&sig, &message, None));
            assert_eq!(&hex::encode(sig), expect_hex);
        }
    }

    #[test]
    fn sig_g1_aug() {
        // test vectors from https://github.com/algorand/bls_sigs_ref/pull/7/files
        // First lines of test-vectors/sig_g1_aug/fips_186_3_B283
        let tests: &[(&str,&str,&str)] = &[
            ("067f27bbcecbad85277fa3629da11a24b2f19ba1e65a69d827fad430346c9d102e1b4452d04147c8133acc1e268490cd342a54065a1bd6470aabbad42fbddc54a9a76c68aceba397cb350327c5e6f5a6df0b5b5560f04700d536b384dd4b412e74fd1b8f782611e9426bf8ca77b2448d9a9f415bcfee30dda1ccb49737994f2d","0299ff06e019b5f78a1aec39706b22213abb601bd62b9979bf9bc89fb702e724e3ada994","aaa1ba14a100902b89aa04239faadd48be036d118acbbc12fd7847bfc492534b77ded3b05fbf0a9fc863f77a2fed548d"),
            ("44adcb7e2462247b44c59608cbe228ada574ecb9f6f38baf30e42b589fb9b157bb0560e5a2aa5523b71cc0d7f583b502bec45d9b8352f29ee1842f42a17a5b16136feaa2efa4a0ae306402940ecd6b71e57d1467c98e7960de2a97f88b43487e4f4016af1292381d70c18c7e6eed99a14cdeb5b3caf73688658e4c5b54c81e08","009c2804f8cab768248fb3fff8a055b3f4585c00de5c1615a19f9425b9432ea09afba8f2","a648266d72c8c47293dda9ecefb9f7ec4eff5b1a7676b87b03e9cf3ab41cc985f787ce25c55c87a2d782f8827f46a3d4"),
            ("cffee6252c7eb6d91d8fe100a1e62f0ad9f862d78ca2b747a6c17b8c9ea8980dc239b3b673310e6e7483582399163e39d889abc1a613fe77849ebc09b4f7f4fe0688b8a9869ae918a88294c7ee199be50ee9460db14725ae70b449d0cb48f30e7d817ec02c0cd586119341dba0b74f0279330807cfccc99c8c340b72c1764a45","02e625a6bc6d0ce7c06231de827068bdb0abc8ffb57c82b35ee3a0f873b9473905974d34","a75a5dbdf03daba8467d50ad2af6b400becc3bcdcd89a72d8da94c5d8f44d3497758bcd58995e10570425cda4f58ee56"),
            ("d058ab5dc07228253707ef224897ea0fcd09c3d5cc91fdce9e03c1c59c53fb4596be2ed929c7455e67ac7f4891aed3eb06ad88f2c4aaaabff045b959f900d1019d706b60526375851bb891494e99995928e4cd51c9616aa651ec77bd7e398916bb9ed3156391bf7fb1e29181e2b011dae2edaf803607def2ac6b194929a57f45","0376ac24e1b86f8a55c052d92a0bdc6472fa03acdcdbccbf7c321ec0ccd97aa0a66b4181","ad256fbe6c2634f0ff3e374e8f28ea6784c57b458942b939972c4fa7cb2ea930d237b65a5b5be4ef81855a8e1fca4a06"),
            ("c86f2cc7ab5df5cf1a236fd83792769474cef464032800ffe98a44cf29dbfb6f24088160eb31a11a382ff2a49f3e05e983462f5304272f96c0a002b69af3d233aebe867ee63fa46666760a6889d022c18645b491f8d71b6a3b6b4ef058e280cf625198715b64b025bf0449445d3dd7e1f27153926e617bd2c96638345431d1ed","02b50a6395fc02b9ac1841323de4520292f913519bc0d6a471aa28021322fc4dbcd7b802","a676ae116b734121d9a0263a37da6bdc63b9cd60a97e98e45570ae2433a75ac323b396ec5a188fda20e86992301d28ed"),
        ];
        for (message, sk_hex, expect_hex) in tests {
            let message = hex::decode(message).unwrap();
            let seed = hex::decode(sk_hex).unwrap();
            let sk = Bls12PrivateKey::from_seed(&seed).unwrap();
            let sig = sk.g1_sign_aug::<sha2::Sha256>(&message, None);
            assert!(sk
                .g2_public_key()
                .verify_aug::<sha2::Sha256>(&sig, &message, None));
            assert_eq!(&hex::encode(sig), expect_hex);
        }
    }

    #[test]
    fn sig_g2_aug() {
        // test vectors from https://github.com/algorand/bls_sigs_ref/pull/7/files
        // First lines of test-vectors/sig_g2_aug/fips_186_3_B283
        let tests: &[(&str,&str,&str)] = &[
            ("067f27bbcecbad85277fa3629da11a24b2f19ba1e65a69d827fad430346c9d102e1b4452d04147c8133acc1e268490cd342a54065a1bd6470aabbad42fbddc54a9a76c68aceba397cb350327c5e6f5a6df0b5b5560f04700d536b384dd4b412e74fd1b8f782611e9426bf8ca77b2448d9a9f415bcfee30dda1ccb49737994f2d","0299ff06e019b5f78a1aec39706b22213abb601bd62b9979bf9bc89fb702e724e3ada994","905c02745f0f549b3c6e2c4f246a8f65a4062f8e3d82dc32a9c97607eac2ad749c01083e3e13cd573e8229e227d798861400b9ad2cfc91126059c1a097ae9762791e4940c5f11a686250f83565e78a111f2977bfad30ac15b5dc4828b34eb9d0"),
            ("44adcb7e2462247b44c59608cbe228ada574ecb9f6f38baf30e42b589fb9b157bb0560e5a2aa5523b71cc0d7f583b502bec45d9b8352f29ee1842f42a17a5b16136feaa2efa4a0ae306402940ecd6b71e57d1467c98e7960de2a97f88b43487e4f4016af1292381d70c18c7e6eed99a14cdeb5b3caf73688658e4c5b54c81e08","009c2804f8cab768248fb3fff8a055b3f4585c00de5c1615a19f9425b9432ea09afba8f2","aa16169aaaf4ea98f5a20d132dce6388f533c7f01ff7aaf015c9b78f6e1072a5642b3192119d7f169caca757e923b44b0381bf45909591455b750356fcdaba451f4293090322e5ddc9a3b17b91ed2550ec983314b7cc9f4f762dd57a07a8d4af"),
            ("cffee6252c7eb6d91d8fe100a1e62f0ad9f862d78ca2b747a6c17b8c9ea8980dc239b3b673310e6e7483582399163e39d889abc1a613fe77849ebc09b4f7f4fe0688b8a9869ae918a88294c7ee199be50ee9460db14725ae70b449d0cb48f30e7d817ec02c0cd586119341dba0b74f0279330807cfccc99c8c340b72c1764a45","02e625a6bc6d0ce7c06231de827068bdb0abc8ffb57c82b35ee3a0f873b9473905974d34","a1abbf78718265c73643ac29aa823c8a11b02c34562c2b06a4a449fd964e19c57341d90e44f2db2849bea7d06a32b5bf114c80312057dd9eb3f46b8466233c52abbd6131314f1d5ec8aa277b58bbd09cedcf15d98dac3f723c534d56c9fef01d"),
            ("d058ab5dc07228253707ef224897ea0fcd09c3d5cc91fdce9e03c1c59c53fb4596be2ed929c7455e67ac7f4891aed3eb06ad88f2c4aaaabff045b959f900d1019d706b60526375851bb891494e99995928e4cd51c9616aa651ec77bd7e398916bb9ed3156391bf7fb1e29181e2b011dae2edaf803607def2ac6b194929a57f45","0376ac24e1b86f8a55c052d92a0bdc6472fa03acdcdbccbf7c321ec0ccd97aa0a66b4181","a00990857bc78b952f7e1b8279de59ecad9b24367b6b03fa5d1d3bbf70d06e8895802faaefa41b514f3dae706d305a86048cd87a3d92da71979f220f4f6649fb6696804f581867b46961b1b10d368a4656386d6f0b52340902bd292157358445"),
            ("c86f2cc7ab5df5cf1a236fd83792769474cef464032800ffe98a44cf29dbfb6f24088160eb31a11a382ff2a49f3e05e983462f5304272f96c0a002b69af3d233aebe867ee63fa46666760a6889d022c18645b491f8d71b6a3b6b4ef058e280cf625198715b64b025bf0449445d3dd7e1f27153926e617bd2c96638345431d1ed","02b50a6395fc02b9ac1841323de4520292f913519bc0d6a471aa28021322fc4dbcd7b802","91f183d0c29ccf5cd8116ace89605a7ae0f4b6e980060dce7e87aa364b04506f59679e0c9d3305a8869ff067e39265780442756b48bcfc07eb5dd289b0fd4062e54d30cf0b4f9a5dd9dae41e7b2cb916266cd88e7c3380c638e9704a58ad025f"),
        ];
        for (message, sk_hex, expect_hex) in tests {
            let message = hex::decode(message).unwrap();
            let seed = hex::decode(sk_hex).unwrap();
            let sk = Bls12PrivateKey::from_seed(&seed).unwrap();
            let sig = sk.g2_sign_aug::<sha2::Sha256>(&message, None);
            assert!(sk
                .g1_public_key()
                .verify_aug::<sha2::Sha256>(&sig, &message, None));
            assert_eq!(&hex::encode(sig), expect_hex);
        }
    }
}
