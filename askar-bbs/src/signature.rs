use askar_crypto::alg::bls::{BlsKeyPair, G2};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::Field;
use group::Curve;
use rand::{CryptoRng, Rng};
use subtle::ConstantTimeEq;

use crate::{
    commitment::Commitment,
    error::Error,
    generators::Generators,
    util::{random_nonce, HashScalar},
    Blinding,
};

#[cfg(feature = "getrandom")]
use crate::util::default_rng;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message(pub(crate) Scalar);

impl Message {
    pub fn hash(input: impl AsRef<[u8]>) -> Self {
        Self(HashScalar::digest(input))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl From<Scalar> for Message {
    fn from(m: Scalar) -> Self {
        Self(m)
    }
}

impl From<u64> for Message {
    fn from(m: u64) -> Self {
        Self(m.into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
    a: G1Affine,
    e: Scalar,
    s: Scalar,
}

impl Signature {
    pub const SIZE: usize = 48 + 32 + 32;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[..48].copy_from_slice(&self.a.to_compressed()[..]);
        buf[48..80].copy_from_slice(&self.e.to_bytes()[..]);
        buf[80..].copy_from_slice(&self.s.to_bytes()[..]);
        buf
    }

    pub fn unblind(self, blinding: Blinding) -> Self {
        let Signature { a, e, s } = self;
        Self {
            a,
            e,
            s: s + blinding.0,
        }
    }
}

// TODO: buffer messages and use sum-of-products in batches
#[derive(Clone, Debug)]
pub struct SignatureMessages<'g, G: Generators> {
    accum: G1Projective,
    count: usize,
    generators: &'g G,
}

impl<'g, G: Generators> SignatureMessages<'g, G> {
    pub fn new(generators: &'g G) -> Self {
        Self {
            accum: G1Projective::generator(),
            count: 0,
            generators,
        }
    }

    pub fn from_commitment(commitment: Commitment, generators: &'g G) -> Self {
        Self {
            accum: G1Projective::generator() + commitment.0,
            count: 0,
            generators,
        }
    }
}

impl<G: Generators> SignatureMessages<'_, G> {
    pub fn push(&mut self, message: Message) -> Result<(), Error> {
        if self.count >= self.generators.message_count() {
            return Err(err_msg!(Usage, "Message index exceeds generator count"));
        }
        self.accum += self.generators.message(self.count) * message.0;
        self.count += 1;
        Ok(())
    }

    pub fn append(&mut self, messages: impl IntoIterator<Item = Message>) -> Result<(), Error> {
        for msg in messages {
            self.push(msg)?;
        }
        Ok(())
    }

    pub fn push_committed(&mut self, count: usize) -> Result<(), Error> {
        let c = self.count + count;
        if c > self.generators.message_count() {
            return Err(err_msg!(Usage, "Message index exceeds generator count"));
        }
        self.count = c;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.count
    }

    #[inline]
    fn get_b(&self, s: Scalar) -> Result<G1Projective, Error> {
        if self.count != self.generators.message_count() {
            return Err(err_msg!(
                Usage,
                "Message count does not match generator count"
            ));
        }
        Ok(self.accum + self.generators.blinding() * s)
    }

    #[cfg(feature = "getrandom")]
    pub fn sign(&self, signer_key: &BlsKeyPair<G2>) -> Result<Signature, Error> {
        self.sign_with_rng(signer_key, default_rng())
    }

    pub fn sign_with_rng(
        &self,
        signer_key: &BlsKeyPair<G2>,
        mut rng: impl CryptoRng + Rng,
    ) -> Result<Signature, Error> {
        let e = random_nonce(&mut rng);
        let s = random_nonce(&mut rng);
        self._sign(signer_key, e, s)
    }

    pub(crate) fn _sign(
        &self,
        signer_key: &BlsKeyPair<G2>,
        e: Scalar,
        s: Scalar,
    ) -> Result<Signature, Error> {
        let sk = signer_key
            .bls_secret_scalar()
            .ok_or_else(|| err_msg!(MissingSecretKey))?;
        if sk.is_zero() {
            return Err(err_msg!(MissingSecretKey));
        }
        if self.count != self.generators.message_count() {
            return Err(err_msg!(
                Usage,
                "Message count does not match generator count"
            ));
        }
        let b = self.get_b(s)?;
        let a = (b * (sk + e).invert().unwrap()).to_affine();
        Ok(Signature { a, e, s })
    }

    pub fn verify_signature(
        &self,
        pk: &BlsKeyPair<G2>,
        signature: &Signature,
    ) -> Result<bool, Error> {
        let b = self.get_b(signature.s)?.to_affine();
        Ok(pairing(
            &signature.a,
            &(G2Projective::generator() * signature.e + pk.bls_public_key()).to_affine(),
        )
        .ct_eq(&pairing(&b, &G2Affine::generator()))
        .into())
    }
}
