use core::convert::TryInto;

use askar_crypto::alg::bls::{BlsKeyPair, G2};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::Field;
use group::Curve;
use subtle::ConstantTimeEq;

use crate::{
    commitment::{Blinding, Commitment},
    error::Error,
    generators::Generators,
    hash::HashScalar,
    util::AccumG1,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message(pub(crate) Scalar);

impl Message {
    pub fn hash(input: impl AsRef<[u8]>) -> Self {
        Self(HashScalar::digest(input, None))
    }

    pub fn from_bytes(buf: &[u8; 32]) -> Result<Self, Error> {
        let mut b = *buf;
        b.reverse(); // into big-endian
        if let Some(s) = Scalar::from_bytes(&b).into() {
            Ok(Message(s))
        } else {
            Err(err_msg!(Usage, "Message bytes not in canonical format"))
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut b = self.0.to_bytes();
        b.reverse(); // into big-endian
        b
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
    pub(crate) a: G1Affine,
    pub(crate) e: Scalar,
    pub(crate) s: Scalar,
}

impl Signature {
    pub const SIZE: usize = 48 + 32 + 32;

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[..48].copy_from_slice(&self.a.to_compressed()[..]);
        buf[48..80].copy_from_slice(&self.e.to_bytes()[..]);
        buf[48..80].reverse(); // into big endian
        buf[80..].copy_from_slice(&self.s.to_bytes()[..]);
        buf[80..].reverse(); // into big endian
        buf
    }

    pub fn from_bytes(sig: impl AsRef<[u8]>) -> Result<Self, Error> {
        let buf = sig.as_ref();
        if buf.len() != Self::SIZE {
            return Err(err_msg!(InvalidSignature));
        }
        let a = G1Affine::from_compressed(&buf[..48].try_into().unwrap());
        let mut scalar: [u8; 32] = buf[48..80].try_into().unwrap();
        scalar.reverse(); // from big endian
        let e = Scalar::from_bytes(&scalar);
        scalar.copy_from_slice(&buf[80..]);
        scalar.reverse(); // from big endian
        let s = Scalar::from_bytes(&scalar);
        if let (Some(a), Some(e), Some(s)) = (a.into(), e.into(), s.into()) {
            Ok(Self { a, e, s })
        } else {
            Err(err_msg!(InvalidSignature))
        }
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

#[derive(Clone, Debug)]
pub struct SignatureBuilder<'g, G: Generators> {
    accum_b: AccumG1,
    generators: &'g G,
    hash_es: HashScalar<'static>,
    key: &'g BlsKeyPair<G2>,
    message_count: usize,
}

impl<'g, G: Generators> SignatureBuilder<'g, G> {
    pub fn new(generators: &'g G, key: &'g BlsKeyPair<G2>) -> Self {
        Self::from_accum(generators, key, G1Projective::generator())
    }

    pub fn from_commitment(
        generators: &'g G,
        key: &'g BlsKeyPair<G2>,
        commitment: Commitment,
    ) -> Self {
        Self::from_accum(generators, key, G1Projective::generator() + commitment.0)
    }

    #[inline]
    fn from_accum(generators: &'g G, key: &'g BlsKeyPair<G2>, sum: G1Projective) -> Self {
        Self {
            accum_b: AccumG1::new_with(sum),
            generators,
            hash_es: HashScalar::new_with_input(&sum.to_affine().to_compressed(), None),
            key,
            message_count: 0,
        }
    }
}

impl<G: Generators> SignatureBuilder<'_, G> {
    pub fn push_message(&mut self, message: Message) -> Result<(), Error> {
        let c = self.message_count;
        if c >= self.generators.message_count() {
            return Err(err_msg!(Usage, "Message index exceeds generator count"));
        }
        self.accum_b.push(self.generators.message(c), message.0);
        self.hash_es.update(&message.0.to_bytes());
        self.message_count = c + 1;
        Ok(())
    }

    pub fn append_messages(
        &mut self,
        messages: impl IntoIterator<Item = Message>,
    ) -> Result<(), Error> {
        for msg in messages {
            self.push_message(msg)?;
        }
        Ok(())
    }

    pub fn push_committed_count(&mut self, count: usize) -> Result<(), Error> {
        let c = self.message_count + count;
        if c > self.generators.message_count() {
            return Err(err_msg!(Usage, "Message index exceeds generator count"));
        }
        self.message_count = c;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.message_count
    }

    pub fn sign(self) -> Result<Signature, Error> {
        if self.message_count != self.generators.message_count() {
            return Err(err_msg!(
                Usage,
                "Message count does not match generator count"
            ));
        }
        let sk = self
            .key
            .bls_secret_scalar()
            .ok_or_else(|| err_msg!(MissingSecretKey))?;
        if sk.is_zero().into() {
            return Err(err_msg!(MissingSecretKey));
        }
        let mut hash_es = self.hash_es.clone();
        hash_es.update(sk.to_bytes());
        let mut hash_read = hash_es.finalize();
        let e = hash_read.next();
        let s = hash_read.next();
        let b = self.accum_b.sum_with(self.generators.blinding(), s);
        let a = (b * (sk + e).invert().unwrap()).to_affine();
        Ok(Signature { a, e, s })
    }
}

#[derive(Clone, Debug)]
pub struct SignatureVerifier<'g, G: Generators> {
    accum_b: AccumG1,
    generators: &'g G,
    key: &'g BlsKeyPair<G2>,
    message_count: usize,
}

impl<'g, G: Generators> SignatureVerifier<'g, G> {
    pub fn new(generators: &'g G, key: &'g BlsKeyPair<G2>) -> Self {
        Self {
            accum_b: AccumG1::new_with(G1Projective::generator()),
            generators,
            key,
            message_count: 0,
        }
    }
}

impl<G: Generators> SignatureVerifier<'_, G> {
    pub fn push_message(&mut self, message: Message) -> Result<(), Error> {
        let c = self.message_count;
        if c >= self.generators.message_count() {
            return Err(err_msg!(Usage, "Message index exceeds generator count"));
        }
        self.accum_b.push(self.generators.message(c), message.0);
        self.message_count = c + 1;
        Ok(())
    }

    pub fn append_messages(
        &mut self,
        messages: impl IntoIterator<Item = Message>,
    ) -> Result<(), Error> {
        for msg in messages {
            self.push_message(msg)?;
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.message_count
    }

    pub fn verify(&self, signature: &Signature) -> Result<(), Error> {
        if self.message_count != self.generators.message_count() {
            return Err(err_msg!(
                Usage,
                "Message count does not match generator count"
            ));
        }
        let b = self
            .accum_b
            .sum_with(self.generators.blinding(), signature.s);
        let valid: bool = pairing(
            &signature.a,
            &(G2Projective::generator() * signature.e + self.key.bls_public_key()).to_affine(),
        )
        .ct_eq(&pairing(&b.to_affine(), &G2Affine::generator()))
        .into();
        if valid {
            Ok(())
        } else {
            Err(err_msg!(InvalidSignature))
        }
    }
}
