#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use askar_crypto::{
    alg::bls::{BlsKeyPair, G2},
    buffer::WriteBuffer,
};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, Scalar};
use group::Curve;
use rand::{CryptoRng, Rng};
use subtle::ConstantTimeEq;

use crate::{
    commitment::Blinding,
    error::Error,
    generators::Generators,
    signature::{Message, Signature},
    util::{random_nonce, AccumG1, HashScalar, Nonce},
};

#[cfg(feature = "getrandom")]
use crate::util::default_rng;

pub type ProofChallenge = Nonce;

#[derive(Clone, Debug)]
pub struct ProverMessages<'g, G: Generators> {
    accum_b: AccumG1,
    count: usize,
    generators: &'g G,
    hidden: Vec<(G1Projective, Scalar, Blinding)>,
}

#[cfg(feature = "alloc")]
impl<'g, G: Generators> ProverMessages<'g, G> {
    pub fn new(generators: &'g G) -> Self {
        Self {
            accum_b: AccumG1::new_with(G1Projective::generator()),
            count: 0,
            generators,
            hidden: Vec::new(),
        }
    }
}

impl<G: Generators> ProverMessages<'_, G> {
    pub fn push_revealed(&mut self, message: Message) -> Result<(), Error> {
        let c = self.count;
        if c >= self.generators.message_count() {
            return Err(err_msg!(Usage, "Message index exceeds generator count"));
        }
        self.accum_b.push(self.generators.message(c), message.0);
        self.count = c + 1;
        Ok(())
    }

    pub fn append_revealed(
        &mut self,
        messages: impl IntoIterator<Item = Message>,
    ) -> Result<(), Error> {
        for msg in messages {
            self.push_revealed(msg)?;
        }
        Ok(())
    }

    #[cfg(feature = "getrandom")]
    pub fn push_hidden(&mut self, message: Message) -> Result<(), Error> {
        self.push_hidden_with(message, Blinding::new())
    }

    pub fn push_hidden_with(&mut self, message: Message, blinding: Blinding) -> Result<(), Error> {
        let c = self.count;
        if c >= self.generators.message_count() {
            return Err(err_msg!(Usage, "Message index exceeds generator count"));
        }
        let base = self.generators.message(c);
        self.hidden.push((base, message.0, blinding));
        self.accum_b.push(self.generators.message(c), message.0);
        self.count = c + 1;
        Ok(())
    }

    fn get_b(&self, s: Scalar) -> Result<G1Projective, Error> {
        if self.count != self.generators.message_count() {
            return Err(err_msg!(
                Usage,
                "Message count does not match generator count"
            ));
        }
        Ok(self.accum_b.sum_with(self.generators.blinding(), s))
    }

    #[cfg(feature = "getrandom")]
    pub fn prepare(&self, signature: &Signature) -> Result<SignatureProofContext, Error> {
        self.prepare_with_rng(signature, default_rng())
    }

    pub fn prepare_with_rng(
        &self,
        signature: &Signature,
        mut rng: impl CryptoRng + Rng,
    ) -> Result<SignatureProofContext, Error> {
        let Signature { a, e, s } = *signature;
        let b = self.get_b(s)?;
        let h0 = self.generators.blinding();
        let r1 = random_nonce(&mut rng);
        let r2 = random_nonce(&mut rng);
        let r3 = r1.invert().unwrap();
        let e_rand = random_nonce(&mut rng);
        let r2_rand = random_nonce(&mut rng);
        let r3_rand = random_nonce(&mut rng);
        let s_rand = random_nonce(&mut rng);

        let b_r1 = b * r1;
        let a_prime = a * r1;
        let a_bar = a_prime * (-e) + b_r1;
        let d = h0 * (-r2) + b_r1;
        let s_prime = s - r2 * r3;

        let c1 = AccumG1::calc(&[(a_prime, e_rand), (h0, r2_rand)]);
        let mut c2_accum = AccumG1::from(&[(d, r3_rand), (h0, s_rand)][..]);

        let mut hidden = Vec::new();
        for (base, msg, blinding) in self.hidden.iter() {
            c2_accum.push(*base, blinding.0);
            hidden.push((*base, *msg, *blinding));
        }

        let mut cvals = [G1Affine::identity(); 5];
        G1Projective::batch_normalize(&[a_prime, a_bar, d, c1, c2_accum.sum()], &mut cvals[..]);

        Ok(SignatureProofContext {
            cvals: ChallengeValues {
                a_prime: cvals[0],
                a_bar: cvals[1],
                d: cvals[2],
                c1: cvals[3],
                c2: cvals[4],
            },
            e,
            e_rand,
            r2,
            r2_rand,
            r3,
            r3_rand,
            s_prime,
            s_rand,
            h0,
            hidden,
        })
    }
}

#[derive(Clone, Debug)]
pub struct SignatureProofContext {
    cvals: ChallengeValues,
    e: Scalar,
    e_rand: Scalar,
    r2: Scalar,
    r2_rand: Scalar,
    r3: Scalar,
    r3_rand: Scalar,
    s_prime: Scalar,
    s_rand: Scalar,
    h0: G1Projective, // TODO h0 only used in challenge, currently
    hidden: Vec<(G1Projective, Scalar, Blinding)>, // TODO base only used in challenge, currently
}

impl SignatureProofContext {
    pub fn complete(&self, challenge: ProofChallenge) -> Result<SignatureProof, Error> {
        let c = challenge.0;
        let hidden_resp = self
            .hidden
            .iter()
            .map(|(_base, msg, m_rand)| m_rand.0 - c * msg)
            .collect();
        Ok(SignatureProof {
            cvals: self.cvals,
            e_resp: self.e_rand + c * self.e,
            r2_resp: self.r2_rand - c * self.r2,
            r3_resp: self.r3_rand + c * self.r3,
            s_resp: self.s_rand - c * self.s_prime,
            hidden_resp,
        })
    }

    pub fn create_challenge(&self, nonce: Nonce) -> ProofChallenge {
        let mut c_hash = HashScalar::new();
        self.write_challenge_bytes(&mut c_hash).unwrap();
        c_hash.update(&nonce.0.to_bytes());
        Nonce(c_hash.finalize())
    }

    pub fn write_challenge_bytes<W>(&self, writer: &mut W) -> Result<(), askar_crypto::Error>
    where
        W: WriteBuffer,
    {
        self.cvals.write_challenge_bytes(
            self.h0,
            self.hidden.iter().map(|(base, _, _)| *base),
            writer,
        )
    }
}

#[derive(Clone, Copy, Debug)]
struct ChallengeValues {
    a_prime: G1Affine,
    a_bar: G1Affine,
    d: G1Affine,
    c1: G1Affine,
    c2: G1Affine,
}

impl ChallengeValues {
    pub fn write_challenge_bytes<W, H>(
        &self,
        h0: G1Projective,
        hi: H,
        writer: &mut W,
    ) -> Result<(), askar_crypto::Error>
    where
        W: WriteBuffer,
        H: IntoIterator<Item = G1Projective>,
    {
        writer.buffer_write(&self.a_bar.to_uncompressed())?;
        writer.buffer_write(&self.a_prime.to_uncompressed())?;
        writer.buffer_write(&h0.to_affine().to_uncompressed())?;
        writer.buffer_write(&self.c1.to_uncompressed())?;
        writer.buffer_write(&self.d.to_uncompressed())?;
        writer.buffer_write(&h0.to_affine().to_uncompressed())?;
        for h in hi {
            writer.buffer_write(&h.to_affine().to_uncompressed())?;
        }
        writer.buffer_write(&self.c2.to_uncompressed())?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct SignatureProof {
    cvals: ChallengeValues,
    e_resp: Scalar,
    r2_resp: Scalar,
    r3_resp: Scalar,
    s_resp: Scalar,
    hidden_resp: Vec<Scalar>,
}

impl SignatureProof {
    pub fn verify<G: Generators>(
        &self,
        keypair: &BlsKeyPair<G2>,
        messages: &VerifierMessages<G>,
        challenge: ProofChallenge,
    ) -> Result<bool, Error> {
        if messages.hidden.len() != self.hidden_resp.len() {
            return Err(err_msg!(
                InvalidProof,
                "Number of hidden messages does not correspond with responses"
            ));
        }

        let ChallengeValues {
            a_prime,
            a_bar,
            d,
            c1,
            c2,
        } = self.cvals;

        let h0 = messages.generators.blinding();
        let check_c1 = AccumG1::calc(&[
            (a_prime.into(), self.e_resp),
            (h0, self.r2_resp),
            (G1Projective::from(a_bar) - d, challenge.0),
        ]);

        let mut c2_accum = AccumG1::from(
            &[
                (d.into(), self.r3_resp),
                (h0, self.s_resp),
                (
                    G1Projective::generator() + messages.accum_reveal()?,
                    -challenge.0,
                ),
            ][..],
        );
        for (base, resp) in messages
            .hidden
            .iter()
            .copied()
            .zip(self.hidden_resp.iter().copied())
        {
            c2_accum.push(base, resp);
        }

        let mut checks = [G1Affine::identity(); 2];
        G1Projective::batch_normalize(&[check_c1, c2_accum.sum()], &mut checks[..]);

        let check_pair = pairing(&a_prime, keypair.bls_public_key())
            .ct_eq(&pairing(&a_bar, &G2Affine::generator()));

        Ok(
            (!a_prime.is_identity() & checks[0].ct_eq(&c1) & checks[1].ct_eq(&c2) & check_pair)
                .into(),
        )
    }

    pub fn create_challenge<G: Generators>(
        &self,
        messages: &VerifierMessages<G>,
        nonce: Nonce,
    ) -> ProofChallenge {
        let mut c_hash = HashScalar::new();
        self.write_challenge_bytes(messages, &mut c_hash).unwrap();
        c_hash.update(&nonce.0.to_bytes());
        Nonce(c_hash.finalize())
    }

    pub fn write_challenge_bytes<G: Generators, W: WriteBuffer>(
        &self,
        messages: &VerifierMessages<G>,
        writer: &mut W,
    ) -> Result<(), askar_crypto::Error> {
        self.cvals.write_challenge_bytes(
            messages.generators.blinding(),
            messages.hidden.iter().copied(),
            writer,
        )
    }
}

#[derive(Clone, Debug)]
pub struct VerifierMessages<'g, G: Generators> {
    accum_reveal: AccumG1,
    count: usize,
    generators: &'g G,
    hidden: Vec<G1Projective>,
}

impl<'g, G: Generators> VerifierMessages<'g, G> {
    pub fn new(generators: &'g G) -> Self {
        Self {
            accum_reveal: AccumG1::zero(),
            count: 0,
            generators,
            hidden: Vec::new(),
        }
    }
}

impl<G: Generators> VerifierMessages<'_, G> {
    pub fn push_revealed(&mut self, message: Message) -> Result<(), Error> {
        let c = self.count;
        if c >= self.generators.message_count() {
            return Err(err_msg!(Usage, "Message index exceeds generator count"));
        }
        self.accum_reveal
            .push(self.generators.message(c), message.0);
        self.count = c + 1;
        Ok(())
    }

    pub fn append_revealed(
        &mut self,
        messages: impl IntoIterator<Item = Message>,
    ) -> Result<(), Error> {
        for msg in messages {
            self.push_revealed(msg)?;
        }
        Ok(())
    }

    pub fn push_hidden_count(&mut self, count: usize) -> Result<(), Error> {
        let c = self.count + count;
        if c >= self.generators.message_count() {
            return Err(err_msg!(Usage, "Message index exceeds generator count"));
        }
        for index in self.count..c {
            self.hidden.push(self.generators.message(index));
        }
        self.count = c;
        Ok(())
    }

    fn accum_reveal(&self) -> Result<G1Projective, Error> {
        if self.count != self.generators.message_count() {
            return Err(err_msg!(
                Usage,
                "Message count does not match generator count"
            ));
        }
        Ok(self.accum_reveal.sum())
    }
}
