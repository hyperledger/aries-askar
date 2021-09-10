use askar_crypto::{
    alg::bls::{BlsKeyPair, G2},
    buffer::WriteBuffer,
};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, Scalar};
use rand::{CryptoRng, Rng};
use subtle::ConstantTimeEq;

use crate::{
    challenge::{CreateChallenge, ProofChallenge},
    collect::{DefaultSeq, Seq, Vec},
    commitment::Blinding,
    error::Error,
    generators::Generators,
    signature::{Message, Signature},
    util::{random_nonce, AccumG1},
};

#[cfg(feature = "getrandom")]
use crate::util::default_rng;

#[derive(Clone, Debug)]
pub struct SignatureProver<'g, G, S = DefaultSeq<128>>
where
    G: Generators,
    S: Seq<(Message, Blinding)>,
{
    accum_b: AccumG1,
    accum_c2: AccumG1,
    count: usize,
    generators: &'g G,
    hidden: Vec<(Message, Blinding), S>,
    sig: Signature,
}

impl<'g, G, S> SignatureProver<'g, G, S>
where
    G: Generators,
    S: Seq<(Message, Blinding)>,
{
    pub fn custom(generators: &'g G, signature: &Signature) -> Self {
        Self {
            accum_b: AccumG1::new_with(G1Projective::generator()),
            accum_c2: AccumG1::zero(),
            count: 0,
            generators,
            hidden: Vec::new(),
            sig: *signature,
        }
    }
}

impl<'g, G> SignatureProver<'g, G>
where
    G: Generators,
{
    pub fn new(
        generators: &'g G,
        signature: &Signature,
    ) -> SignatureProver<'g, G, DefaultSeq<128>> {
        Self::custom(generators, signature)
    }
}

impl<G, S> SignatureProver<'_, G, S>
where
    G: Generators,
    S: Seq<(Message, Blinding)>,
{
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
        self.hidden.push((message, blinding))?;
        self.accum_b.push(base, message.0);
        self.accum_c2.push(base, blinding.0);
        self.count = c + 1;
        Ok(())
    }

    #[cfg(feature = "getrandom")]
    pub fn prepare(self) -> Result<SignatureProofContext<S>, Error> {
        self.prepare_with_rng(default_rng())
    }

    pub fn prepare_with_rng(
        mut self,
        mut rng: impl CryptoRng + Rng,
    ) -> Result<SignatureProofContext<S>, Error> {
        if self.count != self.generators.message_count() {
            return Err(err_msg!(
                Usage,
                "Message count does not match generator count"
            ));
        }

        let Signature { a, e, s } = self.sig;
        self.accum_b.push(self.generators.blinding(), s);
        let b = self.accum_b.sum();
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
        self.accum_c2.append(&[(d, r3_rand), (h0, s_rand)][..]);

        let mut affine = [G1Affine::identity(); 5];
        G1Projective::batch_normalize(
            &[a_prime, a_bar, d, c1, self.accum_c2.sum()],
            &mut affine[..],
        );

        Ok(SignatureProofContext {
            params: ProofPublicParams {
                a_prime: affine[0],
                a_bar: affine[1],
                d: affine[2],
            },
            c1: affine[3],
            c2: affine[4],
            e,
            e_rand,
            r2,
            r2_rand,
            r3,
            r3_rand,
            s_prime,
            s_rand,
            hidden: self.hidden,
        })
    }
}

#[derive(Clone, Debug)]
pub struct SignatureProofContext<S>
where
    S: Seq<(Message, Blinding)>,
{
    params: ProofPublicParams,
    c1: G1Affine,
    c2: G1Affine,
    e: Scalar,
    e_rand: Scalar,
    r2: Scalar,
    r2_rand: Scalar,
    r3: Scalar,
    r3_rand: Scalar,
    s_prime: Scalar,
    s_rand: Scalar,
    hidden: Vec<(Message, Blinding), S>,
}

impl<S> SignatureProofContext<S>
where
    S: Seq<(Message, Blinding)>,
    S: Seq<Scalar>,
{
    pub fn complete(&self, challenge: ProofChallenge) -> Result<SignatureProof<S>, Error> {
        let c = challenge.0;
        let mut hidden_resp = Vec::with_capacity(self.hidden.len());
        for (msg, m_rand) in self.hidden.iter() {
            hidden_resp.push(m_rand.0 - c * msg.0)?;
        }
        Ok(SignatureProof {
            params: self.params,
            e_resp: self.e_rand + c * self.e,
            r2_resp: self.r2_rand - c * self.r2,
            r3_resp: self.r3_rand + c * self.r3,
            s_resp: self.s_rand - c * self.s_prime,
            hidden_resp,
        })
    }
}

impl<S> CreateChallenge for SignatureProofContext<S>
where
    S: Seq<(Message, Blinding)>,
{
    fn write_challenge_bytes(
        &self,
        writer: &mut dyn WriteBuffer,
    ) -> Result<(), askar_crypto::Error> {
        self.params
            .write_challenge_bytes(&self.c1, &self.c2, writer)
    }
}

#[derive(Clone, Copy, Debug)]
struct ProofPublicParams {
    a_prime: G1Affine,
    a_bar: G1Affine,
    d: G1Affine,
}

impl ProofPublicParams {
    pub fn write_challenge_bytes(
        &self,
        c1: &G1Affine,
        c2: &G1Affine,
        writer: &mut dyn WriteBuffer,
    ) -> Result<(), askar_crypto::Error> {
        writer.buffer_write(&self.a_bar.to_uncompressed())?;
        writer.buffer_write(&self.a_prime.to_uncompressed())?;
        writer.buffer_write(&self.d.to_uncompressed())?;
        writer.buffer_write(&c1.to_uncompressed())?;
        writer.buffer_write(&c2.to_uncompressed())?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct SignatureProof<S>
where
    S: Seq<Scalar>,
{
    params: ProofPublicParams,
    e_resp: Scalar,
    r2_resp: Scalar,
    r3_resp: Scalar,
    s_resp: Scalar,
    hidden_resp: Vec<Scalar, S>,
}

impl<S> SignatureProof<S>
where
    S: Seq<Scalar>,
{
    pub fn verifier<'v, G>(
        &'v self,
        generators: &'v G,
        challenge: ProofChallenge,
    ) -> Result<SignatureProofVerifier<'v, G, S>, Error>
    where
        G: Generators,
    {
        SignatureProofVerifier::new(generators, self, challenge)
    }
}

pub struct SignatureProofVerifier<'v, G, S>
where
    G: Generators,
    S: Seq<Scalar>,
{
    generators: &'v G,
    proof: &'v SignatureProof<S>,
    challenge: Scalar,
    c1: G1Projective,
    accum_c2: AccumG1,
    hidden_count: usize,
    message_count: usize,
}

impl<'v, G, S> SignatureProofVerifier<'v, G, S>
where
    G: Generators,
    S: Seq<Scalar>,
{
    pub(crate) fn new(
        generators: &'v G,
        proof: &'v SignatureProof<S>,
        challenge: ProofChallenge,
    ) -> Result<Self, Error> {
        let ProofPublicParams { a_prime, a_bar, d } = proof.params;
        let challenge = challenge.0;
        let neg_c = -challenge;

        let h0 = generators.blinding();
        let c1 = AccumG1::calc(&[
            (a_prime.into(), proof.e_resp),
            (h0, proof.r2_resp),
            (G1Projective::from(a_bar) - d, challenge),
        ]);
        let accum_c2 = AccumG1::from(
            &[
                (d.into(), proof.r3_resp),
                (h0, proof.s_resp),
                (G1Projective::generator(), neg_c),
            ][..],
        );

        Ok(Self {
            challenge: neg_c, // negate early for multiplying
            generators,
            proof,
            c1,
            accum_c2,
            hidden_count: 0,
            message_count: 0,
        })
    }
}

impl<G, S> SignatureProofVerifier<'_, G, S>
where
    G: Generators,
    S: Seq<Scalar>,
{
    pub fn push_revealed(&mut self, message: Message) -> Result<(), Error> {
        let c = self.message_count;
        if c >= self.generators.message_count() {
            return Err(err_msg!(Usage, "Message index exceeds generator count"));
        }
        self.accum_c2
            .push(self.generators.message(c), message.0 * self.challenge);
        self.message_count = c + 1;
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
        let c = self.message_count + count;
        if c > self.generators.message_count() {
            return Err(err_msg!(Usage, "Message index exceeds generator count"));
        }
        if self.hidden_count + c > self.proof.hidden_resp.len() {
            return Err(err_msg!(
                Usage,
                "Hidden message count exceeded response count"
            ));
        }
        for index in self.message_count..c {
            self.accum_c2.push(
                self.generators.message(index),
                self.proof.hidden_resp[self.hidden_count],
            );
            self.hidden_count += 1;
        }
        self.message_count = c;
        Ok(())
    }

    pub fn verify(&self, keypair: &BlsKeyPair<G2>) -> Result<bool, Error> {
        // NOTE: MUST verify the Fiat-Shamir challenge value as well

        if self.message_count != self.generators.message_count() {
            return Err(err_msg!(
                InvalidProof,
                "Number of messages does not correspond with generators"
            ));
        }
        if self.hidden_count != self.proof.hidden_resp.len() {
            return Err(err_msg!(
                InvalidProof,
                "Number of hidden messages does not correspond with responses"
            ));
        }

        let ProofPublicParams { a_prime, a_bar, .. } = self.proof.params;
        let check_pair = pairing(&a_prime, keypair.bls_public_key())
            .ct_eq(&pairing(&a_bar, &G2Affine::generator()));

        Ok((!a_prime.is_identity() & check_pair).into())
    }
}

impl<G, S> CreateChallenge for SignatureProofVerifier<'_, G, S>
where
    G: Generators,
    S: Seq<Scalar>,
{
    fn write_challenge_bytes(
        &self,
        writer: &mut dyn WriteBuffer,
    ) -> Result<(), askar_crypto::Error> {
        let mut checks = [G1Affine::identity(); 2];
        G1Projective::batch_normalize(&[self.c1, self.accum_c2.sum()], &mut checks[..]);
        self.proof
            .params
            .write_challenge_bytes(&checks[0], &checks[1], writer)
    }
}
