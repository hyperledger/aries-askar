#[cfg(feature = "alloc")]
use alloc::vec::Vec as StdVec;

use askar_crypto::{
    alg::bls::{BlsKeyPair, G2},
    buffer::WriteBuffer,
};
use bls12_381::{pairing, G1Affine, G1Projective, G2Affine, Scalar};
use rand::{CryptoRng, Rng};
use subtle::ConstantTimeEq;

#[cfg(feature = "getrandom")]
use askar_crypto::random::default_rng;

use crate::{
    challenge::{CreateChallenge, ProofChallenge},
    collect::{DefaultSeq, Seq, Vec},
    commitment::Blinding,
    generators::Generators,
    io::{CompressedBytes, Cursor, FixedLengthBytes},
    signature::{Message, Signature},
    util::{random_nonce, AccumG1, Nonce},
    Error,
};

#[derive(Clone, Debug)]
/// Generate a signature proof of knowledge
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

impl<'g, G> SignatureProver<'g, G>
where
    G: Generators,
{
    /// Create a new signature prover
    pub fn new(
        generators: &'g G,
        signature: &Signature,
    ) -> SignatureProver<'g, G, DefaultSeq<128>> {
        Self::new_sized(generators, signature)
    }
}

impl<'g, G, S> SignatureProver<'g, G, S>
where
    G: Generators,
    S: Seq<(Message, Blinding)>,
{
    /// Create a new signature prover with a specific backing sequence type
    pub fn new_sized(generators: &'g G, signature: &Signature) -> Self {
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

impl<G, S> SignatureProver<'_, G, S>
where
    G: Generators,
    S: Seq<(Message, Blinding)>,
{
    /// Push a revealed signed message
    pub fn push_message(&mut self, message: Message) -> Result<(), Error> {
        let c = self.count;
        if c >= self.generators.message_count() {
            return Err(err_msg!(Usage, "Message index exceeds generator count"));
        }
        self.accum_b.push(self.generators.message(c), message.0);
        self.count = c + 1;
        Ok(())
    }

    /// Push a sequence of revealed signed messages
    pub fn append_messages(
        &mut self,
        messages: impl IntoIterator<Item = Message>,
    ) -> Result<(), Error> {
        for msg in messages {
            self.push_message(msg)?;
        }
        Ok(())
    }

    #[cfg(feature = "getrandom")]
    /// Push a hidden signed message
    pub fn push_hidden_message(&mut self, message: Message) -> Result<(), Error> {
        self.push_hidden_message_with(message, Blinding::new())
    }

    /// Push a hidden signed message with a specific blinding value
    pub fn push_hidden_message_with(
        &mut self,
        message: Message,
        blinding: Blinding,
    ) -> Result<(), Error> {
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
    /// Prepare the context for generating the final proof
    pub fn prepare(self) -> Result<SignatureProofContext<S>, Error> {
        self.prepare_with_rng(default_rng())
    }

    /// Prepare the context for generating the final proof
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

    #[cfg(feature = "getrandom")]
    /// Complete an independent signature proof of knowledge
    pub fn complete(self, nonce: Nonce) -> Result<(ProofChallenge, SignatureProof<S>), Error>
    where
        S: Seq<Scalar>,
    {
        self.complete_with_rng(default_rng(), nonce)
    }

    /// Complete an independent signature proof of knowledge with a given RNG
    pub fn complete_with_rng(
        self,
        rng: impl CryptoRng + Rng,
        nonce: Nonce,
    ) -> Result<(ProofChallenge, SignatureProof<S>), Error>
    where
        S: Seq<Scalar>,
    {
        let context = self.prepare_with_rng(rng)?;
        let challenge = context.create_challenge(nonce);
        let proof = context.complete(challenge)?;
        Ok((challenge, proof))
    }
}

#[derive(Clone, Debug)]
/// A prepared context for generating a signature proof of knowledge
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
    /// Complete the signature proof of knowledge given a Fiat-Shamir challenge value
    pub fn complete(&self, challenge: ProofChallenge) -> Result<SignatureProof<S>, Error> {
        let c = challenge.0;
        let mut m_resp = Vec::with_capacity(self.hidden.len());
        for (msg, m_rand) in self.hidden.iter() {
            m_resp.push(m_rand.0 - c * msg.0)?;
        }
        Ok(SignatureProof {
            params: self.params,
            e_resp: self.e_rand + c * self.e,
            r2_resp: self.r2_rand - c * self.r2,
            r3_resp: self.r3_rand + c * self.r3,
            s_resp: self.s_rand - c * self.s_prime,
            m_resp,
        })
    }
}

impl<S> CreateChallenge for SignatureProofContext<S>
where
    S: Seq<(Message, Blinding)>,
{
    fn write_challenge_bytes(&self, writer: &mut dyn WriteBuffer) -> Result<(), Error> {
        self.params
            .write_challenge_bytes(&self.c1, &self.c2, writer)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
/// A signature proof of knowledge
pub struct SignatureProof<S>
where
    S: Seq<Scalar>,
{
    params: ProofPublicParams,
    e_resp: Scalar,
    r2_resp: Scalar,
    r3_resp: Scalar,
    s_resp: Scalar,
    m_resp: Vec<Scalar, S>,
}

impl SignatureProof<DefaultSeq<128>> {
    /// Convert a signature proof of knowledge from a byte slice
    pub fn from_bytes(buf: &[u8]) -> Result<Self, Error> {
        Self::from_bytes_sized(buf)
    }
}

impl<S> SignatureProof<S>
where
    S: Seq<Scalar>,
{
    /// Verify an independent commitment proof
    pub fn verify<G, I>(
        &self,
        generators: &G,
        keypair: &BlsKeyPair<G2>,
        challenge: ProofChallenge,
        nonce: Nonce,
    ) -> Result<(), Error>
    where
        G: Generators,
        I: IntoIterator<Item = usize>,
    {
        let verifier = self.verifier(generators, keypair, challenge)?;
        if verifier.create_challenge(nonce) != challenge {
            return Err(err_msg!(
                Invalid,
                "Signature proof of knowledge challenge mismatch"
            ));
        }
        Ok(())
    }

    /// Create a verifier for the signature proof of knowledge
    pub fn verifier<'v, G>(
        &'v self,
        generators: &'v G,
        keypair: &'v BlsKeyPair<G2>,
        challenge: ProofChallenge,
    ) -> Result<SignatureProofVerifier<'v, G, S>, Error>
    where
        G: Generators,
    {
        SignatureProofVerifier::new(generators, self, keypair, challenge)
    }

    /// Write the signature proof of knowledge to an output buffer
    pub fn write_bytes(&self, buf: &mut dyn WriteBuffer) -> Result<(), Error> {
        self.params.a_prime.write_compressed(&mut *buf)?;
        self.params.a_bar.write_compressed(&mut *buf)?;
        self.params.d.write_compressed(&mut *buf)?;
        self.e_resp.write_bytes(&mut *buf)?;
        self.r2_resp.write_bytes(&mut *buf)?;
        self.r3_resp.write_bytes(&mut *buf)?;
        self.s_resp.write_bytes(&mut *buf)?;
        buf.buffer_write(&(self.m_resp.len() as u32).to_be_bytes())?;
        for resp in self.m_resp.iter() {
            resp.write_bytes(&mut *buf)?;
        }
        Ok(())
    }

    #[cfg(feature = "alloc")]
    /// Output the signature proof of knowledge as a byte vec
    pub fn to_bytes(&self) -> Result<StdVec<u8>, Error> {
        let mut out = StdVec::with_capacity(48 * 3 + 32 * 5 + 4);
        self.write_bytes(&mut out)?;
        Ok(out)
    }

    /// Convert a signature proof of knowledge from a byte slice
    pub fn from_bytes_sized(buf: &[u8]) -> Result<Self, Error> {
        let mut cur = Cursor::new(buf);
        let params = ProofPublicParams {
            a_prime: G1Affine::read_compressed(&mut cur)?,
            a_bar: G1Affine::read_compressed(&mut cur)?,
            d: G1Affine::read_compressed(&mut cur)?,
        };
        let e_resp = Scalar::read_bytes(&mut cur)?;
        let r2_resp = Scalar::read_bytes(&mut cur)?;
        let r3_resp = Scalar::read_bytes(&mut cur)?;
        let s_resp = Scalar::read_bytes(&mut cur)?;
        let m_len = u32::from_be_bytes(*cur.read_fixed()?) as usize;
        let mut m_resp = Vec::with_capacity(m_len);
        for _ in 0..m_len {
            m_resp.push(Scalar::read_bytes(&mut cur)?)?;
        }
        if cur.len() != 0 {
            return Err(err_msg!(Invalid, "Invalid length"));
        }
        Ok(Self {
            params,
            e_resp,
            r2_resp,
            r3_resp,
            s_resp,
            m_resp,
        })
    }
}

impl<S, T> PartialEq<SignatureProof<T>> for SignatureProof<S>
where
    S: Seq<Scalar>,
    T: Seq<Scalar>,
{
    fn eq(&self, other: &SignatureProof<T>) -> bool {
        self.params == other.params
            && self.e_resp == other.e_resp
            && self.r2_resp == other.r2_resp
            && self.r3_resp == other.r3_resp
            && self.s_resp == other.s_resp
            && &*self.m_resp == &*other.m_resp
    }
}
impl<S> Eq for SignatureProof<S> where S: Seq<Scalar> {}

#[derive(Clone, Debug)]
/// A verifier for a signature proof of knowledge
pub struct SignatureProofVerifier<'v, G, S>
where
    G: Generators,
    S: Seq<Scalar>,
{
    generators: &'v G,
    proof: &'v SignatureProof<S>,
    keypair: &'v BlsKeyPair<G2>,
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
        keypair: &'v BlsKeyPair<G2>,
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
            keypair,
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
    /// Push a revealed signed message
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

    /// Push a sequence of revealed signed messages
    pub fn append_revealed(
        &mut self,
        messages: impl IntoIterator<Item = Message>,
    ) -> Result<(), Error> {
        for msg in messages {
            self.push_revealed(msg)?;
        }
        Ok(())
    }

    /// Push a number of hidden signed messages
    pub fn push_hidden_count(&mut self, count: usize) -> Result<(), Error> {
        let c = self.message_count + count;
        if c > self.generators.message_count() {
            return Err(err_msg!(Usage, "Message index exceeds generator count"));
        }
        if self.hidden_count + c > self.proof.m_resp.len() {
            return Err(err_msg!(
                Usage,
                "Hidden message count exceeded response count"
            ));
        }
        for index in self.message_count..c {
            self.accum_c2.push(
                self.generators.message(index),
                self.proof.m_resp[self.hidden_count],
            );
            self.hidden_count += 1;
        }
        self.message_count = c;
        Ok(())
    }

    /// Verify the public parameters of the signature proof of knowledge
    /// NOTE: MUST verify that the Fiat-Shamir challenge value matches as well
    pub fn verify(&self) -> Result<(), Error> {
        if self.message_count != self.generators.message_count() {
            return Err(err_msg!(
                Invalid,
                "Number of messages does not correspond with generators"
            ));
        }
        if self.hidden_count != self.proof.m_resp.len() {
            return Err(err_msg!(
                Invalid,
                "Number of hidden messages does not correspond with responses"
            ));
        }

        let ProofPublicParams { a_prime, a_bar, .. } = self.proof.params;
        let check_pair = pairing(&a_prime, self.keypair.bls_public_key())
            .ct_eq(&pairing(&a_bar, &G2Affine::generator()));

        let verify: bool = (!a_prime.is_identity() & check_pair).into();
        if verify {
            Ok(())
        } else {
            Err(err_msg!(Invalid))
        }
    }
}

impl<G, S> CreateChallenge for SignatureProofVerifier<'_, G, S>
where
    G: Generators,
    S: Seq<Scalar>,
{
    fn write_challenge_bytes(&self, writer: &mut dyn WriteBuffer) -> Result<(), Error> {
        let mut checks = [G1Affine::identity(); 2];
        G1Projective::batch_normalize(&[self.c1, self.accum_c2.sum()], &mut checks[..]);
        self.proof
            .params
            .write_challenge_bytes(&checks[0], &checks[1], writer)
    }
}
