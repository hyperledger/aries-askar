#[cfg(feature = "alloc")]
use alloc::vec::Vec as StdVec;

use askar_crypto::buffer::WriteBuffer;
use bls12_381::{G1Affine, G1Projective, Scalar};
use group::Curve;
use rand::{CryptoRng, Rng};

#[cfg(feature = "getrandom")]
use askar_crypto::random::default_rng;

use crate::{
    challenge::{CreateChallenge, ProofChallenge},
    collect::{DefaultSeq, Seq, Vec},
    generators::Generators,
    io::{Cursor, FixedLengthBytes},
    signature::Message,
    util::{random_scalar, AccumG1, Nonce},
    Error,
};

const G1_COMPRESSED_SIZE: usize = 48;

/// A nonce value used as a blinding
pub type Blinding = Nonce;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// A commitment to a set of blinded messages for signing
pub struct Commitment(pub(crate) G1Affine);

impl FixedLengthBytes for Commitment {
    const LENGTH: usize = G1_COMPRESSED_SIZE;

    type Buffer = [u8; G1_COMPRESSED_SIZE];

    fn from_bytes(buf: &Self::Buffer) -> Result<Self, Error> {
        if let Some(pt) = G1Affine::from_compressed(buf).into() {
            Ok(Self(pt))
        } else {
            Err(err_msg!(Invalid))
        }
    }

    fn with_bytes<R>(&self, f: impl FnOnce(&Self::Buffer) -> R) -> R {
        f(&self.0.to_compressed())
    }
}

impl From<G1Affine> for Commitment {
    fn from(pt: G1Affine) -> Self {
        Self(pt)
    }
}

#[derive(Clone, Debug)]
/// A builder used to generate and prove a commitment to a set of messages
pub struct CommitmentBuilder<'g, G, S>
where
    G: Generators,
    S: Seq<(Message, Blinding)>,
{
    accum_commitment: AccumG1,
    accum_c1: AccumG1,
    messages: Vec<(Message, Blinding), S>,
    generators: &'g G,
}

impl<'g, G> CommitmentBuilder<'g, G, DefaultSeq<32>>
where
    G: Generators,
{
    /// Create a new commitment builder
    pub fn new(generators: &'g G) -> Self {
        Self::new_sized(generators)
    }
}

impl<'g, G, S> CommitmentBuilder<'g, G, S>
where
    G: Generators,
    S: Seq<(Message, Blinding)>,
{
    /// Create a new commitment builder with a specific backing sequence type
    pub fn new_sized(generators: &'g G) -> Self {
        Self {
            accum_commitment: AccumG1::zero(),
            accum_c1: AccumG1::zero(),
            messages: Vec::with_capacity(16),
            generators,
        }
    }
}

impl<G, S> CommitmentBuilder<'_, G, S>
where
    G: Generators,
    S: Seq<(Message, Blinding)>,
{
    #[cfg(feature = "getrandom")]
    /// Add a hidden message with a random blinding value
    pub fn add_message(&mut self, index: usize, message: Message) -> Result<(), Error> {
        self.add_message_with(index, message, Blinding::random())
    }

    /// Add a hidden message with a pre-selected blinding value
    pub fn add_message_with(
        &mut self,
        index: usize,
        message: Message,
        blinding: Blinding,
    ) -> Result<(), Error> {
        if index > self.generators.message_count() {
            Err(err_msg!(Usage, "Message index exceeds generator count"))
        } else {
            self.messages.push((message, blinding))?;
            let base = self.generators.message(index);
            self.accum_commitment.push(base, message.0);
            self.accum_c1.push(base, blinding.0);
            Ok(())
        }
    }
}

impl<G, S> CommitmentBuilder<'_, G, S>
where
    G: Generators,
    S: Seq<(Message, Blinding)> + Seq<Scalar>,
{
    #[cfg(feature = "getrandom")]
    /// Prepare the commitment proof context
    pub fn prepare(self) -> Result<CommitmentProofContext<S>, Error> {
        self.prepare_with_rng(default_rng())
    }

    /// Prepare the commitment proof context with a specific RNG
    pub fn prepare_with_rng(
        mut self,
        mut rng: impl CryptoRng + Rng,
    ) -> Result<CommitmentProofContext<S>, Error> {
        if self.messages.is_empty() {
            return Err(err_msg!(Usage, "No messages provided for commitment"));
        }

        let h0 = self.generators.blinding();
        let s_prime = random_scalar(&mut rng); // s'
        let s_blind = random_scalar(&mut rng); // s~
        self.accum_commitment.push(h0, s_prime);
        self.accum_c1.push(h0, s_blind);

        let mut affine = [G1Affine::identity(); 2];
        G1Projective::batch_normalize(
            &[self.accum_commitment.sum(), self.accum_c1.sum()],
            &mut affine[..],
        );
        Ok(CommitmentProofContext {
            commitment: affine[0].into(),
            c1: affine[1],
            messages: self.messages,
            s_prime,
            s_blind,
        })
    }

    #[cfg(feature = "getrandom")]
    /// Complete an independent commitment proof of knowledge
    pub fn complete(
        self,
        nonce: Nonce,
    ) -> Result<(ProofChallenge, Blinding, Commitment, CommitmentProof<S>), Error> {
        self.complete_with_rng(default_rng(), nonce)
    }

    /// Complete an independent commitment proof with a specific RNG
    pub fn complete_with_rng(
        self,
        rng: impl CryptoRng + Rng,
        nonce: Nonce,
    ) -> Result<(ProofChallenge, Blinding, Commitment, CommitmentProof<S>), Error> {
        let context = self.prepare_with_rng(rng)?;
        let challenge = context.create_challenge(nonce)?;
        let (blinding, commitment, proof) = context.complete(challenge)?;
        Ok((challenge, blinding, commitment, proof))
    }
}

#[derive(Clone, Debug)]
/// A prepared context for generating a commitment proof of knowledge
pub struct CommitmentProofContext<S>
where
    S: Seq<(Message, Blinding)>,
{
    commitment: Commitment,
    c1: G1Affine,
    messages: Vec<(Message, Blinding), S>,
    s_prime: Scalar,
    s_blind: Scalar,
}

impl<S> CommitmentProofContext<S>
where
    S: Seq<(Message, Blinding)>,
    S: Seq<Scalar>,
{
    /// Complete the commitment proof of knowledge given a Fiat-Shamir challenge value
    pub fn complete(
        &self,
        challenge: ProofChallenge,
    ) -> Result<(Blinding, Commitment, CommitmentProof<S>), Error> {
        let c = challenge.0;
        let s_resp = self.s_blind + c * self.s_prime;
        let mut m_resp = Vec::with_capacity(self.messages.len());
        for (msg, m_rand) in self.messages.iter().copied() {
            m_resp.push(m_rand.0 + c * msg.0)?;
        }
        Ok((
            self.s_prime.into(),
            self.commitment,
            CommitmentProof { s_resp, m_resp },
        ))
    }
}

impl<S> CreateChallenge for CommitmentProofContext<S>
where
    S: Seq<(Message, Blinding)>,
{
    fn write_challenge_bytes(&self, writer: &mut dyn WriteBuffer) -> Result<(), Error> {
        writer.buffer_write(&self.commitment.0.to_uncompressed())?;
        writer.buffer_write(&self.c1.to_uncompressed())?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
/// A proof of a commitment to hidden messages for signing
pub struct CommitmentProof<S>
where
    S: Seq<Scalar>,
{
    pub(crate) s_resp: Scalar,
    pub(crate) m_resp: Vec<Scalar, S>,
}

impl CommitmentProof<DefaultSeq<32>> {
    /// Convert a signature proof of knowledge from a byte slice
    pub fn from_bytes(buf: &[u8]) -> Result<Self, Error> {
        Self::from_bytes_sized(buf)
    }
}

impl<S> CommitmentProof<S>
where
    S: Seq<Scalar>,
{
    /// Verify an independent commitment proof
    pub fn verify<G, I>(
        &self,
        generators: &G,
        commitment: Commitment,
        committed_indices: I,
        challenge: ProofChallenge,
        nonce: Nonce,
    ) -> Result<(), Error>
    where
        G: Generators,
        I: IntoIterator<Item = usize>,
    {
        let verifier = self.verifier(generators, commitment, committed_indices, challenge)?;
        let challenge_v = verifier.create_challenge(nonce)?;
        verifier.verify(challenge_v)
    }

    /// Create a verifier for the commitment proof
    pub fn verifier<G, I>(
        &self,
        generators: &G,
        commitment: Commitment,
        committed_indices: I,
        challenge: ProofChallenge,
    ) -> Result<CommitmentProofVerifier, Error>
    where
        G: Generators,
        I: IntoIterator<Item = usize>,
    {
        CommitmentProofVerifier::new(
            generators,
            commitment,
            self,
            committed_indices.into_iter(),
            challenge,
        )
    }

    /// Write the commitment proof of knowledge to an output buffer
    pub fn write_bytes(&self, buf: &mut dyn WriteBuffer) -> Result<(), Error> {
        buf.buffer_write(&((self.m_resp.len() + 1) as u32).to_be_bytes())?;
        self.s_resp.write_bytes(&mut *buf)?;
        for resp in self.m_resp.iter() {
            resp.write_bytes(&mut *buf)?;
        }
        Ok(())
    }

    #[cfg(feature = "alloc")]
    /// Output the signature proof of knowledge as a byte vec
    pub fn to_bytes(&self) -> Result<StdVec<u8>, Error> {
        let mut out = StdVec::with_capacity(4 + (1 + self.m_resp.len()) * 32);
        self.write_bytes(&mut out)?;
        Ok(out)
    }

    /// Convert a signature proof of knowledge from a byte slice
    pub fn from_bytes_sized(buf: &[u8]) -> Result<Self, Error> {
        let mut cur = Cursor::new(buf);
        let mut m_len = u32::from_be_bytes(*cur.read_fixed()?) as usize;
        if m_len < 2 {
            return Err(err_msg!(Invalid, "Invalid proof response count"));
        }
        let s_resp = Scalar::read_bytes(&mut cur)?;
        m_len -= 1;
        let mut m_resp = Vec::with_capacity(m_len);
        for _ in 0..m_len {
            m_resp.push(Scalar::read_bytes(&mut cur)?)?;
        }
        Ok(Self { s_resp, m_resp })
    }

    /// Get the response value from the post-challenge phase of the sigma protocol
    /// for a given message index
    pub fn get_response(&self, index: usize) -> Result<Blinding, Error> {
        self.m_resp
            .get(index)
            .map(Blinding::from)
            .ok_or_else(|| err_msg!(Usage, "Invalid index for committed message"))
    }
}

impl<S, T> PartialEq<CommitmentProof<T>> for CommitmentProof<S>
where
    S: Seq<Scalar>,
    T: Seq<Scalar>,
{
    fn eq(&self, other: &CommitmentProof<T>) -> bool {
        self.s_resp == other.s_resp && &*self.m_resp == &*other.m_resp
    }
}
impl<S> Eq for CommitmentProof<S> where S: Seq<Scalar> {}

#[derive(Clone, Debug)]
/// A verifier for a commitment proof of knowledge
pub struct CommitmentProofVerifier {
    challenge: Scalar,
    commitment: G1Affine,
    c1: G1Affine,
}

impl CommitmentProofVerifier {
    pub(crate) fn new<G, S, I>(
        generators: &G,
        commitment: Commitment,
        proof: &CommitmentProof<S>,
        committed_indices: I,
        challenge: ProofChallenge,
    ) -> Result<Self, Error>
    where
        G: Generators,
        S: Seq<Scalar>,
        I: Iterator<Item = usize>,
    {
        let mut accum_c1 = AccumG1::from(
            &[
                (commitment.0.into(), -challenge.0),
                (generators.blinding(), proof.s_resp),
            ][..],
        );
        for (index, resp) in committed_indices.zip(proof.m_resp.iter().copied()) {
            if index >= generators.message_count() {
                return Err(err_msg!(Invalid, "Message index exceeds generator count"));
            }
            accum_c1.push(generators.message(index), resp);
        }

        Ok(Self {
            challenge: challenge.0,
            commitment: commitment.0,
            c1: accum_c1.sum().to_affine(),
        })
    }

    /// Verify the public parameters of the commitment proof of knowledge
    pub fn verify(&self, challenge_v: ProofChallenge) -> Result<(), Error> {
        if challenge_v.0 != self.challenge {
            return Err(err_msg!(Invalid, "Commitment proof challenge mismatch"));
        }
        Ok(())
    }
}

impl CreateChallenge for CommitmentProofVerifier {
    fn write_challenge_bytes(&self, writer: &mut dyn WriteBuffer) -> Result<(), Error> {
        writer.buffer_write(&self.commitment.to_uncompressed())?;
        writer.buffer_write(&self.c1.to_uncompressed())?;
        Ok(())
    }
}
