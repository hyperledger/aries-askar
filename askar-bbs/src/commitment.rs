use askar_crypto::buffer::WriteBuffer;
use bls12_381::{G1Affine, G1Projective, Scalar};
use group::Curve;
use rand::{CryptoRng, Rng};

use crate::{
    challenge::{CreateChallenge, ProofChallenge},
    collect::{DefaultSeq, Seq, Vec},
    error::Error,
    generators::Generators,
    signature::Message,
    util::{random_nonce, AccumG1, Nonce},
};

#[cfg(feature = "getrandom")]
use crate::util::default_rng;

const G1_COMPRESSED_SIZE: usize = 48;

pub type Blinding = Nonce;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment(pub(crate) G1Affine);

impl Commitment {
    pub fn from_bytes(buf: &[u8; G1_COMPRESSED_SIZE]) -> Result<Self, Error> {
        if let Some(pt) = G1Affine::from_compressed(buf).into() {
            Ok(Self(pt))
        } else {
            Err(err_msg!(InvalidCommitment))
        }
    }

    pub fn to_bytes(&self) -> [u8; G1_COMPRESSED_SIZE] {
        self.0.to_compressed()
    }
}

impl From<G1Affine> for Commitment {
    fn from(pt: G1Affine) -> Self {
        Self(pt)
    }
}

#[derive(Clone, Debug)]
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
    pub fn new(generators: &'g G) -> Self {
        Self::custom(generators)
    }
}

impl<'g, G, S> CommitmentBuilder<'g, G, S>
where
    G: Generators,
    S: Seq<(Message, Blinding)>,
{
    pub fn custom(generators: &'g G) -> Self {
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
    pub fn add_message(&mut self, index: usize, message: Message) -> Result<(), Error> {
        self.add_message_with(index, message, Blinding::new())
    }

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
    pub fn prepare(self) -> Result<CommitmentProofContext<S>, Error> {
        self.prepare_with_rng(default_rng())
    }

    pub fn prepare_with_rng(
        mut self,
        mut rng: impl CryptoRng + Rng,
    ) -> Result<CommitmentProofContext<S>, Error> {
        if self.messages.is_empty() {
            return Err(err_msg!(Usage, "No messages provided for commitment"));
        }

        let h0 = self.generators.blinding();
        let s_prime = random_nonce(&mut rng); // s'
        let s_blind = random_nonce(&mut rng); // s~
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
    pub fn complete(
        self,
        nonce: Nonce,
    ) -> Result<(ProofChallenge, Blinding, Commitment, CommitmentProof<S>), Error> {
        self.complete_with_rng(default_rng(), nonce)
    }

    pub fn complete_with_rng(
        self,
        rng: impl CryptoRng + Rng,
        nonce: Nonce,
    ) -> Result<(ProofChallenge, Blinding, Commitment, CommitmentProof<S>), Error> {
        let context = self.prepare_with_rng(rng)?;
        let challenge = context.create_challenge(nonce);
        let (blinding, commitment, proof) = context.complete(challenge)?;
        Ok((challenge, blinding, commitment, proof))
    }
}

#[derive(Clone, Debug)]
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
    pub fn complete(
        &self,
        challenge: ProofChallenge,
    ) -> Result<(Blinding, Commitment, CommitmentProof<S>), Error> {
        let c = challenge.0;
        let mut resp = Vec::with_capacity(self.messages.len() + 1);
        resp.push(self.s_blind + c * self.s_prime)?;
        for (msg, m_rand) in self.messages.iter().copied() {
            resp.push(m_rand.0 + c * msg.0)?;
        }
        Ok((
            self.s_prime.into(),
            self.commitment,
            CommitmentProof { resp },
        ))
    }
}

impl<S> CreateChallenge for CommitmentProofContext<S>
where
    S: Seq<(Message, Blinding)>,
{
    fn write_challenge_bytes(
        &self,
        writer: &mut dyn WriteBuffer,
    ) -> Result<(), askar_crypto::Error> {
        writer.buffer_write(&self.commitment.0.to_uncompressed())?;
        writer.buffer_write(&self.c1.to_uncompressed())?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentProof<S = DefaultSeq<32>>
where
    S: Seq<Scalar>,
{
    pub(crate) resp: Vec<Scalar, S>,
}

impl<S> CommitmentProof<S>
where
    S: Seq<Scalar>,
{
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
        if verifier.create_challenge(nonce) != challenge {
            return Err(err_msg!(
                InvalidProof,
                "Commitment proof challenge mismatch"
            ));
        }
        Ok(())
    }

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
}

#[derive(Clone, Debug)]
pub struct CommitmentProofVerifier {
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
        if proof.resp.len() < 1 {
            return Err(err_msg!(InvalidProof, "Invalid proof response count"));
        }

        let mut accum_c1 = AccumG1::from(
            &[
                (commitment.0.into(), -challenge.0),
                (generators.blinding(), proof.resp[0]),
            ][..],
        );
        for (index, resp) in committed_indices.zip(proof.resp[1..].iter().copied()) {
            if index >= generators.message_count() {
                return Err(err_msg!(
                    InvalidProof,
                    "Message index exceeds generator count"
                ));
            }
            accum_c1.push(generators.message(index), resp);
        }

        Ok(Self {
            commitment: commitment.0,
            c1: accum_c1.sum().to_affine(),
        })
    }
}

impl CreateChallenge for CommitmentProofVerifier {
    fn write_challenge_bytes(
        &self,
        writer: &mut dyn WriteBuffer,
    ) -> Result<(), askar_crypto::Error> {
        writer.buffer_write(&self.commitment.to_uncompressed())?;
        writer.buffer_write(&self.c1.to_uncompressed())?;
        Ok(())
    }
}
