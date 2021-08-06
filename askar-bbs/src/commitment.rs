#[cfg(feature = "alloc")]
use alloc::collections::BTreeMap;

use bls12_381::{G1Affine, Scalar};
use group::Curve;
use rand::{CryptoRng, Rng};
use subtle::ConstantTimeEq;

use crate::{
    error::Error,
    generators::Generators,
    signature::Message,
    util::{random_nonce, AccumG1, HashScalar, Nonce},
};

#[cfg(feature = "getrandom")]
use crate::util::default_rng;

pub type Blinding = Nonce;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment(pub(crate) G1Affine);

impl Commitment {
    #[cfg(feature = "getrandom")]
    pub fn commit<G: Generators>(
        generators: &G,
        entries: &[(usize, Message, Blinding)],
        nonce: Nonce,
    ) -> Result<(Blinding, Commitment, CommitmentProof), Error> {
        Self::commit_with_rng(generators, entries, nonce, default_rng())
    }

    pub fn commit_with_rng<G: Generators>(
        generators: &G,
        entries: &[(usize, Message, Blinding)],
        nonce: Nonce,
        mut rng: impl CryptoRng + Rng,
    ) -> Result<(Blinding, Commitment, CommitmentProof), Error> {
        // FIXME: ensure subgroup check on generators, may be enforced by bls12_381
        // TODO: optimize with sum-of-products

        let ec = entries.len();
        if ec == 0 {
            return Err(err_msg!(Usage, "No messages provided for commitment"));
        }
        let mc = generators.message_count();

        let commit_blind = random_nonce(&mut rng); // s'
        let resp_blind = random_nonce(&mut rng); // s~
        let mut proofs = Vec::with_capacity(1 + ec);
        proofs.push(resp_blind);
        let mut factors = Vec::with_capacity(1 + ec);
        factors.push(commit_blind);

        let h0 = generators.blinding();
        let mut commit_accum = AccumG1::from((h0, commit_blind));
        let mut resp_accum = AccumG1::from((h0, resp_blind));

        for (index, message, blinding) in entries.iter().copied() {
            if index > mc {
                return Err(err_msg!(Usage, "Invalid committed message index"));
            }
            let base = generators.message(index);
            commit_accum.push(base, message.0);
            resp_accum.push(base, blinding.0);
            proofs.push(blinding.0);
            factors.push(message.0);
        }

        // FIXME batch normalize
        let commitment = commit_accum.sum().to_affine();
        let response = resp_accum.sum().to_affine();

        let mut challenge_hash = HashScalar::new();
        challenge_hash.update(&commitment.to_uncompressed());
        challenge_hash.update(&response.to_uncompressed());
        challenge_hash.update(&nonce.0.to_bytes());
        let challenge = challenge_hash.finalize();

        for (idx, f) in factors.into_iter().enumerate() {
            // s^ = s~ + c * s'
            // r^[i] = r~[i] + c * msg[i]
            proofs[idx] += challenge * f;
        }

        Ok((
            commit_blind.into(),
            commitment.into(),
            CommitmentProof { challenge, proofs },
        ))
    }

    pub fn verify_proof<G: Generators>(
        &self,
        committed_indices: &[usize],
        generators: &G,
        proof: &CommitmentProof,
        nonce: Nonce,
    ) -> Result<(), Error> {
        if committed_indices.len() + 1 != proof.proofs.len() {
            return Err(err_msg!(
                InvalidProof,
                "Mismatch between committed indices and proof count"
            ));
        }

        let mut pok_accum = -(self.0 * proof.challenge) + generators.blinding() * proof.proofs[0];

        for (pos, index) in committed_indices.into_iter().copied().enumerate() {
            if index >= generators.message_count() {
                return Err(err_msg!(
                    InvalidProof,
                    "Message index exceeds generator count"
                ));
            }
            pok_accum += generators.message(index) * proof.proofs[pos + 1];
        }

        let mut verify_hash = HashScalar::new();
        verify_hash.update(&self.0.to_uncompressed()[..]);
        verify_hash.update(&pok_accum.to_affine().to_uncompressed()[..]);
        verify_hash.update(&nonce.0.to_bytes()[..]);
        let c_verify = verify_hash.finalize();

        if c_verify.ct_eq(&proof.challenge).into() {
            Ok(())
        } else {
            Err(err_msg!(InvalidProof, "Verification failed"))
        }
    }
}

impl From<G1Affine> for Commitment {
    fn from(pt: G1Affine) -> Self {
        Self(pt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitmentProof {
    pub(crate) challenge: Scalar,
    pub(crate) proofs: Vec<Scalar>,
}

impl From<(Scalar, Vec<Scalar>)> for CommitmentProof {
    fn from((challenge, proofs): (Scalar, Vec<Scalar>)) -> Self {
        Self { challenge, proofs }
    }
}

#[cfg(feature = "alloc")]
pub struct CommittedMessages<'g, G: Generators> {
    entries: BTreeMap<usize, (Message, Blinding)>,
    generators: &'g G,
}

#[cfg(feature = "alloc")]
impl<'g, G: Generators> CommittedMessages<'g, G> {
    pub fn new(generators: &'g G) -> Self {
        Self {
            entries: BTreeMap::new(),
            generators,
        }
    }
}

#[cfg(feature = "alloc")]
impl<G: Generators> CommittedMessages<'_, G> {
    #[cfg(feature = "getrandom")]
    pub fn insert(&mut self, index: usize, message: Message) -> Result<(), Error> {
        self.insert_with(index, message, Blinding::new())
    }

    pub fn insert_with(
        &mut self,
        index: usize,
        message: Message,
        blinding: Blinding,
    ) -> Result<(), Error> {
        if self.entries.contains_key(&index) {
            Err(err_msg!(Usage, "Duplicate committed message index"))
        } else if index > self.generators.message_count() {
            Err(err_msg!(Usage, "Message index exceeds generator count"))
        } else {
            self.entries.insert(index, (message, blinding));
            Ok(())
        }
    }

    #[cfg(feature = "getrandom")]
    pub fn commit(&self, nonce: Nonce) -> Result<(Blinding, Commitment, CommitmentProof), Error> {
        self.commit_with_rng(nonce, default_rng())
    }

    pub fn commit_with_rng(
        &self,
        nonce: Nonce,
        rng: impl CryptoRng + Rng,
    ) -> Result<(Blinding, Commitment, CommitmentProof), Error> {
        let entries: Vec<_> = self
            .entries
            .iter()
            .map(|(index, (message, blinding))| (*index, *message, *blinding))
            .collect();
        Commitment::commit_with_rng(self.generators, &entries[..], nonce, rng)
    }
}
