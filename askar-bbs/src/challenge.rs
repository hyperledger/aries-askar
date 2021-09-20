use askar_crypto::buffer::WriteBuffer;

use crate::{hash::HashScalar, util::Nonce, Error};

impl_scalar_type!(ProofChallenge, "Fiat-Shamir proof challenge value");

impl ProofChallenge {
    /// Create a new proof challenge value from a set of prepared proofs
    pub fn create(
        proofs: &[&dyn CreateChallenge],
        nonce: Nonce,
        dst: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let mut c_hash = HashScalar::new(dst);
        for proof in proofs {
            proof.write_challenge_bytes(&mut c_hash)?;
        }
        c_hash.update(&nonce.0.to_bytes());
        Ok(ProofChallenge(c_hash.finalize().next()))
    }
}

/// Support for outputting bytes for use in proof challenge generation
pub trait CreateChallenge {
    /// Create a new independent proof challenge
    fn create_challenge(&self, nonce: Nonce, dst: Option<&[u8]>) -> Result<ProofChallenge, Error> {
        let mut c_hash = HashScalar::new(dst);
        self.write_challenge_bytes(&mut c_hash)?;
        c_hash.update(&nonce.0.to_bytes());
        Ok(ProofChallenge(c_hash.finalize().next()))
    }

    /// Write the challenge bytes to a target
    fn write_challenge_bytes(&self, writer: &mut dyn WriteBuffer) -> Result<(), Error>;
}
