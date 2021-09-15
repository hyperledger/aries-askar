use askar_crypto::buffer::WriteBuffer;

use crate::{hash::HashScalar, util::Nonce, Error};

impl_scalar_type!(ProofChallenge, "Fiat-Shamir proof challenge value");

/// Support for outputting bytes for use in proof challenge generation
pub trait CreateChallenge {
    /// Create a new independent proof challenge
    fn create_challenge(&self, nonce: Nonce) -> ProofChallenge {
        let mut c_hash = HashScalar::new(None);
        self.write_challenge_bytes(&mut c_hash).unwrap();
        c_hash.update(&nonce.0.to_bytes());
        ProofChallenge(c_hash.finalize().next())
    }

    /// Write the challenge bytes to a target
    fn write_challenge_bytes(&self, writer: &mut dyn WriteBuffer) -> Result<(), Error>;
}
