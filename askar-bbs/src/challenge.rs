use askar_crypto::buffer::WriteBuffer;

use crate::util::{HashScalar, Nonce};

pub type ProofChallenge = Nonce;

pub trait CreateChallenge {
    fn create_challenge(&self, nonce: Nonce) -> ProofChallenge {
        let mut c_hash = HashScalar::new(None);
        self.write_challenge_bytes(&mut c_hash).unwrap();
        c_hash.update(&nonce.0.to_bytes());
        Nonce(c_hash.finalize().next())
    }

    fn write_challenge_bytes(
        &self,
        writer: &mut dyn WriteBuffer,
    ) -> Result<(), askar_crypto::Error>;
}
