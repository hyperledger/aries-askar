#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub use bls12_381;

#[macro_use]
mod error;
pub use error::{Error, ErrorKind};

mod challenge;
pub use challenge::{CreateChallenge, ProofChallenge};

mod collect;

mod commitment;
pub use commitment::{Blinding, Commitment, CommitmentBuilder, CommitmentProof};

mod generators;
pub use generators::{DynGeneratorsV1, Generators, VecGenerators};

mod proof;
pub use proof::{SignatureProof, SignatureProofContext, SignatureProofVerifier, SignatureProver};

mod signature;
pub use signature::{Message, Signature, SignatureMessages};

mod util;
pub use util::Nonce;
