// #![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub use bls12_381;

#[macro_use]
mod error;
pub use error::{Error, ErrorKind};

mod collect;

mod commitment;
pub use commitment::{Blinding, Commitment, CommitmentProof};

#[cfg(feature = "alloc")]
pub use commitment::CommittedMessages;

mod generators;
pub use generators::{DynGeneratorsV1, Generators, VecGenerators};

mod proof;
pub use proof::{
    ProofChallenge, ProverMessages, ProverMessagesT, SignatureProof, SignatureProofContext,
    VerifierMessages, VerifierMessagesT,
};

mod signature;
pub use signature::{Message, Signature, SignatureMessages};

mod util;
pub use util::Nonce;
