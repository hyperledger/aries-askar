//! BBS+ signature support for aries-askar

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(missing_debug_implementations, missing_docs, rust_2018_idioms)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub use bls12_381;

#[macro_use]
extern crate askar_crypto;
pub use askar_crypto::{Error, ErrorKind};

#[macro_use]
mod macros;

mod challenge;
pub use challenge::{CreateChallenge, ProofChallenge};

pub mod collect;

mod commitment;
pub use commitment::{
    Blinding, Commitment, CommitmentBuilder, CommitmentProof, CommitmentProofContext,
    CommitmentProofVerifier,
};

mod generators;
pub use generators::{DynGenerators, Generators, GeneratorsSeq, VecGenerators};

pub mod hash;

pub mod io;

mod proof;
pub use proof::{SignatureProof, SignatureProofContext, SignatureProofVerifier, SignatureProver};

mod signature;
pub use signature::{Message, Signature, SignatureBuilder, SignatureVerifier};

mod util;
pub use util::Nonce;
