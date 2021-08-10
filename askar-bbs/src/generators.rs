use core::fmt::Debug;

use askar_crypto::alg::bls::{BlsKeyPair, G2};
use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    G1Projective,
};

use crate::{
    collect::{DefaultSeq, Seq, Vec},
    error::Error,
};

const DST_G1_V1: &'static [u8] = b"BLS12381G1_XMD:BLAKE2B_SSWU_RO_BBS+_SIGNATURES:1_0_0";
const G2_UNCOMPRESSED_SIZE: usize = 192;

pub trait Generators: Clone + Debug {
    #[inline]
    fn blinding(&self) -> G1Projective {
        self.generator(0)
    }

    #[inline]
    fn message(&self, index: usize) -> G1Projective {
        self.generator(index + 1)
    }

    fn message_count(&self) -> usize;

    fn generator(&self, index: usize) -> G1Projective;

    fn iter(&self) -> GeneratorsIter<'_, Self> {
        GeneratorsIter {
            index: 0,
            count: self.message_count() + 1,
            gens: self,
        }
    }
}

pub struct GeneratorsIter<'g, G: Generators> {
    index: usize,
    count: usize,
    gens: &'g G,
}

impl<G: Generators> Iterator for GeneratorsIter<'_, G> {
    type Item = G1Projective;

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.count - self.index;
        (len, Some(len))
    }

    fn next(&mut self) -> Option<Self::Item> {
        let idx = self.index;
        if idx < self.count {
            self.index += 1;
            Some(self.gens.generator(idx))
        } else {
            None
        }
    }
}

impl<G: Generators> ExactSizeIterator for GeneratorsIter<'_, G> {}

pub type VecGenerators = GeneratorsSeq<DefaultSeq<128>>;

#[derive(Debug)]
pub struct GeneratorsSeq<S>
where
    S: Seq<G1Projective>,
{
    h: Vec<G1Projective, S>,
}

impl<S> Clone for GeneratorsSeq<S>
where
    S: Seq<G1Projective>,
    Vec<G1Projective, S>: Clone,
{
    fn clone(&self) -> Self {
        Self { h: self.h.clone() }
    }
}

impl<S> Generators for GeneratorsSeq<S>
where
    S: Seq<G1Projective>,
{
    fn generator(&self, index: usize) -> G1Projective {
        self.h[index]
    }

    fn message_count(&self) -> usize {
        self.h.len() - 1
    }
}

impl<S> GeneratorsSeq<S>
where
    S: Seq<G1Projective>,
{
    pub fn copy_from<G: Generators>(gens: &G) -> Result<Self, Error> {
        Ok(Self {
            h: Vec::from_iter(gens.iter())?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DynGeneratorsV1 {
    count: usize,
    pk: [u8; G2_UNCOMPRESSED_SIZE],
}

impl DynGeneratorsV1 {
    pub fn new(pk: &BlsKeyPair<G2>, message_count: usize) -> Self {
        Self {
            count: message_count,
            pk: pk.bls_public_key().to_uncompressed(),
        }
    }

    pub fn to_vec(&self) -> Result<VecGenerators, Error> {
        VecGenerators::copy_from(self)
    }
}

impl Generators for DynGeneratorsV1 {
    fn generator(&self, index: usize) -> G1Projective {
        const HASH_BUF_SIZE: usize = 10 + G2_UNCOMPRESSED_SIZE;

        let mut hash_buf = [0u8; HASH_BUF_SIZE];
        hash_buf[..G2_UNCOMPRESSED_SIZE].copy_from_slice(&self.pk[..]);
        hash_buf[(G2_UNCOMPRESSED_SIZE + 1)..(G2_UNCOMPRESSED_SIZE + 5)]
            .copy_from_slice(&(index as u32).to_be_bytes()[..]);
        hash_buf[(G2_UNCOMPRESSED_SIZE + 6)..(G2_UNCOMPRESSED_SIZE + 10)]
            .copy_from_slice(&(self.count as u32).to_be_bytes()[..]);

        <G1Projective as HashToCurve<ExpandMsgXmd<blake2::Blake2b>>>::hash_to_curve(
            &hash_buf[..],
            DST_G1_V1,
        )
    }

    fn message_count(&self) -> usize {
        self.count
    }
}
