use askar_crypto::{
    buffer::WriteBuffer,
    generic_array::{typenum::Unsigned, GenericArray},
};
use blake2::{
    digest::{Update, VariableOutput},
    VarBlake2b,
};
use bls12_381::{hash_to_curve::HashToField, G1Projective, Scalar};
use ff::Field;
use rand::{CryptoRng, Rng};

#[cfg(feature = "getrandom")]
use rand::rngs::OsRng;

#[cfg(feature = "getrandom")]
type DefaultRng = OsRng;

#[cfg(feature = "getrandom")]
pub fn default_rng() -> DefaultRng {
    OsRng
}

pub fn random_nonce<R: CryptoRng + Rng>(mut rng: R) -> Scalar {
    let mut r;
    loop {
        r = Scalar::random(&mut rng);
        if !r.is_zero() {
            break r;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nonce(pub(crate) Scalar);

impl Nonce {
    #[cfg(feature = "getrandom")]
    pub fn new() -> Self {
        Self(random_nonce(default_rng()))
    }

    pub fn new_with_rng(rng: impl CryptoRng + Rng) -> Self {
        Self(random_nonce(rng))
    }
}

impl From<Scalar> for Nonce {
    fn from(s: Scalar) -> Self {
        Self(s)
    }
}

#[derive(Debug)]
pub struct HashScalar {
    hasher: VarBlake2b,
}

impl HashScalar {
    pub fn new() -> Self {
        Self {
            hasher: VarBlake2b::new(<Scalar as HashToField>::InputLength::USIZE)
                .expect("Invalid hasher output size"),
        }
    }

    #[inline]
    pub fn digest(input: impl AsRef<[u8]>) -> Scalar {
        let mut state = Self::new();
        state.update(input.as_ref());
        state.finalize()
    }

    pub fn update(&mut self, input: impl AsRef<[u8]>) {
        self.hasher.update(input.as_ref());
    }

    pub fn finalize(self) -> Scalar {
        let mut buf = GenericArray::default();
        self.hasher.finalize_variable(|hash| {
            buf.copy_from_slice(hash);
        });
        Scalar::from_okm(&buf)
    }
}

impl WriteBuffer for HashScalar {
    fn buffer_write(&mut self, data: &[u8]) -> Result<(), askar_crypto::Error> {
        self.update(data);
        Ok(())
    }
}

// will modify to use sum-of-products
#[derive(Clone, Debug)]
pub(crate) struct AccumG1 {
    accum: G1Projective,
}

impl AccumG1 {
    pub fn zero() -> Self {
        Self {
            accum: G1Projective::identity(),
        }
    }

    pub fn new_with(accum: impl Into<G1Projective>) -> Self {
        Self {
            accum: accum.into(),
        }
    }

    pub fn calc(pairs: &[(G1Projective, Scalar)]) -> G1Projective {
        let mut acc = Self::zero();
        acc.append(pairs);
        acc.sum()
    }

    #[inline]
    pub fn push(&mut self, base: G1Projective, message: Scalar) {
        self.accum += base * message;
    }

    pub fn append(&mut self, pairs: &[(G1Projective, Scalar)]) {
        for (base, factor) in pairs.into_iter().copied() {
            self.push(base, factor);
        }
    }

    pub fn sum(&self) -> G1Projective {
        self.accum
    }

    pub fn sum_with(&self, base: G1Projective, message: Scalar) -> G1Projective {
        self.accum + base * message
    }
}
