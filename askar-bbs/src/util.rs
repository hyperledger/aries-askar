use askar_crypto::generic_array::{typenum::Unsigned, GenericArray};
use blake2::{
    digest::{Update, VariableOutput},
    VarBlake2b,
};
use bls12_381::{hash_to_curve::HashToField, Scalar};
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

#[derive(Clone, Copy, PartialEq, Eq)]
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
