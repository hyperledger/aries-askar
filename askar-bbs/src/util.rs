use bls12_381::{G1Projective, Scalar};
use rand::{CryptoRng, Rng};
use subtle::ConstantTimeEq;

#[cfg(feature = "getrandom")]
use askar_crypto::random::default_rng;

pub(crate) fn random_nonce<R: CryptoRng + Rng>(mut rng: R) -> Scalar {
    let mut buf = [0u8; 64];
    let mut s;
    loop {
        rng.fill_bytes(&mut buf);
        s = Scalar::from_bytes_wide(&buf);
        if !bool::from(s.ct_eq(&Scalar::zero())) {
            break s;
        }
    }
}

impl_scalar_type!(Nonce, "A nonce used in proof verification");

impl Nonce {
    #[cfg(feature = "getrandom")]
    /// Generate a new random nonce value
    pub fn new() -> Self {
        Self(random_nonce(default_rng()))
    }

    /// Generate a new random nonce value from a specific RNG
    pub fn new_with_rng(rng: impl CryptoRng + Rng) -> Self {
        Self(random_nonce(rng))
    }
}

// sum-of-products impl:

// const ACCUM_BATCH: usize = 16;

// #[derive(Clone, Debug)]
// pub(crate) struct AccumG1 {
//     accum: G1Projective,
//     stack_base: [G1Projective; ACCUM_BATCH],
//     stack_factor: [Scalar; ACCUM_BATCH],
//     stack_size: usize,
// }

// impl AccumG1 {
//     pub fn zero() -> Self {
//         Self::new_with(G1Projective::identity())
//     }

//     pub fn new_with(accum: impl Into<G1Projective>) -> Self {
//         Self {
//             accum: accum.into(),
//             stack_base: [G1Projective::identity(); ACCUM_BATCH],
//             stack_factor: [Scalar::zero(); ACCUM_BATCH],
//             stack_size: 0,
//         }
//     }

//     pub fn calc(pairs: &[(G1Projective, Scalar)]) -> G1Projective {
//         let mut acc = Self::zero();
//         acc.append(pairs);
//         acc.sum()
//     }

//     #[inline]
//     fn rollup(&mut self) -> G1Projective {
//         let sz = self.stack_size;
//         G1Projective::sum_of_products_in_place(&self.stack_base[..sz], &mut self.stack_factor[..sz])
//     }

//     #[inline]
//     pub fn push(&mut self, base: G1Projective, factor: Scalar) {
//         let mut sz = self.stack_size;
//         if sz == ACCUM_BATCH {
//             let sum = self.rollup();
//             self.accum += sum;
//             sz = 0;
//         };
//         self.stack_base[sz] = base;
//         self.stack_factor[sz] = factor;
//         self.stack_size = sz + 1;
//     }

//     pub fn append(&mut self, pairs: &[(G1Projective, Scalar)]) {
//         for (base, factor) in pairs.into_iter().copied() {
//             self.push(base, factor);
//         }
//     }

//     pub fn sum(&self) -> G1Projective {
//         let mut sum = self.accum;
//         let sz = self.stack_size;
//         if sz > 0 {
//             let mut factors = self.stack_factor;
//             sum +=
//                 G1Projective::sum_of_products_in_place(&self.stack_base[..sz], &mut factors[..sz]);
//         }
//         sum
//     }

//     pub fn sum_mut(&mut self) -> G1Projective {
//         if self.stack_size > 0 {
//             let sum = self.rollup();
//             self.accum += sum;
//             self.stack_size = 0;
//         }
//         self.accum
//     }

//     pub fn sum_with(&self, base: G1Projective, factor: Scalar) -> G1Projective {
//         let sum = self.accum;
//         let mut sz = self.stack_size;
//         if sz > 0 {
//             let mut bases = [G1Projective::identity(); ACCUM_BATCH + 1];
//             let mut factors = [Scalar::zero(); ACCUM_BATCH + 1];
//             bases[..sz].copy_from_slice(&self.stack_base[..sz]);
//             factors[..sz].copy_from_slice(&self.stack_factor[..sz]);
//             bases[sz] = base;
//             factors[sz] = factor;
//             sz += 1;
//             sum + G1Projective::sum_of_products_in_place(&bases[..sz], &mut factors[..sz])
//         } else {
//             sum + base * factor
//         }
//     }
// }

#[derive(Clone, Debug)]
pub(crate) struct AccumG1 {
    accum: G1Projective,
}

impl AccumG1 {
    pub fn zero() -> Self {
        Self::new_with(G1Projective::identity())
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
    pub fn push(&mut self, base: G1Projective, factor: Scalar) {
        self.accum += base * factor;
    }

    pub fn append(&mut self, pairs: &[(G1Projective, Scalar)]) {
        for (base, factor) in pairs.into_iter().copied() {
            self.push(base, factor);
        }
    }

    pub fn sum(&self) -> G1Projective {
        self.accum
    }

    pub fn sum_with(&self, base: G1Projective, factor: Scalar) -> G1Projective {
        self.accum + base * factor
    }
}

impl From<G1Projective> for AccumG1 {
    fn from(accum: G1Projective) -> Self {
        AccumG1::new_with(accum)
    }
}

impl From<(G1Projective, Scalar)> for AccumG1 {
    fn from((base, factor): (G1Projective, Scalar)) -> Self {
        let mut acc = AccumG1::zero();
        acc.push(base, factor);
        acc
    }
}

impl From<&[(G1Projective, Scalar)]> for AccumG1 {
    fn from(pairs: &[(G1Projective, Scalar)]) -> Self {
        let mut acc = AccumG1::zero();
        acc.append(pairs);
        acc
    }
}
