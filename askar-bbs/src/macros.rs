macro_rules! impl_scalar_type {
    ($type:ident, $doc:expr) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[doc = $doc]
        pub struct $type(pub(crate) bls12_381::Scalar);

        impl $crate::io::FixedLengthBytes for $type {
            const LENGTH: usize = 32;

            type Buffer = [u8; 32];

            fn from_bytes(buf: &Self::Buffer) -> Result<Self, $crate::error::Error> {
                let mut b = *buf;
                b.reverse(); // into little-endian
                if let Some(s) = bls12_381::Scalar::from_bytes(&b).into() {
                    Ok(Self(s))
                } else {
                    Err(err_msg!(Usage, "Scalar bytes not in canonical format"))
                }
            }

            fn with_bytes<R>(&self, f: impl FnOnce(&Self::Buffer) -> R) -> R {
                let mut b = self.0.to_bytes();
                b.reverse(); // into big-endian
                f(&b)
            }
        }

        impl subtle::ConstantTimeEq for $type {
            fn ct_eq(&self, other: &Self) -> subtle::Choice {
                self.0.ct_eq(&other.0)
            }
        }

        impl From<&bls12_381::Scalar> for $type {
            fn from(s: &bls12_381::Scalar) -> Self {
                Self(*s)
            }
        }

        impl From<bls12_381::Scalar> for $type {
            fn from(s: bls12_381::Scalar) -> Self {
                Self(s)
            }
        }

        impl From<u64> for $type {
            fn from(s: u64) -> Self {
                Self(bls12_381::Scalar::from(s))
            }
        }
    };
}
