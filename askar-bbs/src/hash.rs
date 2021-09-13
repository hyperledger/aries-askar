use askar_crypto::buffer::WriteBuffer;
use bls12_381::Scalar;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Sha3XofReader, Shake256,
};

#[derive(Clone, Debug)]
pub struct HashScalar<'d> {
    hasher: Shake256,
    dst: Option<&'d [u8]>,
}

impl<'d> HashScalar<'d> {
    pub fn new(dst: Option<&'d [u8]>) -> Self {
        Self {
            hasher: Shake256::default(),
            dst,
        }
    }
}

impl HashScalar<'_> {
    #[inline]
    pub fn digest(input: impl AsRef<[u8]>, dst: Option<&[u8]>) -> Scalar {
        let mut state = HashScalar::new(dst);
        state.update(input.as_ref());
        state.finalize().next()
    }

    #[inline]
    pub fn update(&mut self, input: impl AsRef<[u8]>) {
        self.hasher.update(input.as_ref());
    }

    pub fn finalize(mut self) -> HashScalarRead {
        if let Some(dst) = self.dst {
            self.hasher.update(dst);
        }
        HashScalarRead(self.hasher.finalize_xof())
    }
}

impl WriteBuffer for HashScalar<'_> {
    fn buffer_write(&mut self, data: &[u8]) -> Result<(), askar_crypto::Error> {
        self.update(data);
        Ok(())
    }
}

pub struct HashScalarRead(Sha3XofReader);

impl HashScalarRead {
    pub fn next(&mut self) -> Scalar {
        let mut buf = [0u8; 64];
        self.0.read(&mut buf);
        Scalar::from_bytes_wide(&buf)
    }
}
