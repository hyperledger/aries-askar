//! ConcatKDF from NIST 800-56ar for ECDH-ES / ECDH-1PU

use core::marker::PhantomData;

use digest::Digest;

use crate::generic_array::GenericArray;

use crate::{buffer::WriteBuffer, error::Error};

pub struct ConcatKDF<H>(PhantomData<H>);

#[derive(Clone, Copy, Default)]
pub struct ConcatKDFParams<'p> {
    pub alg: &'p [u8],
    pub apu: &'p [u8],
    pub apv: &'p [u8],
    pub pub_info: &'p [u8],
    pub prv_info: &'p [u8],
}

impl<H> ConcatKDF<H>
where
    H: Digest,
{
    pub fn derive_key(
        message: &[u8],
        params: ConcatKDFParams<'_>,
        mut output: &mut [u8],
    ) -> Result<(), Error> {
        let output_len = output.len();
        if output_len > u32::MAX as usize / 8 {
            // output_len is used as SuppPubInfo later
            return Err(err_msg!(Usage, "Exceeded max output size for concat KDF"));
        }
        let mut hasher = ConcatKDFHash::<H>::new();
        let mut remain = output_len;
        while remain > 0 {
            hasher.start_pass();
            hasher.hash_message(message);
            hasher.hash_params(params);
            let hashed = hasher.finish_pass();
            let cp_size = hashed.len().min(remain);
            &output[..cp_size].copy_from_slice(&hashed[..cp_size]);
            output = &mut output[cp_size..];
            remain -= cp_size;
        }
        Ok(())
    }
}

pub struct ConcatKDFHash<H: Digest> {
    hasher: H,
    counter: u32,
}

impl<H: Digest> ConcatKDFHash<H> {
    pub fn new() -> Self {
        Self {
            hasher: H::new(),
            counter: 1,
        }
    }

    pub fn start_pass(&mut self) {
        self.hasher.update(self.counter.to_be_bytes());
        self.counter += 1;
    }

    pub fn hash_message(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    pub fn hash_params(&mut self, params: ConcatKDFParams<'_>) {
        let hash = &mut self.hasher;
        hash.update((params.alg.len() as u32).to_be_bytes());
        hash.update(params.alg);
        hash.update((params.apu.len() as u32).to_be_bytes());
        hash.update(params.apu);
        hash.update((params.apv.len() as u32).to_be_bytes());
        hash.update(params.apv);
        hash.update(params.pub_info);
        hash.update(params.prv_info);
    }

    pub fn finish_pass(&mut self) -> GenericArray<u8, H::OutputSize> {
        self.hasher.finalize_reset()
    }
}

const HASH_BUFFER_SIZE: usize = 128;

impl<D: Digest> WriteBuffer for ConcatKDFHash<D> {
    fn write_slice(&mut self, data: &[u8]) -> Result<(), Error> {
        self.hasher.update(data);
        Ok(())
    }

    fn write_with(
        &mut self,
        max_len: usize,
        f: impl FnOnce(&mut [u8]) -> Result<usize, Error>,
    ) -> Result<usize, Error> {
        // this could use a Vec to support larger inputs
        // but for current purposes a small fixed buffer is fine
        if max_len > HASH_BUFFER_SIZE {
            return Err(err_msg!(Usage, "Exceeded hash buffer size"));
        }
        let mut buf = [0u8; HASH_BUFFER_SIZE];
        let written = f(&mut buf[..max_len])?;
        self.write_slice(&buf[..written])?;
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    #[test]
    // testing with ConcatKDF - single pass via ConcatKDFHash is tested elsewhere
    fn expected_1pu_output() {
        let z = hex!(
            "9e56d91d817135d372834283bf84269cfb316ea3da806a48f6daa7798cfe90c4
            e3ca3474384c9f62b30bfd4c688b3e7d4110a1b4badc3cc54ef7b81241efd50d"
        );
        let mut output = [0u8; 32];
        ConcatKDF::<Sha256>::derive_key(
            &z,
            ConcatKDFParams {
                alg: b"A256GCM",
                apu: b"Alice",
                apv: b"Bob",
                pub_info: &(256u32).to_be_bytes(),
                prv_info: &[],
            },
            &mut output,
        )
        .unwrap();
        assert_eq!(
            output,
            hex!("6caf13723d14850ad4b42cd6dde935bffd2fff00a9ba70de05c203a5e1722ca7")
        );
    }
}
