//! ConcatKDF from NIST 800-56ar for ECDH-ES / ECDH-1PU

use core::marker::PhantomData;

use digest::{Digest, FixedOutput};

use crate::error::Error;

pub struct ConcatKDF<H>(PhantomData<H>);

#[derive(Default)]
pub struct Params<'p> {
    alg: &'p [u8],
    apu: &'p [u8],
    apv: &'p [u8],
}

impl<H> ConcatKDF<H>
where
    H: Digest + FixedOutput,
{
    pub fn derive_key(
        message: &[u8],
        params: Params<'_>,
        mut output: &mut [u8],
    ) -> Result<(), Error> {
        let output_len = output.len();
        if output_len > u32::MAX as usize / 8 {
            // output_len is used as SuppPubInfo later
            return Err(err_msg!("exceeded max output size for concat KDF"));
        }
        let mut counter = 1u32;
        let mut remain = output_len;
        let mut hash = H::new();
        while remain > 0 {
            hash.update(counter.to_be_bytes());
            hash.update(message);
            hash.update((params.alg.len() as u32).to_be_bytes());
            hash.update(params.alg);
            hash.update((params.apu.len() as u32).to_be_bytes());
            hash.update(params.apu);
            hash.update((params.apv.len() as u32).to_be_bytes());
            hash.update(params.apv);
            hash.update((output_len as u32 * 8).to_be_bytes());
            let hashed = hash.finalize_reset();
            let cp_size = hashed.len().min(remain);
            &output[..cp_size].copy_from_slice(&hashed[..cp_size]);
            output = &mut output[cp_size..];
            remain -= cp_size;
            counter += 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha256;

    #[test]
    fn expected_1pu_output() {
        let z = hex!(
            "9e56d91d817135d372834283bf84269cfb316ea3da806a48f6daa7798cfe90c4
            e3ca3474384c9f62b30bfd4c688b3e7d4110a1b4badc3cc54ef7b81241efd50d"
        );
        let mut output = [0u8; 32];
        ConcatKDF::<Sha256>::derive_key(
            &z,
            Params {
                alg: b"A256GCM",
                apu: b"Alice",
                apv: b"Bob",
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
