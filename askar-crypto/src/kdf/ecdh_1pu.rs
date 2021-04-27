use sha2::Sha256;
use zeroize::Zeroize;

use super::{
    concat::{ConcatKDFHash, ConcatKDFParams},
    KeyDerivation, KeyExchange,
};
use crate::error::Error;

#[derive(Debug)]
pub struct Ecdh1PU<'d, Key: KeyExchange + ?Sized> {
    ephem_key: &'d Key,
    send_key: &'d Key,
    recip_key: &'d Key,
    alg: &'d [u8],
    apu: &'d [u8],
    apv: &'d [u8],
}

impl<'d, Key: KeyExchange + ?Sized> Ecdh1PU<'d, Key> {
    pub fn new(
        ephem_key: &'d Key,
        send_key: &'d Key,
        recip_key: &'d Key,
        alg: &'d [u8],
        apu: &'d [u8],
        apv: &'d [u8],
    ) -> Self {
        Self {
            ephem_key,
            send_key,
            recip_key,
            alg,
            apu,
            apv,
        }
    }
}

impl<Key: KeyExchange + ?Sized> KeyDerivation for Ecdh1PU<'_, Key> {
    fn derive_key_bytes(&mut self, key_output: &mut [u8]) -> Result<(), Error> {
        let output_len = key_output.len();
        // one-pass KDF only produces 256 bits of output
        assert!(output_len <= 32);
        let mut kdf = ConcatKDFHash::<Sha256>::new();
        kdf.start_pass();

        // hash Zs and Ze directly into the KDF
        self.ephem_key
            .key_exchange_buffer(self.recip_key, &mut kdf)?;
        self.send_key
            .key_exchange_buffer(self.recip_key, &mut kdf)?;

        kdf.hash_params(ConcatKDFParams {
            alg: self.alg,
            apu: self.apu,
            apv: self.apv,
            pub_info: &(output_len * 8).to_be_bytes(), // output length in bits
            prv_info: &[],
        });

        let mut key = kdf.finish_pass();
        key_output.copy_from_slice(&key[..output_len]);
        key.zeroize();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // from RFC: https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-03#appendix-A
    fn expected_1pu_direct_output() {
        use crate::alg::p256::P256KeyPair;
        use crate::jwk::FromJwk;

        let alice_sk = P256KeyPair::from_jwk(
            r#"{"kty":"EC",
            "crv":"P-256",
            "x":"WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
            "y":"y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
            "d":"Hndv7ZZjs_ke8o9zXYo3iq-Yr8SewI5vrqd0pAvEPqg"}"#,
        )
        .unwrap();
        let bob_sk = P256KeyPair::from_jwk(
            r#"{"kty":"EC",
            "crv":"P-256",
            "x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}"#,
        )
        .unwrap();
        let ephem_sk = P256KeyPair::from_jwk(
            r#"{"kty":"EC",
            "crv":"P-256",
            "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
            "d":"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"}"#,
        )
        .unwrap();

        let mut key_output = [0u8; 32];

        Ecdh1PU::new(&ephem_sk, &alice_sk, &bob_sk, b"A256GCM", b"Alice", b"Bob")
            .derive_key_bytes(&mut key_output)
            .unwrap();

        assert_eq!(
            key_output,
            hex!("6caf13723d14850ad4b42cd6dde935bffd2fff00a9ba70de05c203a5e1722ca7")
        );
    }
}
