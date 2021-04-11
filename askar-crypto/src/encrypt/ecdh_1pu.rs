use sha2::Sha256;
use zeroize::Zeroize;

use crate::{
    buffer::WriteBuffer,
    caps::KeyGen,
    encrypt::KeyExchange,
    error::Error,
    jwk::{JwkEncoder, ToJwk},
    kdf::concat::{ConcatKDFHash, ConcatKDFParams},
};

fn ecdh_1pu_derive_shared<Key>(
    send_key: &Key,
    recip_key: &Key,
    ephem_key: &Key,
    params: ConcatKDFParams,
    key_output: &mut [u8],
) -> Result<(), Error>
where
    Key: KeyExchange,
{
    let output_len = key_output.len();
    // one-pass KDF only produces 256 bits of output
    assert!(output_len <= 32);
    let mut kdf = ConcatKDFHash::<Sha256>::new();
    kdf.start_pass();

    // hash Zs and Ze directly into the KDF
    ephem_key.key_exchange_buffer(recip_key, &mut kdf)?;
    send_key.key_exchange_buffer(recip_key, &mut kdf)?;

    let mut key = kdf.finish_pass(params, output_len);
    key_output.copy_from_slice(&key[..output_len]);
    key.zeroize();

    Ok(())
}

pub fn ecdh_1pu_direct<Key, B: WriteBuffer>(
    send_key: &Key,
    recip_key: &Key,
    alg: &[u8],
    apu: &[u8],
    apv: &[u8],
    key_output: &mut [u8],
    jwk_output: &mut JwkEncoder<B>,
) -> Result<(), Error>
where
    Key: KeyGen + KeyExchange + ToJwk,
{
    let ephem_key = Key::generate()?;
    ephem_key.to_jwk_buffer(jwk_output)?;

    let params = ConcatKDFParams { alg, apu, apv };
    ecdh_1pu_derive_shared(send_key, recip_key, &ephem_key, params, key_output)?;

    // SECURITY: keys must zeroize themselves on drop
    drop(ephem_key);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // from RFC: https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-03#appendix-A
    fn expected_1pu_direct_output() {
        use crate::alg::p256::P256KeyPair;
        use crate::jwk::{FromJwk, Jwk};

        let alice_sk = P256KeyPair::from_jwk(Jwk::from(
            r#"{"kty":"EC",
            "crv":"P-256",
            "x":"WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
            "y":"y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
            "d":"Hndv7ZZjs_ke8o9zXYo3iq-Yr8SewI5vrqd0pAvEPqg"}"#,
        ))
        .unwrap();
        let bob_sk = P256KeyPair::from_jwk(Jwk::from(
            r#"{"kty":"EC",
            "crv":"P-256",
            "x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
            "d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}"#,
        ))
        .unwrap();
        let ephem_sk = P256KeyPair::from_jwk(Jwk::from(
            r#"{"kty":"EC",
            "crv":"P-256",
            "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
            "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
            "d":"0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"}"#,
        ))
        .unwrap();

        let mut key_output = [0u8; 32];

        ecdh_1pu_derive_shared(
            &alice_sk,
            &bob_sk,
            &ephem_sk,
            ConcatKDFParams {
                alg: b"A256GCM",
                apu: b"Alice",
                apv: b"Bob",
            },
            &mut key_output,
        )
        .unwrap();

        assert_eq!(
            key_output,
            hex!("6caf13723d14850ad4b42cd6dde935bffd2fff00a9ba70de05c203a5e1722ca7")
        );
    }
}
