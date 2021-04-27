use sha2::Sha256;
use zeroize::Zeroize;

use super::{
    concat::{ConcatKDFHash, ConcatKDFParams},
    KeyDerivation, KeyExchange,
};
use crate::error::Error;

#[derive(Debug)]
pub struct EcdhEs<'d, Key>
where
    Key: KeyExchange + ?Sized,
{
    ephem_key: &'d Key,
    recip_key: &'d Key,
    alg: &'d [u8],
    apu: &'d [u8],
    apv: &'d [u8],
}

impl<'d, Key: KeyExchange + ?Sized> EcdhEs<'d, Key> {
    pub fn new(
        ephem_key: &'d Key,
        recip_key: &'d Key,
        alg: &'d [u8],
        apu: &'d [u8],
        apv: &'d [u8],
    ) -> Self {
        Self {
            ephem_key,
            recip_key,
            alg,
            apu,
            apv,
        }
    }
}

impl<Key: KeyExchange + ?Sized> KeyDerivation for EcdhEs<'_, Key> {
    fn derive_key_bytes(&mut self, key_output: &mut [u8]) -> Result<(), Error> {
        let output_len = key_output.len();
        // one-pass KDF only produces 256 bits of output
        assert!(output_len <= 32);
        let mut kdf = ConcatKDFHash::<Sha256>::new();
        kdf.start_pass();

        // hash Z directly into the KDF
        self.ephem_key
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
    // based on RFC sample keys
    // https://tools.ietf.org/html/rfc8037#appendix-A.6
    fn expected_es_direct_output() {
        use crate::alg::x25519::X25519KeyPair;
        use crate::jwk::FromJwk;

        let bob_pk = X25519KeyPair::from_jwk(
            r#"{"kty":"OKP","crv":"X25519","kid":"Bob",
            "x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}"#,
        )
        .unwrap();
        let ephem_sk = X25519KeyPair::from_jwk(
            r#"{"kty":"OKP","crv":"X25519",
            "d":"dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo",
            "x":"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"}
         "#,
        )
        .unwrap();

        let xk = ephem_sk.key_exchange_bytes(&bob_pk).unwrap();
        assert_eq!(
            xk,
            &hex!("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")[..]
        );

        let mut key_output = [0u8; 32];

        EcdhEs::new(&ephem_sk, &bob_pk, b"A256GCM", b"Alice", b"Bob")
            .derive_key_bytes(&mut key_output)
            .unwrap();

        assert_eq!(
            key_output,
            hex!("2f3636918ddb57fe0b3569113f19c4b6c518c2843f8930f05db25cd55dee53c1")
        );
    }
}
