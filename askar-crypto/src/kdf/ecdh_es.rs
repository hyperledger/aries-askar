//! ECDH-ES key derivation

use sha2::Sha256;
use zeroize::Zeroizing;

use super::{
    concat::{ConcatKDF, ConcatKDFParams},
    KeyDerivation,
};
use crate::{alg::AnyKey, buffer::Writer, error::Error};

/// An instantiation of the ECDH-ES key derivation
#[derive(Debug)]
pub struct EcdhEs<'d> {
    ephem_key: &'d dyn AnyKey,
    recip_key: &'d dyn AnyKey,
    alg: &'d [u8],
    apu: &'d [u8],
    apv: &'d [u8],
    receive: bool,
}

impl<'d> EcdhEs<'d> {
    /// Create a new KDF instance
    pub fn new(
        ephem_key: &'d dyn AnyKey,
        recip_key: &'d dyn AnyKey,
        alg: &'d [u8],
        apu: &'d [u8],
        apv: &'d [u8],
        receive: bool,
    ) -> Self {
        Self {
            ephem_key,
            recip_key,
            alg,
            apu,
            apv,
            receive,
        }
    }
}

impl KeyDerivation for EcdhEs<'_> {
    fn derive_key_bytes(&mut self, key_output: &mut [u8]) -> Result<(), Error> {
        let output_len = if key_output.len() < (u32::MAX as usize / 8) {
            (key_output.len() * 8) as u32
        } else {
            return Err(err_msg!(Unsupported, "Exceeded maximum output length"));
        };

        // hash Z
        let mut buf = Zeroizing::new([0u8; 256]);
        let mut buf_w = Writer::from_slice(&mut buf[..]);
        if self.receive {
            self.recip_key
                .write_key_exchange(self.ephem_key, &mut buf_w)?
        } else {
            self.ephem_key
                .write_key_exchange(self.recip_key, &mut buf_w)?
        }

        ConcatKDF::<Sha256>::derive_key(
            buf_w.as_ref(),
            ConcatKDFParams {
                alg: self.alg,
                apu: self.apu,
                apv: self.apv,
                pub_info: &output_len.to_be_bytes(), // output length in bits
                prv_info: &[],
            },
            key_output,
        )
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[cfg(feature = "ed25519")]
    #[test]
    // based on RFC sample keys
    // https://tools.ietf.org/html/rfc8037#appendix-A.6
    fn expected_es_direct_output() {
        use crate::alg::x25519::X25519KeyPair;
        use crate::jwk::FromJwk;
        use crate::kdf::DynKeyExchange;

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

        EcdhEs::new(&ephem_sk, &bob_pk, b"A256GCM", b"Alice", b"Bob", false)
            .derive_key_bytes(&mut key_output)
            .unwrap();

        assert_eq!(
            key_output,
            hex!("2f3636918ddb57fe0b3569113f19c4b6c518c2843f8930f05db25cd55dee53c1")
        );
    }
}
