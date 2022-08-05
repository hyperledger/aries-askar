//! ECDH-1PU key derivation

use sha2::Sha256;
use zeroize::Zeroizing;

use super::{
    concat::{ConcatKDF, ConcatKDFParams},
    KeyDerivation,
};
use crate::{
    alg::AnyKey,
    buffer::{WriteBuffer, Writer},
    error::Error,
};

/// An instantiation of the ECDH-1PU key derivation
#[derive(Debug)]
pub struct Ecdh1PU<'d> {
    ephem_key: &'d dyn AnyKey,
    send_key: &'d dyn AnyKey,
    recip_key: &'d dyn AnyKey,
    alg: &'d [u8],
    apu: &'d [u8],
    apv: &'d [u8],
    cc_tag: &'d [u8],
    receive: bool,
}

impl<'d> Ecdh1PU<'d> {
    /// Create a new KDF instance
    pub fn new(
        ephem_key: &'d dyn AnyKey,
        send_key: &'d dyn AnyKey,
        recip_key: &'d dyn AnyKey,
        alg: &'d [u8],
        apu: &'d [u8],
        apv: &'d [u8],
        cc_tag: &'d [u8],
        receive: bool,
    ) -> Self {
        Self {
            ephem_key,
            send_key,
            recip_key,
            alg,
            apu,
            apv,
            cc_tag,
            receive,
        }
    }
}

impl KeyDerivation for Ecdh1PU<'_> {
    fn derive_key_bytes(&mut self, key_output: &mut [u8]) -> Result<(), Error> {
        let output_len = if key_output.len() < (u32::MAX as usize / 8) {
            (key_output.len() * 8) as u32
        } else {
            return Err(err_msg!(Unsupported, "Exceeded maximum output length"));
        };
        if self.cc_tag.len() > 128 {
            return Err(err_msg!(Unsupported, "Exceeded maximum length for cc_tag"));
        }

        // hash Zs and Ze
        let mut buf = Zeroizing::new([0u8; 512]);
        let mut buf_w = Writer::from_slice(&mut buf[..]);
        if self.receive {
            self.recip_key
                .write_key_exchange(self.ephem_key, &mut buf_w)?;
            self.recip_key
                .write_key_exchange(self.send_key, &mut buf_w)?;
        } else {
            self.ephem_key
                .write_key_exchange(self.recip_key, &mut buf_w)?;
            self.send_key
                .write_key_exchange(self.recip_key, &mut buf_w)?;
        };

        // the authentication tag is appended to pub_info, if any.
        let mut pub_info = [0u8; 132];
        let mut pub_w = Writer::from_slice(&mut pub_info[..]);
        pub_w.buffer_write(&output_len.to_be_bytes())?; // output length in bits
        if !self.cc_tag.is_empty() {
            pub_w.buffer_write(&(self.cc_tag.len() as u32).to_be_bytes())?;
            pub_w.buffer_write(&self.cc_tag)?;
        }

        ConcatKDF::<Sha256>::derive_key(
            buf_w.as_ref(),
            ConcatKDFParams {
                alg: self.alg,
                apu: self.apu,
                apv: self.apv,
                pub_info: pub_w.as_ref(),
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

    #[cfg(feature = "p256")]
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

        Ecdh1PU::new(
            &ephem_sk,
            &alice_sk,
            &bob_sk,
            b"A256GCM",
            b"Alice",
            b"Bob",
            &[],
            false,
        )
        .derive_key_bytes(&mut key_output)
        .unwrap();

        assert_eq!(
            key_output,
            hex!("6caf13723d14850ad4b42cd6dde935bffd2fff00a9ba70de05c203a5e1722ca7")
        );
    }

    #[cfg(feature = "ed25519")]
    #[test]
    // from RFC: https://tools.ietf.org/html/draft-madden-jose-ecdh-1pu-04#appendix-B
    fn expected_1pu_wrapped_output() {
        use crate::alg::x25519::X25519KeyPair;
        use crate::jwk::FromJwk;

        let alice_sk = X25519KeyPair::from_jwk(
            r#"{"kty": "OKP",
            "crv": "X25519",
            "x": "Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4",
            "d": "i9KuFhSzEBsiv3PKVL5115OCdsqQai5nj_Flzfkw5jU"}"#,
        )
        .unwrap();
        let bob_sk = X25519KeyPair::from_jwk(
            r#"{"kty": "OKP",
            "crv": "X25519",
            "x": "BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw",
            "d": "1gDirl_r_Y3-qUa3WXHgEXrrEHngWThU3c9zj9A2uBg"}"#,
        )
        .unwrap();
        let ephem_sk = X25519KeyPair::from_jwk(
            r#"{"kty": "OKP",
            "crv": "X25519",
            "x": "k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc",
            "d": "x8EVZH4Fwk673_mUujnliJoSrLz0zYzzCWp5GUX2fc8"}"#,
        )
        .unwrap();

        let mut key_output = [0u8; 16];

        Ecdh1PU::new(
            &ephem_sk,
            &alice_sk,
            &bob_sk,
            b"ECDH-1PU+A128KW",
            b"Alice",
            b"Bob and Charlie",
            &hex!(
                "1cb6f87d3966f2ca469a28f74723acda
                02780e91cce21855470745fe119bdd64"
            ),
            false,
        )
        .derive_key_bytes(&mut key_output)
        .unwrap();

        assert_eq!(key_output, hex!("df4c37a0668306a11e3d6b0074b5d8df"));
    }
}
