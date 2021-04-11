use crate::{buffer::WriteBuffer, error::Error};

use super::ops::KeyOpsSet;

struct JwkBuffer<'s, B>(&'s mut B);

impl<B: WriteBuffer> bs58::encode::EncodeTarget for JwkBuffer<'_, B> {
    fn encode_with(
        &mut self,
        max_len: usize,
        f: impl FnOnce(&mut [u8]) -> Result<usize, bs58::encode::Error>,
    ) -> Result<usize, bs58::encode::Error> {
        self.0
            .write_with(max_len, |buf| {
                // this cannot fail - there is enough space allocated
                Ok(f(buf).unwrap())
            })
            .map_err(|_| bs58::encode::Error::BufferTooSmall)
    }
}

pub struct JwkEncoder<'b, B: WriteBuffer> {
    buffer: &'b mut B,
    secret: bool,
}

impl<'b, B: WriteBuffer> JwkEncoder<'b, B> {
    pub fn new(buffer: &'b mut B, kty: &str, secret: bool) -> Result<Self, Error> {
        buffer.write_slice(b"{\"kty\":\"")?;
        buffer.write_slice(kty.as_bytes())?;
        buffer.write_slice(b"\"")?;
        Ok(Self { buffer, secret })
    }

    pub fn add_str(&mut self, key: &str, value: &str) -> Result<(), Error> {
        let buffer = &mut *self.buffer;
        buffer.write_slice(b",\"")?;
        buffer.write_slice(key.as_bytes())?;
        buffer.write_slice(b"\":\"")?;
        buffer.write_slice(value.as_bytes())?;
        buffer.write_slice(b"\"")?;
        Ok(())
    }

    pub fn add_as_base64(&mut self, key: &str, value: &[u8]) -> Result<(), Error> {
        let buffer = &mut *self.buffer;
        buffer.write_slice(b",\"")?;
        buffer.write_slice(key.as_bytes())?;
        buffer.write_slice(b"\":\"")?;
        let enc_size = ((value.len() << 2) + 2) / 3;
        buffer.write_with(enc_size, |mbuf| {
            let len = base64::encode_config_slice(value, base64::URL_SAFE_NO_PAD, mbuf);
            Ok(len)
        })?;
        buffer.write_slice(b"\"")?;
        Ok(())
    }

    pub fn add_key_ops(&mut self, ops: impl Into<KeyOpsSet>) -> Result<(), Error> {
        let buffer = &mut *self.buffer;
        buffer.write_slice(b",\"key_ops\":[")?;
        for (idx, op) in ops.into().into_iter().enumerate() {
            if idx > 0 {
                buffer.write_slice(b",\"")?;
            } else {
                buffer.write_slice(b"\"")?;
            }
            buffer.write_slice(op.as_str().as_bytes())?;
            buffer.write_slice(b"\"")?;
        }
        buffer.write_slice(b"]")?;
        Ok(())
    }

    pub fn is_secret(&self) -> bool {
        self.secret
    }

    pub fn finalize(self) -> Result<(), Error> {
        self.buffer.write_slice(b"}")?;
        Ok(())
    }
}
