use crate::{buffer::WriteBuffer, error::Error};

use super::ops::KeyOpsSet;

struct JwkBuffer<'s, B>(&'s mut B);

impl<B: WriteBuffer> bs58::encode::EncodeTarget for JwkBuffer<'_, B> {
    fn encode_with(
        &mut self,
        max_len: usize,
        f: impl for<'a> FnOnce(&'a mut [u8]) -> Result<usize, bs58::encode::Error>,
    ) -> Result<usize, bs58::encode::Error> {
        if let Some(ext) = self.0.extend_buffer(max_len) {
            let len = f(ext)?;
            if len < max_len {
                self.0.truncate_by(max_len - len);
            }
            Ok(len)
        } else {
            Err(bs58::encode::Error::BufferTooSmall)
        }
    }
}

pub struct JwkEncoder<'b, B: WriteBuffer> {
    buffer: &'b mut B,
}

impl<'b, B: WriteBuffer> JwkEncoder<'b, B> {
    pub fn new(buffer: &'b mut B, kty: &str) -> Result<Self, Error> {
        buffer.extend_from_slice(b"{\"kty\":\"")?;
        buffer.extend_from_slice(kty.as_bytes())?;
        buffer.extend_from_slice(b"\"")?;
        Ok(Self { buffer })
    }

    pub fn add_str(&mut self, key: &str, value: &str) -> Result<(), Error> {
        let buffer = &mut *self.buffer;
        buffer.extend_from_slice(b",\"")?;
        buffer.extend_from_slice(key.as_bytes())?;
        buffer.extend_from_slice(b"\":\"")?;
        buffer.extend_from_slice(value.as_bytes())?;
        buffer.extend_from_slice(b"\"")?;
        Ok(())
    }

    pub fn add_as_base64(&mut self, key: &str, value: &[u8]) -> Result<(), Error> {
        let buffer = &mut *self.buffer;
        buffer.extend_from_slice(b",\"")?;
        buffer.extend_from_slice(key.as_bytes())?;
        buffer.extend_from_slice(b"\":\"")?;
        let enc_size = ((value.len() << 2) + 2) / 3;
        if let Some(mbuf) = buffer.extend_buffer(enc_size) {
            let len = base64::encode_config_slice(value, base64::URL_SAFE_NO_PAD, mbuf);
            if len < enc_size {
                buffer.truncate_by(enc_size - len);
            }
        } else {
            return Err(err_msg!("buffer too small"));
        }
        buffer.extend_from_slice(b"\"")?;
        Ok(())
    }

    pub fn add_key_ops(&mut self, ops: impl Into<KeyOpsSet>) -> Result<(), Error> {
        let buffer = &mut *self.buffer;
        buffer.extend_from_slice(b",\"key_ops\":[")?;
        for (idx, op) in ops.into().into_iter().enumerate() {
            if idx > 0 {
                buffer.extend_from_slice(b",\"")?;
            } else {
                buffer.extend_from_slice(b"\"")?;
            }
            buffer.extend_from_slice(op.as_str().as_bytes())?;
            buffer.extend_from_slice(b"\"")?;
        }
        buffer.extend_from_slice(b"]")?;
        Ok(())
    }

    pub fn finalize(self) -> Result<(), Error> {
        self.buffer.extend_from_slice(b"}")?;
        Ok(())
    }
}
