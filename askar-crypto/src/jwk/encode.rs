use core::fmt::Write;

use crate::{
    buffer::{WriteBuffer, Writer},
    error::Error,
};

use super::ops::KeyOpsSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JwkEncoderMode {
    PublicKey,
    SecretKey,
    Thumbprint,
}

#[derive(Debug)]
pub struct JwkEncoder<'b> {
    buffer: &'b mut dyn WriteBuffer,
    empty: bool,
    mode: JwkEncoderMode,
}

impl<'b> JwkEncoder<'b> {
    pub fn new<B: WriteBuffer>(buffer: &'b mut B, mode: JwkEncoderMode) -> Result<Self, Error> {
        Ok(Self {
            buffer,
            empty: true,
            mode,
        })
    }
}

impl JwkEncoder<'_> {
    fn start_attr(&mut self, key: &str) -> Result<(), Error> {
        let buffer = &mut *self.buffer;
        if self.empty {
            buffer.buffer_write(b"{\"")?;
            self.empty = false;
        } else {
            buffer.buffer_write(b",\"")?;
        }
        buffer.buffer_write(key.as_bytes())?;
        buffer.buffer_write(b"\":")?;
        Ok(())
    }

    pub fn add_str(&mut self, key: &str, value: &str) -> Result<(), Error> {
        self.start_attr(key)?;
        let buffer = &mut *self.buffer;
        buffer.buffer_write(b"\"")?;
        buffer.buffer_write(value.as_bytes())?;
        buffer.buffer_write(b"\"")?;
        Ok(())
    }

    pub fn add_as_base64(&mut self, key: &str, value: &[u8]) -> Result<(), Error> {
        self.start_attr(key)?;
        let buffer = &mut *self.buffer;
        buffer.buffer_write(b"\"")?;
        write!(
            Writer::from_buffer(&mut *buffer),
            "{}",
            base64::display::Base64Display::with_config(value, base64::URL_SAFE_NO_PAD)
        )
        .map_err(|_| err_msg!(Unexpected, "Error writing to JWK buffer"))?;
        buffer.buffer_write(b"\"")?;
        Ok(())
    }

    pub fn add_key_ops(&mut self, ops: impl Into<KeyOpsSet>) -> Result<(), Error> {
        self.start_attr("key_ops")?;
        let buffer = &mut *self.buffer;
        for (idx, op) in ops.into().into_iter().enumerate() {
            if idx > 0 {
                buffer.buffer_write(b",\"")?;
            } else {
                buffer.buffer_write(b"\"")?;
            }
            buffer.buffer_write(op.as_str().as_bytes())?;
            buffer.buffer_write(b"\"")?;
        }
        buffer.buffer_write(b"]")?;
        Ok(())
    }

    pub fn mode(&self) -> JwkEncoderMode {
        self.mode
    }

    pub fn is_public(&self) -> bool {
        matches!(self.mode, JwkEncoderMode::PublicKey)
    }

    pub fn is_secret(&self) -> bool {
        matches!(self.mode, JwkEncoderMode::SecretKey)
    }

    pub fn is_thumbprint(&self) -> bool {
        matches!(self.mode, JwkEncoderMode::Thumbprint)
    }

    pub fn finalize(self) -> Result<(), Error> {
        if !self.empty {
            self.buffer.buffer_write(b"}")?;
        }
        Ok(())
    }
}
