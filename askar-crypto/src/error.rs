#[cfg(feature = "std")]
use alloc::boxed::Box;
use core::fmt::{self, Display, Formatter};

#[cfg(feature = "std")]
use std::error::Error as StdError;

/// The possible kinds of error produced by the crate
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// An encryption or decryption operation failed
    Encryption,

    /// Out of space in provided buffer
    ExceededBuffer,

    /// The provided input was invalid
    InvalidData,

    /// The provided key was invalid
    InvalidKeyData,

    /// The provided nonce was invalid (bad length)
    InvalidNonce,

    /// A secret key is required but not present
    MissingSecretKey,

    /// An unexpected error occurred
    Unexpected,

    /// The input parameters to the method were incorrect
    Usage,

    /// An unsupported operation was requested
    Unsupported,
}

impl ErrorKind {
    /// Convert the error kind to a string reference
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Encryption => "Encryption error",
            Self::ExceededBuffer => "Exceeded allocated buffer",
            Self::InvalidData => "Invalid data",
            Self::InvalidNonce => "Invalid encryption nonce",
            Self::InvalidKeyData => "Invalid key data",
            Self::MissingSecretKey => "Missing secret key",
            Self::Unexpected => "Unexpected error",
            Self::Usage => "Usage error",
            Self::Unsupported => "Unsupported",
        }
    }
}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The standard crate error type
#[derive(Debug)]
pub struct Error {
    pub(crate) kind: ErrorKind,
    #[cfg(feature = "std")]
    pub(crate) cause: Option<Box<dyn StdError + Send + Sync + 'static>>,
    pub(crate) message: Option<&'static str>,
}

impl Error {
    /// Create a new error instance with message text
    pub fn from_msg(kind: ErrorKind, msg: &'static str) -> Self {
        Self {
            kind,
            #[cfg(feature = "std")]
            cause: None,
            message: Some(msg),
        }
    }

    /// Accessor for the error kind
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Accessor for the error message
    pub fn message(&self) -> &'static str {
        self.message.unwrap_or_else(|| self.kind.as_str())
    }

    #[cfg(feature = "std")]
    pub(crate) fn with_cause<T: Into<Box<dyn StdError + Send + Sync>>>(mut self, err: T) -> Self {
        self.cause = Some(err.into());
        self
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(msg) = self.message {
            f.write_str(msg)?;
        } else {
            f.write_str(self.kind.as_str())?;
        }
        #[cfg(feature = "std")]
        if let Some(cause) = self.cause.as_ref() {
            write!(f, "\nCaused by: {}", cause)?;
        }
        Ok(())
    }
}

#[cfg(feature = "std")]
impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.cause
            .as_ref()
            .map(|err| unsafe { std::mem::transmute(&**err) })
    }
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.message == other.message
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self {
            kind,
            #[cfg(feature = "std")]
            cause: None,
            message: None,
        }
    }
}

macro_rules! err_msg {
    ($kind:ident) => {
        $crate::error::Error::from($crate::error::ErrorKind::$kind)
    };
    ($kind:ident, $msg:expr) => {
        $crate::error::Error::from_msg($crate::error::ErrorKind::$kind, $msg)
    };
}

#[cfg(feature = "std")]
macro_rules! err_map {
    ($($params:tt)*) => {
        |err| err_msg!($($params)*).with_cause(err)
    };
}

#[cfg(not(feature = "std"))]
macro_rules! err_map {
    ($($params:tt)*) => {
        |_| err_msg!($($params)*)
    };
}
