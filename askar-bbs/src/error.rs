use core::fmt::{self, Display, Formatter};

#[cfg(feature = "std")]
use std::error::Error as StdError;

/// The possible kinds of error produced by the crate
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// A proof did not pass verification
    InvalidProof,

    /// A signature did not pass verification
    InvalidSignature,

    /// A secret key is required but not present
    MissingSecretKey,

    /// An unexpected error occurred
    Unexpected,

    /// An unsupported operation was requested
    Unsupported,

    /// Method parameters are incorrect
    Usage,
}

impl ErrorKind {
    /// Convert the error kind to a string reference
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidProof => "Invalid proof",
            Self::InvalidSignature => "Invalid signature",
            Self::MissingSecretKey => "Missing secret key",
            Self::Unexpected => "Unexpected error",
            Self::Unsupported => "Unsupported",
            Self::Usage => "Usage error",
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
    pub(crate) message: Option<&'static str>,
}

impl Error {
    /// Create a new error instance with message text
    pub fn from_msg(kind: ErrorKind, msg: &'static str) -> Self {
        Self {
            kind,
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
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(msg) = self.message {
            f.write_str(msg)?;
        } else {
            f.write_str(self.kind.as_str())?;
        }
        Ok(())
    }
}

#[cfg(feature = "std")]
impl StdError for Error {}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.message == other.message
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self {
            kind,
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
