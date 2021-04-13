use alloc::string::String;
use core::fmt::{self, Display, Formatter};

#[cfg(feature = "std")]
use std::error::Error as StdError;

/// The possible kinds of error produced by the crate
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// An encryption or decryption operation failed
    Encryption,

    /// The input parameters to the method were incorrect
    Input,

    /// The provided nonce was invalid (bad length)
    InvalidNonce,

    /// A secret key is required but not present
    MissingSecretKey,

    /// An unexpected error occurred
    Unexpected,

    /// An unsupported operation was requested
    Unsupported,
}

impl ErrorKind {
    /// Convert the error kind to a string reference
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Encryption => "Encryption error",
            Self::Input => "Input error",
            Self::InvalidNonce => "Invalid encryption nonce",
            Self::MissingSecretKey => "Missing secret key",
            Self::Unexpected => "Unexpected error",
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
    #[cfg(not(feature = "std"))]
    pub(crate) cause: Option<String>,
    #[cfg(feature = "std")]
    pub(crate) cause: Option<Box<dyn StdError + Send + Sync + 'static>>,
    pub(crate) message: Option<String>,
}

impl Error {
    pub(crate) fn from_msg<T: Into<String>>(kind: ErrorKind, msg: T) -> Self {
        Self {
            kind,
            cause: None,
            message: Some(msg.into()),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn from_opt_msg<T: Into<String>>(kind: ErrorKind, msg: Option<T>) -> Self {
        Self {
            kind,
            cause: None,
            message: msg.map(Into::into),
        }
    }

    /// Accessor for the error kind
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    #[cfg(not(feature = "std"))]
    pub(crate) fn with_cause<T: Into<Option<String>>>(mut self, err: T) -> Self {
        self.cause = err.into();
        self
    }

    #[cfg(feature = "std")]
    pub(crate) fn with_cause<T: Into<Box<dyn StdError + Send + Sync>>>(mut self, err: T) -> Self {
        self.cause = Some(err.into());
        self
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(msg) = self.message.as_ref() {
            f.write_str(msg)?;
        } else {
            f.write_str(self.kind.as_str())?;
        }
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
            cause: None,
            message: None,
        }
    }
}

macro_rules! err_msg {
    () => {
        $crate::error::Error::from($crate::error::ErrorKind::Input)
    };
    ($kind:ident) => {
        $crate::error::Error::from($crate::error::ErrorKind::$kind)
    };
    ($kind:ident, $($args:tt)+) => {
        $crate::error::Error::from_msg($crate::error::ErrorKind::$kind, $crate::alloc::format!($($args)+))
    };
    ($($args:tt)+) => {
        $crate::error::Error::from_msg($crate::error::ErrorKind::Input, $crate::alloc::format!($($args)+))
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
        |err| err_msg!($($params)*).with_cause(alloc::string::ToString::to_string(&err))
    };
}
