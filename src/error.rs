use std::error::Error as StdError;
use std::fmt::{self, Display, Formatter};

pub type Result<T> = std::result::Result<T, Error>;

/// The possible kinds of error produced by the crate
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    Backend,
    Busy,
    Duplicate,
    Encryption,
    Input,
    NotFound,
    Unexpected,
    Unsupported,
}

impl ErrorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Backend => "Backend error",
            Self::Busy => "Busy",
            Self::Duplicate => "Duplicate",
            Self::Encryption => "Encryption error",
            Self::Input => "Input error",
            Self::NotFound => "Not found",
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

/// The standard crate error
#[derive(Debug)]
pub struct Error {
    pub kind: ErrorKind,
    pub cause: Option<Box<dyn StdError + Send + Sync + 'static>>,
    pub message: Option<String>,
}

impl Error {
    pub fn from_msg<T: Into<String>>(kind: ErrorKind, msg: T) -> Self {
        Self {
            kind,
            cause: None,
            message: Some(msg.into()),
        }
    }

    pub fn from_opt_msg<T: Into<String>>(kind: ErrorKind, msg: Option<T>) -> Self {
        Self {
            kind,
            cause: None,
            message: msg.map(Into::into),
        }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn with_cause<T: Into<Box<dyn StdError + Send + Sync>>>(mut self, err: T) -> Self {
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

// FIXME would be preferable to remove this auto-conversion and handle
// all sqlx errors manually, to ensure there is some context around the error
#[cfg(any(feature = "indy_compat", feature = "postgres", feature = "sqlite"))]
impl From<sqlx::Error> for Error {
    fn from(err: sqlx::Error) -> Self {
        Error::from(ErrorKind::Backend).with_cause(err)
    }
}

impl From<indy_utils::EncryptionError> for Error {
    fn from(err: indy_utils::EncryptionError) -> Self {
        Error::from_opt_msg(ErrorKind::Encryption, err.context)
    }
}

impl From<indy_utils::UnexpectedError> for Error {
    fn from(err: indy_utils::UnexpectedError) -> Self {
        Error::from_opt_msg(ErrorKind::Unexpected, err.context)
    }
}

impl From<indy_utils::ValidationError> for Error {
    fn from(err: indy_utils::ValidationError) -> Self {
        Error::from_opt_msg(ErrorKind::Input, err.context)
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
        $crate::error::Error::from_msg($crate::error::ErrorKind::$kind, format!($($args)+))
    };
    ($($args:tt)+) => {
        $crate::error::Error::from_msg($crate::error::ErrorKind::Input, format!($($args)+))
    };
}

macro_rules! err_map {
    ($($params:tt)*) => {
        |err| err_msg!($($params)*).with_cause(err)
    };
}
