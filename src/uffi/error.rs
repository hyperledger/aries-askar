use std::fmt::{self, Display, Formatter};

use crate::error::{Error, ErrorKind};
use crate::storage::{Error as StorageError, ErrorKind as StorageErrorKind};

#[derive(Debug, PartialEq, Clone, Serialize, uniffi::Error)]
pub enum ErrorCode {
    Success { message: String },
    Backend { message: String },
    Busy { message: String },
    Duplicate { message: String },
    Encryption { message: String },
    Input { message: String },
    NotFound { message: String },
    Unexpected { message: String },
    Unsupported { message: String },
    Custom { message: String },
}

impl From<Error> for ErrorCode {
    fn from(err: Error) -> ErrorCode {
        match err.kind() {
            ErrorKind::Backend => ErrorCode::Backend { message: err.to_string() },
            ErrorKind::Busy => ErrorCode::Busy { message: err.to_string() },
            ErrorKind::Duplicate => ErrorCode::Duplicate { message: err.to_string() },
            ErrorKind::Encryption => ErrorCode::Encryption { message: err.to_string() },
            ErrorKind::Input => ErrorCode::Input { message: err.to_string() },
            ErrorKind::NotFound => ErrorCode::NotFound { message: err.to_string() },
            ErrorKind::Unexpected => ErrorCode::Unexpected { message: err.to_string() },
            ErrorKind::Unsupported => ErrorCode::Unsupported { message: err.to_string() },
            ErrorKind::Custom => ErrorCode::Custom { message: err.to_string() },
        }
    }
}

impl From<StorageError> for ErrorCode {
    fn from(err: StorageError) -> ErrorCode {
        match err.kind() {
            StorageErrorKind::Backend => ErrorCode::Backend { message: err.to_string() },
            StorageErrorKind::Busy => ErrorCode::Busy { message: err.to_string() },
            StorageErrorKind::Duplicate => ErrorCode::Duplicate { message: err.to_string() },
            StorageErrorKind::Encryption => ErrorCode::Encryption { message: err.to_string() },
            StorageErrorKind::Input => ErrorCode::Input { message: err.to_string() },
            StorageErrorKind::NotFound => ErrorCode::NotFound { message: err.to_string() },
            StorageErrorKind::Unexpected => ErrorCode::Unexpected { message: err.to_string() },
            StorageErrorKind::Unsupported => ErrorCode::Unsupported { message: err.to_string() },
            StorageErrorKind::Custom => ErrorCode::Custom { message: err.to_string() },
        }
    }
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
