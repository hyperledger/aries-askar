// use async_resource::AcquireError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Busy,
    BackendError(String),
    Disconnected,
    EncryptionError,
    InputError(String),
    KeyError(String),
    LockFailure,
    Timeout,
    UnknownKey,
    Unexpected,
    Unsupported,
}

// impl<E> From<AcquireError<E>> for Error
// where
//     E: Into<Error>,
// {
//     fn from(err: AcquireError<E>) -> Self {
//         match err {
//             AcquireError::PoolBusy => Error::Busy,
//             AcquireError::PoolClosed => Error::Disconnected,
//             AcquireError::ResourceError(err) => err.into(),
//             AcquireError::Timeout => Error::Timeout,
//         }
//     }
// }

impl From<sqlx::Error> for Error {
    fn from(err: sqlx::Error) -> Self {
        Error::BackendError(err.to_string())
    }
}

impl From<indy_utils::EncryptionError> for Error {
    fn from(_err: indy_utils::EncryptionError) -> Self {
        Error::EncryptionError
    }
}

impl From<indy_utils::ValidationError> for Error {
    fn from(err: indy_utils::ValidationError) -> Self {
        Error::InputError(err.to_string())
    }
}

macro_rules! err_msg {
    (Backend, $($args:tt)+) => {
        $crate::error::Error::BackendError(format!($($args)+))
    };
    (Key, $($args:tt)+) => {
        $crate::error::Error::KeyError(format!($($args)+))
    };
    (Input, $($args:tt)+) => {
        $crate::error::Error::InputError(format!($($args)+))
    };
    ($($args:tt)+) => {
        $crate::error::Error::InputError(format!($($args)+))
    };
}
