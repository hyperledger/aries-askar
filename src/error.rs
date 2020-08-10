use async_resource::AcquireError;

pub type KvResult<T> = Result<T, KvError>;

#[derive(Debug)] // FIXME
pub enum KvError {
    Busy,
    BackendError(String),
    Disconnected,
    EncryptionError,
    InputError(String),
    LockFailure,
    Timeout,
    UnknownKey,
    Unexpected,
    Unsupported,
}

impl<E> From<AcquireError<E>> for KvError
where
    E: Into<KvError>,
{
    fn from(err: AcquireError<E>) -> Self {
        match err {
            AcquireError::PoolBusy => KvError::Busy,
            AcquireError::PoolClosed => KvError::Disconnected,
            AcquireError::ResourceError(err) => err.into(),
            AcquireError::Timeout => KvError::Timeout,
        }
    }
}

impl From<sqlx::Error> for KvError {
    fn from(err: sqlx::Error) -> Self {
        KvError::BackendError(err.to_string())
    }
}

impl From<indy_utils::EncryptionError> for KvError {
    fn from(_err: indy_utils::EncryptionError) -> Self {
        KvError::EncryptionError
    }
}
