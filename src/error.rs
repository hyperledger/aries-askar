use super::pool::AcquireError;

pub type KvResult<T> = Result<T, KvError>;

#[derive(Debug)] // FIXME
pub enum KvError {
    Busy,
    BackendError(String),
    Disconnected,
    LockFailure,
    Timeout,
    UnknownKey,
}

impl<T> From<AcquireError<T>> for KvError
where
    T: Into<KvError>,
{
    fn from(err: AcquireError<T>) -> Self {
        match err {
            AcquireError::Busy => KvError::Busy,
            AcquireError::ResourceError(err) => err.into(),
            AcquireError::Stopped => KvError::Disconnected,
            AcquireError::Timeout => KvError::Timeout,
        }
    }
}
