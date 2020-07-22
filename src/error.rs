pub type KvResult<T> = Result<T, KvError>;

#[derive(Debug)] // FIXME
pub enum KvError {
    Busy,
    BackendError(String),
    Disconnected,
    EncryptionError,
    InputError,
    LockFailure,
    Timeout,
    UnknownKey,
    Unexpected,
    Unsupported,
}

impl<E> From<async_resource::AcquireError<E>> for KvError
where
    E: Into<KvError>,
{
    fn from(err: async_resource::AcquireError<E>) -> Self {
        match err {
            // AcquireError::Busy => KvError::Busy,
            async_resource::AcquireError::PoolClosed => KvError::Disconnected,
            async_resource::AcquireError::ResourceError(err) => err.into(),
            async_resource::AcquireError::Timeout => KvError::Timeout,
        }
    }
}

impl From<indy_utils::EncryptionError> for KvError {
    fn from(_err: indy_utils::EncryptionError) -> Self {
        KvError::EncryptionError
    }
}
