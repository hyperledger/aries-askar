pub type KvResult<T> = Result<T, KvError>;

#[derive(Debug)] // FIXME
pub enum KvError {
    BackendError(String),
    Disconnected,
    LockFailure,
    Timeout,
    UnknownKey,
}
