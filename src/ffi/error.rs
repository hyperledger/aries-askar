use crate::error::{Error, ErrorKind};

use std::collections::BTreeMap;
use std::os::raw::c_char;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ffi_support::rust_string_to_c;
use once_cell::sync::Lazy;

struct StoredError {
    error: Error,
    time: Instant,
}

static ERRORS: Lazy<Mutex<BTreeMap<ErrorHandle, StoredError>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

static ERROR_INDEX: AtomicI64 = AtomicI64::new(1);

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ErrorHandle(i64);

impl ErrorHandle {
    pub const OK: Self = Self(0);

    pub fn next() -> Self {
        Self(ERROR_INDEX.fetch_add(1, Ordering::Relaxed))
    }
}

pub const ERROR_EXPIRY: Duration = Duration::from_secs(30);

#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize)]
#[repr(i64)]
pub enum ErrorCode {
    Success = 0,
    Backend = 1,
    Busy = 2,
    Duplicate = 3,
    Encryption = 4,
    Input = 5,
    NotFound = 6,
    Unexpected = 7,
    Unsupported = 8,
    Custom = 100,
}

impl From<ErrorKind> for ErrorCode {
    fn from(kind: ErrorKind) -> ErrorCode {
        match kind {
            ErrorKind::Backend => ErrorCode::Backend,
            ErrorKind::Busy => ErrorCode::Busy,
            ErrorKind::Custom => ErrorCode::Custom,
            ErrorKind::Duplicate => ErrorCode::Duplicate,
            ErrorKind::Encryption => ErrorCode::Encryption,
            ErrorKind::Input => ErrorCode::Input,
            ErrorKind::NotFound => ErrorCode::NotFound,
            ErrorKind::Unexpected => ErrorCode::Unexpected,
            ErrorKind::Unsupported => ErrorCode::Unsupported,
        }
    }
}

impl<T> From<Result<T, Error>> for ErrorCode {
    fn from(result: Result<T, Error>) -> ErrorCode {
        match result {
            Ok(_) => ErrorCode::Success,
            Err(err) => ErrorCode::from(err.kind()),
        }
    }
}

#[no_mangle]
pub extern "C" fn askar_fetch_error(
    handle: ErrorHandle,
    error_json_p: *mut *const c_char,
) -> ErrorCode {
    trace!("askar_fetch_error");

    let error = rust_string_to_c(fetch_error_json(handle));
    unsafe { *error_json_p = error };

    ErrorCode::Success
}

pub fn fetch_error_json(handle: ErrorHandle) -> String {
    #[derive(Serialize)]
    struct ErrorJson {
        code: usize,
        message: String,
    }

    let mut errors = ERRORS.lock().unwrap();
    if let Some(err) = errors.remove(&handle) {
        let message = err.error.to_string();
        let code = ErrorCode::from(err.error.kind()) as usize;
        serde_json::json!(&ErrorJson { code, message }).to_string()
    } else {
        r#"{"code":0,"message":null}"#.to_owned()
    }
}

pub fn store_error(error: Error) -> ErrorHandle {
    trace!("askar_store_error");
    let mut errors = ERRORS.lock().unwrap();
    let time = Instant::now();
    while let Some(entry) = errors.first_entry() {
        if entry.get().time + ERROR_EXPIRY < time {
            entry.remove();
        }
    }
    let handle = ErrorHandle::next();
    errors.insert(handle, StoredError { error, time });
    handle
}
