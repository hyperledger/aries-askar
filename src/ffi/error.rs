use crate::error::{Error, ErrorKind, Result};

use std::os::raw::c_char;
use std::sync::RwLock;

use ffi_support::rust_string_to_c;

use once_cell::sync::Lazy;

static LAST_ERROR: Lazy<RwLock<Option<Error>>> = Lazy::new(|| RwLock::new(None));

#[derive(Debug, PartialEq, Copy, Clone, Serialize)]
#[repr(usize)]
pub enum ErrorCode {
    Success = 0,
    Backend = 1,
    Busy = 2,
    Disconnected = 3,
    Duplicate = 4,
    Encryption = 5,
    Input = 6,
    Lock = 7,
    Timeout = 8,
    Unexpected = 9,
    Unsupported = 10,
}

impl From<ErrorKind> for ErrorCode {
    fn from(kind: ErrorKind) -> ErrorCode {
        match kind {
            ErrorKind::Backend => ErrorCode::Backend,
            ErrorKind::Busy => ErrorCode::Busy,
            ErrorKind::Disconnected => ErrorCode::Disconnected,
            ErrorKind::Duplicate => ErrorCode::Duplicate,
            ErrorKind::Encryption => ErrorCode::Encryption,
            ErrorKind::Input => ErrorCode::Input,
            ErrorKind::Lock => ErrorCode::Lock,
            ErrorKind::Timeout => ErrorCode::Timeout,
            ErrorKind::Unexpected => ErrorCode::Unexpected,
            ErrorKind::Unsupported => ErrorCode::Unsupported,
        }
    }
}

impl<T> From<Result<T>> for ErrorCode {
    fn from(result: Result<T>) -> ErrorCode {
        match result {
            Ok(_) => ErrorCode::Success,
            Err(err) => ErrorCode::from(err.kind()),
        }
    }
}

#[no_mangle]
pub extern "C" fn askar_get_current_error(error_json_p: *mut *const c_char) -> ErrorCode {
    trace!("askar_get_current_error");

    let error = rust_string_to_c(get_current_error_json());
    unsafe { *error_json_p = error };

    ErrorCode::Success
}

pub fn get_current_error_json() -> String {
    if let Some(err) = Option::take(&mut *LAST_ERROR.write().unwrap()) {
        let message = err.to_string();
        let code = ErrorCode::from(err.kind()) as usize;
        // let extra = err.extra();
        json!({"code": code, "message": message}).to_string()
    } else {
        r#"{"code":0,"message":null}"#.to_owned()
    }
}

pub fn set_last_error(error: Option<Error>) -> ErrorCode {
    trace!("askar_set_last_error");
    let code = match error.as_ref() {
        Some(err) => err.kind.into(),
        None => ErrorCode::Success,
    };
    *LAST_ERROR.write().unwrap() = error;
    code
}
