use std::marker::PhantomData;
use std::os::raw::c_char;

use ffi_support::{define_string_destructor, rust_string_to_c};

pub static LIB_VERSION: &str = env!("CARGO_PKG_VERSION");

#[macro_use]
mod macros;

mod error;

mod store;

use self::error::ErrorCode;
use crate::error::Error;

pub type CallbackId = usize;

define_string_destructor!(askar_string_free);

pub struct EnsureCallback<T, F: Fn(Result<T, Error>)> {
    f: F,
    _pd: PhantomData<T>,
}

impl<T, F: Fn(Result<T, Error>)> EnsureCallback<T, F> {
    pub fn new(f: F) -> Self {
        Self {
            f,
            _pd: PhantomData,
        }
    }

    pub fn resolve(self, value: Result<T, Error>) {
        (self.f)(value);
        std::mem::forget(self);
    }
}

impl<T, F: Fn(Result<T, Error>)> Drop for EnsureCallback<T, F> {
    fn drop(&mut self) {
        // if std::thread::panicking()  - capture trace?
        (self.f)(Err(err_msg!(Unexpected)));
    }
}

#[no_mangle]
pub extern "C" fn askar_set_default_logger() -> ErrorCode {
    catch_err! {
        env_logger::init();
        debug!("Initialized default logger");
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_version() -> *mut c_char {
    rust_string_to_c(LIB_VERSION.to_owned())
}
