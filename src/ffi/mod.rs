use std::marker::PhantomData;
use std::os::raw::c_char;
use std::str::FromStr;

use ffi_support::{rust_string_to_c, ByteBuffer, FfiStr};

pub static LIB_VERSION: &str = env!("CARGO_PKG_VERSION");

#[macro_use]
mod macros;

mod error;

mod store;

use self::error::ErrorCode;
use crate::error::Error;
use crate::keys::{derive_verkey, verify_signature, wrap::generate_raw_wrap_key, KeyAlg};

pub type CallbackId = i64;

ffi_support::define_bytebuffer_destructor!(askar_buffer_free);
ffi_support::define_string_destructor!(askar_string_free);

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
pub extern "C" fn askar_derive_verkey(
    alg: FfiStr,
    seed: ByteBuffer,
    verkey: *mut *const c_char,
) -> ErrorCode {
    catch_err! {
        trace!("Derive verkey");
        let alg = alg.as_opt_str().map(|alg| KeyAlg::from_str(alg).unwrap()).ok_or_else(|| err_msg!("Key algorithm not provided"))?;
        let vk_result = derive_verkey(alg, seed.as_slice())?;
        unsafe { *verkey = rust_string_to_c(vk_result) };

        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_generate_raw_key(seed: FfiStr, result_p: *mut *const c_char) -> ErrorCode {
    catch_err! {
        trace!("Create raw key");
        check_useful_c_ptr!(result_p);
        let seed = seed.as_opt_str().map(str::as_bytes);
        let key = generate_raw_wrap_key(seed)?;
        unsafe { *result_p = rust_string_to_c(key); }
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_verify_signature(
    signer_vk: FfiStr,
    message: ByteBuffer,
    signature: ByteBuffer,
    result_p: *mut i8,
) -> ErrorCode {
    catch_err! {
        trace!("Verify signature");
        let signer_vk = signer_vk.as_opt_str().ok_or_else(|| err_msg!("Signer verkey not provided"))?;
        let message = message.as_slice();
        let signature = signature.as_slice();
        let result = verify_signature(
            signer_vk,
            message,
            signature
        )?;
        unsafe { *result_p = result as i8 };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_version() -> *mut c_char {
    rust_string_to_c(LIB_VERSION.to_owned())
}
