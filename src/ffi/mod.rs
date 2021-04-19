use std::marker::PhantomData;
use std::os::raw::c_char;

use ffi_support::rust_string_to_c;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

pub static LIB_VERSION: &str = env!("CARGO_PKG_VERSION");

#[macro_use]
mod handle;

#[macro_use]
mod macros;

mod error;

mod key;

mod log;

mod secret;

mod store;

use self::error::ErrorCode;
use crate::error::Error;

pub type CallbackId = i64;

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

// #[no_mangle]
// pub extern "C" fn askar_verify_signature(
//     signer_vk: FfiStr<'_>,
//     message: ByteBuffer,
//     signature: ByteBuffer,
//     cb: Option<extern "C" fn(cb_id: CallbackId, err: ErrorCode, verify: i8)>,
//     cb_id: CallbackId,
// ) -> ErrorCode {
//     catch_err! {
//         trace!("Verify signature");
//         let signer_vk = signer_vk.into_opt_string().ok_or_else(|| err_msg!("Signer verkey not provided"))?;
//         let message = message.as_slice().to_vec();
//         let signature = signature.as_slice().to_vec();
//         let cb = cb.ok_or_else(|| err_msg!("No callback provided"))?;
//         let cb = EnsureCallback::new(move |result|
//             match result {
//                 Ok(verify) => cb(cb_id, ErrorCode::Success, verify as i8),
//                 Err(err) => cb(cb_id, set_last_error(Some(err)), 0),
//             }
//         );
//         spawn_ok(async move {
//             let result = unblock(move || verify_signature(
//                 &signer_vk,
//                 &message,
//                 &signature
//             )).await;
//             cb.resolve(result);
//         });
//         Ok(ErrorCode::Success)
//     }
// }

#[no_mangle]
pub extern "C" fn askar_version() -> *mut c_char {
    rust_string_to_c(LIB_VERSION.to_owned())
}
