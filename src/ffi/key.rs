use std::os::raw::c_char;

use ffi_support::{rust_string_to_c, ByteBuffer, FfiStr};

use super::{handle::ArcHandle, ErrorCode};
use crate::key::LocalKey;

pub type LocalKeyHandle = ArcHandle<LocalKey>;

#[no_mangle]
pub extern "C" fn askar_key_generate(
    alg: FfiStr<'_>,
    ephemeral: i8,
    out: *mut LocalKeyHandle,
) -> ErrorCode {
    catch_err! {
        trace!("Generate key: {}", alg.as_str());
        check_useful_c_ptr!(out);
        let key = LocalKey::generate(alg.as_str(), ephemeral != 0)?;
        let handle = LocalKeyHandle::create(key);
        unsafe { *out = handle };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_from_jwk(jwk: FfiStr<'_>, out: *mut LocalKeyHandle) -> ErrorCode {
    catch_err! {
        trace!("Load key from JWK");
        check_useful_c_ptr!(out);
        let key = LocalKey::from_jwk(jwk.as_str())?;
        let handle = LocalKeyHandle::create(key);
        unsafe { *out = handle };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_from_public_bytes(
    alg: FfiStr<'_>,
    public: ByteBuffer,
    out: *mut LocalKeyHandle,
) -> ErrorCode {
    catch_err! {
        trace!("Load key from public: {}", alg.as_str());
        check_useful_c_ptr!(out);
        let key = LocalKey::from_public_bytes(alg.as_str(), public.as_slice())?;
        let handle = LocalKeyHandle::create(key);
        unsafe { *out = handle };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_from_secret_bytes(
    alg: FfiStr<'_>,
    secret: ByteBuffer,
    out: *mut LocalKeyHandle,
) -> ErrorCode {
    catch_err! {
        trace!("Load key from secret: {}", alg.as_str());
        check_useful_c_ptr!(out);
        let key = LocalKey::from_secret_bytes(alg.as_str(), secret.as_slice())?;
        let handle = LocalKeyHandle::create(key);
        unsafe { *out = handle };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_free(handle: LocalKeyHandle) {
    handle.remove();
}

#[no_mangle]
pub extern "C" fn askar_key_get_algorithm(
    handle: LocalKeyHandle,
    out: *mut *const c_char,
) -> ErrorCode {
    catch_err! {
        trace!("Get key algorithm: {}", handle);
        check_useful_c_ptr!(out);
        let key = handle.load()?;
        unsafe { *out = rust_string_to_c(key.algorithm()) };
        Ok(ErrorCode::Success)
    }
}

#[no_mangle]
pub extern "C" fn askar_key_get_jwk_public(
    handle: LocalKeyHandle,
    out: *mut *const c_char,
) -> ErrorCode {
    catch_err! {
        trace!("Get key JWK public: {}", handle);
        handle.validate()?;
        check_useful_c_ptr!(out);
        let key = handle.load()?;
        let jwk = key.to_jwk_public()?;
        unsafe { *out = rust_string_to_c(jwk) };
        Ok(ErrorCode::Success)
    }
}

// #[no_mangle]
// pub extern "C" fn askar_key_get_jwk_secret(
//     handle: LocalKeyHandle,
//     out: *mut FfiSecret,
// ) -> ErrorCode {
//     catch_err! {
//         trace!("Get key JWK secret: {}", handle);
//         handle.validate()?;
//         check_useful_c_ptr!(out);
//         let key = handle.load()?;
//         let jwk = key.to_jwk_secret()?;
//         unsafe { *out = FfiSecret::from(jwk) };
//         Ok(ErrorCode::Success)
//     }
// }
