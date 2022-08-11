use std::{ffi::CString, os::raw::c_char, ptr};

pub(crate) trait ToFfiString {
    fn to_vec(self) -> Vec<u8>;
}

impl ToFfiString for &str {
    fn to_vec(self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.len() + 1);
        buf.extend_from_slice(self.as_bytes());
        buf
    }
}

impl ToFfiString for String {
    fn to_vec(self) -> Vec<u8> {
        self.into()
    }
}

impl ToFfiString for &String {
    fn to_vec(self) -> Vec<u8> {
        self.as_str().to_vec()
    }
}

pub(crate) fn encode_cstr(strval: impl ToFfiString) -> *const c_char {
    let bytes = strval.to_vec();
    if bytes.is_empty() {
        return ptr::null();
    }
    CString::new(bytes)
        .expect("encountered NUL in category name")
        .into_raw()
}
