use std::{convert::TryFrom, mem, ptr};

use crate::crypto::buffer::SecretBytes;

#[no_mangle]
pub extern "C" fn askar_buffer_free(buffer: SecretBuffer) {
    ffi_support::abort_on_panic::with_abort_on_panic(|| {
        drop(buffer.destroy_into_secret());
    })
}

// Structure consistent with ffi_support ByteBuffer, but zeroized on drop
#[repr(C)]
pub struct SecretBuffer {
    // must be >= 0, signed int was chosen for compatibility
    len: i64,
    // nullable
    data: *mut u8,
}

impl Default for SecretBuffer {
    fn default() -> Self {
        Self {
            len: 0,
            data: ptr::null_mut(),
        }
    }
}

impl SecretBuffer {
    pub fn from_secret(buffer: impl Into<SecretBytes>) -> Self {
        let mut buf = buffer.into().into_boxed_slice();
        let len = i64::try_from(buf.len()).expect("secret length exceeds i64::MAX");
        let data = buf.as_mut_ptr();
        mem::forget(buf);
        Self { len, data }
    }

    pub fn destroy_into_secret(self) -> SecretBytes {
        if self.data.is_null() {
            SecretBytes::default()
        } else {
            if self.len < 0 {
                panic!("found negative length for secret buffer");
            }
            let len = self.len as usize;
            SecretBytes::from(unsafe { Vec::from_raw_parts(self.data, len, len) })
        }
    }
}
