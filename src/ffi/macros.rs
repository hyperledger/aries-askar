macro_rules! catch_err {
    ($($e:tt)*) => {
        match std::panic::catch_unwind(|| -> $crate::error::Result<_> {$($e)*}) {
            Ok(Ok(a)) => a,
            Ok(Err(err)) => { // lib error
                $crate::ffi::error::set_last_error(Some(err))
            }
            Err(_) => { // panic error
                let err: $crate::error::Error = err_msg!(Unexpected, "Panic during execution");
                $crate::ffi::error::set_last_error(Some(err))
            }
        }
    }
}

macro_rules! check_useful_c_ptr {
    ($e:expr) => {
        if ($e).is_null() {
            return Err(err_msg!("Invalid pointer for result value"));
        }
    };
}

macro_rules! slice_from_c_ptr {
    ($bytes:expr, $len:expr) => {{
        if ($bytes).is_null() {
            Err(err_msg!("Invalid pointer for input value"))
        } else if ($len) <= 0 {
            Err(err_msg!("Buffer size must be greater than zero"))
        } else {
            Ok(unsafe { std::slice::from_raw_parts($bytes, $len) })
        }
    }};
}

macro_rules! read_lock {
    ($e:expr) => {
        ($e).read()
            .map_err(err_map!(Unexpected, "Error acquiring read lock: {}"))
    };
}

macro_rules! write_lock {
    ($e:expr) => {
        ($e).write()
            .map_err(err_map!(Unexpected, "Error acquiring write lock: {}"))
    };
}
