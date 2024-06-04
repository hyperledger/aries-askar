macro_rules! catch_err {
    ($($e:tt)*) => {
        match std::panic::catch_unwind(move || -> Result<_, $crate::error::Error> {$($e)*}) {
            Ok(Ok(a)) => a,
            Ok(Err(err)) => { // lib error
                $crate::ffi::error::set_last_error(Some(err))
            }
            Err(e) => { // panic error
                let panic_msg = e.downcast_ref::<&str>().unwrap_or(&"no message");
                let err: $crate::error::Error = err_msg!(Unexpected, "Panic during execution: '{panic_msg}'");
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
