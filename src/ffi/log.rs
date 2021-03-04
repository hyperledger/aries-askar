use std::ffi::CString;
use std::os::raw::{c_char, c_void};
use std::ptr;

use log::{LevelFilter, Metadata, Record};

use super::error::ErrorCode;
use crate::error::Error;

pub type EnabledCallback = extern "C" fn(context: *const c_void, level: i32) -> i8;

pub type LogCallback = extern "C" fn(
    context: *const c_void,
    level: i32,
    target: *const c_char,
    message: *const c_char,
    module_path: *const c_char,
    file: *const c_char,
    line: i32,
);

pub type FlushCallback = extern "C" fn(context: *const c_void);

pub struct CustomLogger {
    context: *const c_void,
    enabled: Option<EnabledCallback>,
    log: LogCallback,
    flush: Option<FlushCallback>,
}

impl CustomLogger {
    fn new(
        context: *const c_void,
        enabled: Option<EnabledCallback>,
        log: LogCallback,
        flush: Option<FlushCallback>,
    ) -> Self {
        CustomLogger {
            context,
            enabled,
            log,
            flush,
        }
    }
}

impl log::Log for CustomLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        if let Some(enabled_cb) = self.enabled {
            enabled_cb(self.context, metadata.level() as i32) != 0
        } else {
            true
        }
    }

    fn log(&self, record: &Record<'_>) {
        let log_cb = self.log;

        let level = record.level() as i32;
        let target = CString::new(record.target()).unwrap();
        let message = CString::new(record.args().to_string()).unwrap();

        let module_path = record.module_path().map(|s| CString::new(s).unwrap());
        let file = record.file().map(|s| CString::new(s).unwrap());
        let line = record.line().unwrap_or(0) as i32;

        log_cb(
            self.context,
            level,
            target.as_ptr(),
            message.as_ptr(),
            module_path
                .as_ref()
                .map(|s| s.as_ptr())
                .unwrap_or(ptr::null_mut()),
            file.as_ref().map(|s| s.as_ptr()).unwrap_or(ptr::null_mut()),
            line,
        )
    }

    fn flush(&self) {
        if let Some(flush) = self.flush {
            flush(self.context)
        }
    }
}

unsafe impl Send for CustomLogger {}
unsafe impl Sync for CustomLogger {}

#[no_mangle]
pub extern "C" fn askar_set_custom_logger(
    context: *const c_void,
    log: LogCallback,
    enabled: Option<EnabledCallback>,
    flush: Option<FlushCallback>,
    max_level: i32,
) -> ErrorCode {
    catch_err! {
        let max_level = get_level_filter(max_level)?;
        let logger = CustomLogger::new(context, enabled, log, flush);
        log::set_boxed_logger(Box::new(logger)).map_err(err_map!(Unexpected))?;
        log::set_max_level(max_level);
        debug!("Initialized custom logger");
        Ok(ErrorCode::Success)
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
pub extern "C" fn askar_set_max_log_level(max_level: i32) -> ErrorCode {
    catch_err! {
        log::set_max_level(get_level_filter(max_level)?);
        Ok(ErrorCode::Success)
    }
}

fn get_level_filter(max_level: i32) -> Result<LevelFilter, Error> {
    Ok(match max_level {
        -1 => {
            // load from RUST_LOG environment variable
            // defaults to ERROR if unspecified
            env_logger::Logger::from_default_env().filter()
        }
        0 => LevelFilter::Off,
        1 => LevelFilter::Error,
        2 => LevelFilter::Warn,
        3 => LevelFilter::Info,
        4 => LevelFilter::Debug,
        5 => LevelFilter::Trace,
        _ => return Err(err_msg!(Input, "Invalid log level")),
    })
}
