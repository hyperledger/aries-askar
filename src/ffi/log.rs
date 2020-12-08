use std::ffi::CString;
use std::os::raw::{c_char, c_void};
use std::ptr;

use log::{LevelFilter, Metadata, Record};

use super::error::ErrorCode;

pub type EnabledCallback =
    extern "C" fn(context: *const c_void, level: u32, target: *const c_char) -> bool;

pub type LogCallback = extern "C" fn(
    context: *const c_void,
    level: u32,
    target: *const c_char,
    message: *const c_char,
    module_path: *const c_char,
    file: *const c_char,
    line: u32,
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
    fn enabled(&self, metadata: &Metadata) -> bool {
        if let Some(enabled_cb) = self.enabled {
            let level = metadata.level() as u32;
            let target = CString::new(metadata.target()).unwrap();

            enabled_cb(self.context, level, target.as_ptr())
        } else {
            true
        }
    }

    fn log(&self, record: &Record) {
        let log_cb = self.log;

        let level = record.level() as u32;
        let target = CString::new(record.target()).unwrap();
        let message = CString::new(record.args().to_string()).unwrap();

        let module_path = record.module_path().map(|s| CString::new(s).unwrap());
        let file = record.file().map(|s| CString::new(s).unwrap());
        let line = record.line().unwrap_or(0);

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
) -> ErrorCode {
    catch_err! {
        let logger = CustomLogger::new(context, enabled, log, flush);
        log::set_boxed_logger(Box::new(logger)).map_err(err_map!(Unexpected))?;
        log::set_max_level(LevelFilter::Trace);
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
