macro_rules! trace {
    ($record:expr, $message:expr $(,)?) => {{
        #[cfg(debug_assertions)]
        {
            let message: String = ($message).into();
            let record: &mut crate::Record = $record;
            if record.trace.len() < 16 {
                record.trace.push(message.chars().take(160).collect());
            }
        }
    }};
}

mod companion;
#[cfg(target_os = "android")]
mod control;
mod observer;
mod patcher;
mod protocol;
mod state;

use serde::{Deserialize, Serialize};
use std::ffi::{c_char, c_int, c_void, CStr};

const PACKAGE: &str = "com.miHoYo.Yuanshen";
const DATA: &str = "/data/adb/genshin-fps-unlocker";
#[cfg(target_os = "android")]
const MODULE: &str = "/data/adb/modules/genshin-fps-unlocker-zygisk";
const MAX_FRAME: usize = 8192;
const WAIT_SECONDS: u64 = 120;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Error {
    code: String,
    message: String,
    number: i32,
}
impl Error {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            number: 0,
        }
    }
    fn io(code: &str, message: &str) -> Self {
        Self::from_io(code, message, std::io::Error::last_os_error())
    }
    fn from_io(code: &str, message: &str, e: std::io::Error) -> Self {
        Self {
            code: code.into(),
            message: format!("{message}: {e}"),
            number: e.raw_os_error().unwrap_or(0),
        }
    }
}
type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Config {
    enabled: bool,
    revision: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Session {
    pid: u32,
    uid: u32,
    start: u64,
    boot: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    session: Session,
    config: Config,
    sequence: u32,
    state: String,
    stage: String,
    library: String,
    build_id: String,
    offset: usize,
    written: bool,
    restored: bool,
    error: Option<Error>,
    cleanup: Option<Error>,
    reporting: Option<Error>,
    trace: Vec<String>,
}
impl Record {
    fn new(session: Session, config: Config) -> Self {
        Self {
            session,
            config,
            sequence: 1,
            state: if config.enabled {
                "waiting"
            } else {
                "disabled"
            }
            .into(),
            stage: "configuration".into(),
            library: String::new(),
            build_id: String::new(),
            offset: 0,
            written: false,
            restored: true,
            error: None,
            cleanup: None,
            reporting: None,
            trace: Vec::new(),
        }
    }
    fn fail(&mut self, stage: &str, error: Error) {
        self.state = "failed".into();
        self.stage = stage.into();
        self.error = Some(error);
    }
}
#[cfg(target_os = "android")]
extern "C" {
    fn bridge_connect(api: *mut c_void) -> c_int;
    fn bridge_module_dir(api: *mut c_void) -> c_int;
    fn bridge_load_fd(fd: c_int) -> *mut c_void;
    fn bridge_clear_cache(address: *mut c_void, size: usize);
    fn __android_log_write(priority: c_int, tag: *const c_char, text: *const c_char) -> c_int;
}
fn log_error(e: &Error) {
    #[cfg(target_os = "android")]
    if let Ok(text) =
        std::ffi::CString::new(format!("{}: {} (errno={})", e.code, e.message, e.number))
    {
        unsafe {
            __android_log_write(6, c"GenshinUnlock".as_ptr(), text.as_ptr());
        }
    }
    #[cfg(not(target_os = "android"))]
    eprintln!("{}: {}", e.code, e.message);
}

/// # Safety
/// The bridge supplies a live Zygisk API and nullable NUL-terminated JNI strings
/// borrowed only for this call. Rust retains no JNI references.
#[no_mangle]
pub unsafe extern "C" fn rust_pre(
    api: *mut c_void,
    name: *const c_char,
    data: *const c_char,
    uid: u32,
) -> *mut c_void {
    if name.is_null() || CStr::from_ptr(name).to_bytes() != PACKAGE.as_bytes() {
        return std::ptr::null_mut();
    }
    if data.is_null()
        || CStr::from_ptr(data)
            .to_bytes()
            .rsplit(|c| *c == b'/')
            .next()
            != Some(PACKAGE.as_bytes())
        || uid % 100000 < 10000
    {
        log_error(&Error::new(
            "SESSION_IDENTITY_INVALID",
            "Target application identity invalid",
        ));
        return std::ptr::null_mut();
    }
    #[cfg(target_os = "android")]
    {
        observer::prepare(api, uid).map_or(std::ptr::null_mut(), |r| Box::into_raw(r).cast())
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = api;
        std::ptr::null_mut()
    }
}
/// # Safety
/// Runtime is null or a retained pointer returned by rust_pre, called once
/// after specialization on the callback thread.
#[no_mangle]
pub unsafe extern "C" fn rust_post(runtime: *mut c_void) {
    if !runtime.is_null() {
        observer::start(&*runtime.cast::<observer::Runtime>());
    }
}
/// # Safety
/// The companion transfers ownership of a valid connected socket FD.
#[no_mangle]
pub unsafe extern "C" fn rust_companion(fd: c_int) {
    companion::run(fd);
}
