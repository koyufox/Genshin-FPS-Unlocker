use crate::{companion::FinalReport, patcher, *};
#[cfg(target_os = "android")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Mutex,
};
use std::time::{Duration, Instant};

const WAITING: u32 = 0;
const PATCHING: u32 = 1;
const AWAITING_POST: u32 = 2;
const DONE: u32 = 3;
const EXPIRED: u32 = 4;
type Callback = unsafe extern "C" fn(*mut libc::dl_phdr_info, usize, *mut c_void);
type Callbacks = unsafe extern "C" fn(Option<Callback>, Option<Callback>, *mut c_void) -> c_int;
pub struct Runtime {
    active: bool,
    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    handle: usize,
    register: Option<Callbacks>,
    unregister: Option<Callbacks>,
    attempt: AtomicU32,
    record: Mutex<Record>,
    patch: patcher::VSyncOverride,
    report: Mutex<Option<FinalReport>>,
}
fn record(r: &Runtime) -> std::sync::MutexGuard<'_, Record> {
    r.record.lock().unwrap_or_else(|e| e.into_inner())
}
unsafe fn target(info: *const libc::dl_phdr_info, size: usize) -> bool {
    !info.is_null()
        && size
            >= std::mem::offset_of!(libc::dl_phdr_info, dlpi_phnum)
                + std::mem::size_of::<libc::Elf64_Half>()
        && !(*info).dlpi_name.is_null()
        && CStr::from_ptr((*info).dlpi_name)
            .to_bytes()
            .rsplit(|b| *b == b'/')
            .next()
            == Some(b"libyuanshen.so")
}
unsafe extern "C" fn before(info: *mut libc::dl_phdr_info, size: usize, opaque: *mut c_void) {
    if !target(info, size) {
        return;
    }
    let r = &*opaque.cast::<Runtime>();
    if r.attempt
        .compare_exchange(WAITING, PATCHING, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let mut rec = record(r);
    let path = CStr::from_ptr((*info).dlpi_name).to_string_lossy();
    rec.library = path.chars().take(1024).collect();
    trace!(&mut rec, "Target pre-initialization callback");
    if !path.starts_with("/data/app/") || !path.contains(&format!("/{PACKAGE}-")) {
        rec.fail(
            "image_validation",
            Error::new(
                "LIBRARY_IDENTITY_INVALID",
                "Target ELF is outside selected package installation",
            ),
        );
    } else {
        r.patch.apply(
            (*info).dlpi_addr as usize,
            (*info).dlpi_phdr,
            (*info).dlpi_phnum as usize,
            &mut rec,
        );
    }
    r.attempt.store(
        if rec.error.is_some() {
            DONE
        } else {
            AWAITING_POST
        },
        Ordering::Release,
    );
}
unsafe extern "C" fn after(info: *mut libc::dl_phdr_info, size: usize, opaque: *mut c_void) {
    if !target(info, size) {
        return;
    }
    let r = &*opaque.cast::<Runtime>();
    if r.attempt
        .compare_exchange(AWAITING_POST, PATCHING, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let mut rec = record(r);
    if !r.patch.verify((*info).dlpi_addr as usize, &mut rec) {
        r.attempt.store(AWAITING_POST, Ordering::Release);
        return;
    }
    r.attempt.store(DONE, Ordering::Release);
}
unsafe extern "C" fn existing(
    info: *mut libc::dl_phdr_info,
    size: usize,
    data: *mut c_void,
) -> c_int {
    if target(info, size) {
        *data.cast::<bool>() = true;
        1
    } else {
        0
    }
}
fn already_loaded() -> bool {
    let mut present = false;
    unsafe {
        libc::dl_iterate_phdr(Some(existing), (&mut present as *mut bool).cast());
    }
    present
}
#[cfg(target_os = "android")]
pub unsafe fn prepare(api: *mut c_void, uid: u32) -> Option<Box<Runtime>> {
    let session = Session {
        pid: std::process::id(),
        uid,
        start: state::process_start(std::process::id()),
        boot: state::boot_id(),
    };
    let fd = bridge_connect(api);
    if fd < 0 {
        log_error(&Error::new(
            "CONFIG_READ_FAILED",
            "Cannot connect to root companion",
        ));
        return None;
    }
    let socket = OwnedFd::from_raw_fd(fd);
    let (startup, initial_record) = match companion::Startup::begin(socket, session) {
        Ok(startup) => startup,
        Err(e) => {
            log_error(&e);
            return None;
        }
    };
    let config = initial_record.config;
    let mut r = Box::new(Runtime {
        active: false,
        handle: 0,
        register: None,
        unregister: None,
        attempt: AtomicU32::new(WAITING),
        record: Mutex::new(initial_record),
        patch: patcher::VSyncOverride::default(),
        report: Mutex::new(None),
    });
    if config.enabled && record(&r).error.is_none() {
        let setup = (|| {
            let dir = bridge_module_dir(api);
            if dir < 0 {
                return Err(Error::new(
                    "LOAD_OBSERVER_INIT_FAILED",
                    "Module directory unavailable",
                ));
            }
            let owned_dir = OwnedFd::from_raw_fd(dir);
            initialize(&mut r, owned_dir.as_raw_fd())
        })();
        if let Err(e) = setup {
            record(&r).fail("load_observation", e);
        }
    }
    trace!(
        &mut record(&r),
        format!(
            "Startup snapshot: enabled={} revision={} observer={}",
            config.enabled,
            config.revision,
            r.handle != 0
        ),
    );
    let published = startup.complete(&record(&r));
    match published {
        Ok(report) => {
            r.active = report.is_some();
            *r.report.lock().unwrap() = report;
        }
        Err(e) => log_error(&e),
    }
    if r.active || r.handle != 0 {
        Some(r)
    } else {
        None
    }
}
#[cfg(target_os = "android")]
unsafe fn initialize(r: &mut Runtime, dir: c_int) -> Result<()> {
    let fd = libc::openat(
        dir,
        c"lib/arm64-v8a/libshadowhook.so".as_ptr(),
        libc::O_RDONLY | libc::O_CLOEXEC,
    );
    if fd < 0 {
        return Err(Error::io("LOAD_OBSERVER_INIT_FAILED", "Observer open"));
    }
    let owned = OwnedFd::from_raw_fd(fd);
    let handle = bridge_load_fd(owned.as_raw_fd());
    drop(owned);
    r.handle = handle as usize;
    if handle.is_null() {
        let message = libc::dlerror();
        return Err(Error::new(
            "LOAD_OBSERVER_INIT_FAILED",
            if message.is_null() {
                "Observer load failed".into()
            } else {
                CStr::from_ptr(message).to_string_lossy().into_owned()
            },
        ));
    }
    let init = libc::dlsym(handle, c"genshin_shadowhook_init".as_ptr());
    let register = libc::dlsym(handle, c"shadowhook_register_dl_init_callback".as_ptr());
    let unregister = libc::dlsym(handle, c"shadowhook_unregister_dl_init_callback".as_ptr());
    let errmsg = libc::dlsym(handle, c"shadowhook_to_errmsg".as_ptr());
    if [init, register, unregister, errmsg]
        .iter()
        .any(|p| p.is_null())
    {
        return Err(Error::new(
            "LOAD_OBSERVER_INIT_FAILED",
            "Missing observer exports",
        ));
    }
    r.register = Some(std::mem::transmute::<*mut c_void, Callbacks>(register));
    r.unregister = Some(std::mem::transmute::<*mut c_void, Callbacks>(unregister));
    let fd = libc::openat(
        dir,
        c"lib/arm64-v8a/libshadowhook_nothing.so".as_ptr(),
        libc::O_RDONLY | libc::O_CLOEXEC,
    );
    if fd < 0 {
        return Err(Error::io(
            "LOAD_OBSERVER_INIT_FAILED",
            "Observer helper open",
        ));
    }
    let owned = OwnedFd::from_raw_fd(fd);
    let init: unsafe extern "C" fn(c_int, bool, c_int) -> c_int = std::mem::transmute(init);
    let rc = init(0, cfg!(debug_assertions), owned.as_raw_fd());
    if rc != 0 {
        let errmsg: unsafe extern "C" fn(c_int) -> *const c_char = std::mem::transmute(errmsg);
        return Err(Error::new(
            "LOAD_OBSERVER_INIT_FAILED",
            CStr::from_ptr(errmsg(rc)).to_string_lossy(),
        ));
    }
    Ok(())
}
fn unregister(r: &Runtime) -> Result<()> {
    let rc = unsafe {
        r.unregister.ok_or_else(|| {
            Error::new("LOAD_OBSERVER_UNREGISTER_FAILED", "No unregister function")
        })?(
            Some(before),
            Some(after),
            (r as *const Runtime).cast_mut().cast(),
        )
    };
    if rc != 0 {
        return Err(Error::new(
            "LOAD_OBSERVER_UNREGISTER_FAILED",
            format!("Unregister returned {rc}"),
        ));
    }
    Ok(())
}
fn finish(r: &Runtime) {
    let mut rec = record(r);
    let mut slot = r.report.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(report) = slot.take() {
        if let Err(e) = report.publish(&mut rec) {
            log_error(&e);
        }
    }
}
pub fn start(r: &'static Runtime) {
    if !r.active {
        return;
    }
    let result = (|| {
        if already_loaded() {
            return Err(Error::new(
                "LIBRARY_ALREADY_INITIALIZED",
                "Target loaded before observer registration",
            ));
        }
        let rc = unsafe {
            r.register.ok_or_else(|| {
                Error::new(
                    "LOAD_OBSERVER_REGISTER_FAILED",
                    "Missing callback registration",
                )
            })?(
                Some(before),
                Some(after),
                (r as *const Runtime).cast_mut().cast(),
            )
        };
        if rc != 0 {
            return Err(Error::new(
                "LOAD_OBSERVER_REGISTER_FAILED",
                format!("Registration returned {rc}"),
            ));
        }
        trace!(&mut record(r), "Initialization callbacks registered");
        if already_loaded()
            && r.attempt
                .compare_exchange(WAITING, EXPIRED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            if let Err(e) = unregister(r) {
                record(r).cleanup = Some(e);
            }
            return Err(Error::new(
                "LIBRARY_ALREADY_INITIALIZED",
                "Target load raced observer registration",
            ));
        }
        match std::thread::Builder::new()
            .name("genshin-report".into())
            .spawn(move || reporter(r))
        {
            Ok(_) => Ok(()),
            Err(e) => {
                let _ = r.attempt.compare_exchange(
                    WAITING,
                    EXPIRED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                if let Err(e) = unregister(r) {
                    record(r).cleanup = Some(e);
                }
                Err(Error::new("REPORTER_START_FAILED", e.to_string()))
            }
        }
    })();
    if let Err(e) = result {
        stop_attempt(r);
        record(r).fail("load_observation", e);
        finish(r);
    }
}
// Freeze pending work and let an already claimed write finish before reporting.
fn stop_attempt(r: &Runtime) {
    loop {
        let state = r.attempt.load(Ordering::Acquire);
        if state == PATCHING {
            std::thread::sleep(Duration::from_millis(20));
        } else if state == WAITING || state == AWAITING_POST {
            if r.attempt
                .compare_exchange(state, EXPIRED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        } else {
            break;
        }
    }
}
fn reporter(r: &Runtime) {
    let deadline = Instant::now() + Duration::from_secs(WAIT_SECONDS);
    loop {
        let state = r.attempt.load(Ordering::Acquire);
        if state == DONE || state == EXPIRED {
            break;
        }
        if Instant::now() >= deadline
            && (state == WAITING || state == AWAITING_POST)
            && r.attempt
                .compare_exchange(state, EXPIRED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            record(r).fail(
                "load_observation",
                Error::new(
                    if state == WAITING {
                        "LIBRARY_WAIT_TIMEOUT"
                    } else {
                        "LIBRARY_INIT_TIMEOUT"
                    },
                    "Target initialization exceeded 120 seconds",
                ),
            );
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // Never hold the record mutex while waiting for ShadowHook's callback-list lock.
    if let Err(e) = unregister(r) {
        record(r).cleanup = Some(e);
    }
    trace!(&mut record(r), "Observer cleanup and final report");
    finish(r);
    // Zygisk bridge, Runtime, and dependency mappings stay valid for process lifetime.
}
