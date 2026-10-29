use crate::*;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub fn boot_id() -> String {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap_or_default()
        .trim()
        .into()
}
pub fn process_start(pid: u32) -> u64 {
    fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|s| {
            s.rsplit_once(')')
                .and_then(|(_, tail)| tail.split_whitespace().nth(19))
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(0)
}
pub fn session_alive(s: &Session) -> bool {
    s.start != 0
        && s.boot == boot_id()
        && process_start(s.pid) == s.start
        && fs::metadata(format!("/proc/{}", s.pid)).is_ok_and(|m| m.uid() == s.uid)
        && fs::read(format!("/proc/{}/cmdline", s.pid))
            .is_ok_and(|b| b.split(|c| *c == 0).next() == Some(PACKAGE.as_bytes()))
}
pub fn package_uid(uid: u32) -> bool {
    uid % 100000 >= 10000
        && fs::read_to_string("/data/system/packages.list").is_ok_and(|s| {
            s.lines().any(|l| {
                let mut fields = l.split_whitespace();
                fields.next() == Some(PACKAGE)
                    && fields.next().and_then(|v| v.parse::<u32>().ok()) == Some(uid % 100000)
            })
        })
}

pub struct Store {
    root: PathBuf,
    _lock: File,
}
impl Store {
    pub fn initialize(root: &Path) -> Result<Self> {
        match fs::DirBuilder::new().mode(0o700).create(root) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(Error::from_io("STATE_WRITE_FAILED", "Data directory", e)),
        }
        let store = Self::open(root)?;
        store.log_directory()?;
        match store.read("config", 128) {
            Ok(bytes) => {
                parse_config(&bytes)?;
            }
            Err(e) if e.number == libc::ENOENT => {
                store.write_config(Config {
                    enabled: true,
                    revision: 1,
                })?;
            }
            Err(e) => return Err(e),
        }
        Ok(store)
    }
    pub fn open(root: &Path) -> Result<Self> {
        let meta = fs::symlink_metadata(root)
            .map_err(|e| Error::from_io("CONFIG_READ_FAILED", "Cannot open data directory", e))?;
        if !meta.is_dir() || meta.uid() != unsafe { libc::getuid() } || meta.mode() & 0o077 != 0 {
            return Err(Error::new(
                "CONFIG_INVALID",
                "Invalid data directory ownership or permissions",
            ));
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(root.join(".lock"))
            .map_err(|e| Error::from_io("CONFIG_READ_FAILED", "Cannot open state lock", e))?;
        let deadline = Instant::now() + Duration::from_secs(3);
        while unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let e = std::io::Error::last_os_error().raw_os_error();
            if !matches!(e, Some(libc::EINTR | libc::EWOULDBLOCK)) || Instant::now() >= deadline {
                return Err(Error::io("CONFIG_READ_FAILED", "State lock unavailable"));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(Self {
            root: root.into(),
            _lock: lock,
        })
    }
    fn read(&self, name: &str, limit: u64) -> Result<Vec<u8>> {
        use std::io::Read;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(self.root.join(name))
            .map_err(|e| Error::from_io("STATE_READ_FAILED", name, e))?;
        let meta = file
            .metadata()
            .map_err(|e| Error::from_io("STATE_READ_FAILED", name, e))?;
        if !meta.is_file()
            || meta.uid() != unsafe { libc::getuid() }
            || meta.mode() & 0o077 != 0
            || meta.len() > limit
        {
            return Err(Error::new(
                "STATE_INVALID",
                format!("Invalid state file: {name}"),
            ));
        }
        let mut bytes = Vec::new();
        file.take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| Error::from_io("STATE_READ_FAILED", name, e))?;
        if bytes.len() as u64 > limit {
            return Err(Error::new("STATE_INVALID", "State file too large"));
        }
        Ok(bytes)
    }
    fn atomic(&self, name: &str, bytes: &[u8]) -> Result<()> {
        atomic_file(&self.root, name, bytes, 0o600)
    }
    pub fn config(&self) -> Result<Config> {
        parse_config(&self.read("config", 128)?)
    }
    fn write_config(&self, config: Config) -> Result<Config> {
        let bytes = format!(
            "schema=1\nenabled={}\nrevision={}\n",
            u8::from(config.enabled),
            config.revision
        );
        self.atomic("config", bytes.as_bytes())?;
        let confirmed = self.config()?;
        if confirmed != config {
            return Err(Error::new(
                "STATE_WRITE_FAILED",
                "Configuration readback failed",
            ));
        }
        Ok(confirmed)
    }
    pub fn toggle(&self) -> Result<Config> {
        let config = self.config()?;
        if config.revision == i64::MAX as u64 {
            return Err(Error::new(
                "CONFIG_INVALID",
                "Configuration revision exhausted",
            ));
        }
        self.write_config(Config {
            enabled: !config.enabled,
            revision: config.revision + 1,
        })
    }
    fn failures(&self, boot: &str) -> Result<String> {
        if boot.is_empty() {
            return Err(Error::new("STATE_INVALID", "Boot identity unavailable"));
        }
        let mut failures = match self.read("failures", 1024 * 1024) {
            Ok(bytes) => String::from_utf8(bytes)
                .map_err(|_| Error::new("STATE_INVALID", "Invalid failure ledger"))?,
            Err(e) if e.number == libc::ENOENT => String::new(),
            Err(e) => return Err(e),
        };
        if failures.lines().next() != Some(boot) {
            failures = format!("{boot}\n");
            self.atomic("failures", failures.as_bytes())?;
        }
        Ok(failures)
    }
    pub fn publish_status(&self, module: &Path) -> Result<()> {
        let config = self.config()?;
        let failures = self.failures(&boot_id())?.lines().skip(1).count();
        let mut status = format!(
            "Status: {}",
            if config.enabled {
                "enabled"
            } else {
                "disabled"
            }
        );
        if failures > 0 {
            status.push_str(&format!(" | Inject failed({failures})"));
        }
        let properties = fs::read_to_string(module.join("module.prop")).map_err(|e| {
            Error::from_io("STATUS_REPORT_FAILED", "Cannot read module properties", e)
        })?;
        let mut updated = String::new();
        for line in properties.lines() {
            if line.starts_with("description=") {
                updated.push_str(&format!("description={status}\n"));
            } else {
                updated.push_str(line);
                updated.push('\n');
            }
        }
        atomic_file(module, "module.prop", updated.as_bytes(), 0o644)?;
        let ksud = Path::new("/data/adb/ksu/bin/ksud");
        if ksud.is_file() {
            let command = || {
                let mut command = std::process::Command::new(ksud);
                command
                    .env("KSU_MODULE", "genshin-fps-unlocker-zygisk")
                    .args(["module", "config"])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
                command
            };
            if command().arg("list").status().is_ok_and(|s| s.success())
                && !command()
                    .args(["set", "--temp", "override.description", &status])
                    .status()
                    .is_ok_and(|s| s.success())
            {
                return Err(Error::new(
                    "STATUS_REPORT_FAILED",
                    "Manager description update failed",
                ));
            }
        }
        Ok(())
    }
    pub fn save(&self, record: &Record) -> Result<()> {
        let boot = boot_id();
        if record.session.boot != boot {
            return Err(Error::new("SESSION_IDENTITY_INVALID", "Old boot report"));
        }
        let previous = match self.read("session.json", MAX_FRAME as u64) {
            Ok(bytes) => Some(protocol::decode::<Record>(&bytes)?),
            Err(e) if e.number == libc::ENOENT => None,
            Err(e) => return Err(e),
        };
        if let Some(previous) = &previous {
            if previous.session == record.session && previous.sequence >= record.sequence {
                return Err(Error::new("STATUS_REPORT_FAILED", "Stale session sequence"));
            }
        }
        // Android may specialize a pre-created process whose start ticks predate
        // an exited session. Only a still-live session can outrank its report.
        if previous.as_ref().is_none_or(|r| {
            r.session.boot != boot
                || !session_alive(&r.session)
                || r.session.start <= record.session.start
        }) {
            self.atomic("session.json", &protocol::encode(record)?)?;
        }
        if record.state == "failed" {
            let mut failures = self.failures(&boot)?;
            let key = format!("{}:{}", record.session.pid, record.session.start);
            if !failures.lines().skip(1).any(|line| line == key) {
                failures.push_str(&format!("{key}\n"));
                self.atomic("failures", failures.as_bytes())?;
            }
        }
        if record.state == "failed" || cfg!(debug_assertions) {
            // File-log failure never changes the recorded patch result.
            if let Err(e) = self.log(record) {
                log_error(&e);
            }
        }
        Ok(())
    }
    fn log_directory(&self) -> Result<PathBuf> {
        let dir = self.root.join("log");
        if !dir.exists() {
            fs::create_dir(&dir).map_err(|e| {
                Error::from_io("LOG_WRITE_FAILED", "Cannot create log directory", e)
            })?;
        }
        let meta = fs::symlink_metadata(&dir)
            .map_err(|e| Error::from_io("LOG_WRITE_FAILED", "Cannot inspect log directory", e))?;
        if !meta.is_dir() || meta.uid() != unsafe { libc::getuid() } {
            return Err(Error::new("LOG_WRITE_FAILED", "Invalid log directory"));
        }
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| Error::from_io("LOG_WRITE_FAILED", "Log permissions", e))?;
        Ok(dir)
    }
    fn log(&self, r: &Record) -> Result<()> {
        let dir = self.log_directory()?;
        let path = dir.join("module.log");
        if fs::symlink_metadata(&path).is_ok_and(|m| m.len() >= 1024 * 1024) {
            fs::rename(&path, dir.join("module.log.1"))
                .map_err(|e| Error::from_io("LOG_WRITE_FAILED", "Log rotation failed", e))?;
        }
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| Error::from_io("LOG_WRITE_FAILED", "Cannot open log", e))?;
        let line = if cfg!(debug_assertions) {
            format!(
                "{} version={} {r:#?}\n",
                timestamp(),
                env!("CARGO_PKG_VERSION")
            )
        } else {
            format!("{} pid={} start={} boot={} stage={} error={:?} cleanup={:?} reporting={:?} written={} restored={}\n",
                timestamp(), r.session.pid, r.session.start, r.session.boot, r.stage, r.error, r.cleanup, r.reporting, r.written, r.restored)
        };
        file.write_all(line.as_bytes())
            .map_err(|e| Error::from_io("LOG_WRITE_FAILED", "Cannot write log", e))
    }
}
pub fn config() -> Result<Config> {
    Store::open(Path::new(DATA))?.config()
}
pub fn save(record: &Record) -> Result<()> {
    Store::open(Path::new(DATA))?.save(record)
}
pub fn refresh_description() {
    // Reacquire the shared lock and reread state after the report is acknowledged.
    #[cfg(target_os = "android")]
    {
        if let Err(e) =
            Store::open(Path::new(DATA)).and_then(|store| store.publish_status(Path::new(MODULE)))
        {
            log_error(&e);
        }
    }
}
fn atomic_file(root: &Path, name: &str, bytes: &[u8], mode: u32) -> Result<()> {
    let temp = root.join(format!("{name}.tmp"));
    let _ = fs::remove_file(&temp);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temp)
        .map_err(|e| Error::from_io("STATE_WRITE_FAILED", "Cannot create temporary file", e))?;
    file.set_permissions(fs::Permissions::from_mode(mode))
        .and_then(|_| file.write_all(bytes))
        .and_then(|_| file.sync_all())
        .and_then(|_| fs::rename(&temp, root.join(name)))
        .and_then(|_| File::open(root)?.sync_all())
        .map_err(|e| Error::from_io("STATE_WRITE_FAILED", "Cannot commit state", e))
}
fn timestamp() -> String {
    unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut tm = std::mem::zeroed();
        let mut buf = [0 as c_char; 64];
        if libc::localtime_r(&now, &mut tm).is_null() {
            return now.to_string();
        }
        libc::strftime(
            buf.as_mut_ptr(),
            buf.len(),
            c"%Y-%m-%d %H:%M:%S".as_ptr(),
            &tm,
        );
        CStr::from_ptr(buf.as_ptr()).to_string_lossy().into_owned()
    }
}
fn parse_config(bytes: &[u8]) -> Result<Config> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::new("CONFIG_INVALID", "Configuration encoding"))?;
    let mut lines = text.split('\n');
    if lines.next() != Some("schema=1") {
        return Err(Error::new("CONFIG_INVALID", "Configuration schema"));
    }
    let enabled = match lines.next() {
        Some("enabled=1") => true,
        Some("enabled=0") => false,
        _ => return Err(Error::new("CONFIG_INVALID", "Enablement value")),
    };
    let revision = lines
        .next()
        .and_then(|s| s.strip_prefix("revision="))
        .filter(|s| !s.is_empty() && !s.starts_with('0') && s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n > 0 && *n <= i64::MAX as u64);
    if lines.next() != Some("") || lines.next().is_some() || revision.is_none() {
        return Err(Error::new(
            "CONFIG_INVALID",
            "Configuration revision or trailing data",
        ));
    }
    Ok(Config {
        enabled,
        revision: revision.unwrap_or(0),
    })
}
