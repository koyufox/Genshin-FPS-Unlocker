use crate::{
    protocol::{self, ReportMap},
    *,
};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    config: Config,
    error: Option<Error>,
}
fn reply(fd: c_int, config: Config, result: &Result<()>) -> Result<()> {
    protocol::send(
        fd,
        3,
        &Reply {
            config,
            error: result.as_ref().err().cloned(),
        },
    )
}
#[cfg(target_os = "android")]
fn read_reply(fd: c_int) -> Result<Config> {
    let (reply, _, uid): (Reply, _, _) = protocol::receive(fd, 3, 3)?;
    if uid != 0 {
        return Err(Error::new(
            "SESSION_IDENTITY_INVALID",
            "Companion is not root",
        ));
    }
    if let Some(e) = reply.error {
        return Err(e);
    }
    if reply.config.revision == 0 {
        return Err(Error::new("CONFIG_INVALID", "Missing config revision"));
    }
    Ok(reply.config)
}
#[cfg(target_os = "android")]
pub struct Startup {
    socket: OwnedFd,
    report: Option<FinalReport>,
}
#[cfg(target_os = "android")]
impl Startup {
    pub fn begin(socket: OwnedFd, session: Session) -> Result<(Self, Record)> {
        let fd = socket.as_raw_fd();
        protocol::send(fd, 1, &session)?;
        let config = read_reply(fd)?;
        let mut record = Record::new(session, config);
        let mut report = None;
        if config.enabled {
            match ReportMap::create(fd).and_then(|map| read_reply(fd).map(|_| FinalReport(map))) {
                Ok(map) => report = Some(map),
                Err(e) => record.fail("load_observation", e),
            }
        }
        Ok((Self { socket, report }, record))
    }

    // Consuming startup closes its socket before the retained reporter escapes.
    pub fn complete(self, record: &Record) -> Result<Option<FinalReport>> {
        let Self { socket, report } = self;
        protocol::send(socket.as_raw_fd(), 2, record)?;
        read_reply(socket.as_raw_fd())?;
        drop(socket);
        Ok(report.filter(|_| record.config.enabled && record.error.is_none()))
    }
}

pub struct FinalReport(ReportMap);
impl FinalReport {
    // The mapping is consumed exactly once, including when acknowledgement fails.
    pub fn publish(self, record: &mut Record) -> Result<()> {
        record.state = if record.error.is_some() || record.cleanup.is_some() {
            "failed"
        } else {
            "patched"
        }
        .into();
        record.sequence = 2;
        for e in [&record.error, &record.cleanup, &record.reporting]
            .into_iter()
            .flatten()
        {
            log_error(e);
        }
        self.0.publish(record)
    }
}
pub unsafe fn run(fd: c_int) {
    let owned = OwnedFd::from_raw_fd(fd);
    if let Err(e) = handle(owned) {
        log_error(&e);
    }
}
fn handle(fd: OwnedFd) -> Result<()> {
    let raw = fd.as_raw_fd();
    let (session, pid, uid): (Session, _, _) = protocol::receive(raw, 1, 3)?;
    if uid != 0
        || session.pid != pid as u32
        || session.start == 0
        || session.start != state::process_start(session.pid)
        || session.boot != state::boot_id()
        || !state::package_uid(session.uid)
    {
        return Err(Error::new(
            "SESSION_IDENTITY_INVALID",
            "Invalid startup identity",
        ));
    }
    let config = match state::config() {
        Ok(c) => c,
        Err(e) => {
            let _ = reply(raw, Config::default(), &Err(e.clone()));
            let mut r = Record::new(session, Config::default());
            r.fail("configuration", e.clone());
            if let Err(save) = state::save(&r) {
                log_error(&save);
            } else {
                state::refresh_description();
            }
            return Err(e);
        }
    };
    reply(raw, config, &Ok(()))?;
    let map = if config.enabled {
        match ReportMap::receive(raw) {
            Ok(map) => {
                reply(raw, config, &Ok(()))?;
                Some(map)
            }
            Err(e) => {
                let _ = reply(raw, config, &Err(e.clone()));
                let mut r = Record::new(session, config);
                r.fail("status_reporting", e.clone());
                if let Err(save) = state::save(&r) {
                    log_error(&save);
                } else {
                    state::refresh_description();
                }
                return Err(e);
            }
        }
    } else {
        None
    };
    let (record, sender, sender_uid): (Record, _, _) = protocol::receive(raw, 2, 3)?;
    let result = if record.session != session
        || record.config != config
        || record.sequence != 1
        || sender != pid
        || (sender_uid != 0 && sender_uid != session.uid)
        || state::process_start(session.pid) != session.start
    {
        Err(Error::new(
            "SESSION_IDENTITY_INVALID",
            "Invalid startup report identity",
        ))
    } else {
        state::save(&record)
    };
    reply(raw, config, &result)?;
    result?;
    drop(fd);
    if record.state == "failed" {
        state::refresh_description();
    }
    if record.state != "waiting" {
        return Ok(());
    }
    let map = map.ok_or_else(|| Error::new("STATUS_REPORT_FAILED", "Missing final mapping"))?;
    let deadline = Instant::now() + Duration::from_secs(WAIT_SECONDS + 10);
    while Instant::now() < deadline && state::process_start(session.pid) == session.start {
        match map.read() {
            Ok(Some(r)) => {
                let result = if r.session != session
                    || r.config != config
                    || r.sequence != 2
                    || !matches!(r.state.as_str(), "patched" | "failed")
                    || !state::session_alive(&session)
                {
                    Err(Error::new(
                        "SESSION_IDENTITY_INVALID",
                        "Invalid final report identity",
                    ))
                } else {
                    state::save(&r)
                };
                map.acknowledge(result.is_ok());
                if result.is_ok() && r.state == "failed" {
                    state::refresh_description();
                }
                return result;
            }
            Err(e) => {
                map.acknowledge(false);
                return Err(e);
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    // A missing final result is not proof that the patch was applied.
    Err(Error::new(
        "STATUS_REPORT_FAILED",
        "Session exited or final report timed out",
    ))
}

#[cfg(test)]
#[path = "acceptance.rs"]
mod acceptance;
