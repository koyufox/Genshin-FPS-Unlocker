use crate::*;
use serde::de::DeserializeOwned;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let bytes =
        serde_json::to_vec(value).map_err(|e| Error::new("STATUS_REPORT_FAILED", e.to_string()))?;
    if bytes.len() > MAX_FRAME {
        return Err(Error::new(
            "STATUS_REPORT_FAILED",
            "Report exceeds frame bound",
        ));
    }
    Ok(bytes)
}
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.len() > MAX_FRAME {
        return Err(Error::new("STATUS_REPORT_FAILED", "Frame too large"));
    }
    serde_json::from_slice(bytes).map_err(|e| Error::new("STATUS_REPORT_FAILED", e.to_string()))
}
pub fn wait(fd: c_int, events: i16, deadline: Instant) -> Result<()> {
    loop {
        let left = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(i32::MAX as u128) as i32;
        if left == 0 {
            return Err(Error::new("STATUS_REPORT_FAILED", "IPC deadline expired"));
        }
        let mut p = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut p, 1, left) };
        if n > 0 && p.revents & events != 0 {
            return Ok(());
        }
        if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(Error::io("STATUS_REPORT_FAILED", "IPC unavailable"));
    }
}
fn retry() -> bool {
    matches!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EINTR | libc::EAGAIN)
    )
}

pub fn send<T: Serialize>(fd: c_int, op: u32, value: &T) -> Result<()> {
    let body = encode(value)?;
    let mut bytes = Vec::with_capacity(body.len() + 16);
    for v in [0x4750555au32, 2, op, body.len() as u32] {
        bytes.extend(v.to_le_bytes());
    }
    bytes.extend(body);
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut sent = 0;
    while sent < bytes.len() {
        wait(fd, libc::POLLOUT, deadline)?;
        unsafe {
            let mut control = [0usize; 8];
            let mut io = libc::iovec {
                iov_base: bytes[sent..].as_ptr() as *mut c_void,
                iov_len: bytes.len() - sent,
            };
            let mut msg: libc::msghdr = zeroed();
            msg.msg_iov = &mut io;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = libc::CMSG_SPACE(size_of::<libc::ucred>() as u32) as _;
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_CREDENTIALS;
            (*c).cmsg_len = libc::CMSG_LEN(size_of::<libc::ucred>() as u32) as _;
            std::ptr::write_unaligned(
                libc::CMSG_DATA(c).cast::<libc::ucred>(),
                libc::ucred {
                    pid: libc::getpid(),
                    uid: libc::getuid(),
                    gid: libc::getgid(),
                },
            );
            let n = libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT);
            if n < 0 && retry() {
                continue;
            }
            if n <= 0 {
                return Err(Error::io("STATUS_REPORT_FAILED", "Socket write failed"));
            }
            sent += n as usize;
        }
    }
    Ok(())
}
fn read_exact(
    fd: c_int,
    bytes: &mut [u8],
    deadline: Instant,
    peer: &mut Option<(i32, u32)>,
) -> Result<()> {
    let mut pos = 0;
    while pos < bytes.len() {
        wait(fd, libc::POLLIN, deadline)?;
        unsafe {
            let mut control = [0usize; 32];
            let mut io = libc::iovec {
                iov_base: bytes[pos..].as_mut_ptr().cast(),
                iov_len: bytes.len() - pos,
            };
            let mut msg: libc::msghdr = zeroed();
            msg.msg_iov = &mut io;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = size_of_val(&control) as _;
            let n = libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC);
            if n < 0 && retry() {
                continue;
            }
            if n <= 0 {
                return Err(Error::io("STATUS_REPORT_FAILED", "Socket read failed"));
            }
            let mut credentials = None;
            let mut unexpected_fd = false;
            let mut c = libc::CMSG_FIRSTHDR(&msg);
            while !c.is_null() {
                if (*c).cmsg_level == libc::SOL_SOCKET
                    && (*c).cmsg_type == libc::SCM_CREDENTIALS
                    && (*c).cmsg_len as usize
                        == libc::CMSG_LEN(size_of::<libc::ucred>() as u32) as usize
                {
                    let p = std::ptr::read_unaligned(libc::CMSG_DATA(c).cast::<libc::ucred>());
                    credentials = Some((p.pid, p.uid));
                } else if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS
                {
                    unexpected_fd = true;
                    let count = ((*c).cmsg_len as usize).saturating_sub(libc::CMSG_LEN(0) as usize)
                        / size_of::<c_int>();
                    for i in 0..count {
                        libc::close(std::ptr::read_unaligned(
                            libc::CMSG_DATA(c).cast::<c_int>().add(i),
                        ));
                    }
                }
                c = libc::CMSG_NXTHDR(&msg, c);
            }
            if unexpected_fd
                || msg.msg_flags & libc::MSG_CTRUNC != 0
                || credentials.is_none()
                || (peer.is_some() && *peer != credentials)
            {
                return Err(Error::new(
                    "SESSION_IDENTITY_INVALID",
                    "Invalid frame credentials or control data",
                ));
            }
            *peer = credentials;
            pos += n as usize;
        }
    }
    Ok(())
}
pub fn receive<T: DeserializeOwned>(fd: c_int, op: u32, seconds: u64) -> Result<(T, i32, u32)> {
    let enabled: c_int = 1;
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&enabled as *const c_int).cast(),
            size_of::<c_int>() as _,
        )
    } != 0
    {
        return Err(Error::io(
            "STATUS_REPORT_FAILED",
            "Cannot enable socket credentials",
        ));
    }
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut peer = None;
    let mut header = [0u8; 16];
    read_exact(fd, &mut header, deadline, &mut peer)?;
    let words: Vec<u32> = header
        .as_chunks::<4>()
        .0
        .iter()
        .map(|b| u32::from_le_bytes(*b))
        .collect();
    if words[0] != 0x4750555a || words[1] != 2 || words[2] != op || words[3] as usize > MAX_FRAME {
        return Err(Error::new(
            "STATUS_REPORT_FAILED",
            "Invalid protocol header",
        ));
    }
    let mut bytes = vec![0; words[3] as usize];
    read_exact(fd, &mut bytes, deadline, &mut peer)?;
    let (pid, uid) =
        peer.ok_or_else(|| Error::new("SESSION_IDENTITY_INVALID", "Missing credentials"))?;
    Ok((decode(&bytes)?, pid, uid))
}

#[repr(C)]
struct Shared {
    state: AtomicU32,
    size: u32,
    payload: [u8; MAX_FRAME],
}
pub struct ReportMap(*mut Shared);
// Each mapping has one publisher and one consumer, coordinated by state's release/acquire protocol.
unsafe impl Send for ReportMap {}
impl Drop for ReportMap {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.0.cast(), size_of::<Shared>());
        }
    }
}
impl ReportMap {
    fn map(fd: c_int) -> Result<Self> {
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size_of::<Shared>(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(Error::io("STATUS_REPORT_FAILED", "Cannot map report"));
        }
        Ok(Self(p.cast()))
    }
    pub fn create(fd: c_int) -> Result<Self> {
        unsafe {
            let raw = libc::syscall(
                libc::SYS_memfd_create,
                c"genshin-report".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            ) as c_int;
            if raw < 0 {
                return Err(Error::io(
                    "STATUS_REPORT_FAILED",
                    "Cannot create report memfd",
                ));
            }
            let owned = OwnedFd::from_raw_fd(raw);
            if libc::ftruncate(raw, size_of::<Shared>() as _) != 0
                || libc::fcntl(
                    raw,
                    libc::F_ADD_SEALS,
                    libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
                ) != 0
            {
                return Err(Error::io(
                    "STATUS_REPORT_FAILED",
                    "Cannot seal report memfd",
                ));
            }
            let map = Self::map(raw)?;
            wait(fd, libc::POLLOUT, Instant::now() + Duration::from_secs(3))?;
            let mut marker = 1u8;
            let mut control = [0usize; 8];
            let mut io = libc::iovec {
                iov_base: (&mut marker as *mut u8).cast(),
                iov_len: 1,
            };
            let mut msg: libc::msghdr = zeroed();
            msg.msg_iov = &mut io;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = libc::CMSG_SPACE(size_of::<c_int>() as u32) as _;
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(size_of::<c_int>() as u32) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(c).cast::<c_int>(), owned.as_raw_fd());
            if libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) != 1 {
                return Err(Error::io(
                    "STATUS_REPORT_FAILED",
                    "Cannot transfer report memfd",
                ));
            }
            Ok(map)
        }
    }
    pub fn receive(fd: c_int) -> Result<Self> {
        wait(fd, libc::POLLIN, Instant::now() + Duration::from_secs(3))?;
        unsafe {
            let mut control = [0usize; 32];
            let mut marker = 0u8;
            let mut io = libc::iovec {
                iov_base: (&mut marker as *mut u8).cast(),
                iov_len: 1,
            };
            let mut msg: libc::msghdr = zeroed();
            msg.msg_iov = &mut io;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = size_of_val(&control) as _;
            let n = libc::recvmsg(fd, &mut msg, libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT);
            let mut received = Vec::new();
            let mut c = libc::CMSG_FIRSTHDR(&msg);
            while !c.is_null() {
                if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                    let count = ((*c).cmsg_len as usize).saturating_sub(libc::CMSG_LEN(0) as usize)
                        / size_of::<c_int>();
                    for i in 0..count {
                        received.push(OwnedFd::from_raw_fd(std::ptr::read_unaligned(
                            libc::CMSG_DATA(c).cast::<c_int>().add(i),
                        )));
                    }
                }
                c = libc::CMSG_NXTHDR(&msg, c);
            }
            if n != 1 || marker != 1 || msg.msg_flags & libc::MSG_CTRUNC != 0 || received.len() != 1
            {
                return Err(Error::new(
                    "STATUS_REPORT_FAILED",
                    "Invalid report memfd transfer",
                ));
            }
            let raw = received[0].as_raw_fd();
            let mut st: libc::stat = zeroed();
            let seals = libc::fcntl(raw, libc::F_GET_SEALS);
            if libc::fstat(raw, &mut st) != 0
                || st.st_mode & libc::S_IFMT != libc::S_IFREG
                || st.st_size != size_of::<Shared>() as libc::off_t
                || seals < 0
                || seals & (libc::F_SEAL_GROW | libc::F_SEAL_SHRINK)
                    != (libc::F_SEAL_GROW | libc::F_SEAL_SHRINK)
            {
                return Err(Error::new(
                    "STATUS_REPORT_FAILED",
                    "Invalid sealed report size or seals",
                ));
            }
            Self::map(raw)
        }
    }
    pub fn publish(&self, record: &Record) -> Result<()> {
        let bytes = encode(record)?;
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                std::ptr::addr_of_mut!((*self.0).payload).cast(),
                bytes.len(),
            );
            (*self.0).size = bytes.len() as u32;
            (*self.0).state.store(1, Ordering::Release);
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                match (*self.0).state.load(Ordering::Acquire) {
                    2 => return Ok(()),
                    3 => {
                        return Err(Error::new(
                            "STATUS_REPORT_FAILED",
                            "Companion rejected report",
                        ))
                    }
                    _ => std::thread::sleep(Duration::from_millis(20)),
                }
            }
        }
        Err(Error::new(
            "STATUS_REPORT_FAILED",
            "Report acknowledgement timed out",
        ))
    }
    pub fn read(&self) -> Result<Option<Record>> {
        unsafe {
            if (*self.0).state.load(Ordering::Acquire) != 1 {
                return Ok(None);
            }
            let size = (*self.0).size as usize;
            if size == 0 || size > MAX_FRAME {
                return Err(Error::new("STATUS_REPORT_FAILED", "Mapped report bounds"));
            }
            let mut snapshot = vec![0u8; size];
            std::ptr::copy_nonoverlapping(
                std::ptr::addr_of!((*self.0).payload).cast(),
                snapshot.as_mut_ptr(),
                size,
            );
            decode(&snapshot).map(Some)
        }
    }
    pub fn acknowledge(&self, success: bool) {
        unsafe {
            (*self.0)
                .state
                .store(if success { 2 } else { 3 }, Ordering::Release);
        }
    }
}
