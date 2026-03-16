//! Violation monitoring via seccomp user notifications on Linux.

#[cfg(target_os = "linux")]
use std::mem::MaybeUninit;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::path::PathBuf;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::error::{SandboxError, SandboxViolationEvent};
#[cfg(target_os = "linux")]
use crate::sandbox::linux::LinuxWritePolicy;
#[cfg(target_os = "linux")]
use crate::utils::normalize_path_components;
#[cfg(target_os = "linux")]
use crate::violation::linux_filesystem_write_event;
use crate::violation::linux_seccomp_event;

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct SeccompData {
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct SeccompNotif {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct SeccompNotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

#[cfg(target_os = "linux")]
nix::ioctl_readwrite!(seccomp_ioctl_notif_recv, b'!', 0, SeccompNotif);
#[cfg(target_os = "linux")]
nix::ioctl_readwrite!(seccomp_ioctl_notif_send, b'!', 1, SeccompNotifResp);

/// Log monitor for seccomp violations on Linux.
#[allow(dead_code)]
pub struct LinuxLogMonitor {
    #[cfg(target_os = "linux")]
    listener_fd: Option<OwnedFd>,
    #[cfg(target_os = "linux")]
    task: Option<JoinHandle<()>>,
}

impl LinuxLogMonitor {
    #[cfg(target_os = "linux")]
    pub async fn start(
        listener_fd: OwnedFd,
        command: Option<String>,
        #[cfg(target_os = "linux")] write_policy: LinuxWritePolicy,
        tx: mpsc::Sender<SandboxViolationEvent>,
    ) -> Result<Self, SandboxError> {
        let raw_fd = listener_fd.as_raw_fd();
        let task =
            tokio::task::spawn_blocking(move || monitor_loop(raw_fd, command, write_policy, tx));

        Ok(Self {
            listener_fd: Some(listener_fd),
            task: Some(task),
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn start(
        _listener_fd: (),
        _command: Option<String>,
        #[cfg(not(target_os = "linux"))] _write_policy: (),
        _tx: mpsc::Sender<SandboxViolationEvent>,
    ) -> Result<Self, SandboxError> {
        Ok(Self {})
    }

    pub async fn stop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.listener_fd.take();
            if let Some(task) = self.task.take() {
                let _ = task.await;
            }
        }
    }
}

impl Drop for LinuxLogMonitor {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.listener_fd.take();
            if let Some(task) = self.task.take() {
                task.abort();
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn monitor_loop(
    raw_fd: i32,
    command: Option<String>,
    write_policy: LinuxWritePolicy,
    tx: mpsc::Sender<SandboxViolationEvent>,
) {
    const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

    loop {
        let mut poll_fd = libc::pollfd {
            fd: raw_fd,
            events: libc::POLLIN,
            revents: 0,
        };

        let poll_result = unsafe { libc::poll(&mut poll_fd, 1, 100) };
        if poll_result < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if poll_result == 0 {
            continue;
        }
        if (poll_fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 {
            break;
        }

        let mut req = MaybeUninit::<SeccompNotif>::zeroed();
        let recv_result = unsafe { seccomp_ioctl_notif_recv(raw_fd, req.as_mut_ptr()) };
        if let Err(errno) = recv_result {
            if errno == nix::errno::Errno::ENOENT || errno == nix::errno::Errno::EINTR {
                continue;
            }
            break;
        }

        let req = unsafe { req.assume_init() };
        let decision = evaluate_request(&req, command.clone(), &write_policy);

        let mut resp = SeccompNotifResp {
            id: req.id,
            val: 0,
            error: libc::EPERM,
            flags: 0,
        };

        match decision {
            RequestDecision::Continue => {
                resp.error = 0;
                resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            }
            RequestDecision::Deny(event) => {
                let _ = tx.blocking_send(event);
            }
        }

        let _ = unsafe { seccomp_ioctl_notif_send(raw_fd, &mut resp) };
    }
}

#[cfg(target_os = "linux")]
enum RequestDecision {
    Continue,
    Deny(SandboxViolationEvent),
}

#[cfg(target_os = "linux")]
fn evaluate_request(
    req: &SeccompNotif,
    command: Option<String>,
    write_policy: &LinuxWritePolicy,
) -> RequestDecision {
    let syscall = crate::violation::syscall_name(req.data.nr, req.data.arch);

    if syscall == "socket" {
        if req.data.args[0] == libc::AF_UNIX as u64 {
            return RequestDecision::Deny(linux_seccomp_event(
                req.pid,
                req.data.nr,
                req.data.arch,
                req.data.args,
                req.data.instruction_pointer,
                command,
            ));
        }
        return RequestDecision::Continue;
    }

    match syscall {
        "openat" => match openat_write_target(req.pid, req.data.args) {
            Some(path) if !write_policy.allows(&path) => RequestDecision::Deny(
                linux_filesystem_write_event(
                    req.pid,
                    "openat",
                    path.display().to_string(),
                    command,
                ),
            ),
            Some(_) | None => RequestDecision::Continue,
        },
        "openat2" => match openat2_write_target(req.pid, req.data.args) {
            Some(path) if !write_policy.allows(&path) => RequestDecision::Deny(
                linux_filesystem_write_event(
                    req.pid,
                    "openat2",
                    path.display().to_string(),
                    command,
                ),
            ),
            Some(_) | None => RequestDecision::Continue,
        },
        _ => RequestDecision::Continue,
    }
}

#[cfg(target_os = "linux")]
fn openat_write_target(pid: u32, args: [u64; 6]) -> Option<PathBuf> {
    let flags = args[2];
    if !is_write_open_flags(flags) {
        return None;
    }

    resolve_path_arg(pid, args[0] as i64, args[1])
}

#[cfg(target_os = "linux")]
fn openat2_write_target(pid: u32, args: [u64; 6]) -> Option<PathBuf> {
    let how = read_open_how(pid, args[2])?;
    if !is_write_open_flags(how.flags) {
        return None;
    }

    resolve_path_arg(pid, args[0] as i64, args[1])
}

#[cfg(target_os = "linux")]
fn is_write_open_flags(flags: u64) -> bool {
    let access_mode = flags & libc::O_ACCMODE as u64;
    access_mode == libc::O_WRONLY as u64
        || access_mode == libc::O_RDWR as u64
        || (flags & libc::O_CREAT as u64) != 0
        || (flags & libc::O_TRUNC as u64) != 0
        || (flags & libc::O_APPEND as u64) != 0
}

#[cfg(target_os = "linux")]
fn resolve_path_arg(pid: u32, dirfd: i64, ptr: u64) -> Option<PathBuf> {
    let path = read_process_c_string(pid, ptr)?;
    if path.is_empty() {
        return None;
    }

    let raw_path = PathBuf::from(path);
    if raw_path.is_absolute() {
        return Some(normalize_path_components(&raw_path));
    }

    let base = resolve_dirfd_base(pid, dirfd)?;
    Some(normalize_path_components(&base.join(raw_path)))
}

#[cfg(target_os = "linux")]
fn resolve_dirfd_base(pid: u32, dirfd: i64) -> Option<PathBuf> {
    if dirfd == libc::AT_FDCWD as i64 {
        std::fs::read_link(format!("/proc/{}/cwd", pid)).ok()
    } else {
        std::fs::read_link(format!("/proc/{}/fd/{}", pid, dirfd)).ok()
    }
}

#[cfg(target_os = "linux")]
fn read_process_c_string(pid: u32, ptr: u64) -> Option<String> {
    if ptr == 0 {
        return None;
    }

    const CHUNK: usize = 256;
    const LIMIT: usize = 4096;
    let mut bytes = Vec::new();
    let mut offset = 0usize;

    while offset < LIMIT {
        let chunk = read_process_memory(pid, ptr + offset as u64, CHUNK)?;
        if let Some(pos) = chunk.iter().position(|b| *b == 0) {
            bytes.extend_from_slice(&chunk[..pos]);
            return String::from_utf8(bytes).ok();
        }
        bytes.extend_from_slice(&chunk);
        offset += CHUNK;
    }

    None
}

#[cfg(target_os = "linux")]
fn read_process_memory(pid: u32, remote_addr: u64, len: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: len,
    };
    let remote = libc::iovec {
        iov_base: remote_addr as usize as *mut libc::c_void,
        iov_len: len,
    };

    let read = unsafe { libc::process_vm_readv(pid as i32, &local, 1, &remote, 1, 0) };
    if read <= 0 {
        return None;
    }

    buf.truncate(read as usize);
    Some(buf)
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[cfg(target_os = "linux")]
fn read_open_how(pid: u32, ptr: u64) -> Option<OpenHow> {
    let bytes = read_process_memory(pid, ptr, std::mem::size_of::<OpenHow>())?;
    if bytes.len() < std::mem::size_of::<OpenHow>() {
        return None;
    }

    Some(OpenHow {
        flags: u64::from_ne_bytes(bytes[0..8].try_into().ok()?),
        mode: u64::from_ne_bytes(bytes[8..16].try_into().ok()?),
        resolve: u64::from_ne_bytes(bytes[16..24].try_into().ok()?),
    })
}
#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use crate::violation::{linux_seccomp_event, AUDIT_ARCH_X86_64};

    #[cfg(target_os = "linux")]
    #[test]
    fn test_format_violation_line() {
        let event = linux_seccomp_event(
            42,
            41,
            AUDIT_ARCH_X86_64,
            [1, 1, 0, 0, 0, 0],
            0x1234,
            None,
        );

        assert!(event.line.contains("pid=42"));
        assert!(event.line.contains("syscall=41"));
        assert!(event.line.contains("socket"));
        assert!(event.line.contains("0x1234"));
    }
}
