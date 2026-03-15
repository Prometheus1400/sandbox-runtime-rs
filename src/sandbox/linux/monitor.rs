//! Violation monitoring via seccomp user notifications on Linux.

#[cfg(target_os = "linux")]
use std::mem::MaybeUninit;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, OwnedFd};

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::error::{SandboxError, SandboxViolationEvent};

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
    ) -> Result<(Self, mpsc::Receiver<SandboxViolationEvent>), SandboxError> {
        let raw_fd = listener_fd.as_raw_fd();
        let (tx, rx) = mpsc::channel(100);
        let task = tokio::task::spawn_blocking(move || monitor_loop(raw_fd, command, tx));

        Ok((
            Self {
                listener_fd: Some(listener_fd),
                task: Some(task),
            },
            rx,
        ))
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn start(
        _listener_fd: (),
        _command: Option<String>,
    ) -> Result<(Self, mpsc::Receiver<SandboxViolationEvent>), SandboxError> {
        let (_tx, rx) = mpsc::channel(1);
        Ok((Self {}, rx))
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
fn monitor_loop(raw_fd: i32, command: Option<String>, tx: mpsc::Sender<SandboxViolationEvent>) {
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
        let event = SandboxViolationEvent::with_command(
            format_violation_line(&req),
            command.clone(),
            None,
        );

        if tx.blocking_send(event).is_err() {
            break;
        }

        let mut resp = SeccompNotifResp {
            id: req.id,
            val: 0,
            error: libc::EPERM,
            flags: 0,
        };

        let _ = unsafe { seccomp_ioctl_notif_send(raw_fd, &mut resp) };
    }
}

#[cfg(target_os = "linux")]
fn format_violation_line(req: &SeccompNotif) -> String {
    format!(
        "seccomp violation: pid={} syscall={} ip=0x{:x}",
        req.pid, req.data.nr, req.data.instruction_pointer
    )
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use super::{format_violation_line, SeccompData, SeccompNotif};

    #[cfg(target_os = "linux")]
    #[test]
    fn test_format_violation_line() {
        let req = SeccompNotif {
            id: 1,
            pid: 42,
            flags: 0,
            data: SeccompData {
                nr: 41,
                arch: 0,
                instruction_pointer: 0x1234,
                args: [0; 6],
            },
        };

        let line = format_violation_line(&req);
        assert!(line.contains("pid=42"));
        assert!(line.contains("syscall=41"));
        assert!(line.contains("0x1234"));
    }
}
