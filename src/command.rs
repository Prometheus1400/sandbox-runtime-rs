use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use crate::child::SandboxedChild;
use crate::config::SandboxRuntimeConfig;
use crate::error::{SandboxError, SandboxViolationEvent, SandboxViolationKind, SandboxedExecutionError};
use crate::manager::network::initialize_proxies;
#[cfg(target_os = "linux")]
use crate::sandbox::linux::{
    build_linux_write_policy, extract_seccomp_runner, generate_bwrap_command_with_runner,
    generate_socket_path,
    LinuxLogMonitor, SocatBridge,
};
#[cfg(target_os = "macos")]
use crate::sandbox::macos::{wrap_command as wrap_macos_command, LogMonitor};
use crate::utils::{current_platform, join_args, Platform};
use tokio::process::Command;
use tokio::sync::mpsc;

#[cfg(target_os = "linux")]
const SECCOMP_DIAGNOSTIC_SNIPPET_LIMIT: usize = 512;

pub struct SandboxedCommand {
    program: String,
    args: Vec<String>,
    envs: HashMap<String, String>,
    cwd: Option<PathBuf>,
    stdin: Option<Stdio>,
    stdout: Option<Stdio>,
    stderr: Option<Stdio>,
    config: SandboxRuntimeConfig,
}

#[derive(Debug)]
pub struct SandboxedOutput {
    pub status: std::process::ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub violations: Vec<SandboxViolationEvent>,
}

impl SandboxedCommand {
    pub fn new<S: AsRef<OsStr>>(program: S) -> Self {
        Self {
            program: program.as_ref().to_string_lossy().into_owned(),
            args: Vec::new(),
            envs: HashMap::new(),
            cwd: None,
            stdin: None,
            stdout: None,
            stderr: None,
            config: SandboxRuntimeConfig::default(),
        }
    }

    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Self {
        self.args.push(arg.as_ref().to_string_lossy().into_owned());
        self
    }

    pub fn env<K: AsRef<OsStr>, V: AsRef<OsStr>>(&mut self, key: K, val: V) -> &mut Self {
        self.envs.insert(
            key.as_ref().to_string_lossy().into_owned(),
            val.as_ref().to_string_lossy().into_owned(),
        );
        self
    }

    pub fn envs<I, K, V>(&mut self, vars: I) -> &mut Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        for (key, value) in vars {
            self.env(key, value);
        }
        self
    }

    pub fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Self {
        self.cwd = Some(dir.as_ref().to_path_buf());
        self
    }

    pub fn stdin<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.stdin = Some(cfg.into());
        self
    }

    pub fn stdout<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.stdout = Some(cfg.into());
        self
    }

    pub fn stderr<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.stderr = Some(cfg.into());
        self
    }

    pub fn config(&mut self, config: SandboxRuntimeConfig) -> &mut Self {
        self.config = config;
        self
    }

    pub fn allow_read<P: AsRef<Path>>(&mut self, path: P) -> &mut Self {
        let value = path.as_ref().to_string_lossy().into_owned();
        if !self.config.filesystem.allow_read.contains(&value) {
            self.config.filesystem.allow_read.push(value);
        }
        self
    }

    pub fn allow_write<P: AsRef<Path>>(&mut self, path: P) -> &mut Self {
        let value = path.as_ref().to_string_lossy().into_owned();
        if !self.config.filesystem.allow_write.contains(&value) {
            self.config.filesystem.allow_write.push(value);
        }
        self
    }

    pub fn allow_domain<S: Into<String>>(&mut self, domain: S) -> &mut Self {
        self.config.network.allowed_domains.push(domain.into());
        self
    }

    pub fn deny_domain<S: Into<String>>(&mut self, domain: S) -> &mut Self {
        self.config.network.denied_domains.push(domain.into());
        self
    }

    pub async fn spawn(&mut self) -> Result<SandboxedChild, SandboxError> {
        self.config.validate()?;
        let platform = current_platform()
            .ok_or_else(|| SandboxError::UnsupportedPlatform("Unsupported platform".to_string()))?;
        crate::sandbox::check_dependencies(platform)?;

        let (violations_tx, violations_rx) = mpsc::channel(100);
        let (http_proxy, socks_proxy) =
            initialize_proxies(&self.config.network, violations_tx.clone()).await?;
        let http_port = http_proxy.port();
        let socks_port = socks_proxy.port();
        let cwd = self.resolve_cwd()?;
        let command = self.render_command();

        match platform {
            Platform::MacOS => {
                #[cfg(target_os = "macos")]
                {
                    self.spawn_macos(
                        command,
                        cwd,
                        http_proxy,
                        socks_proxy,
                        http_port,
                        socks_port,
                        violations_tx,
                        violations_rx,
                    )
                    .await
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = (
                        command,
                        cwd,
                        http_proxy,
                        socks_proxy,
                        http_port,
                        socks_port,
                        violations_tx,
                        violations_rx,
                    );
                    Err(SandboxError::UnsupportedPlatform(
                        "macOS sandbox code not compiled on this platform".to_string(),
                    ))
                }
            }
            Platform::Linux => {
                #[cfg(target_os = "linux")]
                {
                    self.spawn_linux(
                        command,
                        cwd,
                        http_proxy,
                        socks_proxy,
                        http_port,
                        socks_port,
                        violations_tx,
                        violations_rx,
                    )
                    .await
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (
                        command,
                        cwd,
                        http_proxy,
                        socks_proxy,
                        http_port,
                        socks_port,
                        violations_tx,
                        violations_rx,
                    );
                    Err(SandboxError::UnsupportedPlatform(
                        "Linux sandbox code not compiled on this platform".to_string(),
                    ))
                }
            }
        }
    }

    pub async fn output(&mut self) -> Result<SandboxedOutput, SandboxError> {
        self.stdin(Stdio::null());
        self.stdout(Stdio::piped());
        self.stderr(Stdio::piped());

        let mut child = self.spawn().await?;
        let output = child.wait_with_output().await?;
        let mut violations = child.drain_violations().await;

        // Stderr heuristic fallback: if the process failed and no violations were
        // captured by the log monitor, check stderr for sandbox-related messages.
        // This handles cases where the log stream is too slow or unavailable.
        if violations.is_empty() && !output.status.success() {
            let stderr_str = String::from_utf8_lossy(&output.stderr);
            let stderr_violations = detect_stderr_violations(&stderr_str);
            violations.extend(stderr_violations);
        }

        if !violations.is_empty() {
            return Err(SandboxError::ExecutionViolation(SandboxedExecutionError {
                status: Some(output.status),
                stdout: output.stdout,
                stderr: output.stderr,
                violations,
            }));
        }

        Ok(SandboxedOutput {
            status: output.status,
            stdout: output.stdout,
            stderr: output.stderr,
            violations,
        })
    }

    fn render_command(&self) -> String {
        let mut parts = Vec::with_capacity(self.args.len() + 1);
        parts.push(self.program.clone());
        parts.extend(self.args.clone());
        join_args(parts)
    }

    fn resolve_cwd(&self) -> Result<PathBuf, SandboxError> {
        match &self.cwd {
            Some(path) => Ok(path.clone()),
            None => Ok(std::env::current_dir()?),
        }
    }

    fn apply_outer_builder(&mut self, command: &mut Command, cwd: &Path) {
        command.current_dir(cwd);
        command.envs(self.envs.clone());
        if let Some(stdin) = self.stdin.take() {
            command.stdin(stdin);
        }
        if let Some(stdout) = self.stdout.take() {
            command.stdout(stdout);
        }
        if let Some(stderr) = self.stderr.take() {
            command.stderr(stderr);
        }
    }

    #[cfg(target_os = "macos")]
    #[allow(clippy::too_many_arguments)]
    async fn spawn_macos(
        &mut self,
        command: String,
        cwd: PathBuf,
        http_proxy: crate::proxy::HttpProxy,
        socks_proxy: crate::proxy::Socks5Proxy,
        http_port: u16,
        socks_port: u16,
        violations_tx: mpsc::Sender<SandboxViolationEvent>,
        violations_rx: mpsc::Receiver<SandboxViolationEvent>,
    ) -> Result<SandboxedChild, SandboxError> {
        let (wrapped, log_tag) = wrap_macos_command(
            &command,
            &self.config,
            Some(http_port),
            Some(socks_port),
            None,
            true,
        )?;

        let mut inner = Command::new("sh");
        inner.arg("-c").arg(&wrapped);
        self.apply_outer_builder(&mut inner, &cwd);

        let mut child = inner.spawn()?;
        let monitor = if let Some(tag) = log_tag {
            Some(LogMonitor::start(tag, Some(command.clone()), violations_tx).await?)
        } else {
            // Drop the sender so the channel can close when proxies are done
            drop(violations_tx);
            None
        };

        Ok(SandboxedChild {
            stdin: child.stdin.take(),
            stdout: child.stdout.take(),
            stderr: child.stderr.take(),
            inner: Some(child),
            violations_rx: Some(violations_rx),
            http_proxy: Some(http_proxy),
            socks_proxy: Some(socks_proxy),
            monitor,
        })
    }

    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    async fn spawn_linux(
        &mut self,
        command: String,
        cwd: PathBuf,
        http_proxy: crate::proxy::HttpProxy,
        socks_proxy: crate::proxy::Socks5Proxy,
        http_port: u16,
        socks_port: u16,
        violations_tx: mpsc::Sender<SandboxViolationEvent>,
        violations_rx: mpsc::Receiver<SandboxViolationEvent>,
    ) -> Result<SandboxedChild, SandboxError> {
        let http_socket_path = generate_socket_path("srt-http");
        let socks_socket_path = generate_socket_path("srt-socks");
        let notify_socket_path = generate_socket_path("srt-seccomp-notify");
        let http_bridge =
            SocatBridge::unix_to_tcp(http_socket_path.clone(), "127.0.0.1", http_port).await?;
        let socks_bridge =
            SocatBridge::unix_to_tcp(socks_socket_path.clone(), "127.0.0.1", socks_port).await?;
        let notify_listener = std::os::unix::net::UnixListener::bind(&notify_socket_path)
            .map_err(SandboxError::Io)?;
        notify_listener
            .set_nonblocking(true)
            .map_err(SandboxError::Io)?;
        let notify_listener =
            tokio::net::UnixListener::from_std(notify_listener).map_err(SandboxError::Io)?;

        // Extract the embedded seccomp-runner binary
        let runner_path = extract_seccomp_runner()?;

        // Generate bwrap command using the runner variant
        let (wrapped, warnings) = generate_bwrap_command_with_runner(
            &command,
            &self.config,
            &cwd,
            Some(http_socket_path.to_string_lossy().as_ref()),
            Some(socks_socket_path.to_string_lossy().as_ref()),
            http_port,
            socks_port,
            None,
            &runner_path,
            &notify_socket_path,
        )?;
        for warning in warnings {
            tracing::warn!("{warning}");
        }
        tracing::debug!(
            runner_path = %runner_path.display(),
            notify_socket_path = %notify_socket_path.display(),
            wrapped_command = %wrapped,
            "starting linux sandbox via seccomp runner"
        );

        let mut inner = Command::new("sh");
        inner.arg("-c").arg(&wrapped);
        self.apply_outer_builder(&mut inner, &cwd);

        let mut child = inner.spawn()?;

        // Receive the seccomp listener fd from the runner via SCM_RIGHTS
        tracing::debug!("waiting for seccomp listener fd from runner");
        let listener_fd = match wait_for_seccomp_listener_fd(&notify_listener).await {
            Ok(fd) => fd,
            Err(recv_error) => {
                let error = collect_seccomp_startup_error(
                    &mut child,
                    recv_error,
                    &wrapped,
                    &runner_path,
                    &notify_socket_path,
                )
                .await;
                let _ = std::fs::remove_file(&notify_socket_path);
                let _ = std::fs::remove_file(&runner_path);
                return Err(error);
            }
        };
        let _ = std::fs::remove_file(&notify_socket_path);
        tracing::debug!("received seccomp listener fd from runner");

        // Clean up runner binary — the child has already exec'd it
        let _ = std::fs::remove_file(&runner_path);

        let (write_policy, write_warnings) = build_linux_write_policy(
            &self.config.filesystem,
            &cwd,
            self.config.ripgrep.as_ref(),
            self.config.mandatory_deny_search_depth,
        );
        for warning in write_warnings {
            tracing::warn!("{warning}");
        }

        let monitor = LinuxLogMonitor::start(
            listener_fd,
            Some(command.clone()),
            write_policy,
            violations_tx,
        )
        .await?;

        Ok(SandboxedChild {
            stdin: child.stdin.take(),
            stdout: child.stdout.take(),
            stderr: child.stderr.take(),
            inner: Some(child),
            violations_rx: Some(violations_rx),
            http_proxy: Some(http_proxy),
            socks_proxy: Some(socks_proxy),
            bridges: vec![http_bridge, socks_bridge],
            monitor: Some(monitor),
        })
    }
}

/// Receive a file descriptor over a Unix socket via SCM_RIGHTS.
/// Counterpart to the `send_fd()` in runner.c.
#[cfg(target_os = "linux")]
fn recv_fd<Fd: std::os::fd::AsRawFd>(
    sock: &Fd,
) -> Result<std::os::fd::OwnedFd, SeccompFdReceiveError> {
    use nix::cmsg_space;
    use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
    use std::os::fd::{FromRawFd, OwnedFd};

    let mut buf = [0u8; 1];
    let mut iov = [std::io::IoSliceMut::new(&mut buf)];
    let mut cmsg_buf = cmsg_space!(i32);

    let msg = recvmsg::<()>(
        sock.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_buf),
        MsgFlags::empty(),
    )
    .map_err(|e| SeccompFdReceiveError {
        summary: format!("recvmsg for listener fd failed: {e}"),
        bytes: None,
        flags: None,
        ancillary: None,
    })?;

    let mut ancillary = Vec::new();
    for cmsg in msg.cmsgs() {
        match cmsg {
            ControlMessageOwned::ScmRights(fds) => {
                ancillary.push(format!("SCM_RIGHTS({})", fds.len()));
                if let Some(&fd) = fds.first() {
                    return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
                }
            }
            other => ancillary.push(format!("{other:?}")),
        }
    }

    Err(SeccompFdReceiveError {
        summary: "no listener fd received from seccomp runner".into(),
        bytes: Some(msg.bytes),
        flags: Some(format!("{:?}", msg.flags)),
        ancillary: Some(if ancillary.is_empty() {
            "none".into()
        } else {
            ancillary.join(", ")
        }),
    })
}

#[cfg(target_os = "linux")]
async fn wait_for_seccomp_listener_fd(
    listener: &tokio::net::UnixListener,
) -> Result<std::os::fd::OwnedFd, SeccompFdReceiveError> {
    let stream = match tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept()).await
    {
        Ok(Ok((stream, _addr))) => stream,
        Ok(Err(err)) => {
            return Err(SeccompFdReceiveError {
                summary: format!("failed to accept seccomp runner connection: {err}"),
                bytes: None,
                flags: None,
                ancillary: None,
            });
        }
        Err(_) => {
            return Err(SeccompFdReceiveError {
                summary: "timed out waiting for seccomp runner connection".into(),
                bytes: None,
                flags: None,
                ancillary: None,
            });
        }
    };

    recv_fd(&stream)
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct SeccompFdReceiveError {
    summary: String,
    bytes: Option<usize>,
    flags: Option<String>,
    ancillary: Option<String>,
}

#[cfg(target_os = "linux")]
async fn collect_seccomp_startup_error(
    child: &mut tokio::process::Child,
    recv_error: SeccompFdReceiveError,
    wrapped_command: &str,
    runner_path: &Path,
    notify_socket_path: &Path,
) -> SandboxError {
    use tokio::io::AsyncReadExt;

    let mut stderr_pipe = child.stderr.take();
    let mut stdout_pipe = child.stdout.take();

    let mut status = match child.try_wait() {
        Ok(status) => status,
        Err(err) => {
            tracing::warn!("failed to query seccomp runner child status: {err}");
            None
        }
    };

    if status.is_none() {
        let _ = child.start_kill();
        status = match tokio::time::timeout(std::time::Duration::from_millis(500), child.wait()).await
        {
            Ok(Ok(exit_status)) => Some(exit_status),
            Ok(Err(err)) => {
                tracing::warn!("failed to wait for seccomp runner child after startup error: {err}");
                None
            }
            Err(_) => None,
        };
    }

    let stderr = if let Some(mut pipe) = stderr_pipe.take() {
        let mut buf = Vec::new();
        match tokio::time::timeout(
            std::time::Duration::from_millis(200),
            pipe.read_to_end(&mut buf),
        )
        .await
        {
            Ok(Ok(_)) => Some(buf),
            Ok(Err(err)) => Some(format!("failed to read stderr: {err}").into_bytes()),
            Err(_) => Some(b"<stderr read timed out>".to_vec()),
        }
    } else {
        None
    };

    let stdout = if let Some(mut pipe) = stdout_pipe.take() {
        let mut buf = Vec::new();
        match tokio::time::timeout(
            std::time::Duration::from_millis(200),
            pipe.read_to_end(&mut buf),
        )
        .await
        {
            Ok(Ok(_)) => Some(buf),
            Ok(Err(err)) => Some(format!("failed to read stdout: {err}").into_bytes()),
            Err(_) => Some(b"<stdout read timed out>".to_vec()),
        }
    } else {
        None
    };

    let message = format_seccomp_startup_error(
        &recv_error,
        status.as_ref().map(ToString::to_string).as_deref(),
        stderr.as_deref(),
        stdout.as_deref(),
        wrapped_command,
        &runner_path.display().to_string(),
        &notify_socket_path.display().to_string(),
    );
    tracing::warn!("{message}");
    SandboxError::Seccomp(message)
}

#[cfg(target_os = "linux")]
fn format_seccomp_startup_error(
    recv_error: &SeccompFdReceiveError,
    child_status: Option<&str>,
    stderr: Option<&[u8]>,
    stdout: Option<&[u8]>,
    wrapped_command: &str,
    runner_path: &str,
    notify_socket_path: &str,
) -> String {
    let mut parts = vec![format!("seccomp runner startup failed: {}", recv_error.summary)];

    if let Some(bytes) = recv_error.bytes {
        parts.push(format!("recvmsg_bytes={bytes}"));
    }
    if let Some(flags) = recv_error.flags.as_deref() {
        parts.push(format!("recvmsg_flags={flags}"));
    }
    if let Some(ancillary) = recv_error.ancillary.as_deref() {
        parts.push(format!("recvmsg_ancillary={ancillary}"));
    }
    if let Some(status) = child_status {
        parts.push(format!("child_status={status}"));
    } else {
        parts.push("child_status=<unavailable>".into());
    }
    if let Some(stderr) = summarize_output(stderr) {
        parts.push(format!("stderr={stderr}"));
    }
    if let Some(stdout) = summarize_output(stdout) {
        parts.push(format!("stdout={stdout}"));
    }
    parts.push(format!("runner_path={runner_path}"));
    parts.push(format!("notify_socket_path={notify_socket_path}"));
    parts.push(format!(
        "command={}",
        summarize_text(wrapped_command, SECCOMP_DIAGNOSTIC_SNIPPET_LIMIT)
    ));

    parts.join("; ")
}

#[cfg(target_os = "linux")]
fn summarize_output(bytes: Option<&[u8]>) -> Option<String> {
    let bytes = bytes?;
    if bytes.is_empty() {
        return None;
    }
    Some(summarize_text(
        &String::from_utf8_lossy(bytes),
        SECCOMP_DIAGNOSTIC_SNIPPET_LIMIT,
    ))
}

#[cfg(any(target_os = "linux", test))]
fn summarize_text(text: &str, max_len: usize) -> String {
    let sanitized = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if sanitized.len() <= max_len {
        sanitized
    } else {
        format!("{}...", &sanitized[..max_len])
    }
}

/// Sandbox-related error patterns in stderr that indicate a violation occurred
/// even when the log monitor didn't capture it.
const STDERR_VIOLATION_PATTERNS: &[&str] = &[
    "Operation not permitted",
    "Permission denied",
    "sandbox-exec: denied",
];

/// Detect sandbox violations from stderr output as a fallback when the log
/// monitor doesn't capture violations (e.g., timing issues on CI).
fn detect_stderr_violations(stderr: &str) -> Vec<SandboxViolationEvent> {
    let mut violations = Vec::new();
    for line in stderr.lines() {
        if STDERR_VIOLATION_PATTERNS
            .iter()
            .any(|pattern| line.contains(pattern))
        {
            let kind = if line.contains("write") || line.contains("create") {
                SandboxViolationKind::FilesystemWrite
            } else {
                SandboxViolationKind::Unknown
            };
            violations.push(
                SandboxViolationEvent::new(format!("stderr: {}", line)).with_details(
                    kind,
                    None::<String>,
                    None::<String>,
                ),
            );
        }
    }
    violations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_summarize_text_collapses_whitespace_and_truncates() {
        assert_eq!(summarize_text("hello\n  world", 32), "hello world");
        assert_eq!(summarize_text("abcdef", 4), "abcd...");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_format_seccomp_startup_error_includes_diagnostics() {
        let message = format_seccomp_startup_error(
            &SeccompFdReceiveError {
                summary: "no listener fd received from seccomp runner".into(),
                bytes: Some(0),
                flags: Some("MsgFlags(0x0)".into()),
                ancillary: Some("none".into()),
            },
            Some("exit status: 67"),
            Some(b"seccomp(SECCOMP_SET_MODE_FILTER): Invalid argument\n"),
            Some(b""),
            "bwrap -- sh -c 'runner /var/tmp/srt-seccomp-notify.sock'",
            "/tmp/seccomp-runner",
            "/var/tmp/srt-seccomp-notify.sock",
        );

        assert!(message.contains("no listener fd received from seccomp runner"));
        assert!(message.contains("recvmsg_bytes=0"));
        assert!(message.contains("child_status=exit status: 67"));
        assert!(message.contains("stderr=seccomp(SECCOMP_SET_MODE_FILTER): Invalid argument"));
        assert!(message.contains("runner_path=/tmp/seccomp-runner"));
        assert!(message.contains("notify_socket_path=/var/tmp/srt-seccomp-notify.sock"));
        assert!(message.contains("command=bwrap -- sh -c 'runner /var/tmp/srt-seccomp-notify.sock'"));
    }
}
