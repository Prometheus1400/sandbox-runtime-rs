use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use crate::child::SandboxedChild;
use crate::config::SandboxRuntimeConfig;
use crate::error::{SandboxError, SandboxViolationEvent, SandboxedExecutionError};
use crate::manager::network::initialize_proxies;
#[cfg(target_os = "linux")]
use crate::sandbox::linux::{
    extract_seccomp_runner, generate_bwrap_command_with_runner, generate_socket_path,
    LinuxLogMonitor, SocatBridge,
};
#[cfg(target_os = "macos")]
use crate::sandbox::macos::{wrap_command as wrap_macos_command, LogMonitor};
use crate::utils::{current_platform, join_args, Platform};
use tokio::process::Command;
use tokio::sync::mpsc;

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
        let violations = child.drain_violations().await;

        if !violations.is_empty() && !output.status.success() {
            return Err(SandboxError::ExecutionViolation(SandboxedExecutionError {
                status: Some(output.status),
                stdout: output.stdout,
                stderr: output.stderr,
                violations,
            }));
        }

        // Heuristic fallback: infer sandbox denial from stderr when no violations were captured
        if violations.is_empty() && !output.status.success() {
            let stderr_str = String::from_utf8_lossy(&output.stderr);
            if looks_like_sandbox_denial(&stderr_str) {
                let synthetic = SandboxViolationEvent::new(format!(
                    "inferred: process exited with {} and stderr suggests sandbox denial",
                    output.status
                ));
                return Err(SandboxError::ExecutionViolation(SandboxedExecutionError {
                    status: Some(output.status),
                    stdout: output.stdout,
                    stderr: output.stderr,
                    violations: vec![synthetic],
                }));
            }
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
        inner.arg("-c").arg(wrapped);
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
        use std::os::unix::io::AsRawFd;

        let http_socket_path = generate_socket_path("srt-http");
        let socks_socket_path = generate_socket_path("srt-socks");
        let http_bridge =
            SocatBridge::unix_to_tcp(http_socket_path.clone(), "127.0.0.1", http_port).await?;
        let socks_bridge =
            SocatBridge::unix_to_tcp(socks_socket_path.clone(), "127.0.0.1", socks_port).await?;

        // Create Unix socketpair for seccomp notification fd passing
        let (parent_sock, child_sock) =
            std::os::unix::net::UnixStream::pair().map_err(SandboxError::Io)?;

        // Set receive timeout on parent socket so we don't block forever
        parent_sock
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .map_err(SandboxError::Io)?;

        // Extract the embedded seccomp-runner binary
        let runner_path = extract_seccomp_runner()?;

        let child_fd = child_sock.as_raw_fd();

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
            child_fd,
        )?;
        for warning in warnings {
            tracing::warn!("{warning}");
        }

        let mut inner = Command::new("sh");
        inner.arg("-c").arg(wrapped);
        self.apply_outer_builder(&mut inner, &cwd);

        // Clear close-on-exec on child_fd so it survives into the child process
        unsafe {
            inner.pre_exec(move || {
                let flags = libc::fcntl(child_fd, libc::F_GETFD);
                if flags < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(child_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let mut child = inner.spawn()?;
        drop(child_sock); // Close child end in parent

        // Receive the seccomp listener fd from the runner via SCM_RIGHTS
        let listener_fd = recv_fd(&parent_sock)?;
        drop(parent_sock);

        // Clean up runner binary — the child has already exec'd it
        let _ = std::fs::remove_file(&runner_path);

        let monitor =
            LinuxLogMonitor::start(listener_fd, Some(command.clone()), violations_tx).await?;

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
fn recv_fd(
    sock: &std::os::unix::net::UnixStream,
) -> Result<std::os::fd::OwnedFd, SandboxError> {
    use nix::cmsg_space;
    use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let mut buf = [0u8; 1];
    let mut iov = [std::io::IoSliceMut::new(&mut buf)];
    let mut cmsg_buf = cmsg_space!(i32);

    let msg = recvmsg::<()>(
        sock.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_buf),
        MsgFlags::empty(),
    )
    .map_err(|e| SandboxError::Seccomp(format!("recvmsg for listener fd: {e}")))?;

    for cmsg in msg.cmsgs() {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            if let Some(&fd) = fds.first() {
                return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
            }
        }
    }

    Err(SandboxError::Seccomp(
        "no listener fd received from seccomp runner".into(),
    ))
}

fn looks_like_sandbox_denial(stderr: &str) -> bool {
    let lower = stderr.to_lowercase();
    if lower.contains("operation not permitted") {
        return true;
    }
    if lower.contains("sandbox") && lower.contains("deny") {
        return true;
    }
    if lower.contains("permission denied") {
        return true;
    }
    if lower.contains("don't have permission to access") {
        return true;
    }
    if lower.contains("afpaccessdenied") {
        return true;
    }
    false
}
