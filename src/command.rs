use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use crate::child::SandboxedChild;
use crate::config::SandboxRuntimeConfig;
use crate::error::{SandboxError, SandboxedExecutionError};
use crate::manager::network::initialize_proxies;
#[cfg(target_os = "linux")]
use crate::sandbox::linux::{
    generate_bwrap_command, generate_socket_path, LinuxLogMonitor, SocatBridge,
};
#[cfg(target_os = "macos")]
use crate::sandbox::macos::{wrap_command as wrap_macos_command, LogMonitor};
use crate::utils::{current_platform, join_args, Platform};
use tokio::process::Command;

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

pub struct SandboxedOutput {
    pub status: std::process::ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
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

        let (http_proxy, socks_proxy) = initialize_proxies(&self.config.network).await?;
        let http_port = http_proxy.port();
        let socks_port = socks_proxy.port();
        let cwd = self.resolve_cwd()?;
        let command = self.render_command();

        match platform {
            Platform::MacOS => {
                #[cfg(target_os = "macos")]
                {
                    self.spawn_macos(command, cwd, http_proxy, socks_proxy, http_port, socks_port)
                        .await
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = (command, cwd, http_proxy, socks_proxy, http_port, socks_port);
                    Err(SandboxError::UnsupportedPlatform(
                        "macOS sandbox code not compiled on this platform".to_string(),
                    ))
                }
            }
            Platform::Linux => {
                #[cfg(target_os = "linux")]
                {
                    self.spawn_linux(command, cwd, http_proxy, socks_proxy, http_port, socks_port)
                        .await
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (command, cwd, http_proxy, socks_proxy, http_port, socks_port);
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
        let violations = child.take_pending_violations();
        if violations.is_empty() {
            Ok(SandboxedOutput {
                status: output.status,
                stdout: output.stdout,
                stderr: output.stderr,
            })
        } else {
            Err(SandboxError::ExecutionViolation(SandboxedExecutionError {
                status: Some(output.status),
                stdout: output.stdout,
                stderr: output.stderr,
                violations,
            }))
        }
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
    async fn spawn_macos(
        &mut self,
        command: String,
        cwd: PathBuf,
        http_proxy: crate::proxy::HttpProxy,
        socks_proxy: crate::proxy::Socks5Proxy,
        http_port: u16,
        socks_port: u16,
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
        let child_id = child.id();
        let (monitor, violations_rx) = if let Some(tag) = log_tag {
            let (monitor, rx) = LogMonitor::start(tag, Some(command.clone())).await?;
            (Some(monitor), rx)
        } else {
            let (_tx, rx) = tokio::sync::mpsc::channel(1);
            (None, rx)
        };
        let _ = child_id;

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
    async fn spawn_linux(
        &mut self,
        command: String,
        cwd: PathBuf,
        http_proxy: crate::proxy::HttpProxy,
        socks_proxy: crate::proxy::Socks5Proxy,
        http_port: u16,
        socks_port: u16,
    ) -> Result<SandboxedChild, SandboxError> {
        let http_socket_path = generate_socket_path("srt-http");
        let socks_socket_path = generate_socket_path("srt-socks");
        let http_bridge =
            SocatBridge::unix_to_tcp(http_socket_path.clone(), "127.0.0.1", http_port).await?;
        let socks_bridge =
            SocatBridge::unix_to_tcp(socks_socket_path.clone(), "127.0.0.1", socks_port).await?;

        let (wrapped, warnings) = generate_bwrap_command(
            &command,
            &self.config,
            &cwd,
            Some(http_socket_path.to_string_lossy().as_ref()),
            Some(socks_socket_path.to_string_lossy().as_ref()),
            http_port,
            socks_port,
            None,
        )?;
        for warning in warnings {
            tracing::warn!("{warning}");
        }

        let mut inner = Command::new("sh");
        inner.arg("-c").arg(wrapped);
        self.apply_outer_builder(&mut inner, &cwd);

        let mut child = inner.spawn()?;
        let (monitor, violations_rx) =
            LinuxLogMonitor::start(child.id(), Some(command.clone())).await?;

        Ok(SandboxedChild {
            stdin: child.stdin.take(),
            stdout: child.stdout.take(),
            stderr: child.stderr.take(),
            inner: Some(child),
            violations_rx: Some(violations_rx),
            http_proxy: Some(http_proxy),
            socks_proxy: Some(socks_proxy),
            bridges: vec![http_bridge, socks_bridge],
            monitor,
        })
    }
}
