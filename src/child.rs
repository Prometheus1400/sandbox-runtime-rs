use std::process::{ExitStatus, Output};

use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout};
use tokio::sync::mpsc::Receiver;

use crate::error::{SandboxError, SandboxViolationEvent, SandboxedExecutionError};
use crate::proxy::{HttpProxy, Socks5Proxy};

#[cfg(target_os = "linux")]
use crate::sandbox::linux::SocatBridge;

#[cfg(target_os = "linux")]
use crate::sandbox::linux::LinuxLogMonitor;

#[cfg(target_os = "macos")]
use crate::sandbox::macos::LogMonitor;

pub struct SandboxedChild {
    pub stdin: Option<ChildStdin>,
    pub stdout: Option<ChildStdout>,
    pub stderr: Option<ChildStderr>,
    pub(crate) inner: Option<Child>,
    pub(crate) violations_rx: Option<Receiver<SandboxViolationEvent>>,
    pub(crate) http_proxy: Option<HttpProxy>,
    pub(crate) socks_proxy: Option<Socks5Proxy>,
    #[cfg(target_os = "linux")]
    pub(crate) bridges: Vec<SocatBridge>,
    #[cfg(target_os = "linux")]
    pub(crate) monitor: Option<LinuxLogMonitor>,
    #[cfg(target_os = "macos")]
    pub(crate) monitor: Option<LogMonitor>,
}

impl SandboxedChild {
    pub async fn wait(&mut self) -> Result<ExitStatus, SandboxError> {
        let status = self
            .inner
            .as_mut()
            .ok_or_else(|| SandboxError::ExecutionFailed("process already waited".to_string()))?
            .wait()
            .await?;

        self.shutdown_runtime().await;
        let violations = self.drain_violations().await;
        if violations.is_empty() {
            Ok(status)
        } else {
            Err(SandboxError::ExecutionViolation(SandboxedExecutionError {
                status: Some(status),
                stdout: Vec::new(),
                stderr: Vec::new(),
                violations,
            }))
        }
    }

    pub fn violations(&mut self) -> Receiver<SandboxViolationEvent> {
        self.violations_rx
            .take()
            .expect("violation stream already taken")
    }

    pub(crate) async fn wait_with_output(&mut self) -> Result<Output, SandboxError> {
        let mut inner = self
            .inner
            .take()
            .ok_or_else(|| SandboxError::ExecutionFailed("process already waited".to_string()))?;
        // Put stdout/stderr back so wait_with_output can capture them
        inner.stdin = self.stdin.take();
        inner.stdout = self.stdout.take();
        inner.stderr = self.stderr.take();
        let output = inner.wait_with_output().await?;
        self.shutdown_runtime().await;
        Ok(output)
    }

    pub(crate) async fn drain_violations(&mut self) -> Vec<SandboxViolationEvent> {
        // Drop proxy structs to signal their accept loops to stop and release senders.
        // The monitor is already stopped in shutdown_runtime, so its sender is dropped.
        // Per-connection handler tasks may briefly hold sender clones until connections close.
        self.http_proxy.take();
        self.socks_proxy.take();

        let mut violations = Vec::new();
        if let Some(mut rx) = self.violations_rx.take() {
            // Drain until channel closed or timeout (safety net for lingering handler tasks)
            loop {
                match tokio::time::timeout(
                    tokio::time::Duration::from_millis(100),
                    rx.recv(),
                )
                .await
                {
                    Ok(Some(event)) => violations.push(event),
                    Ok(None) => break, // channel closed, all senders dropped
                    Err(_) => break,   // timeout, no more events coming
                }
            }
        }
        violations
    }

    async fn shutdown_runtime(&mut self) {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        if let Some(monitor) = self.monitor.as_mut() {
            monitor.stop().await;
        }

        #[cfg(target_os = "linux")]
        for bridge in &mut self.bridges {
            bridge.stop().await;
        }

        // Don't stop proxies here — drain_violations will drop them to close the channel.
        // If drain_violations is not called (e.g. wait() path), we still stop them.
    }
}

impl Drop for SandboxedChild {
    fn drop(&mut self) {
        if let Some(child) = self.inner.as_mut() {
            let _ = child.start_kill();
        }
        if let Some(proxy) = self.http_proxy.as_mut() {
            proxy.stop();
        }
        if let Some(proxy) = self.socks_proxy.as_mut() {
            proxy.stop();
        }
    }
}
