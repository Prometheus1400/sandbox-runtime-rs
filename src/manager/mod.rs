//! Sandbox manager - main orchestration module.

pub mod filesystem;
pub mod network;
pub mod state;

use std::sync::Arc;
use std::path::Path;

use parking_lot::RwLock;

use crate::config::SandboxRuntimeConfig;
use crate::error::SandboxError;
use crate::utils::{current_platform, check_ripgrep, Platform};
use crate::violation::SandboxViolationStore;

use self::state::ManagerState;

pub use filesystem::{FsReadRestrictionConfig, FsWriteRestrictionConfig};

/// Result of wrapping a command with sandbox restrictions.
pub struct WrappedCommand {
    /// The wrapped command string ready for execution.
    pub command: String,
    /// Log tag for violation monitoring (macOS only).
    pub log_tag: Option<String>,
}

/// The sandbox manager - main entry point for sandbox operations.
pub struct SandboxManager {
    state: Arc<RwLock<ManagerState>>,
}

impl Default for SandboxManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SandboxManager {
    /// Create a new sandbox manager.
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(ManagerState::new())),
        }
    }

    /// Check if the current platform is supported.
    pub fn is_supported_platform() -> bool {
        current_platform().is_some()
    }

    /// Check if all required dependencies are available.
    pub fn check_dependencies(&self, config: Option<&SandboxRuntimeConfig>) -> Result<(), SandboxError> {
        let platform = current_platform()
            .ok_or_else(|| SandboxError::UnsupportedPlatform("Unsupported platform".to_string()))?;

        // Check platform-specific dependencies
        crate::sandbox::check_dependencies(platform)?;

        // Check ripgrep (optional on macOS, recommended on Linux)
        if platform == Platform::Linux {
            let rg_config = config.and_then(|c| c.ripgrep.as_ref());
            if !check_ripgrep(rg_config) {
                tracing::warn!("ripgrep not found - dangerous file detection will be limited");
            }
        }

        Ok(())
    }

    /// Initialize the sandbox manager with the given configuration.
    pub async fn initialize(&self, config: SandboxRuntimeConfig) -> Result<(), SandboxError> {
        // Validate configuration
        config.validate()?;

        // Check dependencies
        self.check_dependencies(Some(&config))?;

        let platform = current_platform()
            .ok_or_else(|| SandboxError::UnsupportedPlatform("Unsupported platform".to_string()))?;

        // Initialize proxies
        let (http_proxy, socks_proxy) =
            network::initialize_proxies(&config.network).await?;

        let http_port = http_proxy.port();
        let socks_port = socks_proxy.port();

        // Update state
        let mut state = self.state.write();
        state.http_proxy = Some(http_proxy);
        state.socks_proxy = Some(socks_proxy);
        state.http_proxy_port = Some(http_port);
        state.socks_proxy_port = Some(socks_port);

        // Initialize platform-specific infrastructure
        #[cfg(target_os = "linux")]
        {
            use crate::sandbox::linux::{generate_socket_path, SocatBridge};

            // Create Unix socket bridges for proxies
            let http_socket_path = generate_socket_path("srt-http");
            let socks_socket_path = generate_socket_path("srt-socks");

            let http_bridge =
                SocatBridge::unix_to_tcp(http_socket_path.clone(), "localhost", http_port).await?;
            let socks_bridge =
                SocatBridge::unix_to_tcp(socks_socket_path.clone(), "localhost", socks_port)
                    .await?;

            state.http_socket_path = Some(http_socket_path.display().to_string());
            state.socks_socket_path = Some(socks_socket_path.display().to_string());
            state.bridges.push(http_bridge);
            state.bridges.push(socks_bridge);
        }

        state.config = Some(config);
        state.initialized = true;
        state.network_ready = true;

        tracing::info!(
            "Sandbox manager initialized for {} (HTTP proxy: {}, SOCKS proxy: {})",
            platform.name(),
            http_port,
            socks_port
        );

        Ok(())
    }

    /// Check if the manager is initialized.
    pub fn is_initialized(&self) -> bool {
        self.state.read().initialized
    }

    /// Get the current configuration.
    pub fn get_config(&self) -> Option<SandboxRuntimeConfig> {
        self.state.read().config.clone()
    }

    /// Update the configuration.
    pub fn update_config(&self, config: SandboxRuntimeConfig) -> Result<(), SandboxError> {
        config.validate()?;
        self.state.write().config = Some(config);
        Ok(())
    }

    /// Get the HTTP proxy port.
    pub fn get_proxy_port(&self) -> Option<u16> {
        self.state.read().http_proxy_port
    }

    /// Get the SOCKS proxy port.
    pub fn get_socks_proxy_port(&self) -> Option<u16> {
        self.state.read().socks_proxy_port
    }

    /// Get the HTTP socket path (Linux only).
    #[cfg(target_os = "linux")]
    pub fn get_http_socket_path(&self) -> Option<String> {
        self.state.read().http_socket_path.clone()
    }

    /// Get the SOCKS socket path (Linux only).
    #[cfg(target_os = "linux")]
    pub fn get_socks_socket_path(&self) -> Option<String> {
        self.state.read().socks_socket_path.clone()
    }

    /// Check if network is ready.
    pub fn is_network_ready(&self) -> bool {
        self.state.read().network_ready
    }

    /// Wait for network initialization.
    pub async fn wait_for_network_initialization(&self) -> bool {
        // Already ready in this implementation since we initialize synchronously
        self.is_network_ready()
    }

    /// Get filesystem read restriction config.
    pub fn get_fs_read_config(&self) -> FsReadRestrictionConfig {
        let state = self.state.read();
        if let Some(ref config) = state.config {
            filesystem::process_fs_config(&config.filesystem).0
        } else {
            FsReadRestrictionConfig::default()
        }
    }

    /// Get filesystem write restriction config.
    pub fn get_fs_write_config(&self) -> FsWriteRestrictionConfig {
        let state = self.state.read();
        if let Some(ref config) = state.config {
            filesystem::process_fs_config(&config.filesystem).1
        } else {
            FsWriteRestrictionConfig::default()
        }
    }

    /// Get glob pattern warnings for Linux.
    pub fn get_linux_glob_pattern_warnings(&self) -> Vec<String> {
        #[cfg(target_os = "linux")]
        {
            let state = self.state.read();
            if let Some(ref config) = state.config {
                let mut warnings = Vec::new();
                for path in &config.filesystem.allow_write {
                    if crate::utils::contains_glob_chars(path) {
                        warnings.push(format!(
                            "Glob pattern '{}' is not supported on Linux",
                            path
                        ));
                    }
                }
                for path in &config.filesystem.deny_write {
                    if crate::utils::contains_glob_chars(path) {
                        warnings.push(format!(
                            "Glob pattern '{}' is not supported on Linux",
                            path
                        ));
                    }
                }
                return warnings;
            }
        }
        Vec::new()
    }

    /// Get the violation store.
    pub fn get_violation_store(&self) -> Arc<SandboxViolationStore> {
        self.state.read().violation_store.clone()
    }

    /// Start monitoring for sandbox violations.
    ///
    /// On macOS, starts a `log stream` process filtered by the Seatbelt trace tag.
    /// On Linux, starts `journalctl` filtered for seccomp audit messages.
    /// On other platforms, this is a no-op.
    pub async fn start_monitoring(
        &self,
        log_tag: Option<&str>,
        child_pid: Option<u32>,
        command: &str,
    ) -> Result<(), SandboxError> {
        // These params are used conditionally per platform
        let _ = (&log_tag, &child_pid);

        #[cfg(target_os = "macos")]
        let rx = {
            let tag = match log_tag {
                Some(t) => t,
                None => return Ok(()), // No tag on macOS means nothing to monitor
            };
            let (_, rx) = crate::sandbox::macos::LogMonitor::start(
                tag.to_string(),
                Some(command.to_string()),
            )
            .await?;
            tracing::debug!("Started violation monitoring with tag: {}", tag);
            rx
        };

        #[cfg(target_os = "linux")]
        let rx = {
            let (_, rx) = crate::sandbox::linux::LinuxLogMonitor::start(
                child_pid,
                Some(command.to_string()),
            )
            .await?;
            tracing::debug!("Started seccomp violation monitoring (pid: {:?})", child_pid);
            rx
        };

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = (log_tag, child_pid, command);
            return Ok(());
        }

        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            let store = self.get_violation_store();
            let handle = tokio::spawn(async move {
                let mut rx = rx;
                while let Some(event) = rx.recv().await {
                    store.add_violation(event);
                }
            });

            // Abort any previous monitor before storing the new one
            let mut state = self.state.write();
            if let Some(prev) = state.monitor_task.take() {
                prev.abort();
            }
            state.monitor_task = Some(handle);

            Ok(())
        }
    }

    /// Wrap a command with sandbox restrictions.
    ///
    /// Returns a [`WrappedCommand`] containing the sandboxed command string and,
    /// on macOS, the log tag used for violation monitoring. Does **not** start
    /// monitoring — use [`execute_command`] for the full lifecycle, or call
    /// [`start_monitoring`] manually after spawning the process.
    pub async fn wrap_with_sandbox(
        &self,
        command: &str,
        shell: Option<&str>,
        custom_config: Option<SandboxRuntimeConfig>,
        _cwd: &Path,
    ) -> Result<WrappedCommand, SandboxError> {
        // Extract needed values from state while holding the lock
        let (config, http_port, socks_port) = {
            let state = self.state.read();

            if !state.initialized {
                return Err(SandboxError::ExecutionFailed(
                    "Sandbox manager not initialized".to_string(),
                ));
            }

            let config = custom_config
                .or_else(|| state.config.clone())
                .ok_or_else(|| SandboxError::ExecutionFailed("No configuration available".to_string()))?;

            (config, state.http_proxy_port, state.socks_proxy_port)
        };

        let _platform = current_platform()
            .ok_or_else(|| SandboxError::UnsupportedPlatform("Unsupported platform".to_string()))?;

        // Call platform-specific wrapper
        #[cfg(target_os = "macos")]
        {
            let (wrapped, log_tag) = crate::sandbox::macos::wrap_command(
                command,
                &config,
                http_port,
                socks_port,
                shell,
                true, // enable log monitor
            )?;

            Ok(WrappedCommand {
                command: wrapped,
                log_tag,
            })
        }

        #[cfg(target_os = "linux")]
        {
            let (http_socket, socks_socket) = {
                let state = self.state.read();
                (state.http_socket_path.clone(), state.socks_socket_path.clone())
            };

            let (wrapped, warnings) = crate::sandbox::linux::generate_bwrap_command(
                command,
                &config,
                _cwd,
                http_socket.as_deref(),
                socks_socket.as_deref(),
                http_port.unwrap_or(3128),
                socks_port.unwrap_or(1080),
                shell,
            )?;

            for warning in warnings {
                tracing::warn!("{}", warning);
            }

            Ok(WrappedCommand {
                command: wrapped,
                log_tag: None,
            })
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            Err(SandboxError::UnsupportedPlatform(
                "Platform not supported".to_string(),
            ))
        }
    }

    /// Execute a command inside the sandbox with automatic violation monitoring.
    ///
    /// This is the unified, cross-platform entry point. It wraps the command,
    /// spawns it, starts violation monitoring, waits for completion, and returns
    /// the exit status. Violations are collected in the violation store accessible
    /// via [`get_violation_store`].
    pub async fn execute_command(
        &self,
        command: &str,
        shell: Option<&str>,
        custom_config: Option<SandboxRuntimeConfig>,
        cwd: &Path,
    ) -> Result<std::process::ExitStatus, SandboxError> {
        let wrapped = self.wrap_with_sandbox(command, shell, custom_config, cwd).await?;

        tracing::debug!("Executing sandboxed command: {}", wrapped.command);

        let mut child = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(&wrapped.command)
            .spawn()?;

        // Start violation monitoring — platform-appropriate arguments
        let monitor_result = self
            .start_monitoring(wrapped.log_tag.as_deref(), child.id(), command)
            .await;
        if let Err(e) = monitor_result {
            tracing::warn!("Failed to start violation monitoring: {}", e);
        }

        let status = child.wait().await?;
        Ok(status)
    }

    /// Annotate stderr with sandbox failure information.
    pub fn annotate_stderr_with_sandbox_failures(&self, command: &str, stderr: &str) -> String {
        let store = self.get_violation_store();
        let violations = store.get_violations_for_command(command);

        if violations.is_empty() {
            return stderr.to_string();
        }

        let mut annotated = stderr.to_string();
        annotated.push_str("\n\n--- Sandbox Violations ---\n");
        for violation in violations {
            annotated.push_str(&format!("  {}\n", violation.line));
        }

        annotated
    }

    /// Reset the sandbox manager, cleaning up all resources.
    pub async fn reset(&self) {
        // Clean up temp files on macOS
        #[cfg(target_os = "macos")]
        {
            crate::sandbox::macos::cleanup_temp_profiles();
        }

        let mut state = self.state.write();
        // We need to release the lock before calling async reset
        // So we'll just do the cleanup inline

        // Stop violation monitor
        if let Some(handle) = state.monitor_task.take() {
            handle.abort();
        }

        // Stop proxies
        if let Some(ref mut proxy) = state.http_proxy {
            proxy.stop();
        }
        if let Some(ref mut proxy) = state.socks_proxy {
            proxy.stop();
        }

        // Stop bridges (Linux)
        #[cfg(target_os = "linux")]
        {
            // Note: We can't call async stop here, so we rely on Drop
            state.bridges.clear();
            state.http_socket_path = None;
            state.socks_socket_path = None;
        }

        // Clear state
        state.http_proxy = None;
        state.socks_proxy = None;
        state.http_proxy_port = None;
        state.socks_proxy_port = None;
        state.config = None;
        state.initialized = false;
        state.network_ready = false;

        tracing::info!("Sandbox manager reset");
    }
}

impl Drop for SandboxManager {
    fn drop(&mut self) {
        // Cleanup is handled by reset() or individual component Drop implementations
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::violation::{SandboxViolationEvent, SandboxViolationStore};

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_wrapped_command_returns_log_tag_macos() {
        // We can't fully test wrap_with_sandbox without initializing proxies,
        // but we can verify the WrappedCommand struct supports log_tag
        let wrapped = WrappedCommand {
            command: "sandbox-exec -p '...' sh -c 'echo hello'".to_string(),
            log_tag: Some("CMD64_test_END_12345678".to_string()),
        };
        assert!(wrapped.log_tag.is_some());
        assert!(wrapped.log_tag.unwrap().contains("CMD64_"));
    }

    #[tokio::test]
    async fn test_monitor_task_cleanup_on_reset() {
        let manager = SandboxManager::new();

        // Manually set a monitor task
        {
            let handle = tokio::spawn(async {
                // Simulate a long-running monitor
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            });
            let mut state = manager.state.write();
            state.monitor_task = Some(handle);
        }

        // Verify monitor task is set
        assert!(manager.state.read().monitor_task.is_some());

        // Reset should abort and clear the monitor task
        manager.reset().await;

        assert!(manager.state.read().monitor_task.is_none());
    }

    #[tokio::test]
    async fn test_violation_store_integration() {
        let store = Arc::new(SandboxViolationStore::new());
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);

        // Simulate the drain task pattern used in start_monitoring
        let store_clone = store.clone();
        let handle = tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                store_clone.add_violation(event);
            }
        });

        // Send violations through the channel
        tx.send(SandboxViolationEvent::new("violation 1".to_string()))
            .await
            .unwrap();
        tx.send(SandboxViolationEvent::new("violation 2".to_string()))
            .await
            .unwrap();

        // Drop sender to close the channel
        drop(tx);

        // Wait for drain task to finish
        handle.await.unwrap();

        assert_eq!(store.get_count(), 2);
        let violations = store.get_violations(None);
        assert_eq!(violations[0].line, "violation 1");
        assert_eq!(violations[1].line, "violation 2");
    }
}
