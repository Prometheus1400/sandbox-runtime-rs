//! Sandbox Runtime - OS-level sandboxing for enforcing filesystem and network restrictions.
//!
//! This library provides sandboxing capabilities for arbitrary processes without containerization:
//! - macOS: Uses Seatbelt/sandbox-exec
//! - Linux: Uses bubblewrap + seccomp

pub mod cli;
pub mod config;
pub mod error;
pub mod manager;
pub mod proxy;
pub mod sandbox;
pub mod utils;
pub mod violation;

pub use config::{
    FilesystemConfig, MitmProxyConfig, NetworkConfig, RipgrepConfig, SandboxRuntimeConfig,
    SeccompConfig,
};
pub use error::{ConfigError, Result, SandboxError};
pub use manager::{SandboxManager, WrappedCommand};
pub use violation::{SandboxViolationEvent, SandboxViolationStore};

#[cfg(target_os = "macos")]
pub use sandbox::macos::LogMonitor;

#[cfg(target_os = "linux")]
pub use sandbox::linux::LinuxLogMonitor;

/// Re-export commonly used items.
pub mod prelude {
    pub use crate::config::SandboxRuntimeConfig;
    pub use crate::error::{Result, SandboxError};
    pub use crate::manager::{SandboxManager, WrappedCommand};
    pub use crate::violation::{SandboxViolationEvent, SandboxViolationStore};

    #[cfg(target_os = "macos")]
    pub use crate::sandbox::macos::LogMonitor;

    #[cfg(target_os = "linux")]
    pub use crate::sandbox::linux::LinuxLogMonitor;
}
