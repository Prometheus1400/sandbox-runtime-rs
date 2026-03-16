//! Sandbox Runtime - OS-level sandboxing for enforcing filesystem and network restrictions.
//!
//! This library provides sandboxing capabilities for arbitrary processes without containerization:
//! - macOS: Uses Seatbelt/sandbox-exec
//! - Linux: Uses bubblewrap + seccomp
//!
//! # Example
//!
//! ```no_run
//! use sandbox_runtime::{SandboxedCommand, SandboxError};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), SandboxError> {
//!     let output = SandboxedCommand::new("echo")
//!         .arg("hello")
//!         .allow_read("/usr")
//!         .allow_write("/tmp")
//!         .allow_domain("example.com")
//!         .output()
//!         .await?;
//!
//!     println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
//!     Ok(())
//! }
//! ```

pub mod child;
pub mod command;
pub mod config;
pub mod error;
pub(crate) mod manager;
pub(crate) mod proxy;
pub(crate) mod sandbox;
pub(crate) mod utils;
pub(crate) mod violation;

pub use child::SandboxedChild;
pub use command::{SandboxedCommand, SandboxedOutput};
pub use config::{
    FilesystemConfig, MitmProxyConfig, NetworkConfig, RipgrepConfig, SandboxRuntimeConfig,
    SeccompConfig,
};
pub use error::{ConfigError, Result, SandboxError, SandboxViolationEvent, SandboxViolationKind};

/// Re-export commonly used items.
pub mod prelude {
    pub use crate::child::SandboxedChild;
    pub use crate::command::{SandboxedCommand, SandboxedOutput};
    pub use crate::config::SandboxRuntimeConfig;
    pub use crate::error::{Result, SandboxError, SandboxViolationEvent, SandboxViolationKind};
}
