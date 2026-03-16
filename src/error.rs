//! Error types for the sandbox runtime.

use thiserror::Error;

/// A normalized sandbox violation category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxViolationKind {
    /// A filesystem read operation was denied by sandbox policy.
    FilesystemRead,
    /// A filesystem write or mutation operation was denied by sandbox policy.
    FilesystemWrite,
    /// A network request was denied by policy.
    NetworkDomain,
    /// Unix socket usage was denied by policy.
    UnixSocket,
    /// A sandbox violation occurred, but the runtime could not classify it further.
    Unknown,
}

/// A sandbox violation event.
#[derive(Debug, Clone)]
pub struct SandboxViolationEvent {
    /// The normalized violation category.
    pub kind: SandboxViolationKind,
    /// Human-readable operation name if known.
    pub operation: Option<String>,
    /// Target resource if known (path, host:port, etc.).
    pub resource: Option<String>,
    /// The full violation line from the runtime signal.
    pub line: String,
    /// The original command that triggered the violation.
    pub command: Option<String>,
    /// The base64-encoded command identifier.
    pub encoded_command: Option<String>,
    /// When the violation occurred.
    pub timestamp: std::time::SystemTime,
}

impl SandboxViolationEvent {
    /// Create a new violation event.
    pub fn new(line: String) -> Self {
        Self {
            kind: SandboxViolationKind::Unknown,
            operation: None,
            resource: None,
            line,
            command: None,
            encoded_command: None,
            timestamp: std::time::SystemTime::now(),
        }
    }

    /// Create a new violation event with command info.
    pub fn with_command(line: String, command: Option<String>, encoded: Option<String>) -> Self {
        Self {
            kind: SandboxViolationKind::Unknown,
            operation: None,
            resource: None,
            line,
            command,
            encoded_command: encoded,
            timestamp: std::time::SystemTime::now(),
        }
    }

    /// Attach normalized violation metadata.
    pub fn with_details(
        mut self,
        kind: SandboxViolationKind,
        operation: impl Into<Option<String>>,
        resource: impl Into<Option<String>>,
    ) -> Self {
        self.kind = kind;
        self.operation = operation.into();
        self.resource = resource.into();
        self
    }
}

/// Main error type for the sandbox runtime.
#[derive(Error, Debug)]
pub enum SandboxError {
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("Platform not supported: {0}")]
    UnsupportedPlatform(String),

    #[error("Missing dependency: {0}")]
    MissingDependency(String),

    #[error("Sandbox execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Proxy error: {0}")]
    Proxy(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Command failed: {0}")]
    CommandFailed(String),

    #[error("Profile generation error: {0}")]
    ProfileGeneration(String),

    #[error("Seccomp error: {0}")]
    Seccomp(String),

    #[error("Sandbox execution violated policy")]
    ExecutionViolation(SandboxedExecutionError),
}

/// Configuration-specific errors.
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Invalid domain pattern '{pattern}': {reason}")]
    InvalidDomainPattern { pattern: String, reason: String },

    #[error("Invalid path pattern '{pattern}': {reason}")]
    InvalidPathPattern { pattern: String, reason: String },

    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),
}

#[derive(Debug)]
pub struct SandboxedExecutionError {
    pub status: Option<std::process::ExitStatus>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub violations: Vec<SandboxViolationEvent>,
}

impl std::fmt::Display for SandboxedExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(status) = self.status {
            write!(
                f,
                "process exited with status {status} after {} sandbox violation(s)",
                self.violations.len()
            )
        } else {
            write!(
                f,
                "process triggered {} sandbox violation(s)",
                self.violations.len()
            )
        }
    }
}

impl std::error::Error for SandboxedExecutionError {}

pub type Result<T> = std::result::Result<T, SandboxError>;
