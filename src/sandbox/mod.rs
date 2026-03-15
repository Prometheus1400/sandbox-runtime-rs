//! Platform-specific sandbox implementations.

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

use crate::error::SandboxError;
use crate::utils::Platform;

/// Check if sandboxing dependencies are available for the current platform.
pub fn check_dependencies(platform: Platform) -> Result<(), SandboxError> {
    match platform {
        Platform::MacOS => {
            // sandbox-exec is built into macOS
            Ok(())
        }
        Platform::Linux => {
            #[cfg(target_os = "linux")]
            {
                let mut errors = Vec::new();
                if !linux::check_bwrap() {
                    errors.push("bubblewrap (bwrap) not installed".to_string());
                }
                if !linux::check_socat() {
                    errors.push("socat not installed".to_string());
                }
                if errors.is_empty() {
                    Ok(())
                } else {
                    Err(SandboxError::MissingDependency(errors.join(", ")))
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err(SandboxError::UnsupportedPlatform(
                    "Linux sandbox code not compiled on this platform".to_string(),
                ))
            }
        }
    }
}
