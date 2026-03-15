//! Platform detection utilities.

/// Supported platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Platform {
    MacOS,
    Linux,
}

impl Platform {
    /// Detect the current platform.
    pub fn current() -> Option<Self> {
        #[cfg(target_os = "macos")]
        {
            Some(Platform::MacOS)
        }
        #[cfg(target_os = "linux")]
        {
            Some(Platform::Linux)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            None
        }
    }
}

/// Get the current platform, if supported.
pub fn current_platform() -> Option<Platform> {
    Platform::current()
}

/// Get the CPU architecture.
#[cfg(target_os = "linux")]
pub fn get_arch() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "x64"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "arm64"
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_current() {
        let platform = Platform::current();
        #[cfg(target_os = "macos")]
        assert_eq!(platform, Some(Platform::MacOS));
        #[cfg(target_os = "linux")]
        assert_eq!(platform, Some(Platform::Linux));
    }
}
