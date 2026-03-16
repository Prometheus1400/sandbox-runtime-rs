//! Command wrapping for macOS sandbox-exec.

use crate::config::SandboxRuntimeConfig;
use crate::error::SandboxError;
use crate::sandbox::macos::profile::{generate_log_tag, generate_profile};
use crate::utils::quote;

/// Wrap a command with sandbox-exec.
pub fn wrap_command(
    command: &str,
    config: &SandboxRuntimeConfig,
    http_proxy_port: Option<u16>,
    socks_proxy_port: Option<u16>,
    shell: Option<&str>,
    enable_log_monitor: bool,
) -> Result<(String, Option<String>), SandboxError> {
    let shell = shell.unwrap_or("/bin/bash");

    // Generate log tag for violation monitoring
    let log_tag = if enable_log_monitor {
        Some(generate_log_tag(command))
    } else {
        None
    };

    // Generate the Seatbelt profile
    let profile = generate_profile(
        config,
        http_proxy_port,
        socks_proxy_port,
        log_tag.as_deref(),
    );

    // Write profile to a temporary file
    let profile_path = write_profile_to_temp(&profile)?;

    // Build the wrapped command
    let wrapped = format!(
        "sandbox-exec -f {} {} -c {}",
        quote(&profile_path),
        shell,
        quote(command)
    );

    Ok((wrapped, log_tag))
}

/// Write the profile to a temporary file.
fn write_profile_to_temp(profile: &str) -> Result<String, SandboxError> {
    use std::io::Write;

    let temp_dir = std::env::temp_dir();
    let filename = format!("srt-profile-{}.sb", std::process::id());
    let path = temp_dir.join(filename);

    let mut file = std::fs::File::create(&path)?;
    file.write_all(profile.as_bytes())?;

    Ok(path.display().to_string())
}

