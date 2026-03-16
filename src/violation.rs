//! Helpers for normalizing sandbox violation signals across platforms.

use crate::error::{SandboxViolationEvent, SandboxViolationKind};

#[cfg(target_os = "linux")]
pub(crate) const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
#[cfg(target_os = "linux")]
pub(crate) const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;

pub(crate) fn proxy_network_denied_event(
    operation: impl Into<String>,
    resource: impl Into<String>,
) -> SandboxViolationEvent {
    let operation = operation.into();
    let resource = resource.into();
    SandboxViolationEvent::new(format!("proxy: denied {} to {}", operation, resource))
        .with_details(
            SandboxViolationKind::NetworkDomain,
            Some(operation),
            Some(resource),
        )
}

#[cfg(target_os = "macos")]
pub(crate) fn macos_log_event(
    line: String,
    command: Option<String>,
    encoded_command: Option<String>,
) -> SandboxViolationEvent {
    let mut event = SandboxViolationEvent::with_command(line.clone(), command, encoded_command);

    if let Some((kind, operation, resource)) = parse_macos_violation(&line) {
        event = event.with_details(kind, Some(operation), resource);
    }

    event
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_filesystem_write_event(
    pid: u32,
    operation: impl Into<String>,
    path: impl Into<String>,
    command: Option<String>,
) -> SandboxViolationEvent {
    let operation = operation.into();
    let path = path.into();
    let line = format!(
        "filesystem violation: pid={} operation={} path={}",
        pid, operation, path
    );

    SandboxViolationEvent::with_command(line, command, None).with_details(
        SandboxViolationKind::FilesystemWrite,
        Some(operation),
        Some(path),
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_seccomp_event(
    pid: u32,
    nr: i32,
    arch: u32,
    args: [u64; 6],
    ip: u64,
    command: Option<String>,
) -> SandboxViolationEvent {
    let syscall = syscall_name(nr, arch).to_string();
    let socket_desc = socket_description(syscall.as_str(), args);
    let line = if let Some(desc) = &socket_desc {
        format!(
            "seccomp violation: pid={} syscall={} ({}) target={} ip=0x{:x}",
            pid, nr, syscall, desc, ip
        )
    } else {
        format!(
            "seccomp violation: pid={} syscall={} ({}) ip=0x{:x}",
            pid, nr, syscall, ip
        )
    };

    let (kind, resource) = classify_linux_seccomp(syscall.as_str(), args, socket_desc);

    SandboxViolationEvent::with_command(line, command, None).with_details(
        kind,
        Some(syscall),
        resource,
    )
}

#[cfg(target_os = "macos")]
fn parse_macos_violation(
    line: &str,
) -> Option<(SandboxViolationKind, String, Option<String>)> {
    let deny_index = line.find("deny(")?;
    let after_deny = line[deny_index..].find(')').map(|i| deny_index + i + 1)?;
    let rest = line.get(after_deny..)?.trim();
    if rest.is_empty() {
        return None;
    }

    let mut parts = rest.split_whitespace();
    let operation = parts.next()?.to_string();
    let resource = parts.next().map(|value| value.to_string());
    let kind = if operation.starts_with("network-") {
        SandboxViolationKind::NetworkDomain
    } else if operation.contains("write") || operation.contains("create") || operation.contains("unlink") {
        SandboxViolationKind::FilesystemWrite
    } else if operation.contains("read") {
        SandboxViolationKind::FilesystemRead
    } else {
        SandboxViolationKind::Unknown
    };

    Some((kind, operation, resource))
}

#[cfg(target_os = "linux")]
fn classify_linux_seccomp(
    syscall: &str,
    args: [u64; 6],
    socket_desc: Option<String>,
) -> (SandboxViolationKind, Option<String>) {
    if syscall == "socket" && args[0] == 1 {
        return (SandboxViolationKind::UnixSocket, socket_desc);
    }
    (SandboxViolationKind::Unknown, socket_desc)
}

#[cfg(target_os = "linux")]
fn socket_description(syscall: &str, args: [u64; 6]) -> Option<String> {
    if syscall != "socket" {
        return None;
    }

    let domain = socket_domain_name(args[0])?;
    let socket_type = socket_type_name(args[1] & 0xf)?;
    Some(format!("{}, {}", domain, socket_type))
}

#[cfg(target_os = "linux")]
fn socket_domain_name(domain: u64) -> Option<&'static str> {
    match domain {
        1 => Some("AF_UNIX"),
        2 => Some("AF_INET"),
        10 => Some("AF_INET6"),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn socket_type_name(socket_type: u64) -> Option<&'static str> {
    match socket_type {
        1 => Some("SOCK_STREAM"),
        2 => Some("SOCK_DGRAM"),
        5 => Some("SOCK_SEQPACKET"),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn syscall_name(nr: i32, arch: u32) -> &'static str {
    match arch {
        AUDIT_ARCH_X86_64 => match nr {
            41 => "socket",
            42 => "connect",
            49 => "bind",
            _ => "unknown",
        },
        AUDIT_ARCH_AARCH64 => match nr {
            198 => "socket",
            203 => "connect",
            200 => "bind",
            _ => "unknown",
        },
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_network_denied_event() {
        let event = proxy_network_denied_event("connect", "example.com:443");
        assert_eq!(event.kind, SandboxViolationKind::NetworkDomain);
        assert_eq!(event.operation.as_deref(), Some("connect"));
        assert_eq!(event.resource.as_deref(), Some("example.com:443"));
    }

    #[test]
    fn test_parse_macos_write_violation() {
        let event = macos_log_event(
            "2026-03-14 sandbox: deny(1) file-write-data /tmp/foo TAG".to_string(),
            None,
            Some("TAG".to_string()),
        );
        assert_eq!(event.kind, SandboxViolationKind::FilesystemWrite);
        assert_eq!(event.operation.as_deref(), Some("file-write-data"));
        assert_eq!(event.resource.as_deref(), Some("/tmp/foo"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_linux_seccomp_event_classifies_unix_socket() {
        let event = linux_seccomp_event(
            42,
            41,
            AUDIT_ARCH_X86_64,
            [1, 1, 0, 0, 0, 0],
            0x1234,
            None,
        );
        assert_eq!(event.kind, SandboxViolationKind::UnixSocket);
        assert_eq!(event.operation.as_deref(), Some("socket"));
        assert_eq!(event.resource.as_deref(), Some("AF_UNIX, SOCK_STREAM"));
        assert!(event.line.contains("target=AF_UNIX, SOCK_STREAM"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_linux_filesystem_write_event_classifies_write() {
        let event = linux_filesystem_write_event(7, "openat", "/tmp/out.txt", None);
        assert_eq!(event.kind, SandboxViolationKind::FilesystemWrite);
        assert_eq!(event.operation.as_deref(), Some("openat"));
        assert_eq!(event.resource.as_deref(), Some("/tmp/out.txt"));
    }
}
