//! Violation monitoring via Linux journalctl for seccomp audit messages.

use std::process::Stdio;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

use crate::error::SandboxError;
use crate::violation::SandboxViolationEvent;

/// Log monitor for seccomp violations on Linux.
#[allow(dead_code)]
pub struct LinuxLogMonitor {
    child: Option<Child>,
    target_pid: Option<u32>,
    tx: mpsc::Sender<SandboxViolationEvent>,
}

impl LinuxLogMonitor {
    /// Start monitoring for seccomp violations.
    ///
    /// Spawns `journalctl -k -f -o short --no-pager` and filters for `type=1326`
    /// (AUDIT_SECCOMP) messages. If `target_pid` is `Some`, also filters by PID.
    /// If `journalctl` is not found, logs a warning and returns Ok with a closed channel.
    pub async fn start(
        target_pid: Option<u32>,
        command: Option<String>,
    ) -> Result<(Self, mpsc::Receiver<SandboxViolationEvent>), SandboxError> {
        let (tx, rx) = mpsc::channel(100);

        // Check if journalctl exists
        let journalctl_available = Command::new("which")
            .arg("journalctl")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false);

        if !journalctl_available {
            tracing::warn!(
                "journalctl not found - seccomp violation monitoring unavailable"
            );
            // Return with a closed channel (drop tx)
            drop(tx);
            return Ok((
                Self {
                    child: None,
                    target_pid,
                    tx: mpsc::channel(1).0,
                },
                rx,
            ));
        }

        let child = Command::new("journalctl")
            .args(["-k", "-f", "-o", "short", "--no-pager"])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        let mut monitor = Self {
            child: Some(child),
            target_pid,
            tx: tx.clone(),
        };

        // Spawn a task to read the journal stream
        let child = monitor.child.take();
        if let Some(mut child) = child {
            let pid_filter = target_pid;
            let command_clone = command.clone();

            tokio::spawn(async move {
                if let Some(stdout) = child.stdout.take() {
                    let reader = BufReader::new(stdout);
                    let mut lines = reader.lines();

                    while let Ok(Some(line)) = lines.next_line().await {
                        if let Some(event) =
                            parse_seccomp_violation(&line, pid_filter, command_clone.clone())
                        {
                            if tx.send(event).await.is_err() {
                                break;
                            }
                        }
                    }
                }

                let _ = child.kill().await;
            });
        }

        Ok((monitor, rx))
    }

    /// Stop the log monitor.
    pub async fn stop(&mut self) {
        if let Some(ref mut child) = self.child {
            let _ = child.kill().await;
        }
    }
}

impl Drop for LinuxLogMonitor {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.child {
            let _ = child.start_kill();
        }
    }
}

/// Parse a seccomp violation from a kernel log line.
///
/// Looks for `type=1326` (AUDIT_SECCOMP) in the line. If `target_pid` is `Some`,
/// also checks that `pid=<N>` matches. Returns `None` if the line doesn't match.
pub fn parse_seccomp_violation(
    line: &str,
    target_pid: Option<u32>,
    command: Option<String>,
) -> Option<SandboxViolationEvent> {
    // Must contain the seccomp audit type
    if !line.contains("type=1326") {
        return None;
    }

    // If we have a target PID, filter by it
    if let Some(pid) = target_pid {
        let pid_pattern = format!("pid={}", pid);
        if !line.contains(&pid_pattern) {
            return None;
        }
    }

    // Extract syscall number if present
    let syscall_info = extract_syscall(line);
    let detail = if let Some(syscall) = syscall_info {
        format!("seccomp violation (syscall={}): {}", syscall, line)
    } else {
        format!("seccomp violation: {}", line)
    };

    Some(SandboxViolationEvent::with_command(
        detail,
        command,
        None,
    ))
}

/// Extract the syscall number from an audit line.
fn extract_syscall(line: &str) -> Option<&str> {
    // Pattern: syscall=<number>
    let start = line.find("syscall=")?;
    let rest = &line[start + 8..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    if end > 0 {
        Some(&rest[..end])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_seccomp_violation_valid_line() {
        let line = "audit: type=1326 audit(1234567890.123:456): auid=1000 uid=1000 gid=1000 ses=1 subj=unconfined pid=42 comm=\"python3\" exe=\"/usr/bin/python3\" sig=0 arch=c000003e syscall=41 compat=0 ip=0x7f12345 code=0x80000000";
        let event = parse_seccomp_violation(line, None, Some("test cmd".to_string()));
        assert!(event.is_some());
        let event = event.unwrap();
        assert!(event.line.contains("seccomp violation"));
        assert!(event.line.contains("syscall=41"));
        assert_eq!(event.command, Some("test cmd".to_string()));
    }

    #[test]
    fn test_parse_seccomp_violation_wrong_pid() {
        let line = "audit: type=1326 audit(1234567890.123:456): pid=99 comm=\"python3\" syscall=41";
        let event = parse_seccomp_violation(line, Some(42), None);
        assert!(event.is_none());
    }

    #[test]
    fn test_parse_seccomp_violation_non_seccomp_line() {
        let line = "Mar 14 10:00:00 host kernel: some random kernel message";
        let event = parse_seccomp_violation(line, None, None);
        assert!(event.is_none());
    }

    #[test]
    fn test_parse_seccomp_violation_no_pid_filter() {
        let line = "audit: type=1326 audit(1234567890.123:456): pid=999 comm=\"curl\" syscall=44";
        let event = parse_seccomp_violation(line, None, None);
        assert!(event.is_some());
    }

    #[test]
    fn test_parse_seccomp_violation_matching_pid() {
        let line = "audit: type=1326 audit(1234567890.123:456): pid=42 comm=\"curl\" syscall=44";
        let event = parse_seccomp_violation(line, Some(42), None);
        assert!(event.is_some());
    }

    #[test]
    fn test_parse_seccomp_violation_extracts_syscall() {
        let line = "audit: type=1326 audit(1234567890.123:456): pid=42 syscall=231 code=0x80000000";
        let event = parse_seccomp_violation(line, None, None);
        assert!(event.is_some());
        let event = event.unwrap();
        assert!(event.line.contains("syscall=231"));
    }

    #[test]
    fn test_extract_syscall() {
        assert_eq!(extract_syscall("syscall=41 compat=0"), Some("41"));
        assert_eq!(extract_syscall("syscall=231 code=0x80000000"), Some("231"));
        assert_eq!(extract_syscall("no syscall here"), None);
    }
}
