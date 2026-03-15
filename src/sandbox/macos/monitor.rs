//! Violation monitoring via macOS log stream.

use std::process::Stdio;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::error::{SandboxError, SandboxViolationEvent};

/// Log monitor for sandbox violations.
#[allow(dead_code)]
pub struct LogMonitor {
    child: Option<Child>,
    task: Option<JoinHandle<()>>,
}

impl LogMonitor {
    /// Start monitoring for violations with the given log tag.
    pub async fn start(
        log_tag: String,
        command: Option<String>,
    ) -> Result<(Self, mpsc::Receiver<SandboxViolationEvent>), SandboxError> {
        let (tx, rx) = mpsc::channel(100);

        // Start log stream process
        let child = Command::new("log")
            .args([
                "stream",
                "--predicate",
                &format!(
                    "subsystem == 'com.apple.sandbox' AND eventMessage CONTAINS '{}'",
                    log_tag
                ),
                "--style",
                "compact",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        let mut child = child;
        let stdout = child.stdout.take();
        let task = stdout.map(|stdout| {
            let log_tag_clone = log_tag.clone();
            let command_clone = command.clone();
            tokio::spawn(async move {
                let reader = BufReader::new(stdout);
                let mut lines = reader.lines();

                while let Ok(Some(line)) = lines.next_line().await {
                    // Skip the initial "Filtering the log data" info line from log stream
                    if line.contains("Filtering the log data") {
                        continue;
                    }
                    if line.contains(&log_tag_clone) {
                        let event = SandboxViolationEvent::with_command(
                            line,
                            command_clone.clone(),
                            Some(log_tag_clone.clone()),
                        );

                        if tx.send(event).await.is_err() {
                            break;
                        }
                    }
                }
            })
        });

        Ok((
            Self {
                child: Some(child),
                task,
            },
            rx,
        ))
    }

    /// Stop the log monitor.
    pub async fn stop(&mut self) {
        if let Some(ref mut child) = self.child {
            let _ = child.kill().await;
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for LogMonitor {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.child {
            let _ = child.start_kill();
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Parse a violation from a log line.
#[cfg(test)]
fn parse_violation(line: &str, log_tag: &str) -> Option<SandboxViolationEvent> {
    if line.contains(log_tag) {
        Some(SandboxViolationEvent::with_command(
            line.to_string(),
            None,
            Some(log_tag.to_string()),
        ))
    } else {
        None
    }
}

/// Decode the original command from the log tag.
#[cfg(test)]
fn decode_command_from_tag(tag: &str) -> Option<String> {
    use base64::Engine;

    // Format: CMD64_<base64>_END_<suffix>
    if let Some(start) = tag.find("CMD64_") {
        let rest = &tag[start + 6..];
        if let Some(end) = rest.find("_END_") {
            let encoded = &rest[..end];
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                return String::from_utf8(decoded).ok();
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_command_from_tag() {
        use base64::Engine;
        let command = "echo hello";
        let encoded = base64::engine::general_purpose::STANDARD.encode(command);
        let tag = format!("CMD64_{}_END_12345678", encoded);

        let decoded = decode_command_from_tag(&tag);
        assert_eq!(decoded, Some("echo hello".to_string()));
    }

    #[test]
    fn test_parse_violation_with_tag() {
        let tag = "CMD64_dGVzdA==_END_12345678";
        let line = format!(
            "2026-03-14 sandbox: deny(1) file-write-data /tmp/foo {}",
            tag
        );
        let event = parse_violation(&line, tag);
        assert!(event.is_some());
        let event = event.unwrap();
        assert!(event.line.contains(tag));
        assert_eq!(event.encoded_command, Some(tag.to_string()));
    }

    #[test]
    fn test_parse_violation_without_tag() {
        let tag = "CMD64_dGVzdA==_END_12345678";
        let line = "2026-03-14 sandbox: deny(1) file-write-data /tmp/foo OTHER_TAG";
        let event = parse_violation(line, tag);
        assert!(event.is_none());
    }
}
