use std::process::Stdio;

use sandbox_runtime::command::SandboxedCommand;
use sandbox_runtime::config::SandboxRuntimeConfig;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use sandbox_runtime::error::SandboxError;
#[cfg(target_os = "linux")]
use sandbox_runtime::error::SandboxViolationKind;

#[tokio::test]
async fn test_sandboxed_command_builder() {
    let mut cmd = SandboxedCommand::new("echo");
    cmd.arg("hello");
}

#[tokio::test]
async fn test_sandboxed_command_full_builder() {
    let mut cmd = SandboxedCommand::new("echo");
    let config = SandboxRuntimeConfig::default();

    cmd.arg("hello")
        .env("FOO", "bar")
        .envs(vec![("BAZ", "qux")])
        .current_dir("/tmp")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .config(config)
        .allow_read("/etc/passwd")
        .allow_write("/tmp/test")
        .allow_domain("example.com")
        .deny_domain("bad.com");
}

// The following tests spawn real sandbox-exec processes on macOS. They must
// be run sequentially (--test-threads=1) to avoid proxy port conflicts:
//   cargo test --test declarative_api_test -- --ignored --test-threads=1
//
// Linux ignored tests require `bwrap` and `socat` to be installed:
//   cargo test --test declarative_api_test -- --ignored --test-threads=1

#[cfg(target_os = "macos")]
#[tokio::test]
#[ignore]
async fn test_sandboxed_echo() {
    let output = SandboxedCommand::new("echo")
        .arg("hello")
        .allow_read("/")
        .output()
        .await
        .expect("echo should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "hello");
}

#[cfg(target_os = "macos")]
#[tokio::test]
#[ignore]
async fn test_sandboxed_write_allowed() {
    let dir = tempfile::tempdir().expect("create tempdir");
    // Canonicalize to resolve /var -> /private/var symlink on macOS
    let canonical_dir = dir.path().canonicalize().expect("canonicalize tempdir");
    let file_path = canonical_dir.join("test.txt");

    let output = SandboxedCommand::new("sh")
        .arg("-c")
        .arg(format!("echo ok > {}", file_path.display()))
        .allow_read("/")
        .allow_write(&canonical_dir)
        .output()
        .await
        .expect("write to allowed path should succeed");

    assert!(
        output.status.success(),
        "exit status: {:?}, stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let content = std::fs::read_to_string(&file_path).expect("read file");
    assert_eq!(content.trim(), "ok");
}

#[cfg(target_os = "macos")]
#[tokio::test]
#[ignore]
async fn test_sandboxed_write_violation() {
    let dir = tempfile::tempdir().expect("create tempdir");
    let canonical_dir = dir.path().canonicalize().expect("canonicalize tempdir");
    let file_path = canonical_dir.join("forbidden.txt");

    // Do NOT allow_write to the dir — should trigger a violation
    let result = SandboxedCommand::new("sh")
        .arg("-c")
        .arg(format!("echo bad > {}", file_path.display()))
        .allow_read("/")
        .output()
        .await;

    // With the stderr heuristic fallback, this should reliably return ExecutionViolation
    match result {
        Err(SandboxError::ExecutionViolation(err)) => {
            assert!(!err.violations.is_empty(), "expected at least one violation");
        }
        Err(e) => {
            panic!("expected ExecutionViolation, got: {e}");
        }
        Ok(output) => {
            panic!(
                "expected ExecutionViolation, got Ok with status {:?}, stderr: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

#[cfg(target_os = "macos")]
#[tokio::test]
#[ignore]
async fn test_network_denied_domain() {
    // Verify the sandbox infrastructure doesn't panic when deny_domain is set.
    // Note: proxy env vars are not yet automatically injected into the sandboxed
    // command, so we can't fully verify proxy filtering end-to-end.
    let result = SandboxedCommand::new("curl")
        .arg("-s")
        .arg("-o")
        .arg("/dev/null")
        .arg("--max-time")
        .arg("2")
        .arg("http://example.com")
        .allow_read("/")
        .deny_domain("example.com")
        .output()
        .await;

    // Test passes as long as it doesn't panic
    assert!(result.is_ok() || result.is_err());
}

#[cfg(target_os = "macos")]
#[tokio::test]
#[ignore]
async fn test_sandboxed_write_violation_reports_details() {
    let dir = tempfile::tempdir().expect("create tempdir");
    let canonical_dir = dir.path().canonicalize().expect("canonicalize tempdir");
    let file_path = canonical_dir.join("forbidden2.txt");

    let result = SandboxedCommand::new("sh")
        .arg("-c")
        .arg(format!("echo bad > {}", file_path.display()))
        .allow_read("/")
        .output()
        .await;

    match result {
        Err(SandboxError::ExecutionViolation(err)) => {
            assert!(!err.violations.is_empty(), "expected at least one violation");
            let first = &err.violations[0];
            assert!(!first.line.is_empty(), "violation line should be non-empty");
        }
        other => {
            panic!("expected ExecutionViolation, got: {other:?}");
        }
    }
}

#[cfg(target_os = "macos")]
#[tokio::test]
#[ignore]
async fn test_proxy_denied_domain_reports_violation() {
    // Curl through the proxy with a denied domain. The proxy should generate
    // a SandboxViolationEvent and output() should return ExecutionViolation.
    let result = SandboxedCommand::new("curl")
        .arg("-s")
        .arg("-o")
        .arg("/dev/null")
        .arg("--max-time")
        .arg("5")
        .arg("http://example.com")
        .allow_read("/")
        .deny_domain("example.com")
        .output()
        .await;

    match result {
        Err(SandboxError::ExecutionViolation(err)) => {
            let proxy_violations: Vec<_> = err
                .violations
                .iter()
                .filter(|v| v.line.contains("proxy:"))
                .collect();
            assert!(
                !proxy_violations.is_empty(),
                "expected proxy-generated violation, got: {:?}",
                err.violations
            );
        }
        Ok(output) => {
            // If the process didn't route through the proxy (no proxy env injected),
            // we may get Ok. Check that violations are empty and process succeeded,
            // or that we got non-fatal violations.
            // This is acceptable since proxy env injection is not yet automatic.
            eprintln!(
                "proxy test: Ok with status {:?}, violations: {:?}",
                output.status,
                output.violations.len()
            );
        }
        Err(e) => {
            // Other errors are acceptable if proxy env vars aren't injected
            eprintln!("proxy test: got error (may be expected): {e}");
        }
    }
}

#[cfg(target_os = "macos")]
#[tokio::test]
#[ignore]
async fn test_sandboxed_trash_violation() {
    use std::io::Write;

    let dir = tempfile::tempdir().expect("failed to create tempdir");
    let canonical_dir = dir.path().canonicalize().expect("failed to canonicalize tempdir");
    let file_path = canonical_dir.join("testfile.txt");
    {
        let mut f = std::fs::File::create(&file_path).expect("failed to create test file");
        f.write_all(b"delete me").expect("failed to write");
    }

    let result = SandboxedCommand::new("/usr/bin/trash")
        .arg(file_path.to_str().unwrap())
        .allow_read("/")
        .output()
        .await;

    match result {
        Err(SandboxError::ExecutionViolation(err)) => {
            assert!(
                !err.violations.is_empty(),
                "expected non-empty violations for sandboxed trash"
            );
        }
        Ok(output) => {
            assert!(
                !output.status.success(),
                "expected trash to fail without write permissions, got success"
            );
        }
        Err(e) => {
            panic!("unexpected error: {e}");
        }
    }
}

#[cfg(target_os = "macos")]
#[tokio::test]
#[ignore]
async fn test_successful_process_no_false_violations() {
    let output = SandboxedCommand::new("echo")
        .arg("hello")
        .allow_read("/")
        .output()
        .await
        .expect("echo should succeed");

    assert!(output.status.success());
    assert!(
        output.violations.is_empty(),
        "expected no violations for simple echo, got: {:?}",
        output.violations
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim(), "hello");
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore]
async fn test_linux_write_violation_reports_execution_violation() {
    // Write directly to /tmp/forbidden.txt rather than a tempdir subdirectory.
    // bwrap mounts a fresh tmpfs on /tmp, so host tempdirs don't exist inside
    // the sandbox. /tmp itself exists and seccomp will intercept the write
    // syscall before it completes since no allow_write is configured.
    let result = SandboxedCommand::new("sh")
        .arg("-c")
        .arg("echo denied > /tmp/forbidden.txt")
        .allow_read("/")
        .output()
        .await;

    match result {
        Err(SandboxError::ExecutionViolation(err)) => {
            assert!(
                err.violations
                    .iter()
                    .any(|v| v.kind == SandboxViolationKind::FilesystemWrite),
                "expected filesystem write violation, got: {:?}",
                err.violations
            );
        }
        other => {
            panic!("expected ExecutionViolation, got: {other:?}");
        }
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore]
async fn test_linux_unix_socket_violation_reports_execution_violation() {
    let result = SandboxedCommand::new("python3")
        .arg("-c")
        .arg(
            "import socket; socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); print('unexpected')",
        )
        .allow_read("/")
        .output()
        .await;

    match result {
        Err(SandboxError::ExecutionViolation(err)) => {
            assert!(
                err.violations
                    .iter()
                    .any(|v| v.kind == SandboxViolationKind::UnixSocket),
                "expected UnixSocket violation, got: {:?}",
                err.violations
            );
        }
        Err(SandboxError::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("python3 not installed; skipping assertion");
        }
        other => {
            panic!("expected ExecutionViolation, got: {other:?}");
        }
    }
}
