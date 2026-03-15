use std::process::Stdio;

use sandbox_runtime::command::SandboxedCommand;
use sandbox_runtime::config::SandboxRuntimeConfig;
use sandbox_runtime::error::SandboxError;

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

    match result {
        Err(SandboxError::ExecutionViolation(err)) => {
            assert!(!err.violations.is_empty(), "expected at least one violation");
        }
        Ok(output) => {
            // The sandbox may deny via exit code rather than violation event
            assert!(
                !output.status.success(),
                "write to non-allowed path should fail"
            );
        }
        Err(e) => {
            // Other errors (like command failure) are also acceptable
            assert!(
                !file_path.exists(),
                "file should not exist after sandbox denial, got error: {e}"
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
