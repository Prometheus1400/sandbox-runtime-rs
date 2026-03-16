# Refactor Declarative API Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform `sandbox-runtime` into a pure Rust library with a declarative `SandboxedCommand` API, per-process proxy lifecycle, and detailed error semantics.

**Architecture:** We will replace the CLI and global state with a builder pattern modeled after `std::process::Command`. Each spawned process will spin up its own ephemeral proxies and monitors, ensuring full isolation and clean drop semantics. Linux violations will be captured via seccomp user notifications to match macOS log streaming.

**Tech Stack:** Rust, tokio, bwrap, seccomp, macOS Seatbelt

---

## Chunk 1: Library Refactoring & Core API Skeleton

### Task 1: Delete CLI and Global State

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/lib.rs`
- Delete: `src/main.rs`
- Delete: `src/cli.rs`
- Delete: `src/manager/state.rs`
- Modify: `src/manager/mod.rs`

- [ ] **Step 1: Write the failing test**

Create `tests/declarative_api_test.rs`:
```rust
use sandbox_runtime::command::SandboxedCommand;

#[tokio::test]
async fn test_sandboxed_command_builder() {
    let mut cmd = SandboxedCommand::new("echo");
    cmd.arg("hello");
    // Should compile
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test declarative_api_test`
Expected: FAIL with "unresolved import `sandbox_runtime::command`"

- [ ] **Step 3: Write minimal implementation**

Remove `[[bin]]` section and `clap` dependency from `Cargo.toml`.
Delete `src/main.rs`, `src/cli.rs`, and `src/manager/state.rs`.
Remove references to `cli` and `manager::state` in `src/lib.rs`.
Remove `SandboxManager` struct entirely from `src/manager/mod.rs`.
Create `src/command.rs` with:
```rust
use std::ffi::OsStr;
pub struct SandboxedCommand {
    program: String,
    args: Vec<String>,
}
impl SandboxedCommand {
    pub fn new<S: AsRef<OsStr>>(program: S) -> Self {
        Self {
            program: program.as_ref().to_string_lossy().into_owned(),
            args: Vec::new(),
        }
    }
    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Self {
        self.args.push(arg.as_ref().to_string_lossy().into_owned());
        self
    }
}
```
Add `pub mod command;` and `pub mod child;` to `src/lib.rs`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test declarative_api_test`
Expected: PASS (and `cargo check` should pass without the CLI)

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml src/lib.rs src/main.rs src/cli.rs src/manager/state.rs src/manager/mod.rs src/command.rs tests/declarative_api_test.rs
git commit -m "refactor: remove CLI and implement SandboxedCommand stub"
```

### Task 2: Implement full SandboxedCommand Builder API

**Files:**
- Modify: `src/command.rs`

- [ ] **Step 1: Write the failing test**

Append to `tests/declarative_api_test.rs`:
```rust
use sandbox_runtime::config::SandboxRuntimeConfig;
use std::process::Stdio;

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test declarative_api_test`
Expected: FAIL with "no method named `env` found for struct `SandboxedCommand`"

- [ ] **Step 3: Write minimal implementation**

Update `src/command.rs`:
```rust
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use crate::config::{SandboxRuntimeConfig, FsReadRestrictionConfig, FsWriteRestrictionConfig};

pub struct SandboxedCommand {
    program: String,
    args: Vec<String>,
    envs: HashMap<String, String>,
    cwd: Option<PathBuf>,
    stdin: Option<Stdio>,
    stdout: Option<Stdio>,
    stderr: Option<Stdio>,
    config: SandboxRuntimeConfig,
}

impl SandboxedCommand {
    pub fn new<S: AsRef<OsStr>>(program: S) -> Self {
        Self {
            program: program.as_ref().to_string_lossy().into_owned(),
            args: Vec::new(),
            envs: HashMap::new(),
            cwd: None,
            stdin: None,
            stdout: None,
            stderr: None,
            config: SandboxRuntimeConfig::default(),
        }
    }
    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Self {
        self.args.push(arg.as_ref().to_string_lossy().into_owned());
        self
    }
    pub fn env<K: AsRef<OsStr>, V: AsRef<OsStr>>(&mut self, key: K, val: V) -> &mut Self {
        self.envs.insert(
            key.as_ref().to_string_lossy().into_owned(),
            val.as_ref().to_string_lossy().into_owned(),
        );
        self
    }
    pub fn envs<I, K, V>(&mut self, vars: I) -> &mut Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        for (k, v) in vars {
            self.env(k, v);
        }
        self
    }
    pub fn current_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Self {
        self.cwd = Some(dir.as_ref().to_path_buf());
        self
    }
    pub fn stdin<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.stdin = Some(cfg.into());
        self
    }
    pub fn stdout<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.stdout = Some(cfg.into());
        self
    }
    pub fn stderr<T: Into<Stdio>>(&mut self, cfg: T) -> &mut Self {
        self.stderr = Some(cfg.into());
        self
    }
    pub fn config(&mut self, config: SandboxRuntimeConfig) -> &mut Self {
        self.config = config;
        self
    }
    pub fn allow_read<P: Into<PathBuf>>(&mut self, path: P) -> &mut Self {
        let p = path.into();
        let path_str = p.to_string_lossy().into_owned();
        if !self.config.filesystem.read.allowed_paths.contains(&path_str) {
            self.config.filesystem.read.allowed_paths.push(path_str);
        }
        self
    }
    pub fn allow_write<P: Into<PathBuf>>(&mut self, path: P) -> &mut Self {
        let p = path.into();
        let path_str = p.to_string_lossy().into_owned();
        if !self.config.filesystem.write.allowed_paths.contains(&path_str) {
            self.config.filesystem.write.allowed_paths.push(path_str);
        }
        self
    }
    pub fn allow_domain<S: Into<String>>(&mut self, domain: S) -> &mut Self {
        self.config.network.allowed_domains.push(domain.into());
        self
    }
    pub fn deny_domain<S: Into<String>>(&mut self, domain: S) -> &mut Self {
        if self.config.network.denied_domains.is_none() {
            self.config.network.denied_domains = Some(Vec::new());
        }
        if let Some(ref mut domains) = self.config.network.denied_domains {
            domains.push(domain.into());
        }
        self
    }
}
```

Create `src/child.rs`:
```rust
use std::process::ExitStatus;
use tokio::process::{ChildStdin, ChildStdout, ChildStderr};
use tokio::sync::mpsc::Receiver;
use crate::error::SandboxError;
use crate::violation::SandboxViolationEvent;

pub struct SandboxedChild {
    pub stdin: Option<ChildStdin>,
    pub stdout: Option<ChildStdout>,
    pub stderr: Option<ChildStderr>,
}

impl SandboxedChild {
    pub async fn wait(&mut self) -> Result<ExitStatus, SandboxError> {
        unimplemented!()
    }
    
    pub fn violations(&mut self) -> Receiver<SandboxViolationEvent> {
        unimplemented!()
    }
}
```

Update `src/command.rs`:
```rust
use crate::child::SandboxedChild;

pub struct SandboxedOutput {
    pub status: std::process::ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl SandboxedCommand {
    pub async fn spawn(&mut self) -> Result<SandboxedChild, crate::error::SandboxError> {
        unimplemented!()
    }
    
    pub async fn output(&mut self) -> Result<SandboxedOutput, crate::error::SandboxError> {
        unimplemented!()
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test declarative_api_test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/command.rs tests/declarative_api_test.rs
git commit -m "feat: complete SandboxedCommand builder methods"
```

## Chunk 2: Proxy Lifecycle Integration

### Task 3: Refactor Proxy Initialization for Ephemeral Ports

**Files:**
- Modify: `src/manager/network.rs` (or `src/proxy/mod.rs` depending on where it fits best)

- [ ] **Step 1: Write the failing test**

```rust
// tests/declarative_api_test.rs
use sandbox_runtime::manager::network::initialize_proxies;

#[tokio::test]
async fn test_ephemeral_proxies() {
    let config = sandbox_runtime::config::NetworkConfig::default();
    // This should no longer take pre-configured ports and should return JoinHandles alongside ports
    let (http_proxy, socks_proxy) = initialize_proxies(&config).await.unwrap();
    assert!(http_proxy.port > 0);
    assert!(socks_proxy.port > 0);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test declarative_api_test`
Expected: FAIL (types and return signature of `initialize_proxies` won't match)

- [ ] **Step 3: Write minimal implementation**

Modify `src/manager/network.rs`. Change `initialize_proxies` signature:
```rust
use crate::proxy::{http::HttpProxy, socks5::Socks5Proxy};
use crate::config::NetworkConfig;
use crate::error::SandboxError;

pub struct ProxyInstances {
    pub http_port: u16,
    pub socks_port: u16,
    pub http_task: tokio::task::JoinHandle<()>,
    pub socks_task: tokio::task::JoinHandle<()>,
}

pub async fn initialize_proxies(config: &NetworkConfig) -> Result<ProxyInstances, SandboxError> {
    // Modify to bind to port 0 to get an ephemeral port
    // Ensure the HttpProxy and Socks5Proxy structs expose the bound port.
    // Return the joined handles and the allocated ports.
    unimplemented!()
}
```

Wait, `initialize_proxies` currently takes a `NetworkConfig` and returns `(HttpProxy, Socks5Proxy)`. And `HttpProxy` has a `port()` method. Let's just update `initialize_proxies` to bind to port `0`.

Modify `src/manager/network.rs`:
```rust
// In `initialize_proxies`:
// let http_proxy = HttpProxy::new(0, ...); // bind port 0
// let socks_proxy = Socks5Proxy::new(0, ...); // bind port 0
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test declarative_api_test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/manager/network.rs
git commit -m "refactor: use ephemeral ports for proxies"
```

### Task 4: Integrate Proxies into SandboxedCommand

**Files:**
- Modify: `src/command.rs`
- Modify: `src/child.rs`

- [ ] **Step 1: Write the failing test**

```rust
// tests/declarative_api_test.rs
#[tokio::test]
async fn test_spawn_starts_proxies() {
    let mut cmd = SandboxedCommand::new("echo");
    cmd.arg("hello");
    let child = cmd.spawn().await.unwrap();
    // Child should have proxy handles or ports attached
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test declarative_api_test`
Expected: FAIL (unimplemented in `spawn()`)

- [ ] **Step 3: Write minimal implementation**

Update `SandboxedChild` in `src/child.rs` to hold proxy handles:
```rust
pub struct SandboxedChild {
    pub stdin: Option<tokio::process::ChildStdin>,
    pub stdout: Option<tokio::process::ChildStdout>,
    pub stderr: Option<tokio::process::ChildStderr>,
    pub(crate) _http_proxy: Option<crate::proxy::http::HttpProxy>,
    pub(crate) _socks_proxy: Option<crate::proxy::socks5::Socks5Proxy>,
    pub(crate) _http_port: u16,
    pub(crate) _socks_port: u16,
}
```

Implement `SandboxedCommand::spawn` in `src/command.rs`:
```rust
use crate::manager::network::initialize_proxies;

impl SandboxedCommand {
    pub async fn spawn(&mut self) -> Result<crate::child::SandboxedChild, crate::error::SandboxError> {
        let (http_proxy, socks_proxy) = initialize_proxies(&self.config.network).await?;
        let http_port = http_proxy.port();
        let socks_port = socks_proxy.port();
        
        // Return a child with proxy fields set (dummy for now until execution is tied in)
        Ok(crate::child::SandboxedChild {
            stdin: None,
            stdout: None,
            stderr: None,
            _http_proxy: Some(http_proxy),
            _socks_proxy: Some(socks_proxy),
            _http_port: http_port,
            _socks_port: socks_port,
        })
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test declarative_api_test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/command.rs src/child.rs
git commit -m "feat: attach proxies to SandboxedChild lifecycle"
```

## Chunk 3: macOS Execution & Logging Integration

### Task 5: Inject UUID Tag and Spawns LogMonitor

**Files:**
- Modify: `src/command.rs`
- Modify: `src/child.rs`
- Modify: `src/sandbox/macos/monitor.rs`

- [ ] **Step 1: Write the failing test**

```rust
// tests/macos_test.rs
use sandbox_runtime::command::SandboxedCommand;

#[tokio::test]
#[cfg(target_os = "macos")]
async fn test_macos_log_monitor_uuid() {
    let mut cmd = SandboxedCommand::new("echo");
    let child = cmd.spawn().await.unwrap();
    // Verify child has log receiver
    let mut receiver = child.violations();
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --test macos_test`
Expected: FAIL (unimplemented `violations()` and execution logic)

- [ ] **Step 3: Write minimal implementation**

Run: `cargo add uuid --features v4`

Update `SandboxedChild` in `src/child.rs`:
```rust
use tokio::sync::mpsc::Receiver;
use crate::violation::SandboxViolationEvent;

pub struct SandboxedChild {
    // previous fields...
    pub(crate) rx: Option<Receiver<SandboxViolationEvent>>,
    #[cfg(target_os = "macos")]
    pub(crate) log_monitor: Option<crate::sandbox::macos::monitor::LogMonitor>,
    pub(crate) inner_child: tokio::process::Child,
}

impl SandboxedChild {
    pub fn violations(&mut self) -> Receiver<SandboxViolationEvent> {
        self.rx.take().expect("Violations stream already taken")
    }
}
```

Update `SandboxedCommand::spawn` in `src/command.rs` for macOS:
```rust
use std::process::Stdio;
use tokio::process::Command;
use uuid::Uuid;

#[cfg(target_os = "macos")]
impl SandboxedCommand {
    pub async fn spawn(&mut self) -> Result<crate::child::SandboxedChild, crate::error::SandboxError> {
        // Initialize proxies (from Chunk 2)
        // ...
        
        let tag = Uuid::new_v4().to_string();
        let (log_monitor, rx) = crate::sandbox::macos::monitor::LogMonitor::start(tag.clone(), Some(self.program.clone())).await?;
        
        // Use wrap_with_sandbox logic to get command string with the tag
        // Currently wrap_with_sandbox returns a WrappedCommand.
        // Adapt `src/sandbox/macos/wrapper.rs` to take the tag directly instead of generating it.
        // For brevity, we assume wrap_with_sandbox(config, program, args, tag) returns a string command.
        
        let wrapped_cmd_string = format!("echo 'Sandbox violation tag: {}' > /dev/null; exec sandbox-exec -p '(version 1)(allow default)' {} {:?}", tag, self.program, self.args);
        
        let mut inner_cmd = Command::new("sh");
        inner_cmd.arg("-c").arg(wrapped_cmd_string);
        
        // Pass stdio
        if let Some(cfg) = self.stdin.take() { inner_cmd.stdin(cfg); }
        if let Some(cfg) = self.stdout.take() { inner_cmd.stdout(cfg); }
        if let Some(cfg) = self.stderr.take() { inner_cmd.stderr(cfg); }
        
        let inner_child = inner_cmd.spawn()?;
        
        Ok(crate::child::SandboxedChild {
            stdin: inner_child.stdin.take(),
            stdout: inner_child.stdout.take(),
            stderr: inner_child.stderr.take(),
            _http_proxy: Some(http_proxy),
            _socks_proxy: Some(socks_proxy),
            _http_port: http_port,
            _socks_port: socks_port,
            rx: Some(rx),
            #[cfg(target_os = "macos")]
            log_monitor: Some(log_monitor),
            inner_child,
        })
    }
}
```

Refine `stdin` type in `SandboxedCommand` to remove `Option<Stdio>` and use standard builder pattern which moves `Stdio` or uses a custom enum. For simplicity, just use `std::process::Stdio` and move it in `spawn()`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --test macos_test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/command.rs src/child.rs src/sandbox/macos/monitor.rs
git commit -m "feat: macos execution and LogMonitor tie-in"
```

## Chunk 4: Linux Execution & Seccomp Notify

### Task 6: Implement seccomp-runner in C and build.rs

**Files:**
- Create: `src/sandbox/linux/runner.c`
- Modify: `build.rs`
- Modify: `src/sandbox/linux/seccomp.rs`

- [ ] **Step 1: Write the C runner**

Create `src/sandbox/linux/runner.c`. This C program will:
1. Receive a UNIX socket FD and a BPF file path from CLI args.
2. Read the BPF file and apply seccomp with `SECCOMP_FILTER_FLAG_NEW_LISTENER`.
3. Send the returned listener FD over the UNIX socket via `sendmsg` with `SCM_RIGHTS`.
4. `execvp` the remaining arguments (the target command).

- [ ] **Step 2: Compile in build.rs**

Modify `build.rs` to compile `runner.c` into a static binary using the `cc` crate.
```rust
// build.rs
fn main() {
    #[cfg(target_os = "linux")]
    {
        cc::Build::new()
            .file("src/sandbox/linux/runner.c")
            .compile("seccomp_runner");
    }
}
```
Wait, `cc` produces a static library (`.a`), not an executable!
To produce an executable, we can invoke `std::process::Command::new("cc")` directly in `build.rs`.

```rust
// build.rs
fn main() {
    #[cfg(target_os = "linux")]
    {
        let out_dir = std::env::var("OUT_DIR").unwrap();
        let status = std::process::Command::new("cc")
            .args(["-static", "-o", &format!("{}/seccomp-runner", out_dir), "src/sandbox/linux/runner.c"])
            .status()
            .unwrap();
        assert!(status.success(), "Failed to compile seccomp-runner");
    }
}
```

- [ ] **Step 3: Embed and Extract at Runtime**

Modify `src/sandbox/linux/seccomp.rs` to embed the binary:
```rust
#[cfg(target_os = "linux")]
const SECCOMP_RUNNER_BIN: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/seccomp-runner"));

pub fn extract_seccomp_runner() -> std::io::Result<std::path::PathBuf> {
    let path = std::env::temp_dir().join("srt-seccomp-runner");
    std::fs::write(&path, SECCOMP_RUNNER_BIN)?;
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;
    Ok(path)
}
```

- [ ] **Step 4: Commit**

```bash
git add src/sandbox/linux/runner.c build.rs src/sandbox/linux/seccomp.rs
git commit -m "feat: embed seccomp-runner for SECCOMP_RET_USER_NOTIF"
```

### Task 7: Wire up bwrap, UNIX Sockets, and AsyncFd

**Files:**
- Modify: `src/sandbox/linux/bwrap.rs`
- Modify: `src/sandbox/linux/monitor.rs`
- Modify: `src/command.rs`

- [ ] **Step 1: Write the bwrap execution logic**

In `src/command.rs` (Linux implementation of `spawn()`):
1. Create a UNIX socket pair (`socketpair`).
2. Call `extract_seccomp_runner()`.
3. Construct the `bwrap` command, passing the `seccomp-runner` as the inner command.
   `bwrap ... -- /tmp/srt-seccomp-runner <socket_fd> <target_cmd>`
4. Spawn `socat` bridges using `SocatBridge::unix_to_tcp` pointing to `http_port` and `socks_port` generated from Chunk 2. Pass these to `bwrap` via `--bind <host_path> <container_path>` or whatever mechanism `build_inner_command` currently uses.
5. Spawn `bwrap`.
6. Receive the seccomp listener FD from the parent end of the socket pair using `recvmsg` and `SCM_RIGHTS`.
7. Wrap the listener FD in `tokio::io::unix::AsyncFd`.

- [ ] **Step 2: Implement the Seccomp Monitor**

In `src/sandbox/linux/monitor.rs`, implement a task that loops over the `AsyncFd` using `libc::ioctl`:
```rust
// Use libc::ioctl with SECCOMP_IOCTL_NOTIF_RECV to read `seccomp_notif` structs
// For each notification:
// 1. Check `req.data.nr` (syscall number). If it represents a restricted call (e.g. `openat`),
//    we can optionally check the path via `SECCOMP_IOCTL_NOTIF_ADDFD` or `/proc/pid/mem`.
// 2. Emit `SandboxViolationEvent` to the receiver channel.
// 3. Send a response using `libc::ioctl` with `SECCOMP_IOCTL_NOTIF_SEND` containing a `seccomp_notif_resp` with `error = libc::EPERM` (which translates to `-EPERM` for the calling process).
```

- [ ] **Step 3: Update SandboxedChild**

Tie the Linux `rx` channel to `SandboxedChild` just like macOS.

- [ ] **Step 4: Commit**

```bash
git add src/sandbox/linux/bwrap.rs src/sandbox/linux/monitor.rs src/command.rs
git commit -m "feat: linux seccomp user notification integration"
```

## Chunk 5: Output Handling and Error Semantics

### Task 8: Implement `wait()` and `output()`

**Files:**
- Modify: `src/child.rs`
- Modify: `src/command.rs`
- Modify: `src/error.rs`

- [ ] **Step 1: Write the failing test**

```rust
// tests/declarative_api_test.rs
#[tokio::test]
async fn test_output_returns_violations() {
    let mut cmd = SandboxedCommand::new("cat");
    cmd.arg("/etc/shadow"); // assuming this is denied
    let result = cmd.output().await;
    match result {
        Err(SandboxError::ExecutionViolation(exec_err)) => {
            assert!(!exec_err.violations.is_empty());
        }
        _ => panic!("Expected ExecutionViolation"),
    }
}
```

- [ ] **Step 2: Implement ExecutionViolation**

Modify `src/error.rs` to include `ExecutionViolation`:
```rust
pub struct SandboxedExecutionError {
    pub status: Option<std::process::ExitStatus>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub violations: Vec<crate::violation::SandboxViolationEvent>,
}
```

- [ ] **Step 3: Implement `output()` and `wait()`**

In `src/child.rs`:
```rust
impl SandboxedChild {
    pub async fn wait(&mut self) -> Result<std::process::ExitStatus, SandboxError> {
        let status = self.inner_child.wait().await?;
        // Gather all violations from the receiver channel by awaiting until the stream is closed
        let mut violations = Vec::new();
        while let Some(v) = self.rx.as_mut().unwrap().recv().await {
            violations.push(v);
        }
        if !violations.is_empty() {
            return Err(SandboxError::ExecutionViolation(SandboxedExecutionError {
                status: Some(status),
                stdout: vec![], // For wait(), we don't capture stdout/stderr directly unless configured
                stderr: vec![],
                violations,
            }));
        }
        Ok(status)
    }
}
```

In `src/command.rs`:
```rust
impl SandboxedCommand {
    pub async fn output(&mut self) -> Result<SandboxedOutput, SandboxError> {
        self.stdin(std::process::Stdio::null());
        self.stdout(std::process::Stdio::piped());
        self.stderr(std::process::Stdio::piped());
        let mut child = self.spawn().await?;
        
        let output = child.inner_child.wait_with_output().await?;
        
        let mut violations = Vec::new();
        while let Some(v) = child.rx.as_mut().unwrap().recv().await {
            violations.push(v);
        }
        
        if !violations.is_empty() {
            return Err(SandboxError::ExecutionViolation(SandboxedExecutionError {
                status: Some(output.status),
                stdout: output.stdout,
                stderr: output.stderr,
                violations,
            }));
        }
        
        Ok(SandboxedOutput {
            status: output.status,
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}
```

- [ ] **Step 4: Commit**

```bash
git add src/error.rs src/child.rs src/command.rs tests/declarative_api_test.rs
git commit -m "feat: enforce violation error semantics in wait and output"
```

### Task 9: Implement Drop for SandboxedChild

**Files:**
- Modify: `src/child.rs`

- [ ] **Step 1: Write the Drop implementation**

```rust
impl Drop for SandboxedChild {
    fn drop(&mut self) {
        // Stop proxies
        if let Some(mut http_proxy) = self._http_proxy.take() {
            http_proxy.stop();
        }
        if let Some(mut socks_proxy) = self._socks_proxy.take() {
            socks_proxy.stop();
        }
        
        // Stop macOS log monitor (if applicable)
        #[cfg(target_os = "macos")]
        if let Some(mut monitor) = self.log_monitor.take() {
            // Because stop is async in the current code, we might need to change it to sync
            // or use a shutdown_tx channel. For now, assume we implement a sync `stop()` or drop handles it.
            // If the original LogMonitor doesn't implement Drop correctly, fix it there.
        }
        
        // On Linux, the seccomp monitor task and socat bridges should be tied to a CancellationToken
        // or have their Drop implementations clean them up.
        // We will add `pub(crate) _socat_bridges: Vec<crate::sandbox::linux::bridge::SocatBridge>` 
        // to `SandboxedChild`, and `SocatBridge` already implements Drop.
    }
}
```

- [ ] **Step 2: Fix Hanging Streams in wait() and output()**

Ensure that when the `inner_child` finishes executing in `wait()` and `output()`, we explicitly stop the monitors so the `rx` channel closes:

```rust
    pub async fn wait(&mut self) -> Result<std::process::ExitStatus, SandboxError> {
        let status = self.inner_child.wait().await?;
        
        // Explicitly stop the log monitor so the receiver stream closes
        #[cfg(target_os = "macos")]
        if let Some(mut monitor) = self.log_monitor.take() {
            monitor.stop().await;
        }
        
        // (Linux monitor termination logic should also be triggered here if not handled via child exit)
        
        // Gather all violations from the receiver channel by awaiting until the stream is closed
        let mut violations = Vec::new();
        while let Some(v) = self.rx.as_mut().unwrap().recv().await {
            violations.push(v);
        }
        
        // ... return logic ...
```

- [ ] **Step 3: Commit**

```bash
git add src/child.rs
git commit -m "fix: ensure cleanup of proxies and monitors on drop/exit"
```
