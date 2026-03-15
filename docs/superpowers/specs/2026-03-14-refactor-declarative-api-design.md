# Refactor: Declarative API Design

## Overview
Transform `sandbox-runtime` into a pure Rust library with a declarative API centered around a `SandboxedCommand` builder pattern. This redesign focuses on making the library ergonomic for consumption by other Rust projects, encapsulating complex proxy and sandbox lifecycles into per-process components, and returning actionable error data when sandbox policies are violated.

## Goals
1. **Library-Only Project:** Remove all CLI code (`src/main.rs`, `src/cli.rs`) to focus solely on the library interface.
2. **Declarative API:** Create a `SandboxedCommand` builder modeled after `std::process::Command`.
3. **Structured Error Semantics:** Distinguish between normal process failures (e.g., exit code 1) and sandbox violations. Violations should result in an explicit `Err(SandboxError::Violation(...))` when waiting for process completion.
4. **Per-Process Infrastructure:** Proxies (HTTP/SOCKS) and log/event monitors will run ephemerally per `SandboxedChild` rather than being held in global state.
5. **Platform Support:** Focus exclusively on macOS and Linux. Drop Windows support entirely.
6. **Testing:** Testable primarily on macOS with Linux testing via containers (e.g., podman).

## Architecture & Components

### The `SandboxedCommand` API
The new entry point for the library will be `SandboxedCommand`, replacing `SandboxManager` and `ManagerState`.

```rust
use std::ffi::OsStr;
use std::path::PathBuf;

pub struct SandboxedCommand {
    program: String,
    args: Vec<String>,
    // envs, cwd, etc.
    config: SandboxRuntimeConfig,
}

impl SandboxedCommand {
    pub fn new<S: AsRef<OsStr>>(program: S) -> Self { ... }
    pub fn arg<S: AsRef<OsStr>>(&mut self, arg: S) -> &mut Self { ... }
    pub fn config(&mut self, config: SandboxRuntimeConfig) -> &mut Self { ... }
    
    /// Executes the command and waits for completion, gathering output.
    /// If sandbox violations occur, returns `Err(SandboxError::Violation(...))`.
    pub async fn output(&mut self) -> Result<SandboxedOutput, SandboxError> { ... }
    
    /// Spawns the process and returns a handle to stream outputs/violations.
    pub async fn spawn(&mut self) -> Result<SandboxedChild, SandboxError> { ... }
}

pub struct SandboxedOutput {
    pub status: std::process::ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}
```

### Process Lifecycle and `SandboxedChild`
`SandboxedChild` handles the execution state of a spawned process. It provides streaming access to standard IO and violations, and it manages the lifetime of the ephemeral proxies.

```rust
pub struct SandboxedChild {
    pub stdout: Option<ChildStdout>,
    pub stderr: Option<ChildStderr>,
    // internal handles for proxies, monitors, and the underlying process
}

impl SandboxedChild {
    /// Wait for the process to exit. Returns an Err if any violations occurred during execution.
    pub async fn wait(&mut self) -> Result<std::process::ExitStatus, SandboxError> { ... }
    
    // Future expansion: potentially a method to get a channel/stream of violations as they happen
}
```

### Proxy Lifecycle
- Each `SandboxedCommand::spawn()` invocation will spin up its own HTTP and SOCKS5 proxies on ephemeral ports (port 0).
- Proxies run as background tasks attached to the `SandboxedChild`.
- Dropping `SandboxedChild` aborts the proxy tasks and cleans up sockets.
- This eliminates shared mutable state across process executions.

### Platform Implementations

#### macOS
- `LogMonitor` is instantiated dynamically in `SandboxedCommand::spawn()`.
- The Seatbelt profile will use a unique tag (e.g., a UUID) for the specific process so that concurrent `SandboxedChild` instances don't mix up violation logs.

#### Linux
- `bwrap` remains the core isolation mechanism.
- **Seccomp Notifications:** To detect violations cleanly at runtime, the seccomp filter will use `SECCOMP_RET_USER_NOTIF`.
- A small supervisor task in the parent process (inside `SandboxedChild`) will read from the seccomp listener file descriptor. When a forbidden syscall triggers the filter, the supervisor will log a `SandboxViolationEvent` and return `-EPERM` to the kernel, matching the real-time observability we have on macOS.

## Implementation Steps
1. **Cleanup:** Delete `src/main.rs`, `src/cli.rs`, and remove CLI dependencies/binaries from `Cargo.toml`.
2. **Scaffold API:** Create `src/command.rs` and `src/child.rs` containing the new `SandboxedCommand` and `SandboxedChild` structs.
3. **Refactor Proxies:** Move proxy initialization out of `SandboxManager` and into `SandboxedCommand::spawn()`, utilizing ephemeral ports.
4. **macOS Integration:** Update `src/sandbox/macos/` to generate unique log tags and connect `LogMonitor` to `SandboxedChild`.
5. **Linux Integration:** Update `src/sandbox/linux/` to spawn `socat` bridges per process and implement the `SECCOMP_RET_USER_NOTIF` listener logic.
6. **Tests:** Write comprehensive unit and integration tests against the new declarative API.