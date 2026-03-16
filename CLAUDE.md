# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Upstream Reference

This project is a **Rust implementation** of [sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime), the original TypeScript implementation by Anthropic.

**Key points:**
- The architecture, configuration schema, and sandboxing approach mirror the upstream project
- When implementing new features or fixing bugs, consult the upstream repository for design intent
- Configuration JSON format (`~/.srt-settings.json`) is designed to be compatible with the upstream schema
- Mandatory deny paths, domain filtering logic, and platform-specific sandboxing follow upstream behavior

**When making changes:**
1. Check if the feature/fix exists in the upstream TypeScript implementation
2. Align behavior with upstream unless there's a Rust-specific reason to diverge
3. Document any intentional deviations from upstream in code comments

## Build & Test Commands

```bash
cargo build                   # Debug build
cargo build --release         # Release build
cargo test                    # Run all tests (unit + doc)
cargo test -- --ignored --test-threads=1  # Run sandbox integration tests (macOS)
cargo test config::           # Run specific module tests
cargo test -- --nocapture     # Run with output visible
cargo clippy                  # Lint
```

## Library Usage

This is a **library crate** with a declarative builder-pattern API:

```rust
use sandbox_runtime::{SandboxedCommand, SandboxError};

let output = SandboxedCommand::new("echo")
    .arg("hello")
    .allow_read("/usr")
    .allow_write("/tmp")
    .allow_domain("example.com")
    .output()
    .await?;
```

Key public types: `SandboxedCommand`, `SandboxedChild`, `SandboxedOutput`, `SandboxRuntimeConfig`, `SandboxError`, `SandboxViolationEvent`.

## Architecture

OS-level sandboxing library enforcing filesystem and network restrictions without containerization. Uses proxy-based network filtering (portable, no root required) with platform-specific sandboxing.

### Core Flow

1. `SandboxedCommand::spawn()` - Validates config, starts HTTP/SOCKS5 proxies, wraps command with platform sandbox
2. Returns `SandboxedChild` with stdin/stdout/stderr handles and violation stream
3. `SandboxedCommand::output()` - Convenience: spawn + wait + collect output

### Module Visibility

| Module | Visibility | Purpose |
|--------|-----------|---------|
| `command` | **pub** | `SandboxedCommand` builder API |
| `child` | **pub** | `SandboxedChild` process handle |
| `config` | **pub** | Configuration types and validation |
| `error` | **pub** | Error types and `SandboxViolationEvent` |
| `manager` | pub(crate) | Proxy initialization |
| `proxy` | pub(crate) | HTTP/SOCKS5 proxy with domain filtering |
| `sandbox` | pub(crate) | Platform-specific sandboxing |
| `utils` | pub(crate) | Path, shell, platform utilities |

### Platform Implementations

**macOS** (`src/sandbox/macos/`):
- Uses Seatbelt (`sandbox-exec`) with SBPL profiles
- `profile.rs`: generates `.sb` profile with `generate_profile()`
- Glob patterns → Seatbelt regex via `glob_to_seatbelt_regex()`

**Linux** (`src/sandbox/linux/`):
- Uses bubblewrap + seccomp
- `bwrap.rs`: generates bwrap command with `--unshare-net`, bind mounts
- `bridge.rs`: socat bridges for proxy access inside namespace

### Domain Filter Priority (`src/proxy/filter.rs`)

1. `deniedDomains` checked first (highest priority)
2. `mitmDomains` for MITM routing
3. `allowedDomains`: if empty allow all, otherwise only matching

Pattern matching: `*.example.com` matches `api.example.com` but NOT `example.com`

### Mandatory Deny Paths (`src/config/schema.rs`)

Always write-protected: `.gitconfig`, `.bashrc`, `.zshrc`, `.npmrc`, `.mcp.json`, `.git/hooks`, `.vscode`, `.idea`, `.claude/commands`

## Code Patterns

- Platform code: `#[cfg(target_os = "macos")]` / `#[cfg(target_os = "linux")]`
- Config JSON uses camelCase: `#[serde(rename_all = "camelCase")]`
- Async: `tokio`, Errors: `thiserror`, Logging: `tracing`

## Modifying Sandbox Behavior

**New config option:**
1. Add to struct in `src/config/schema.rs` with `#[serde(default)]`
2. Validate in `SandboxRuntimeConfig::validate()` if needed
3. Handle in `sandbox/macos/profile.rs` or `sandbox/linux/bwrap.rs`

**macOS sandbox:** Edit `src/sandbox/macos/profile.rs` (SBPL generation functions)

**Linux sandbox:** Edit `src/sandbox/linux/bwrap.rs` (command) or `filesystem.rs` (mounts)

## Debugging

```bash
# macOS: Watch sandbox violations
log stream --predicate 'subsystem == "com.apple.sandbox"' --debug
```
