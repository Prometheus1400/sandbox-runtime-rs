//! Utility modules.

pub mod path;
pub mod platform;
#[cfg(target_os = "linux")]
pub mod ripgrep;
pub mod shell;

pub use path::{contains_glob_chars, normalize_path_for_sandbox};
pub use platform::{current_platform, Platform};
pub use shell::{join_args, quote};
