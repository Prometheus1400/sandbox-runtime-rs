//! Utility modules.

pub mod path;
pub mod platform;
#[cfg(target_os = "linux")]
pub mod ripgrep;
pub mod shell;

pub use path::{contains_glob_chars, normalize_path_for_sandbox};
#[cfg(target_os = "linux")]
pub use path::{is_symlink_outside_boundary, normalize_path_components};
pub use platform::{current_platform, Platform};
#[cfg(target_os = "linux")]
pub use platform::get_arch;
#[cfg(target_os = "linux")]
pub use ripgrep::find_dangerous_files;
pub use shell::{join_args, quote};
