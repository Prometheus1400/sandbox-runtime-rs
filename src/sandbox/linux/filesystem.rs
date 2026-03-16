//! Filesystem bind mount generation for bubblewrap.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::config::{FilesystemConfig, RipgrepConfig, DANGEROUS_DIRECTORIES, DANGEROUS_FILES};
use crate::error::SandboxError;
use crate::utils::{
    contains_glob_chars, find_dangerous_files, is_symlink_outside_boundary,
    normalize_path_for_sandbox, remove_trailing_glob_suffix,
};

/// Bind mount specification.
#[derive(Debug, Clone)]
pub struct BindMount {
    /// Source path on host.
    pub source: PathBuf,
    /// Target path in sandbox (usually same as source).
    pub target: PathBuf,
    /// Whether the mount is read-only.
    pub readonly: bool,
    /// Whether to create the path with dev-null if it doesn't exist.
    pub dev_null: bool,
}

#[derive(Debug, Clone)]
pub struct LinuxWritePolicy {
    allowed: Vec<PathBuf>,
    denied: Vec<PathBuf>,
}

impl LinuxWritePolicy {
    pub fn allows(&self, path: &Path) -> bool {
        if self.denied.iter().any(|prefix| path.starts_with(prefix)) {
            return false;
        }

        self.allowed.iter().any(|prefix| path.starts_with(prefix))
    }
}

impl BindMount {
    /// Create a new read-only bind mount.
    pub fn readonly(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        Self {
            source: path.clone(),
            target: path,
            readonly: true,
            dev_null: false,
        }
    }

    /// Create a new writable bind mount.
    pub fn writable(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        Self {
            source: path.clone(),
            target: path,
            readonly: false,
            dev_null: false,
        }
    }

    /// Create a dev-null mount to block a path.
    pub fn block(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        Self {
            source: PathBuf::from("/dev/null"),
            target: path,
            readonly: true,
            dev_null: true,
        }
    }

    /// Convert to bwrap arguments.
    pub fn to_bwrap_args(&self) -> Vec<String> {
        if self.dev_null {
            vec![
                "--ro-bind".to_string(),
                "/dev/null".to_string(),
                self.target.display().to_string(),
            ]
        } else if self.readonly {
            vec![
                "--ro-bind".to_string(),
                self.source.display().to_string(),
                self.target.display().to_string(),
            ]
        } else {
            vec![
                "--bind".to_string(),
                self.source.display().to_string(),
                self.target.display().to_string(),
            ]
        }
    }
}

/// Generate bind mounts for the filesystem configuration.
pub fn generate_bind_mounts(
    config: &FilesystemConfig,
    cwd: &Path,
    ripgrep_config: Option<&RipgrepConfig>,
    max_depth: Option<u32>,
) -> Result<(Vec<BindMount>, Vec<String>), SandboxError> {
    let mut mounts = Vec::new();
    let mut warnings = Vec::new();

    let (writable_paths, deny_paths, mut policy_warnings) =
        collect_linux_write_paths(config, cwd, ripgrep_config, max_depth);
    warnings.append(&mut policy_warnings);

    // Generate mounts
    // First, add writable mounts
    for path in &writable_paths {
        // Check for symlinks that might escape
        if let Ok(resolved) = std::fs::canonicalize(path) {
            if is_symlink_outside_boundary(path, &resolved) {
                mounts.push(BindMount::block(path.clone()));
                continue;
            }
        }

        mounts.push(BindMount::writable(path.clone()));
    }

    // Then, add deny mounts (these override writable mounts)
    for path in &deny_paths {
        if path.exists() {
            mounts.push(BindMount::readonly(path.clone()));
        } else {
            // Block non-existent paths with dev-null
            mounts.push(BindMount::block(path.clone()));
        }
    }

    Ok((mounts, warnings))
}

pub fn build_linux_write_policy(
    config: &FilesystemConfig,
    cwd: &Path,
    ripgrep_config: Option<&RipgrepConfig>,
    max_depth: Option<u32>,
) -> (LinuxWritePolicy, Vec<String>) {
    let (allowed, denied, warnings) =
        collect_linux_write_paths(config, cwd, ripgrep_config, max_depth);

    (
        LinuxWritePolicy {
            allowed: allowed.into_iter().collect(),
            denied: denied.into_iter().collect(),
        },
        warnings,
    )
}

fn collect_linux_write_paths(
    config: &FilesystemConfig,
    cwd: &Path,
    ripgrep_config: Option<&RipgrepConfig>,
    max_depth: Option<u32>,
) -> (HashSet<PathBuf>, HashSet<PathBuf>, Vec<String>) {
    let mut writable_paths: HashSet<PathBuf> = HashSet::new();
    let mut deny_paths: HashSet<PathBuf> = HashSet::new();
    let mut warnings = Vec::new();

    for path in &config.allow_write {
        if contains_glob_chars(path) {
            warnings.push(format!(
                "Glob pattern '{}' is not supported on Linux; ignoring",
                path
            ));
            continue;
        }

        let normalized = normalize_path_for_sandbox(path);
        let path = PathBuf::from(&normalized);

        if path.exists() {
            writable_paths.insert(path);
        } else {
            warnings.push(format!("Write path '{}' does not exist", normalized));
        }
    }

    for path in &config.deny_write {
        if contains_glob_chars(path) {
            warnings.push(format!(
                "Glob pattern '{}' is not supported on Linux; ignoring",
                path
            ));
            continue;
        }

        let normalized = normalize_path_for_sandbox(path);
        deny_paths.insert(PathBuf::from(&normalized));
    }

    let dangerous_files = find_dangerous_files(cwd, ripgrep_config, max_depth).unwrap_or_default();
    for file in dangerous_files {
        deny_paths.insert(PathBuf::from(file));
    }

    for dir in DANGEROUS_DIRECTORIES {
        let path = cwd.join(dir);
        if path.exists() {
            deny_paths.insert(path);
        }

        if let Some(home) = dirs::home_dir() {
            let path = home.join(dir);
            if path.exists() {
                deny_paths.insert(path);
            }
        }
    }

    for file in DANGEROUS_FILES {
        if *file == ".gitconfig" && config.allow_git_config.unwrap_or(false) {
            continue;
        }

        if let Some(home) = dirs::home_dir() {
            let path = home.join(file);
            if path.exists() {
                deny_paths.insert(path);
            }
        }
    }

    (writable_paths, deny_paths, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bind_mount_to_bwrap_args() {
        let mount = BindMount::readonly("/path/to/file");
        let args = mount.to_bwrap_args();
        assert_eq!(args, vec!["--ro-bind", "/path/to/file", "/path/to/file"]);

        let mount = BindMount::writable("/path/to/dir");
        let args = mount.to_bwrap_args();
        assert_eq!(args, vec!["--bind", "/path/to/dir", "/path/to/dir"]);

        let mount = BindMount::block("/path/to/blocked");
        let args = mount.to_bwrap_args();
        assert_eq!(args, vec!["--ro-bind", "/dev/null", "/path/to/blocked"]);
    }

    #[test]
    fn test_linux_write_policy_denied_overrides_allowed() {
        let policy = LinuxWritePolicy {
            allowed: vec![PathBuf::from("/tmp/workspace")],
            denied: vec![PathBuf::from("/tmp/workspace/.git")],
        };

        assert!(policy.allows(Path::new("/tmp/workspace/output.txt")));
        assert!(!policy.allows(Path::new("/tmp/workspace/.git/config")));
        assert!(!policy.allows(Path::new("/etc/passwd")));
    }
}
