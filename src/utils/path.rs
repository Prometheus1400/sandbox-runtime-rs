//! Path normalization utilities.

#[cfg(any(test, target_os = "linux"))]
use std::path::{Component, Path, PathBuf};

/// Normalize a path for sandbox use.
/// - Expands ~ to home directory
/// - Resolves to canonical path if possible
/// - Returns the normalized path string
pub fn normalize_path_for_sandbox(path: &str) -> String {
    let expanded = expand_home(path);

    // Try to canonicalize (resolves symlinks)
    match std::fs::canonicalize(&expanded) {
        Ok(canonical) => canonical.display().to_string(),
        Err(_) => expanded,
    }
}

/// Expand ~ to the home directory.
pub fn expand_home(path: &str) -> String {
    if path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            return format!("{}{}", home.display(), &path[1..]);
        }
    } else if path == "~" {
        if let Some(home) = dirs::home_dir() {
            return home.display().to_string();
        }
    }
    path.to_string()
}

/// Check if a path contains glob characters.
pub fn contains_glob_chars(path: &str) -> bool {
    path.contains('*') || path.contains('?') || path.contains('[') || path.contains('{')
}

/// Normalize path components lexically without touching the filesystem.
#[cfg(any(test, target_os = "linux"))]
pub fn normalize_path_components(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }

    normalized
}

/// Strip trailing glob components from a path.
///
/// For example, `/foo/bar/**` becomes `/foo/bar` and `/foo/*/baz` becomes `/foo`.
/// Used to extract the base directory from a glob pattern for bind-mounting.
#[cfg(target_os = "linux")]
pub fn remove_trailing_glob_suffix(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    let mut base_parts = Vec::new();
    for part in &parts {
        if contains_glob_chars(part) {
            break;
        }
        base_parts.push(*part);
    }
    let result = base_parts.join("/");
    if result.is_empty() {
        "/".to_string()
    } else {
        result
    }
}

/// Check if a resolved (canonicalized) path escapes the boundary of the original path's parent.
///
/// Returns `true` if the symlink target is outside the parent directory of `path`.
#[cfg(target_os = "linux")]
pub fn is_symlink_outside_boundary(path: &std::path::Path, resolved: &std::path::Path) -> bool {
    if let Some(parent) = path.parent() {
        !resolved.starts_with(parent)
    } else {
        // Root path — resolved can't escape
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_home() {
        let home = dirs::home_dir().unwrap();

        assert_eq!(expand_home("~"), home.display().to_string());
        assert_eq!(
            expand_home("~/Documents"),
            format!("{}/Documents", home.display())
        );
        assert_eq!(expand_home("/absolute/path"), "/absolute/path");
        assert_eq!(expand_home("relative/path"), "relative/path");
    }

    #[test]
    fn test_contains_glob_chars() {
        assert!(contains_glob_chars("*.txt"));
        assert!(contains_glob_chars("src/**/*.rs"));
        assert!(contains_glob_chars("file?.txt"));
        assert!(contains_glob_chars("file[0-9].txt"));
        assert!(contains_glob_chars("file{a,b}.txt"));
        assert!(!contains_glob_chars("/plain/path"));
    }

    #[test]
    fn test_normalize_path_components() {
        let path = Path::new("/tmp/../var/./log");
        assert_eq!(normalize_path_components(path), PathBuf::from("/var/log"));
    }
}
