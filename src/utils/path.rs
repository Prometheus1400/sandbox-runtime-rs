//! Path normalization utilities.

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
}
