//! Database of known malicious npm packages.
//!
//! Data is externalized to `data/malicious-packages.json` for easy maintenance.
//! The JSON is embedded at compile time via `include_str!()`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Embedded JSON database of malicious packages.
const MALICIOUS_JSON: &str = include_str!("../../data/malicious-packages.json");

/// JSON file wrapper.
#[derive(Debug, Deserialize)]
struct MaliciousPackageFile {
    packages: Vec<MaliciousPackage>,
}

/// A known malicious package entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaliciousPackage {
    /// Package name.
    pub name: String,
    /// Affected versions (empty means all versions).
    #[serde(default)]
    pub versions: Vec<String>,
    /// Why this package is malicious.
    pub reason: String,
    /// Severity level (critical, high, medium, low).
    pub severity: String,
    /// CVE identifier if available.
    pub cve: Option<String>,
    /// Reference URL for more information.
    pub reference: Option<String>,
    /// Date the package was identified as malicious.
    pub discovered: Option<String>,
    /// Tags for categorization.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Database of known malicious packages.
pub struct MaliciousPackageDb {
    /// Map of package name to malicious package info.
    packages: HashMap<String, MaliciousPackage>,
}

impl MaliciousPackageDb {
    /// Load the built-in malicious package database from embedded JSON.
    pub fn load_builtin() -> Self {
        let file: MaliciousPackageFile = serde_json::from_str(MALICIOUS_JSON)
            .expect("Failed to parse embedded malicious-packages.json");

        let mut map = HashMap::new();
        for pkg in file.packages {
            map.insert(pkg.name.clone(), pkg);
        }

        Self { packages: map }
    }

    /// Look up a package by name and version.
    /// Returns Some if the package is known to be malicious.
    pub fn lookup(&self, name: &str, version: &str) -> Option<&MaliciousPackage> {
        if let Some(pkg) = self.packages.get(name) {
            // If no specific versions listed, all versions are affected
            if pkg.versions.is_empty() {
                return Some(pkg);
            }
            // Check if the specific version is affected
            if pkg.versions.iter().any(|v| version_matches(version, v)) {
                return Some(pkg);
            }
        }
        None
    }

    /// Get the total number of packages in the database.
    pub fn len(&self) -> usize {
        self.packages.len()
    }

    /// Check if the database is empty.
    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }
}

/// Check if a version string matches a pattern.
/// Supports exact match, prefix match with *, and semver ranges.
fn version_matches(version: &str, pattern: &str) -> bool {
    // Strip any leading ^ or ~ from the installed version
    let clean_version = version.trim_start_matches('^').trim_start_matches('~');

    if pattern == "*" {
        return true;
    }

    if pattern.ends_with('*') {
        let prefix = pattern.trim_end_matches('*');
        return clean_version.starts_with(prefix);
    }

    // Exact match
    clean_version == pattern || version == pattern
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_builtin() {
        let db = MaliciousPackageDb::load_builtin();
        assert!(!db.is_empty());
        assert!(db.len() >= 30);
    }

    #[test]
    fn test_lookup_event_stream() {
        let db = MaliciousPackageDb::load_builtin();

        // Affected version
        assert!(db.lookup("event-stream", "3.3.6").is_some());

        // Safe version
        assert!(db.lookup("event-stream", "3.3.5").is_none());
        assert!(db.lookup("event-stream", "4.0.0").is_none());
    }

    #[test]
    fn test_lookup_any_version() {
        let db = MaliciousPackageDb::load_builtin();

        // crossenv is malicious regardless of version
        assert!(db.lookup("crossenv", "1.0.0").is_some());
        assert!(db.lookup("crossenv", "99.99.99").is_some());
    }

    #[test]
    fn test_safe_package() {
        let db = MaliciousPackageDb::load_builtin();

        assert!(db.lookup("lodash", "4.17.21").is_none());
        assert!(db.lookup("express", "4.18.2").is_none());
    }

    #[test]
    fn test_version_with_prefix() {
        let db = MaliciousPackageDb::load_builtin();

        // Should match even with ^ prefix
        assert!(db.lookup("event-stream", "^3.3.6").is_some());
        assert!(db.lookup("event-stream", "~3.3.6").is_some());
    }
}
