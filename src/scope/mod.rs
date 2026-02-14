//! Installation scope detection for scan results.
//!
//! Determines whether files in a scanned directory are part of the installed/published
//! package or are dev-only (tests, examples, CI configs). Dev-only findings are
//! capped at Low severity by default since they don't ship to end users.

pub mod conventional;
pub mod npm;

use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Whether a file is part of the installed package or dev-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallScope {
    /// File ships with the installed package.
    Installed,
    /// File is dev-only (tests, examples, docs, CI).
    DevOnly,
}

impl std::fmt::Display for InstallScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallScope::Installed => write!(f, "installed"),
            InstallScope::DevOnly => write!(f, "dev-only"),
        }
    }
}

/// Detected project type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectType {
    Npm,
    Cargo,
    Python,
    Unknown,
}

/// Pre-compiled scope classification data for a scan root.
pub struct ScopeMap {
    /// What project type was detected.
    pub project_type: ProjectType,
    /// Whether an explicit manifest whitelist was found (e.g., npm `files`).
    pub manifest_based: bool,
    /// Patterns that are always considered installed (agent instructions, manifests).
    always_in_scope: GlobSet,
    /// Manifest-based whitelist (npm `files`). If present, unlisted files are DevOnly.
    include_globs: Option<GlobSet>,
    /// Conventional dev-only patterns (tests, examples, CI).
    dev_only_globs: GlobSet,
}

impl ScopeMap {
    /// Classify a file path relative to the scan root.
    ///
    /// Applies layers in order:
    /// 1. Always-in-scope files → Installed
    /// 2. Manifest whitelist → Installed if matched, DevOnly if not
    /// 3. Conventional patterns → DevOnly if matched
    /// 4. Default → Installed
    pub fn classify(&self, path: &Path, scan_root: &Path) -> InstallScope {
        let relative = self.relative_path(path, scan_root);

        // Layer 1: Always-in-scope files (agent instructions, manifests)
        if self.always_in_scope.is_match(&relative) {
            return InstallScope::Installed;
        }

        // Also check just the filename for patterns like "SKILL.md" — but only
        // if the file is NOT inside a dev-only directory (e.g. examples/SKILL.md
        // is a test fixture, not a real instruction file).
        if let Some(file_name) = relative.file_name() {
            if self.always_in_scope.is_match(Path::new(file_name))
                && !self.dev_only_globs.is_match(&relative)
            {
                return InstallScope::Installed;
            }
        }

        // Layer 2: Manifest whitelist (e.g., npm `files`)
        if let Some(ref include) = self.include_globs {
            return if include.is_match(&relative) {
                InstallScope::Installed
            } else {
                InstallScope::DevOnly
            };
        }

        // Layer 3: Conventional dev-only patterns
        if self.dev_only_globs.is_match(&relative) {
            return InstallScope::DevOnly;
        }

        // Also check just the filename for file-level patterns
        if let Some(file_name) = relative.file_name() {
            if self.dev_only_globs.is_match(Path::new(file_name)) {
                return InstallScope::DevOnly;
            }
        }

        // Layer 4: Default
        InstallScope::Installed
    }

    fn relative_path<'a>(&self, path: &'a Path, scan_root: &Path) -> std::borrow::Cow<'a, Path> {
        match path.strip_prefix(scan_root) {
            Ok(rel) => std::borrow::Cow::Borrowed(rel),
            Err(_) => std::borrow::Cow::Borrowed(path),
        }
    }
}

/// Build the always-in-scope GlobSet for agent instruction files and manifests.
fn build_always_in_scope() -> GlobSet {
    let mut builder = GlobSetBuilder::new();

    let patterns = [
        // Agent instruction files
        "SKILL.md",
        "CLAUDE.md",
        ".cursorrules",
        ".clinerules",
        "copilot-instructions.md",
        ".github/copilot-instructions.md",
        // Manifests
        "package.json",
        "Cargo.toml",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        // Standard includes
        "README*",
        "readme*",
        "LICENSE*",
        "license*",
        "LICENCE*",
        "CHANGELOG*",
        "changelog*",
    ];

    for pattern in &patterns {
        if let Ok(glob) = Glob::new(pattern) {
            builder.add(glob);
        }
    }

    builder
        .build()
        .unwrap_or_else(|_| GlobSetBuilder::new().build().unwrap())
}

/// Detect the project type from the scan root.
fn detect_project_type(scan_root: &Path) -> ProjectType {
    if npm::is_npm_project(scan_root) {
        ProjectType::Npm
    } else if scan_root.join("Cargo.toml").exists() {
        ProjectType::Cargo
    } else if scan_root.join("pyproject.toml").exists() || scan_root.join("setup.py").exists() {
        ProjectType::Python
    } else {
        ProjectType::Unknown
    }
}

/// Detect installation scope for a scan root.
///
/// Reads manifests (one file read at most), builds pre-compiled GlobSets,
/// and returns a `ScopeMap` that can classify any file path efficiently.
pub fn detect_scope(scan_root: &Path) -> ScopeMap {
    let project_type = detect_project_type(scan_root);
    let always_in_scope = build_always_in_scope();
    let dev_only_globs = conventional::build_dev_only_globs();

    // Try manifest-based whitelist
    let include_globs = match project_type {
        ProjectType::Npm => npm::detect_npm_files_whitelist(scan_root),
        // Cargo and Python deferred to later phases
        _ => None,
    };

    let manifest_based = include_globs.is_some();

    ScopeMap {
        project_type,
        manifest_based,
        always_in_scope,
        include_globs,
        dev_only_globs,
    }
}

/// Rule IDs exempt from scope-based severity capping.
/// These are content-attack rules that matter even in test/dev files.
const SCOPE_CAP_EXEMPT_PREFIXES: &[&str] = &["INJECT-", "AUTH-", "HIDDEN-", "MDCODE-"];

/// Check if a rule ID is exempt from scope-based severity capping.
///
/// When `manifest_based` is true, the project has an explicit manifest whitelist
/// (e.g., npm `files` field) that definitively declares what ships. In that case,
/// no rules are exempt — if the manifest says the file doesn't ship, it doesn't
/// reach the user's machine regardless of rule category.
pub fn is_scope_cap_exempt(rule_id: &str, manifest_based: bool) -> bool {
    if manifest_based {
        return false;
    }
    SCOPE_CAP_EXEMPT_PREFIXES
        .iter()
        .any(|prefix| rule_id.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn setup_empty_project() -> TempDir {
        TempDir::new().unwrap()
    }

    fn setup_npm_project_with_files() -> TempDir {
        let tmp = TempDir::new().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"name": "test", "version": "1.0.0", "files": ["dist", "lib"], "main": "dist/index.js"}"#,
        )
        .unwrap();
        tmp
    }

    fn setup_npm_project_no_files() -> TempDir {
        let tmp = TempDir::new().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"name": "test", "version": "1.0.0"}"#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn test_detect_project_type_npm() {
        let tmp = setup_npm_project_no_files();
        assert_eq!(detect_project_type(tmp.path()), ProjectType::Npm);
    }

    #[test]
    fn test_detect_project_type_unknown() {
        let tmp = setup_empty_project();
        assert_eq!(detect_project_type(tmp.path()), ProjectType::Unknown);
    }

    #[test]
    fn test_agent_instructions_always_installed() {
        let tmp = setup_empty_project();
        let scope = detect_scope(tmp.path());
        let root = tmp.path();

        assert_eq!(
            scope.classify(&root.join("SKILL.md"), root),
            InstallScope::Installed
        );
        assert_eq!(
            scope.classify(&root.join("CLAUDE.md"), root),
            InstallScope::Installed
        );
        assert_eq!(
            scope.classify(&root.join(".cursorrules"), root),
            InstallScope::Installed
        );
        assert_eq!(
            scope.classify(&root.join("package.json"), root),
            InstallScope::Installed
        );
        assert_eq!(
            scope.classify(&root.join("README.md"), root),
            InstallScope::Installed
        );
    }

    #[test]
    fn test_conventional_dev_only() {
        let tmp = setup_empty_project();
        let scope = detect_scope(tmp.path());
        let root = tmp.path();

        assert_eq!(
            scope.classify(&root.join("tests/malicious.js"), root),
            InstallScope::DevOnly
        );
        assert_eq!(
            scope.classify(&root.join(".github/workflows/ci.yml"), root),
            InstallScope::DevOnly
        );
        assert_eq!(
            scope.classify(&root.join("examples/demo.py"), root),
            InstallScope::DevOnly
        );
        assert_eq!(
            scope.classify(&root.join("app.test.js"), root),
            InstallScope::DevOnly
        );
    }

    #[test]
    fn test_production_files_installed() {
        let tmp = setup_empty_project();
        let scope = detect_scope(tmp.path());
        let root = tmp.path();

        assert_eq!(
            scope.classify(&root.join("src/index.js"), root),
            InstallScope::Installed
        );
        assert_eq!(
            scope.classify(&root.join("lib/utils.ts"), root),
            InstallScope::Installed
        );
        assert_eq!(
            scope.classify(&root.join("dist/bundle.js"), root),
            InstallScope::Installed
        );
    }

    #[test]
    fn test_npm_files_whitelist() {
        let tmp = setup_npm_project_with_files();
        let scope = detect_scope(tmp.path());
        let root = tmp.path();

        assert!(scope.manifest_based);

        // Whitelisted paths
        assert_eq!(
            scope.classify(&root.join("dist/index.js"), root),
            InstallScope::Installed
        );
        assert_eq!(
            scope.classify(&root.join("lib/helpers.js"), root),
            InstallScope::Installed
        );
        assert_eq!(
            scope.classify(&root.join("package.json"), root),
            InstallScope::Installed
        );

        // Not whitelisted → DevOnly
        assert_eq!(
            scope.classify(&root.join("src/index.ts"), root),
            InstallScope::DevOnly
        );
        assert_eq!(
            scope.classify(&root.join("tsconfig.json"), root),
            InstallScope::DevOnly
        );
    }

    #[test]
    fn test_agent_instructions_override_npm_whitelist() {
        let tmp = setup_npm_project_with_files();
        let scope = detect_scope(tmp.path());
        let root = tmp.path();

        // SKILL.md is always installed even if not in npm files
        assert_eq!(
            scope.classify(&root.join("SKILL.md"), root),
            InstallScope::Installed
        );
    }

    #[test]
    fn test_instruction_files_in_dev_dirs_are_dev_only() {
        let tmp = setup_empty_project();
        let scope = detect_scope(tmp.path());
        let root = tmp.path();

        // SKILL.md at root → Installed
        assert_eq!(
            scope.classify(&root.join("SKILL.md"), root),
            InstallScope::Installed
        );
        // SKILL.md inside examples/ → DevOnly (test fixture, not real instruction)
        assert_eq!(
            scope.classify(&root.join("examples/malicious-skill/SKILL.md"), root),
            InstallScope::DevOnly
        );
        // CLAUDE.md inside tests/ → DevOnly
        assert_eq!(
            scope.classify(&root.join("tests/fixtures/CLAUDE.md"), root),
            InstallScope::DevOnly
        );
        // SKILL.md in a non-dev subdir → still Installed
        assert_eq!(
            scope.classify(&root.join("plugins/my-plugin/SKILL.md"), root),
            InstallScope::Installed
        );
    }

    #[test]
    fn test_scope_cap_exempt_no_manifest() {
        // Without manifest, INJECT/AUTH/HIDDEN/MDCODE are exempt from capping
        assert!(is_scope_cap_exempt("INJECT-001", false));
        assert!(is_scope_cap_exempt("AUTH-003", false));
        assert!(is_scope_cap_exempt("HIDDEN-002", false));
        assert!(is_scope_cap_exempt("MDCODE-001", false));
        assert!(!is_scope_cap_exempt("EXEC-001", false));
        assert!(!is_scope_cap_exempt("NET-002", false));
        assert!(!is_scope_cap_exempt("PKG-001", false));
    }

    #[test]
    fn test_scope_cap_exempt_with_manifest() {
        // With manifest whitelist, nothing is exempt — manifest is authoritative
        assert!(!is_scope_cap_exempt("INJECT-001", true));
        assert!(!is_scope_cap_exempt("AUTH-003", true));
        assert!(!is_scope_cap_exempt("HIDDEN-002", true));
        assert!(!is_scope_cap_exempt("MDCODE-001", true));
        assert!(!is_scope_cap_exempt("EXEC-001", true));
    }
}
