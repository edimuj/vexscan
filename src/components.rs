//! AI component detection within scan targets.
//!
//! Identifies logical AI components (skills, MCP servers, plugins, packages, crates)
//! by scanning for marker files. Files are assigned to the nearest ancestor component
//! by directory containment.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Kind of AI component detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentKind {
    Skill,
    McpServer,
    Plugin,
    NpmPackage,
    RustCrate,
}

impl ComponentKind {
    /// Detection priority — higher wins when multiple markers exist in one directory.
    fn priority(self) -> u8 {
        match self {
            ComponentKind::Skill => 5,
            ComponentKind::McpServer => 4,
            ComponentKind::Plugin => 3,
            ComponentKind::NpmPackage => 2,
            ComponentKind::RustCrate => 1,
        }
    }
}

impl std::fmt::Display for ComponentKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComponentKind::Skill => write!(f, "Skill"),
            ComponentKind::McpServer => write!(f, "MCP Server"),
            ComponentKind::Plugin => write!(f, "Plugin"),
            ComponentKind::NpmPackage => write!(f, "Npm Package"),
            ComponentKind::RustCrate => write!(f, "Rust Crate"),
        }
    }
}

/// A detected logical AI component within a scan target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedComponent {
    /// What kind of component this is.
    pub kind: ComponentKind,
    /// Human-readable name (from manifest or directory name).
    pub name: String,
    /// Directory containing the manifest (component root).
    pub root: PathBuf,
    /// The marker file that identified this component.
    pub manifest: PathBuf,
}

/// Walk `scan_root`, find marker files, return detected components.
/// When multiple markers exist in the same directory, highest priority wins.
pub fn detect_components(scan_root: &Path) -> Vec<DetectedComponent> {
    let mut components: Vec<DetectedComponent> = Vec::new();

    let walker = match walkdir::WalkDir::new(scan_root)
        .follow_links(false)
        .into_iter()
        .peekable()
        .peek()
    {
        Some(_) => walkdir::WalkDir::new(scan_root).follow_links(false),
        None => return components,
    };

    // Collect all candidate markers: (dir, kind, name, manifest_path)
    let mut candidates: Vec<(PathBuf, ComponentKind, String, PathBuf)> = Vec::new();

    for entry in walker.into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        if !entry.file_type().is_file() {
            continue;
        }

        let dir = match path.parent() {
            Some(d) => d.to_path_buf(),
            None => continue,
        };

        match file_name {
            "SKILL.md" => {
                let name = parse_skill_name(path).unwrap_or_else(|| dir_name_fallback(&dir));
                candidates.push((dir, ComponentKind::Skill, name, path.to_path_buf()));
            }
            "package.json" => {
                let pkg_name =
                    parse_package_json_name(path).unwrap_or_else(|| dir_name_fallback(&dir));

                if has_mcp_sdk_dep(path) {
                    candidates.push((
                        dir.clone(),
                        ComponentKind::McpServer,
                        pkg_name.clone(),
                        path.to_path_buf(),
                    ));
                }
                if has_plugin_manifest(&dir) {
                    candidates.push((
                        dir.clone(),
                        ComponentKind::Plugin,
                        pkg_name.clone(),
                        path.to_path_buf(),
                    ));
                }
                // Always add as NpmPackage candidate (lower priority, deduped later)
                candidates.push((dir, ComponentKind::NpmPackage, pkg_name, path.to_path_buf()));
            }
            "openclaw.plugin.json" => {
                // Plugin detected via its own manifest (name from sibling package.json)
                let pkg_json = dir.join("package.json");
                let name = if pkg_json.exists() {
                    parse_package_json_name(&pkg_json).unwrap_or_else(|| dir_name_fallback(&dir))
                } else {
                    dir_name_fallback(&dir)
                };
                candidates.push((dir, ComponentKind::Plugin, name, path.to_path_buf()));
            }
            "Cargo.toml" => {
                let name = parse_cargo_name(path).unwrap_or_else(|| dir_name_fallback(&dir));
                candidates.push((dir, ComponentKind::RustCrate, name, path.to_path_buf()));
            }
            _ => {}
        }
    }

    // Deduplicate: per directory, keep highest priority kind
    let mut best_per_dir: std::collections::HashMap<PathBuf, (ComponentKind, String, PathBuf)> =
        std::collections::HashMap::new();

    for (dir, kind, name, manifest) in candidates {
        let entry = best_per_dir.entry(dir);
        entry
            .and_modify(|(existing_kind, existing_name, existing_manifest)| {
                if kind.priority() > existing_kind.priority() {
                    *existing_kind = kind;
                    *existing_name = name.clone();
                    *existing_manifest = manifest.clone();
                }
            })
            .or_insert((kind, name, manifest));
    }

    for (dir, (kind, name, manifest)) in best_per_dir {
        components.push(DetectedComponent {
            kind,
            name,
            root: dir,
            manifest,
        });
    }

    // Sort by path depth (most nested first) for correct assignment via longest-prefix match
    components.sort_by(|a, b| {
        let depth_a = a.root.components().count();
        let depth_b = b.root.components().count();
        depth_b.cmp(&depth_a).then_with(|| a.root.cmp(&b.root))
    });

    components
}

/// Pre-built index for O(depth) component assignment instead of O(n) linear scan.
pub struct ComponentIndex {
    root_to_idx: std::collections::HashMap<PathBuf, usize>,
}

impl ComponentIndex {
    /// Build the index from a components slice.
    pub fn new(components: &[DetectedComponent]) -> Self {
        let mut root_to_idx = std::collections::HashMap::with_capacity(components.len());
        for (i, comp) in components.iter().enumerate() {
            root_to_idx.insert(comp.root.clone(), i);
        }
        Self { root_to_idx }
    }

    /// Find which component a file belongs to (nearest ancestor component root).
    /// Walks up the parent chain — O(path depth), not O(num components).
    pub fn assign(&self, file_path: &Path) -> Option<usize> {
        let mut current = file_path.parent();
        while let Some(dir) = current {
            if let Some(&idx) = self.root_to_idx.get(dir) {
                return Some(idx);
            }
            current = dir.parent();
        }
        None
    }
}

/// Find which component a file belongs to (nearest ancestor component root).
/// Returns index into the components slice, or None if ungrouped.
/// For bulk lookups, use ComponentIndex instead.
pub fn assign_component(file_path: &Path, components: &[DetectedComponent]) -> Option<usize> {
    let mut current = file_path.parent();
    while let Some(dir) = current {
        for (i, comp) in components.iter().enumerate() {
            if comp.root == dir {
                return Some(i);
            }
        }
        current = dir.parent();
    }
    None
}

// ── Manifest parsing helpers ──

fn dir_name_fallback(dir: &Path) -> String {
    dir.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string()
}

/// Read `name` field from package.json.
fn parse_package_json_name(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;
    json.get("name")?.as_str().map(|s| s.to_string())
}

/// Extract first `# heading` from SKILL.md.
fn parse_skill_name(skill_md: &Path) -> Option<String> {
    let content = std::fs::read_to_string(skill_md).ok()?;
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(heading) = trimmed.strip_prefix("# ") {
            let name = heading.trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// Read `[package] name` from Cargo.toml.
fn parse_cargo_name(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let toml: toml::Value = content.parse().ok()?;
    toml.get("package")?
        .get("name")?
        .as_str()
        .map(|s| s.to_string())
}

/// Check if package.json has `@modelcontextprotocol/sdk` in deps or devDeps.
fn has_mcp_sdk_dep(package_json: &Path) -> bool {
    let content = match std::fs::read_to_string(package_json) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return false,
    };

    for key in &["dependencies", "devDependencies"] {
        if let Some(deps) = json.get(key).and_then(|v| v.as_object()) {
            if deps.contains_key("@modelcontextprotocol/sdk") {
                return true;
            }
        }
    }
    false
}

/// Check if directory contains openclaw.plugin.json.
fn has_plugin_manifest(dir: &Path) -> bool {
    dir.join("openclaw.plugin.json").exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_dir(base: &Path, structure: &[(&str, &str)]) {
        for (path, content) in structure {
            let full = base.join(path);
            if let Some(parent) = full.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(full, content).unwrap();
        }
    }

    #[test]
    fn test_skill_detection_via_skill_md() {
        let tmp = tempfile::tempdir().unwrap();
        setup_dir(
            tmp.path(),
            &[("my-skill/SKILL.md", "# Code Review\nDoes code review.")],
        );

        let components = detect_components(tmp.path());
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].kind, ComponentKind::Skill);
        assert_eq!(components[0].name, "Code Review");
    }

    #[test]
    fn test_skill_name_fallback_to_dir() {
        let tmp = tempfile::tempdir().unwrap();
        setup_dir(tmp.path(), &[("my-skill/SKILL.md", "No heading here.")]);

        let components = detect_components(tmp.path());
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].name, "my-skill");
    }

    #[test]
    fn test_mcp_server_detection() {
        let tmp = tempfile::tempdir().unwrap();
        setup_dir(
            tmp.path(),
            &[(
                "github-tools/package.json",
                r#"{"name": "@mcp/github-tools", "dependencies": {"@modelcontextprotocol/sdk": "^1.0"}}"#,
            )],
        );

        let components = detect_components(tmp.path());
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].kind, ComponentKind::McpServer);
        assert_eq!(components[0].name, "@mcp/github-tools");
    }

    #[test]
    fn test_plugin_detection_via_openclaw_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        setup_dir(
            tmp.path(),
            &[
                (
                    "my-plugin/package.json",
                    r#"{"name": "@exelerus/my-plugin"}"#,
                ),
                ("my-plugin/openclaw.plugin.json", r#"{"kind": "tool"}"#),
            ],
        );

        let components = detect_components(tmp.path());
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].kind, ComponentKind::Plugin);
        assert_eq!(components[0].name, "@exelerus/my-plugin");
    }

    #[test]
    fn test_npm_package_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        setup_dir(
            tmp.path(),
            &[("some-lib/package.json", r#"{"name": "some-lib"}"#)],
        );

        let components = detect_components(tmp.path());
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].kind, ComponentKind::NpmPackage);
        assert_eq!(components[0].name, "some-lib");
    }

    #[test]
    fn test_rust_crate_detection() {
        let tmp = tempfile::tempdir().unwrap();
        setup_dir(
            tmp.path(),
            &[(
                "my-crate/Cargo.toml",
                "[package]\nname = \"my-crate\"\nversion = \"0.1.0\"\n",
            )],
        );

        let components = detect_components(tmp.path());
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].kind, ComponentKind::RustCrate);
        assert_eq!(components[0].name, "my-crate");
    }

    #[test]
    fn test_priority_skill_over_npm() {
        let tmp = tempfile::tempdir().unwrap();
        setup_dir(
            tmp.path(),
            &[
                ("my-skill/SKILL.md", "# My Skill"),
                ("my-skill/package.json", r#"{"name": "my-skill"}"#),
            ],
        );

        let components = detect_components(tmp.path());
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].kind, ComponentKind::Skill);
        assert_eq!(components[0].name, "My Skill");
    }

    #[test]
    fn test_nested_component_assignment() {
        let tmp = tempfile::tempdir().unwrap();
        setup_dir(
            tmp.path(),
            &[
                (
                    "Cargo.toml",
                    "[package]\nname = \"root-crate\"\nversion = \"0.1.0\"\n",
                ),
                ("skills/review/SKILL.md", "# Review"),
                ("skills/review/main.js", "// code"),
                ("src/lib.rs", "// root code"),
            ],
        );

        let components = detect_components(tmp.path());
        assert_eq!(components.len(), 2);

        // skills/review/main.js → Skill (deepest match)
        let main_js = tmp.path().join("skills/review/main.js");
        let idx = assign_component(&main_js, &components).unwrap();
        assert_eq!(components[idx].kind, ComponentKind::Skill);

        // src/lib.rs → RustCrate (root)
        let lib_rs = tmp.path().join("src/lib.rs");
        let idx = assign_component(&lib_rs, &components).unwrap();
        assert_eq!(components[idx].kind, ComponentKind::RustCrate);
    }

    #[test]
    fn test_ungrouped_file_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        setup_dir(tmp.path(), &[("skills/review/SKILL.md", "# Review")]);

        let components = detect_components(tmp.path());

        // A file outside any component root
        let outside = Path::new("/some/other/path/file.js");
        assert_eq!(assign_component(outside, &components), None);
    }

    #[test]
    fn test_mcp_server_beats_npm_package() {
        let tmp = tempfile::tempdir().unwrap();
        setup_dir(
            tmp.path(),
            &[(
                "server/package.json",
                r#"{"name": "my-server", "dependencies": {"@modelcontextprotocol/sdk": "^1.0"}}"#,
            )],
        );

        let components = detect_components(tmp.path());
        assert_eq!(components.len(), 1);
        assert_eq!(components[0].kind, ComponentKind::McpServer);
    }

    #[test]
    fn test_multiple_components_detected() {
        let tmp = tempfile::tempdir().unwrap();
        setup_dir(
            tmp.path(),
            &[
                ("skill-a/SKILL.md", "# Skill A"),
                ("skill-b/SKILL.md", "# Skill B"),
                (
                    "mcp/package.json",
                    r#"{"name": "mcp-server", "dependencies": {"@modelcontextprotocol/sdk": "^1.0"}}"#,
                ),
            ],
        );

        let components = detect_components(tmp.path());
        assert_eq!(components.len(), 3);

        let kinds: Vec<_> = components.iter().map(|c| c.kind).collect();
        assert!(kinds.contains(&ComponentKind::Skill));
        assert!(kinds.contains(&ComponentKind::McpServer));
    }
}
