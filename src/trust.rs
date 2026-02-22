//! Trust store for suppressing reviewed findings on known-good components.
//!
//! Trust entries are keyed by `<kind>:<name>` and invalidated when the component's
//! content hash changes (files modified since last review).

use crate::components::DetectedComponent;
use crate::types::{ScanReport, ScanResult, Severity};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Trust level assigned to a component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    /// Findings reviewed and accepted — suppress matching rules.
    Accepted,
    /// Known-bad component — inject a synthetic critical finding.
    Quarantined,
}

/// A single trust store entry for one component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEntry {
    pub name: String,
    pub kind: String,
    pub component_hash: String,
    pub trust_level: TrustLevel,
    /// Which rule IDs are accepted (empty = all rules accepted via `trust full`).
    #[serde(default)]
    pub accepted_rules: Vec<String>,
    pub decided_at: DateTime<Utc>,
    pub scanner_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl TrustEntry {
    /// Build the key used in the store map.
    pub fn key(&self) -> String {
        format!("{}:{}", self.kind, self.name)
    }

    /// Whether this entry accepts a specific rule ID.
    pub fn accepts_rule(&self, rule_id: &str) -> bool {
        self.trust_level == TrustLevel::Accepted
            && (self.accepted_rules.is_empty()
                || self.accepted_rules.iter().any(|r| r == rule_id))
    }
}

/// Persistent trust store backed by `~/.vexscan/trust.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustStore {
    pub version: u32,
    pub entries: HashMap<String, TrustEntry>,
}

impl Default for TrustStore {
    fn default() -> Self {
        Self {
            version: 1,
            entries: HashMap::new(),
        }
    }
}

impl TrustStore {
    /// Path to the trust store file.
    pub fn store_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".vexscan")
            .join("trust.json")
    }

    /// Load from disk, returning an empty store if the file doesn't exist.
    pub fn load() -> Result<Self> {
        let path = Self::store_path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read_to_string(&path)?;
        let store: TrustStore = serde_json::from_str(&data)?;
        Ok(store)
    }

    /// Save to disk (atomic write via tmp + rename).
    pub fn save(&self) -> Result<()> {
        let path = Self::store_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp_path = path.with_extension("json.tmp");
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(&tmp_path, &data)?;
        std::fs::rename(&tmp_path, &path)?;
        Ok(())
    }

    /// Add or update a trust entry.
    pub fn add(&mut self, entry: TrustEntry) {
        let key = entry.key();
        self.entries.insert(key, entry);
    }

    /// Revoke trust for a key (returns true if it existed).
    pub fn revoke(&mut self, key: &str) -> bool {
        self.entries.remove(key).is_some()
    }

    /// Look up a trust entry by kind and name.
    pub fn get(&self, kind: &str, name: &str) -> Option<&TrustEntry> {
        let key = format!("{}:{}", kind, name);
        self.entries.get(&key)
    }

    /// Apply trust store to a scan report.
    /// Sets `suppressed_by` on findings that match trusted entries with valid hashes.
    /// Returns the total number of suppressed findings.
    pub fn apply_to_report(&self, report: &mut ScanReport) -> usize {
        if self.entries.is_empty() || report.components.is_empty() {
            return 0;
        }

        let mut total_suppressed = 0;

        for (comp_idx, comp) in report.components.iter().enumerate() {
            let kind_str = component_kind_key(comp);
            let entry = match self.get(&kind_str, &comp.name) {
                Some(e) => e,
                None => continue,
            };

            // Compute current hash from scan results belonging to this component
            let comp_results: Vec<&ScanResult> = report
                .results
                .iter()
                .filter(|r| r.component_idx == Some(comp_idx))
                .collect();

            let current_hash = compute_component_hash(&comp_results);

            if current_hash != entry.component_hash {
                tracing::warn!(
                    "Trust hash mismatch for {}: expected {}, got {} — skipping suppression",
                    entry.key(),
                    &entry.component_hash[..8],
                    &current_hash[..8],
                );
                continue;
            }

            match entry.trust_level {
                TrustLevel::Quarantined => {
                    // Inject synthetic critical finding into the first result of this component
                    for result in report.results.iter_mut() {
                        if result.component_idx == Some(comp_idx) {
                            let finding = crate::types::Finding::new(
                                "TRUST-Q01",
                                "Quarantined component",
                                format!(
                                    "Component '{}' has been quarantined. Do not use.",
                                    comp.name
                                ),
                                Severity::Critical,
                                crate::types::FindingCategory::Other("quarantine".to_string()),
                                crate::types::Location::new(result.path.clone(), 1, 1),
                                "(quarantined by trust store)",
                            );
                            result.findings.push(finding);
                            break;
                        }
                    }
                }
                TrustLevel::Accepted => {
                    let trust_key = entry.key();
                    for result in report.results.iter_mut() {
                        if result.component_idx != Some(comp_idx) {
                            continue;
                        }
                        for finding in &mut result.findings {
                            if finding.suppressed_by.is_none() && entry.accepts_rule(&finding.rule_id)
                            {
                                finding.suppressed_by = Some(trust_key.clone());
                                total_suppressed += 1;
                            }
                        }
                    }
                }
            }
        }

        total_suppressed
    }
}

/// Compute a component hash from scan results (SHA-256 of sorted per-file content hashes).
pub fn compute_component_hash(results: &[&ScanResult]) -> String {
    use sha2::{Digest, Sha256};

    let mut file_hashes: Vec<&str> = results
        .iter()
        .filter_map(|r| r.content_hash.as_deref())
        .collect();
    file_hashes.sort();

    let mut hasher = Sha256::new();
    for h in &file_hashes {
        hasher.update(h.as_bytes());
        hasher.update(b"\n");
    }
    format!("{:x}", hasher.finalize())
}

/// Compute a component hash by walking a directory on disk.
/// Used by `trust accept` / `trust show` commands (no prior scan needed).
pub fn hash_component_dir(root: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};

    let mut file_hashes: Vec<String> = Vec::new();

    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        // Skip hidden files and common non-content dirs
        if path
            .components()
            .any(|c| c.as_os_str().to_string_lossy().starts_with('.'))
        {
            continue;
        }
        let skip_dirs = ["node_modules", "__pycache__", ".venv", "target"];
        if path
            .components()
            .any(|c| skip_dirs.contains(&c.as_os_str().to_string_lossy().as_ref()))
        {
            continue;
        }

        let content = match std::fs::read(path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let mut hasher = Sha256::new();
        hasher.update(&content);
        file_hashes.push(format!("{:x}", hasher.finalize()));
    }

    file_hashes.sort();

    let mut hasher = Sha256::new();
    for h in &file_hashes {
        hasher.update(h.as_bytes());
        hasher.update(b"\n");
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Map a DetectedComponent to its trust key kind string.
pub fn component_kind_key(comp: &DetectedComponent) -> String {
    use crate::components::ComponentKind;
    match comp.kind {
        ComponentKind::Skill => "skill",
        ComponentKind::McpServer => "mcp",
        ComponentKind::Plugin => "plugin",
        ComponentKind::NpmPackage => "npm",
        ComponentKind::RustCrate => "crate",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;
    use std::path::PathBuf;

    fn make_finding(rule_id: &str, severity: Severity) -> Finding {
        Finding::new(
            rule_id,
            "Test finding",
            "desc",
            severity,
            FindingCategory::CodeExecution,
            Location::new(PathBuf::from("test.js"), 1, 1),
            "snippet",
        )
    }

    #[test]
    fn test_trust_entry_key() {
        let entry = TrustEntry {
            name: "my-plugin".into(),
            kind: "skill".into(),
            component_hash: "abc123".into(),
            trust_level: TrustLevel::Accepted,
            accepted_rules: vec!["INJECT-001".into()],
            decided_at: Utc::now(),
            scanner_version: "0.10.6".into(),
            notes: None,
        };
        assert_eq!(entry.key(), "skill:my-plugin");
    }

    #[test]
    fn test_accepts_rule_specific() {
        let entry = TrustEntry {
            name: "x".into(),
            kind: "skill".into(),
            component_hash: "h".into(),
            trust_level: TrustLevel::Accepted,
            accepted_rules: vec!["INJECT-001".into(), "EXEC-002".into()],
            decided_at: Utc::now(),
            scanner_version: "0.10.6".into(),
            notes: None,
        };
        assert!(entry.accepts_rule("INJECT-001"));
        assert!(!entry.accepts_rule("OTHER-999"));
    }

    #[test]
    fn test_accepts_rule_full() {
        let entry = TrustEntry {
            name: "x".into(),
            kind: "skill".into(),
            component_hash: "h".into(),
            trust_level: TrustLevel::Accepted,
            accepted_rules: vec![], // empty = all accepted
            decided_at: Utc::now(),
            scanner_version: "0.10.6".into(),
            notes: None,
        };
        assert!(entry.accepts_rule("ANYTHING-123"));
    }

    #[test]
    fn test_quarantined_does_not_accept() {
        let entry = TrustEntry {
            name: "x".into(),
            kind: "skill".into(),
            component_hash: "h".into(),
            trust_level: TrustLevel::Quarantined,
            accepted_rules: vec![],
            decided_at: Utc::now(),
            scanner_version: "0.10.6".into(),
            notes: None,
        };
        assert!(!entry.accepts_rule("INJECT-001"));
    }

    #[test]
    fn test_compute_component_hash_deterministic() {
        let r1 = ScanResult {
            path: PathBuf::from("a.js"),
            findings: vec![],
            scan_time_ms: 0,
            content_hash: Some("aaa".into()),
            install_scope: None,
            component_idx: None,
        };
        let r2 = ScanResult {
            path: PathBuf::from("b.js"),
            findings: vec![],
            scan_time_ms: 0,
            content_hash: Some("bbb".into()),
            install_scope: None,
            component_idx: None,
        };

        let h1 = compute_component_hash(&[&r1, &r2]);
        let h2 = compute_component_hash(&[&r2, &r1]); // reversed order
        assert_eq!(h1, h2, "Hash should be order-independent");
    }

    #[test]
    fn test_store_add_and_get() {
        let mut store = TrustStore::default();
        let entry = TrustEntry {
            name: "test-skill".into(),
            kind: "skill".into(),
            component_hash: "abc".into(),
            trust_level: TrustLevel::Accepted,
            accepted_rules: vec![],
            decided_at: Utc::now(),
            scanner_version: "0.10.6".into(),
            notes: None,
        };
        store.add(entry);
        assert!(store.get("skill", "test-skill").is_some());
        assert!(store.get("skill", "other").is_none());
    }

    #[test]
    fn test_store_revoke() {
        let mut store = TrustStore::default();
        let entry = TrustEntry {
            name: "x".into(),
            kind: "skill".into(),
            component_hash: "h".into(),
            trust_level: TrustLevel::Accepted,
            accepted_rules: vec![],
            decided_at: Utc::now(),
            scanner_version: "0.10.6".into(),
            notes: None,
        };
        store.add(entry);
        assert!(store.revoke("skill:x"));
        assert!(!store.revoke("skill:x")); // already gone
    }

    #[test]
    fn test_max_active_severity_ignores_suppressed() {
        let mut f1 = make_finding("INJECT-001", Severity::Critical);
        f1.suppressed_by = Some("skill:test".into());

        let f2 = make_finding("EXEC-002", Severity::Low);

        let mut report = ScanReport::new(PathBuf::from("."));
        let mut result = ScanResult::new(PathBuf::from("test.js"));
        result.findings = vec![f1, f2];
        report.results.push(result);

        assert_eq!(report.max_severity(), Some(Severity::Critical));
        assert_eq!(report.max_active_severity(), Some(Severity::Low));
    }
}
