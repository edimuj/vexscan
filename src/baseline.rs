//! Baseline/diff scanning — save scan results and compare future scans against them.

use crate::types::{ScanReport, ScanResult};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Result of diffing a scan against a baseline.
pub struct DiffResult {
    pub report: ScanReport,
    pub files_unchanged: usize,
    pub findings_suppressed: usize,
}

/// Compute a line-insensitive fingerprint for a finding.
/// Uses rule_id + relative file path + trimmed snippet content.
fn finding_fingerprint(rule_id: &str, rel_path: &Path, snippet: &str) -> String {
    let mut h = Sha256::new();
    h.update(rule_id.as_bytes());
    h.update(b"\0");
    h.update(rel_path.to_string_lossy().as_bytes());
    h.update(b"\0");
    h.update(snippet.trim().as_bytes());
    format!("{:x}", h.finalize())
}

/// Load a baseline from a JSON file.
pub fn load(path: &Path) -> Result<ScanReport> {
    let f = std::fs::File::open(path)
        .with_context(|| format!("Failed to open baseline: {}", path.display()))?;
    let report: ScanReport = serde_json::from_reader(f)
        .with_context(|| format!("Failed to parse baseline: {}", path.display()))?;
    Ok(report)
}

/// Save a scan report as a baseline JSON file.
pub fn save(report: &ScanReport, path: &Path) -> Result<()> {
    let f = std::fs::File::create(path)
        .with_context(|| format!("Failed to create baseline: {}", path.display()))?;
    serde_json::to_writer_pretty(f, report)
        .with_context(|| format!("Failed to write baseline: {}", path.display()))?;
    Ok(())
}

/// Filter a scan report to only findings not present in the baseline.
///
/// Uses two-level comparison:
/// 1. File-level: skip entirely if content_hash matches (fast path)
/// 2. Finding-level: compare fingerprints for changed files
pub fn diff(mut current: ScanReport, baseline: &ScanReport) -> DiffResult {
    // Build baseline content_hash lookup: relative_path -> hash
    let baseline_hashes: HashMap<PathBuf, String> = baseline
        .results
        .iter()
        .filter_map(|r| {
            r.content_hash.as_ref().map(|h| {
                let rel = r
                    .path
                    .strip_prefix(&baseline.scan_root)
                    .unwrap_or(&r.path)
                    .to_path_buf();
                (rel, h.clone())
            })
        })
        .collect();

    // Build fingerprint set from all baseline findings
    let baseline_fingerprints: HashSet<String> = baseline
        .results
        .iter()
        .flat_map(|r| {
            let rel = r
                .path
                .strip_prefix(&baseline.scan_root)
                .unwrap_or(&r.path)
                .to_path_buf();
            r.findings
                .iter()
                .map(move |f| finding_fingerprint(&f.rule_id, &rel, &f.snippet))
        })
        .collect();

    let scan_root = current.scan_root.clone();
    let mut files_unchanged = 0usize;
    let mut findings_suppressed = 0usize;

    let results = std::mem::take(&mut current.results);

    let new_results: Vec<ScanResult> = results
        .into_iter()
        .filter_map(|mut result| {
            let rel = result
                .path
                .strip_prefix(&scan_root)
                .unwrap_or(&result.path)
                .to_path_buf();

            // Fast path: file content unchanged — all findings are known
            if let (Some(curr_hash), Some(base_hash)) =
                (&result.content_hash, baseline_hashes.get(&rel))
            {
                if curr_hash == base_hash {
                    findings_suppressed += result.findings.len();
                    files_unchanged += 1;
                    return None;
                }
            }

            // Slow path: compare individual findings by fingerprint
            let before = result.findings.len();
            result.findings.retain(|f| {
                let fp = finding_fingerprint(&f.rule_id, &rel, &f.snippet);
                !baseline_fingerprints.contains(&fp)
            });
            findings_suppressed += before - result.findings.len();

            if result.findings.is_empty() {
                None
            } else {
                Some(result)
            }
        })
        .collect();

    current.results = new_results;
    current.risk_score = current.compute_risk_score();

    DiffResult {
        report: current,
        files_unchanged,
        findings_suppressed,
    }
}
