//! Hash-based scan result caching.
//!
//! Caches scan findings keyed by content SHA-256 hash. A "profile hash"
//! derived from scanner config ensures cache entries are invalidated when
//! analyzers, rules, or the vexscan version change.

use crate::types::Finding;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

/// Bump this to force global cache invalidation across all users.
const CACHE_VERSION: u32 = 1;

/// Maximum age of a cache entry before it's considered stale (7 days).
const MAX_AGE_SECS: i64 = 7 * 24 * 3600;

/// Inputs that affect scan output. Any change produces a different profile hash,
/// causing all existing cache entries to miss.
pub struct ScanProfile {
    pub enable_ast: bool,
    pub enable_deps: bool,
    pub enable_entropy: bool,
    pub rule_count: usize,
}

impl ScanProfile {
    /// Build a profile from the current scanner configuration.
    pub fn from_config(
        enable_ast: bool,
        enable_deps: bool,
        enable_entropy: bool,
        rule_count: usize,
    ) -> Self {
        Self {
            enable_ast,
            enable_deps,
            enable_entropy,
            rule_count,
        }
    }

    /// Compute a deterministic SHA-256 hash of all profile fields.
    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(CACHE_VERSION.to_le_bytes());
        hasher.update(env!("CARGO_PKG_VERSION").as_bytes());
        hasher.update(if self.enable_ast { &[1u8] } else { &[0u8] });
        hasher.update(if self.enable_deps { &[1u8] } else { &[0u8] });
        hasher.update(if self.enable_entropy { &[1u8] } else { &[0u8] });
        hasher.update(self.rule_count.to_le_bytes());
        format!("{:x}", hasher.finalize())
    }
}

/// On-disk format for a cached scan result.
#[derive(Serialize, Deserialize)]
struct CacheEntry {
    profile_hash: String,
    findings: Vec<Finding>,
    cached_at: i64,
}

/// File-system-backed scan result cache.
pub struct ScanCache {
    cache_dir: PathBuf,
    profile_hash: String,
}

impl ScanCache {
    /// Create a new cache, creating the directory if needed.
    pub fn new(profile: ScanProfile) -> Result<Self> {
        let cache_dir = dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("vexscan")
            .join("results");
        std::fs::create_dir_all(&cache_dir)?;
        Ok(Self {
            cache_dir,
            profile_hash: profile.hash(),
        })
    }

    /// Look up cached findings for a content hash. Returns `None` on miss,
    /// profile mismatch, or stale entry.
    pub fn get(&self, content_hash: &str) -> Option<Vec<Finding>> {
        let path = self.cache_dir.join(format!("{}.json", content_hash));
        let data = std::fs::read_to_string(&path).ok()?;
        let entry: CacheEntry = serde_json::from_str(&data).ok()?;

        if entry.profile_hash != self.profile_hash {
            return None;
        }

        let now = chrono::Utc::now().timestamp();
        if now - entry.cached_at > MAX_AGE_SECS {
            let _ = std::fs::remove_file(&path);
            return None;
        }

        Some(entry.findings)
    }

    /// Store findings for a content hash. Uses atomic write (tmp + rename).
    pub fn put(&self, content_hash: &str, findings: &[Finding]) -> Result<()> {
        let entry = CacheEntry {
            profile_hash: self.profile_hash.clone(),
            findings: findings.to_vec(),
            cached_at: chrono::Utc::now().timestamp(),
        };

        let json = serde_json::to_string(&entry)?;
        let tmp_path = self
            .cache_dir
            .join(format!("{}.{}.tmp", content_hash, std::process::id()));
        let final_path = self.cache_dir.join(format!("{}.json", content_hash));

        std::fs::write(&tmp_path, json)?;
        std::fs::rename(&tmp_path, &final_path)?;
        Ok(())
    }

    /// Delete all cache entries. Returns the number of entries removed.
    pub fn clear(&self) -> Result<usize> {
        let mut count = 0;
        if let Ok(entries) = std::fs::read_dir(&self.cache_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("json")
                    && std::fs::remove_file(&path).is_ok()
                {
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    /// Count the number of cached entries.
    pub fn entry_count(&self) -> usize {
        std::fs::read_dir(&self.cache_dir)
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|e| e.path().extension().and_then(|ext| ext.to_str()) == Some("json"))
                    .count()
            })
            .unwrap_or(0)
    }

    /// Total size of all cache files in bytes.
    pub fn total_size_bytes(&self) -> u64 {
        std::fs::read_dir(&self.cache_dir)
            .map(|entries| {
                entries
                    .flatten()
                    .filter_map(|e| e.metadata().ok().map(|m| m.len()))
                    .sum()
            })
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FindingCategory, Location, Severity};

    fn test_profile(ast: bool, deps: bool) -> ScanProfile {
        ScanProfile::from_config(ast, deps, false, 128)
    }

    fn test_finding() -> Finding {
        Finding::new(
            "TEST-001",
            "Test finding",
            "A test finding",
            Severity::Medium,
            FindingCategory::CodeExecution,
            Location::new(PathBuf::from("test.js"), 1, 1),
            "eval(x)",
        )
    }

    #[test]
    fn profile_hash_is_stable() {
        let p1 = test_profile(true, false);
        let p2 = test_profile(true, false);
        assert_eq!(p1.hash(), p2.hash());
    }

    #[test]
    fn profile_hash_changes_with_flags() {
        let p1 = test_profile(true, false);
        let p2 = test_profile(false, false);
        let p3 = test_profile(true, true);
        assert_ne!(p1.hash(), p2.hash());
        assert_ne!(p1.hash(), p3.hash());
    }

    #[test]
    fn profile_hash_changes_with_rule_count() {
        let p1 = ScanProfile::from_config(true, true, false, 128);
        let p2 = ScanProfile::from_config(true, true, false, 130);
        assert_ne!(p1.hash(), p2.hash());
    }

    #[test]
    fn put_get_roundtrip() {
        let cache = ScanCache::new(test_profile(true, false)).unwrap();
        let findings = vec![test_finding()];

        cache.put("abc123", &findings).unwrap();
        let cached = cache.get("abc123").unwrap();
        assert_eq!(cached.len(), 1);
        assert_eq!(cached[0].rule_id, "TEST-001");

        // Cleanup
        cache.clear().unwrap();
    }

    #[test]
    fn profile_mismatch_is_miss() {
        let cache1 = ScanCache::new(test_profile(true, false)).unwrap();
        let cache2 = ScanCache::new(test_profile(false, false)).unwrap();

        cache1.put("mismatch_test", &[test_finding()]).unwrap();
        assert!(cache2.get("mismatch_test").is_none());

        // Cleanup
        cache1.clear().unwrap();
    }

    #[test]
    fn clear_removes_entries() {
        let cache = ScanCache::new(test_profile(true, true)).unwrap();
        cache.put("clear_a", &[test_finding()]).unwrap();
        cache.put("clear_b", &[test_finding()]).unwrap();

        let removed = cache.clear().unwrap();
        assert!(removed >= 2);
        assert!(cache.get("clear_a").is_none());
    }
}
