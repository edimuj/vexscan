//! JSON rule loader for Vexscan.
//!
//! Loads rules from JSON files in the rules/ directory and subdirectories.

use super::{Rule, RuleMetadata, RuleSource, TestCases};
use crate::types::{FindingCategory, Severity};
use serde::Deserialize;
use std::path::Path;

/// JSON structure for a rule file.
#[derive(Debug, Deserialize)]
struct RuleFile {
    category: String,
    #[serde(default)]
    source: Option<String>,
    rules: Vec<JsonRule>,
}

/// JSON structure for test cases.
#[derive(Debug, Deserialize, Clone, Default)]
struct JsonTestCases {
    #[serde(default)]
    should_match: Vec<String>,
    #[serde(default)]
    should_not_match: Vec<String>,
}

/// JSON structure for a single rule.
#[derive(Debug, Deserialize)]
struct JsonRule {
    id: String,
    title: String,
    description: String,
    severity: String,
    /// Single pattern (backward compatible).
    pattern: Option<String>,
    /// Multiple patterns (OR semantics: any match triggers a finding).
    patterns: Option<Vec<String>>,
    #[serde(default)]
    file_extensions: Vec<String>,
    #[serde(default)]
    exclude_patterns: Vec<String>,
    remediation: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
    // Community metadata fields
    author: Option<String>,
    author_url: Option<String>,
    version: Option<String>,
    created: Option<String>,
    updated: Option<String>,
    #[serde(default)]
    references: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    test_cases: Option<JsonTestCases>,
}

fn default_true() -> bool {
    true
}

impl JsonRule {
    /// Convert JSON rule to internal Rule struct.
    fn to_rule(&self, category: &str, source: RuleSource) -> Rule {
        let metadata = if self.author.is_some()
            || self.version.is_some()
            || !self.references.is_empty()
            || !self.tags.is_empty()
            || self.test_cases.is_some()
        {
            Some(RuleMetadata {
                author: self.author.clone(),
                author_url: self.author_url.clone(),
                version: self.version.clone(),
                created: self.created.clone(),
                updated: self.updated.clone(),
                references: self.references.clone(),
                tags: self.tags.clone(),
                test_cases: self.test_cases.as_ref().map(|tc| TestCases {
                    should_match: tc.should_match.clone(),
                    should_not_match: tc.should_not_match.clone(),
                }),
            })
        } else {
            None
        };

        // Merge pattern/patterns: prefer `patterns`, fall back to wrapping `pattern`
        let patterns = if let Some(ref pats) = self.patterns {
            pats.clone()
        } else if let Some(ref pat) = self.pattern {
            vec![pat.clone()]
        } else {
            tracing::warn!(
                "Rule {} has neither pattern nor patterns; will never match",
                self.id
            );
            vec![]
        };

        Rule {
            id: self.id.clone(),
            title: self.title.clone(),
            description: self.description.clone(),
            severity: parse_severity(&self.severity),
            category: parse_category(category),
            patterns,
            file_extensions: self.file_extensions.clone(),
            exclude_patterns: self.exclude_patterns.clone(),
            remediation: self.remediation.clone(),
            enabled: self.enabled,
            source,
            metadata,
        }
    }
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        "info" => Severity::Info,
        _ => Severity::Medium,
    }
}

fn parse_category(s: &str) -> FindingCategory {
    match s.to_lowercase().as_str() {
        "code execution" => FindingCategory::CodeExecution,
        "shell execution" => FindingCategory::ShellExecution,
        "prompt injection" => FindingCategory::PromptInjection,
        "credential access" => FindingCategory::CredentialAccess,
        "data exfiltration" => FindingCategory::DataExfiltration,
        "obfuscation" => FindingCategory::Obfuscation,
        "hidden content" => FindingCategory::HiddenInstructions,
        "sensitive file access" => FindingCategory::SensitiveFileAccess,
        "authority impersonation" => FindingCategory::AuthorityImpersonation,
        other => FindingCategory::Other(other.to_string()),
    }
}

/// Parse rule source from string.
fn parse_source(s: Option<&str>) -> RuleSource {
    match s.map(|s| s.to_lowercase()).as_deref() {
        Some("community") => RuleSource::Community,
        _ => RuleSource::Official,
    }
}

/// Load rules from a JSON file.
pub fn load_rules_from_file(path: &Path) -> Result<Vec<Rule>, Box<dyn std::error::Error>> {
    load_rules_from_file_with_source(path, None)
}

/// Load rules from a JSON file with an optional source override.
pub fn load_rules_from_file_with_source(
    path: &Path,
    source_override: Option<RuleSource>,
) -> Result<Vec<Rule>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let rule_file: RuleFile = serde_json::from_str(&content)?;

    // Determine source: override > file > default (official)
    let source = source_override.unwrap_or_else(|| parse_source(rule_file.source.as_deref()));

    let rules: Vec<Rule> = rule_file
        .rules
        .iter()
        .map(|r| r.to_rule(&rule_file.category, source.clone()))
        .collect();

    Ok(rules)
}

/// Load all rules from JSON files in a directory (non-recursive).
pub fn load_rules_from_directory(dir: &Path) -> Result<Vec<Rule>, Box<dyn std::error::Error>> {
    load_rules_from_directory_with_source(dir, None)
}

/// Load all rules from JSON files in a directory with an optional source override.
pub fn load_rules_from_directory_with_source(
    dir: &Path,
    source_override: Option<RuleSource>,
) -> Result<Vec<Rule>, Box<dyn std::error::Error>> {
    let mut all_rules = Vec::new();

    if !dir.exists() {
        return Ok(all_rules);
    }

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().map(|e| e == "json").unwrap_or(false) {
            // Skip schema file
            if path
                .file_name()
                .map(|n| n == "rule-schema.json")
                .unwrap_or(false)
            {
                continue;
            }

            match load_rules_from_file_with_source(&path, source_override.clone()) {
                Ok(rules) => {
                    tracing::debug!("Loaded {} rules from {:?}", rules.len(), path);
                    all_rules.extend(rules);
                }
                Err(e) => {
                    tracing::warn!("Failed to load rules from {:?}: {}", path, e);
                }
            }
        }
    }

    Ok(all_rules)
}

/// Load rules from a directory tree (official/ and community/ subdirectories).
pub fn load_rules_from_directory_tree(dir: &Path) -> Result<Vec<Rule>, Box<dyn std::error::Error>> {
    let mut all_rules = Vec::new();

    if !dir.exists() {
        return Ok(all_rules);
    }

    // Check for official/ subdirectory
    let official_dir = dir.join("official");
    if official_dir.exists() && official_dir.is_dir() {
        match load_rules_from_directory_with_source(&official_dir, Some(RuleSource::Official)) {
            Ok(rules) => {
                tracing::info!("Loaded {} official rules", rules.len());
                all_rules.extend(rules);
            }
            Err(e) => {
                tracing::warn!("Failed to load official rules: {}", e);
            }
        }
    }

    // Check for community/ subdirectory
    let community_dir = dir.join("community");
    if community_dir.exists() && community_dir.is_dir() {
        match load_rules_from_directory_with_source(&community_dir, Some(RuleSource::Community)) {
            Ok(rules) => {
                tracing::info!("Loaded {} community rules", rules.len());
                all_rules.extend(rules);
            }
            Err(e) => {
                tracing::warn!("Failed to load community rules: {}", e);
            }
        }
    }

    // If no subdirectories found, load from root (backwards compatibility)
    if all_rules.is_empty() {
        all_rules = load_rules_from_directory(dir)?;
    }

    Ok(all_rules)
}

/// Parse rules from a JSON string with an explicit source.
fn load_rules_from_json_str(json: &str, source: RuleSource) -> Vec<Rule> {
    match serde_json::from_str::<RuleFile>(json) {
        Ok(rule_file) => rule_file
            .rules
            .iter()
            .map(|r| r.to_rule(&rule_file.category, source.clone()))
            .collect(),
        Err(e) => {
            tracing::warn!("Failed to parse embedded rule JSON: {}", e);
            Vec::new()
        }
    }
}

/// Embedded official rule JSON files (compiled into the binary).
const EMBEDDED_OFFICIAL: &[&str] = &[
    include_str!("../../rules/official/backdoor-detection.json"),
    include_str!("../../rules/official/code-execution.json"),
    include_str!("../../rules/official/credential-access.json"),
    include_str!("../../rules/official/dangerous-operations.json"),
    include_str!("../../rules/official/data-exfiltration.json"),
    include_str!("../../rules/official/hardcoded-secrets.json"),
    include_str!("../../rules/official/hidden-content.json"),
    include_str!("../../rules/official/obfuscation.json"),
    include_str!("../../rules/official/package-management.json"),
    include_str!("../../rules/official/prompt-injection.json"),
    include_str!("../../rules/official/remote-execution.json"),
    include_str!("../../rules/official/resource-abuse.json"),
    include_str!("../../rules/official/shell-execution.json"),
    include_str!("../../rules/official/shell-scripts.json"),
    include_str!("../../rules/official/powershell.json"),
    include_str!("../../rules/official/batch-scripts.json"),
    include_str!("../../rules/official/mcp-configuration.json"),
];

/// Embedded community rule JSON files (compiled into the binary).
const EMBEDDED_COMMUNITY: &[&str] = &[include_str!("../../rules/community/cloud-security.json")];

/// Load all built-in rules from embedded JSON (compiled into the binary).
/// No filesystem access needed — works in distributed binaries.
pub fn load_builtin_json_rules() -> Vec<Rule> {
    let mut all_rules = Vec::new();

    for json in EMBEDDED_OFFICIAL {
        all_rules.extend(load_rules_from_json_str(json, RuleSource::Official));
    }

    for json in EMBEDDED_COMMUNITY {
        all_rules.extend(load_rules_from_json_str(json, RuleSource::Community));
    }

    if !all_rules.is_empty() {
        tracing::info!("Loaded {} embedded rules", all_rules.len());
    } else {
        tracing::debug!("No embedded rules found, using compiled patterns");
    }

    all_rules
}

/// Filter rules by source.
pub fn filter_rules_by_source(rules: &[Rule], source: RuleSource) -> Vec<Rule> {
    rules
        .iter()
        .filter(|r| r.source == source)
        .cloned()
        .collect()
}

/// Filter rules by author.
pub fn filter_rules_by_author(rules: &[Rule], author: &str) -> Vec<Rule> {
    rules
        .iter()
        .filter(|r| {
            r.metadata
                .as_ref()
                .and_then(|m| m.author.as_ref())
                .map(|a| a.to_lowercase().contains(&author.to_lowercase()))
                .unwrap_or(false)
        })
        .cloned()
        .collect()
}

/// Filter rules by tag.
pub fn filter_rules_by_tag(rules: &[Rule], tag: &str) -> Vec<Rule> {
    rules
        .iter()
        .filter(|r| {
            r.metadata
                .as_ref()
                .map(|m| m.tags.iter().any(|t| t.eq_ignore_ascii_case(tag)))
                .unwrap_or(false)
        })
        .cloned()
        .collect()
}

/// Result of testing a single rule.
#[derive(Debug)]
pub struct RuleTestResult {
    pub rule_id: String,
    pub rule_title: String,
    pub passed: bool,
    pub should_match_passed: Vec<(String, bool)>,
    pub should_not_match_passed: Vec<(String, bool)>,
    pub error: Option<String>,
}

impl RuleTestResult {
    pub fn total_tests(&self) -> usize {
        self.should_match_passed.len() + self.should_not_match_passed.len()
    }

    pub fn passed_tests(&self) -> usize {
        self.should_match_passed.iter().filter(|(_, p)| *p).count()
            + self
                .should_not_match_passed
                .iter()
                .filter(|(_, p)| *p)
                .count()
    }

    pub fn failed_tests(&self) -> usize {
        self.total_tests() - self.passed_tests()
    }
}

/// Test a rule against its test cases.
pub fn test_rule(rule: &Rule) -> RuleTestResult {
    let mut result = RuleTestResult {
        rule_id: rule.id.clone(),
        rule_title: rule.title.clone(),
        passed: true,
        should_match_passed: Vec::new(),
        should_not_match_passed: Vec::new(),
        error: None,
    };

    // Try to compile the regex
    let compiled = match rule.compile() {
        Ok(c) => c,
        Err(e) => {
            result.passed = false;
            result.error = Some(format!("Failed to compile pattern: {}", e));
            return result;
        }
    };

    // Get test cases (if any)
    let test_cases = match &rule.metadata {
        Some(m) => m.test_cases.as_ref(),
        None => None,
    };

    if let Some(tc) = test_cases {
        // Test should_match cases
        for case in &tc.should_match {
            let matched = compiled.is_match(case);
            if !matched {
                result.passed = false;
            }
            result.should_match_passed.push((case.clone(), matched));
        }

        // Test should_not_match cases
        for case in &tc.should_not_match {
            let not_matched = !compiled.is_match(case);
            if !not_matched {
                result.passed = false;
            }
            result
                .should_not_match_passed
                .push((case.clone(), not_matched));
        }
    }

    result
}

/// Test all rules and return results.
pub fn test_all_rules(rules: &[Rule]) -> Vec<RuleTestResult> {
    rules.iter().map(test_rule).collect()
}

/// Test rules from a specific file.
pub fn test_rules_from_file(
    path: &Path,
) -> Result<Vec<RuleTestResult>, Box<dyn std::error::Error>> {
    let rules = load_rules_from_file(path)?;
    Ok(test_all_rules(&rules))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_severity() {
        assert!(matches!(parse_severity("critical"), Severity::Critical));
        assert!(matches!(parse_severity("HIGH"), Severity::High));
        assert!(matches!(parse_severity("Medium"), Severity::Medium));
        assert!(matches!(parse_severity("low"), Severity::Low));
        assert!(matches!(parse_severity("info"), Severity::Info));
    }

    #[test]
    fn test_load_json_rules() {
        let rules = load_builtin_json_rules();
        assert!(!rules.is_empty(), "Should load at least some JSON rules");
    }
}
