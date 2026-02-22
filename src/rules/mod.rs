//! Security detection rules for the scanner.

pub mod loader;
pub mod patterns;

use crate::types::{FindingCategory, Severity};
use regex::{Regex, RegexSet};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// Scan context — what kind of content is being scanned.
/// Rules can opt in to specific contexts; rules with no context restriction fire everywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanContext {
    /// Source code files (js, ts, py, sh, etc.)
    Code,
    /// Configuration files (json, toml, yaml, plugin manifests)
    Config,
    /// Agent messages, user input, prompt text
    Message,
    /// Skill definitions (SKILL.md, frontmatter)
    Skill,
    /// Plugin files and manifests
    Plugin,
}

/// Source of a rule (official, community, or external).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleSource {
    #[default]
    Official,
    Community,
    External,
}

impl fmt::Display for RuleSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleSource::Official => write!(f, "official"),
            RuleSource::Community => write!(f, "community"),
            RuleSource::External => write!(f, "external"),
        }
    }
}

/// Test cases for validating rule patterns.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TestCases {
    /// Strings that should match the rule pattern.
    #[serde(default)]
    pub should_match: Vec<String>,
    /// Strings that should NOT match the rule pattern.
    #[serde(default)]
    pub should_not_match: Vec<String>,
}

/// Metadata for community-contributed rules.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleMetadata {
    /// GitHub username or name of the rule author.
    pub author: Option<String>,
    /// URL to author's profile.
    pub author_url: Option<String>,
    /// Semantic version of this rule.
    pub version: Option<String>,
    /// Date the rule was created.
    pub created: Option<String>,
    /// Date the rule was last updated.
    pub updated: Option<String>,
    /// URLs to relevant documentation or CVEs.
    #[serde(default)]
    pub references: Vec<String>,
    /// Searchable tags for categorization.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Test cases to validate the rule pattern.
    pub test_cases: Option<TestCases>,
}

/// A detection rule that matches suspicious patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Unique identifier for this rule.
    pub id: String,
    /// Human-readable title.
    pub title: String,
    /// Detailed description of what this rule detects.
    pub description: String,
    /// Severity when this rule matches.
    pub severity: Severity,
    /// Category of the finding.
    pub category: FindingCategory,
    /// Regex patterns to match (any match triggers a finding).
    pub patterns: Vec<String>,
    /// File extensions this rule applies to (empty = all).
    #[serde(default)]
    pub file_extensions: Vec<String>,
    /// Specific filenames this rule applies to (empty = all).
    /// When both file_extensions and file_names are set, both must match.
    #[serde(default)]
    pub file_names: Vec<String>,
    /// Scan contexts this rule applies to (empty = all contexts).
    /// When set, the rule only fires when scanning content of these types.
    #[serde(default)]
    pub contexts: Vec<ScanContext>,
    /// Patterns that exclude a match (e.g. safe IP ranges). If a match also
    /// matches any exclude pattern, it is silently dropped.
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
    /// Suggested remediation.
    pub remediation: Option<String>,
    /// Whether this rule is enabled by default.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Source of the rule (official or community).
    #[serde(default)]
    pub source: RuleSource,
    /// Optional metadata for community rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<RuleMetadata>,
}

fn default_true() -> bool {
    true
}

impl Rule {
    /// Compile all regex patterns for this rule.
    pub fn compile(&self) -> Result<CompiledRule, regex::Error> {
        let mut regexes = Vec::with_capacity(self.patterns.len());
        for pattern in &self.patterns {
            regexes.push(Regex::new(pattern)?);
        }
        let mut exclude_regexes = Vec::with_capacity(self.exclude_patterns.len());
        for pattern in &self.exclude_patterns {
            exclude_regexes.push(Regex::new(pattern)?);
        }
        Ok(CompiledRule {
            rule: self.clone(),
            regexes,
            exclude_regexes,
        })
    }

    /// Check if this rule applies to a given file extension.
    pub fn applies_to_extension(&self, ext: &str) -> bool {
        if self.file_extensions.is_empty() {
            return true;
        }
        self.file_extensions
            .iter()
            .any(|e| e.eq_ignore_ascii_case(ext))
    }

    /// Check if this rule applies to a specific filename (basename).
    /// Empty `file_names` means the rule applies to all files.
    pub fn applies_to_filename(&self, filename: &str) -> bool {
        if self.file_names.is_empty() {
            return true;
        }
        self.file_names
            .iter()
            .any(|n| n.eq_ignore_ascii_case(filename))
    }

    /// Check if this rule applies to a given scan context.
    /// Empty `contexts` means the rule applies in all contexts.
    pub fn applies_to_context(&self, context: Option<ScanContext>) -> bool {
        match context {
            None => true,
            Some(ctx) => self.contexts.is_empty() || self.contexts.contains(&ctx),
        }
    }
}

/// A rule with its compiled regexes.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub rule: Rule,
    pub regexes: Vec<Regex>,
    /// Compiled exclude patterns — matches hitting these are dropped.
    pub exclude_regexes: Vec<Regex>,
}

impl CompiledRule {
    /// Check if any pattern matches the given content (respecting exclude patterns).
    pub fn is_match(&self, content: &str) -> bool {
        if self.exclude_regexes.is_empty() {
            self.regexes.iter().any(|re| re.is_match(content))
        } else {
            !self.find_matches(content).is_empty()
        }
    }

    /// Find all matches across all patterns, filtering out excluded matches.
    pub fn find_matches<'a>(&'a self, content: &'a str) -> Vec<regex::Match<'a>> {
        let matches: Vec<_> = self
            .regexes
            .iter()
            .flat_map(|re| re.find_iter(content))
            .collect();
        if self.exclude_regexes.is_empty() {
            return matches;
        }
        matches
            .into_iter()
            .filter(|m| {
                !self
                    .exclude_regexes
                    .iter()
                    .any(|ex| ex.is_match(m.as_str()))
            })
            .collect()
    }
}

/// Collection of rules that can be loaded and managed.
#[derive(Debug, Default)]
pub struct RuleSet {
    rules: Vec<CompiledRule>,
    /// Pre-filter: all patterns in a single RegexSet for fast multi-pattern matching.
    regex_set: Option<RegexSet>,
    /// Maps each RegexSet pattern index to its rule index in `self.rules`.
    pattern_to_rule: Vec<usize>,
    /// Rule indices that apply to all extensions (empty file_extensions).
    universal_rules: Vec<usize>,
    /// Rule indices keyed by file extension (pre-computed at build time).
    extension_rules: HashMap<String, Vec<usize>>,
}

impl RuleSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the RegexSet pre-filter and extension index from all current rules.
    fn build_regex_set(&mut self) {
        let mut all_patterns = Vec::new();
        let mut mapping = Vec::new();

        for (rule_idx, rule) in self.rules.iter().enumerate() {
            for pattern in &rule.rule.patterns {
                all_patterns.push(pattern.as_str());
                mapping.push(rule_idx);
            }
        }

        self.pattern_to_rule = mapping;
        self.regex_set = RegexSet::new(all_patterns).ok();

        // Pre-compute per-extension rule indices
        self.universal_rules.clear();
        self.extension_rules.clear();
        for (idx, rule) in self.rules.iter().enumerate() {
            if rule.rule.file_extensions.is_empty() {
                self.universal_rules.push(idx);
            } else {
                for ext in &rule.rule.file_extensions {
                    self.extension_rules
                        .entry(ext.to_lowercase())
                        .or_default()
                        .push(idx);
                }
            }
        }
    }

    /// Load the built-in rules from embedded JSON files.
    pub fn with_builtin_rules(mut self) -> Result<Self, regex::Error> {
        for rule in loader::load_builtin_json_rules() {
            if rule.enabled {
                self.rules.push(rule.compile()?);
            }
        }
        self.build_regex_set();
        Ok(self)
    }

    /// Load rules from JSON files in a directory.
    pub fn with_rules_from_directory(
        mut self,
        dir: &std::path::Path,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let rules = loader::load_rules_from_directory(dir)?;
        for rule in rules {
            if rule.enabled {
                self.rules.push(rule.compile()?);
            }
        }
        self.build_regex_set();
        Ok(self)
    }

    /// Load rules from a directory with source tagging (mutable, graceful on error).
    pub fn add_rules_from_directory(
        &mut self,
        dir: &std::path::Path,
        source_override: Option<RuleSource>,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let rules = loader::load_rules_from_directory_with_source(dir, source_override)?;
        let mut count = 0;
        for rule in rules {
            if rule.enabled {
                self.rules.push(rule.compile()?);
                count += 1;
            }
        }
        self.build_regex_set();
        Ok(count)
    }

    /// Add a custom rule.
    pub fn add_rule(&mut self, rule: Rule) -> Result<(), regex::Error> {
        self.rules.push(rule.compile()?);
        self.build_regex_set();
        Ok(())
    }

    /// Get all rules.
    pub fn rules(&self) -> &[CompiledRule] {
        &self.rules
    }

    /// Number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Get rules applicable to a file extension.
    pub fn rules_for_extension(&self, ext: &str) -> Vec<&CompiledRule> {
        self.rules
            .iter()
            .filter(|r| r.rule.applies_to_extension(ext))
            .collect()
    }

    /// Get only rules that match content for a given extension, using RegexSet pre-filtering.
    /// Returns (rule, matches) pairs — only rules with actual hits.
    pub fn find_matches_for_extension<'a>(
        &'a self,
        content: &'a str,
        ext: &str,
    ) -> Vec<(&'a CompiledRule, Vec<regex::Match<'a>>)> {
        self.find_matches_for_file(content, ext, None)
    }

    pub fn find_matches_for_file<'a>(
        &'a self,
        content: &'a str,
        ext: &str,
        filename: Option<&str>,
    ) -> Vec<(&'a CompiledRule, Vec<regex::Match<'a>>)> {
        self.find_matches_for_file_in_context(content, ext, filename, None)
    }

    /// Like `find_matches_for_file` but also filters rules by scan context.
    /// Rules with no `contexts` restriction always fire. Rules with `contexts`
    /// only fire when the scan context matches.
    pub fn find_matches_for_file_in_context<'a>(
        &'a self,
        content: &'a str,
        ext: &str,
        filename: Option<&str>,
        context: Option<ScanContext>,
    ) -> Vec<(&'a CompiledRule, Vec<regex::Match<'a>>)> {
        // Use RegexSet pre-filter to find which rules have any match
        let matching_rule_indices: HashSet<usize> = if let Some(ref regex_set) = self.regex_set {
            regex_set
                .matches(content)
                .iter()
                .map(|pattern_idx| self.pattern_to_rule[pattern_idx])
                .collect()
        } else {
            // Fallback: all rules are candidates
            (0..self.rules.len()).collect()
        };

        // Combine universal rules with extension-specific rules (pre-computed at init)
        let ext_lower = ext.to_lowercase();
        let ext_specific = self.extension_rules.get(&ext_lower);

        // Only extract match positions from rules that actually hit
        self.universal_rules
            .iter()
            .chain(ext_specific.into_iter().flatten())
            .copied()
            .filter(|idx| matching_rule_indices.contains(idx))
            .filter(|idx| {
                // Apply filename filter if provided
                match filename {
                    Some(fname) => self.rules[*idx].rule.applies_to_filename(fname),
                    None => true,
                }
            })
            .filter(|idx| self.rules[*idx].rule.applies_to_context(context))
            .filter_map(|idx| {
                let rule = &self.rules[idx];
                let matches = rule.find_matches(content);
                if matches.is_empty() {
                    None
                } else {
                    Some((rule, matches))
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_compilation() {
        let rule = Rule {
            id: "test-001".to_string(),
            title: "Test Rule".to_string(),
            description: "A test rule".to_string(),
            severity: Severity::Medium,
            category: FindingCategory::CodeExecution,
            patterns: vec![r"eval\s*\(".to_string()],
            file_extensions: vec!["js".to_string(), "ts".to_string()],
            file_names: vec![],
            contexts: vec![],
            exclude_patterns: vec![],
            remediation: None,
            enabled: true,
            source: RuleSource::Official,
            metadata: None,
        };

        let compiled = rule.compile().unwrap();
        assert!(compiled.is_match("eval(code)"));
        assert!(compiled.is_match("eval (code)"));
        assert!(!compiled.is_match("evaluate(code)"));
    }

    #[test]
    fn test_rule_with_multiple_patterns() {
        let rule = Rule {
            id: "test-002".to_string(),
            title: "Multi-pattern Rule".to_string(),
            description: "A rule with multiple patterns".to_string(),
            severity: Severity::High,
            category: FindingCategory::CodeExecution,
            patterns: vec![
                r"\beval\s*\(".to_string(),
                r"\bnew\s+Function\s*\(".to_string(),
            ],
            file_extensions: vec![],
            file_names: vec![],
            contexts: vec![],
            exclude_patterns: vec![],
            remediation: None,
            enabled: true,
            source: RuleSource::Official,
            metadata: None,
        };

        let compiled = rule.compile().unwrap();
        assert!(compiled.is_match("eval(code)"));
        assert!(compiled.is_match("new Function('code')"));
        assert!(!compiled.is_match("evaluate(code)"));

        // find_matches should find matches from both patterns
        let matches = compiled.find_matches("eval(code) and new Function('x')");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_rule_with_test_cases() {
        let rule = Rule {
            id: "COMM-001".to_string(),
            title: "Test Community Rule".to_string(),
            description: "A test community rule".to_string(),
            severity: Severity::High,
            category: FindingCategory::CredentialAccess,
            patterns: vec![r"AKIA[0-9A-Z]{16}".to_string()],
            file_extensions: vec![],
            file_names: vec![],
            contexts: vec![],
            exclude_patterns: vec![],
            remediation: Some("Remove hardcoded keys".to_string()),
            enabled: true,
            source: RuleSource::Community,
            metadata: Some(RuleMetadata {
                author: Some("test-author".to_string()),
                author_url: Some("https://github.com/test-author".to_string()),
                version: Some("1.0.0".to_string()),
                created: Some("2026-02-02".to_string()),
                updated: Some("2026-02-02".to_string()),
                references: vec!["https://example.com".to_string()],
                tags: vec!["aws".to_string(), "credentials".to_string()],
                test_cases: Some(TestCases {
                    should_match: vec!["AKIAIOSFODNN7EXAMPLE".to_string()],
                    should_not_match: vec!["AKIAI".to_string()],
                }),
            }),
        };

        let compiled = rule.compile().unwrap();

        // Test should_match cases
        if let Some(ref metadata) = rule.metadata {
            if let Some(ref test_cases) = metadata.test_cases {
                for case in &test_cases.should_match {
                    assert!(compiled.is_match(case), "Should match: {}", case);
                }
                for case in &test_cases.should_not_match {
                    assert!(!compiled.is_match(case), "Should not match: {}", case);
                }
            }
        }
    }

    #[test]
    fn test_exclude_patterns() {
        let rule = Rule {
            id: "test-exclude".to_string(),
            title: "IP with excludes".to_string(),
            description: "Test exclude patterns".to_string(),
            severity: Severity::Low,
            category: FindingCategory::DataExfiltration,
            patterns: vec![r#"['"]([0-9]{1,3}\.){3}[0-9]{1,3}['"]"#.to_string()],
            file_extensions: vec![],
            file_names: vec![],
            contexts: vec![],
            exclude_patterns: vec![
                r#"['"]127\."#.to_string(),
                r#"['"]0\.0\.0\.0"#.to_string(),
                r#"['"]192\.168\."#.to_string(),
            ],
            remediation: None,
            enabled: true,
            source: RuleSource::Official,
            metadata: None,
        };

        let compiled = rule.compile().unwrap();

        // Suspicious public IP — should match
        assert!(compiled.is_match(r#""45.33.97.12""#));
        assert!(!compiled.find_matches(r#""45.33.97.12""#).is_empty());

        // Safe IPs — should be excluded
        assert!(!compiled.is_match(r#""127.0.0.1""#));
        assert!(!compiled.is_match(r#""0.0.0.0""#));
        assert!(!compiled.is_match(r#""192.168.1.1""#));
        assert!(compiled.find_matches(r#""127.0.0.1""#).is_empty());

        // Mixed content: only suspicious IP returned
        let content = r#"addr = "127.0.0.1"; c2 = "45.33.97.12""#;
        let matches = compiled.find_matches(content);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].as_str().contains("45.33.97.12"));
    }

    #[test]
    fn test_applies_to_filename_empty() {
        let rule = Rule {
            id: "test".to_string(),
            title: "test".to_string(),
            description: "test".to_string(),
            severity: Severity::Low,
            category: FindingCategory::Other("Test".to_string()),
            patterns: vec!["test".to_string()],
            file_extensions: vec![],
            file_names: vec![],
            contexts: vec![],
            exclude_patterns: vec![],
            remediation: None,
            enabled: true,
            source: RuleSource::Official,
            metadata: None,
        };
        // Empty file_names matches everything
        assert!(rule.applies_to_filename("anything.json"));
        assert!(rule.applies_to_filename("package.json"));
    }

    #[test]
    fn test_applies_to_filename_specific() {
        let rule = Rule {
            id: "test".to_string(),
            title: "test".to_string(),
            description: "test".to_string(),
            severity: Severity::Low,
            category: FindingCategory::Other("Test".to_string()),
            patterns: vec!["test".to_string()],
            file_extensions: vec!["json".to_string()],
            file_names: vec!["mcp.json".to_string(), ".mcp.json".to_string()],
            contexts: vec![],
            exclude_patterns: vec![],
            remediation: None,
            enabled: true,
            source: RuleSource::Official,
            metadata: None,
        };
        // Should match targeted filenames
        assert!(rule.applies_to_filename("mcp.json"));
        assert!(rule.applies_to_filename(".mcp.json"));
        // Case-insensitive
        assert!(rule.applies_to_filename("MCP.JSON"));
        // Should not match other filenames
        assert!(!rule.applies_to_filename("package.json"));
        assert!(!rule.applies_to_filename("tsconfig.json"));
    }

    #[test]
    fn test_find_matches_with_filename_filter() {
        let rule = Rule {
            id: "MCP-TEST".to_string(),
            title: "test mcp rule".to_string(),
            description: "test".to_string(),
            severity: Severity::High,
            category: FindingCategory::Other("MCP Configuration".to_string()),
            patterns: vec![r#""url"\s*:\s*"https?://[^"]+""#.to_string()],
            file_extensions: vec!["json".to_string()],
            file_names: vec!["mcp.json".to_string()],
            contexts: vec![],
            exclude_patterns: vec![],
            remediation: None,
            enabled: true,
            source: RuleSource::Official,
            metadata: None,
        };

        let mut ruleset = RuleSet::new();
        ruleset.add_rule(rule).unwrap();

        let content = r#""url": "https://evil.com/api""#;

        // Should match when filename is mcp.json
        let matches = ruleset.find_matches_for_file(content, "json", Some("mcp.json"));
        assert_eq!(matches.len(), 1);

        // Should NOT match when filename is package.json
        let matches = ruleset.find_matches_for_file(content, "json", Some("package.json"));
        assert!(matches.is_empty());

        // Should match when no filename provided (backwards compat)
        let matches = ruleset.find_matches_for_file(content, "json", None);
        assert_eq!(matches.len(), 1);
    }
}
