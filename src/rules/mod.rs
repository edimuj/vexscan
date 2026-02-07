//! Security detection rules for the scanner.

pub mod loader;
pub mod patterns;

use crate::types::{FindingCategory, Severity};
use regex::{Regex, RegexSet};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;

/// Source of a rule (official or community).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleSource {
    #[default]
    Official,
    Community,
}

impl fmt::Display for RuleSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleSource::Official => write!(f, "official"),
            RuleSource::Community => write!(f, "community"),
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
        Ok(CompiledRule {
            rule: self.clone(),
            regexes,
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
}

/// A rule with its compiled regexes.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub rule: Rule,
    pub regexes: Vec<Regex>,
}

impl CompiledRule {
    /// Check if any pattern matches the given content.
    pub fn is_match(&self, content: &str) -> bool {
        self.regexes.iter().any(|re| re.is_match(content))
    }

    /// Find all matches across all patterns in the given content.
    pub fn find_matches<'a>(&'a self, content: &'a str) -> Vec<regex::Match<'a>> {
        self.regexes
            .iter()
            .flat_map(|re| re.find_iter(content))
            .collect()
    }
}

/// Collection of rules that can be loaded and managed.
#[derive(Debug)]
pub struct RuleSet {
    rules: Vec<CompiledRule>,
    /// Pre-filter: all patterns in a single RegexSet for fast multi-pattern matching.
    regex_set: Option<RegexSet>,
    /// Maps each RegexSet pattern index to its rule index in `self.rules`.
    pattern_to_rule: Vec<usize>,
}

impl Default for RuleSet {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            regex_set: None,
            pattern_to_rule: Vec::new(),
        }
    }
}

impl RuleSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the RegexSet pre-filter from all current rules.
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
    }

    /// Load the built-in rules from JSON files (preferred) or compiled patterns (fallback).
    pub fn with_builtin_rules(mut self) -> Result<Self, regex::Error> {
        // Try JSON rules first
        let json_rules = loader::load_builtin_json_rules();

        if !json_rules.is_empty() {
            for rule in json_rules {
                if rule.enabled {
                    self.rules.push(rule.compile()?);
                }
            }
        } else {
            // Fall back to compiled patterns
            for rule in patterns::builtin_rules() {
                if rule.enabled {
                    self.rules.push(rule.compile()?);
                }
            }
        }
        self.build_regex_set();
        Ok(self)
    }

    /// Load rules from JSON files in a directory.
    pub fn with_rules_from_directory(mut self, dir: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let rules = loader::load_rules_from_directory(dir)?;
        for rule in rules {
            if rule.enabled {
                self.rules.push(rule.compile()?);
            }
        }
        self.build_regex_set();
        Ok(self)
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
        // Determine which rule indices apply to this extension
        let applicable: Vec<usize> = self
            .rules
            .iter()
            .enumerate()
            .filter(|(_, r)| r.rule.applies_to_extension(ext))
            .map(|(i, _)| i)
            .collect();

        // Use RegexSet pre-filter to find which rules have any match
        let matching_rule_indices: HashSet<usize> = if let Some(ref regex_set) = self.regex_set {
            regex_set
                .matches(content)
                .iter()
                .map(|pattern_idx| self.pattern_to_rule[pattern_idx])
                .collect()
        } else {
            // Fallback: all applicable rules are candidates
            applicable.iter().copied().collect()
        };

        // Only extract match positions from rules that actually hit
        applicable
            .into_iter()
            .filter(|idx| matching_rule_indices.contains(idx))
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
}
