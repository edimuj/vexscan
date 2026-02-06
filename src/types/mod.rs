//! Core type definitions for the Vexscan security scanner.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Severity level for security findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

/// Category of security finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    /// Code execution (eval, exec, etc.)
    CodeExecution,
    /// Shell command execution
    ShellExecution,
    /// File system access to sensitive paths
    SensitiveFileAccess,
    /// Network/data exfiltration
    DataExfiltration,
    /// Encoded/obfuscated content
    Obfuscation,
    /// Prompt injection patterns
    PromptInjection,
    /// Authority impersonation
    AuthorityImpersonation,
    /// Credential/secret access
    CredentialAccess,
    /// Permission escalation
    PrivilegeEscalation,
    /// Suspicious dependency
    SuspiciousDependency,
    /// Hidden instructions
    HiddenInstructions,
    /// Other/custom category
    Other(String),
}

impl std::fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FindingCategory::CodeExecution => write!(f, "Code Execution"),
            FindingCategory::ShellExecution => write!(f, "Shell Execution"),
            FindingCategory::SensitiveFileAccess => write!(f, "Sensitive File Access"),
            FindingCategory::DataExfiltration => write!(f, "Data Exfiltration"),
            FindingCategory::Obfuscation => write!(f, "Obfuscation"),
            FindingCategory::PromptInjection => write!(f, "Prompt Injection"),
            FindingCategory::AuthorityImpersonation => write!(f, "Authority Impersonation"),
            FindingCategory::CredentialAccess => write!(f, "Credential Access"),
            FindingCategory::PrivilegeEscalation => write!(f, "Privilege Escalation"),
            FindingCategory::SuspiciousDependency => write!(f, "Suspicious Dependency"),
            FindingCategory::HiddenInstructions => write!(f, "Hidden Instructions"),
            FindingCategory::Other(s) => write!(f, "{}", s),
        }
    }
}

/// Location of a finding within a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    /// File path where the finding was detected.
    pub file: PathBuf,
    /// Starting line number (1-indexed).
    pub start_line: usize,
    /// Ending line number (1-indexed).
    pub end_line: usize,
    /// Starting column (1-indexed, optional).
    pub start_column: Option<usize>,
    /// Ending column (1-indexed, optional).
    pub end_column: Option<usize>,
}

impl Location {
    pub fn new(file: PathBuf, start_line: usize, end_line: usize) -> Self {
        Self {
            file,
            start_line,
            end_line,
            start_column: None,
            end_column: None,
        }
    }

    pub fn with_columns(mut self, start: usize, end: usize) -> Self {
        self.start_column = Some(start);
        self.end_column = Some(end);
        self
    }
}

/// A security finding detected by the scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier for the rule that triggered this finding.
    pub rule_id: String,
    /// Human-readable title of the finding.
    pub title: String,
    /// Detailed description of the security concern.
    pub description: String,
    /// Severity level.
    pub severity: Severity,
    /// Category of the finding.
    pub category: FindingCategory,
    /// Location in the source file.
    pub location: Location,
    /// The actual code/content that triggered the finding.
    pub snippet: String,
    /// Suggested remediation (optional).
    pub remediation: Option<String>,
    /// Additional metadata.
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, String>,
}

impl Finding {
    pub fn new(
        rule_id: impl Into<String>,
        title: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
        category: FindingCategory,
        location: Location,
        snippet: impl Into<String>,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            title: title.into(),
            description: description.into(),
            severity,
            category,
            location,
            snippet: snippet.into(),
            remediation: None,
            metadata: std::collections::HashMap::new(),
        }
    }

    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Result of scanning a single file or component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Path that was scanned.
    pub path: PathBuf,
    /// All findings detected.
    pub findings: Vec<Finding>,
    /// Time taken to scan (in milliseconds).
    pub scan_time_ms: u64,
    /// SHA256 hash of the scanned content.
    pub content_hash: Option<String>,
}

impl ScanResult {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            findings: Vec::new(),
            scan_time_ms: 0,
            content_hash: None,
        }
    }

    pub fn has_findings(&self) -> bool {
        !self.findings.is_empty()
    }

    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    pub fn findings_by_severity(&self, severity: Severity) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .collect()
    }
}

/// Aggregated report from scanning multiple files/components.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    /// Platform that was scanned (if detected).
    pub platform: Option<String>,
    /// Root path that was scanned.
    pub scan_root: PathBuf,
    /// Individual scan results.
    pub results: Vec<ScanResult>,
    /// Total time taken (in milliseconds).
    pub total_time_ms: u64,
    /// Timestamp of the scan.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl ScanReport {
    pub fn new(scan_root: PathBuf) -> Self {
        Self {
            platform: None,
            scan_root,
            results: Vec::new(),
            total_time_ms: 0,
            timestamp: chrono::Utc::now(),
        }
    }

    pub fn total_findings(&self) -> usize {
        self.results.iter().map(|r| r.findings.len()).sum()
    }

    pub fn max_severity(&self) -> Option<Severity> {
        self.results.iter().filter_map(|r| r.max_severity()).max()
    }

    pub fn findings_count_by_severity(&self) -> std::collections::HashMap<Severity, usize> {
        let mut counts = std::collections::HashMap::new();
        for result in &self.results {
            for finding in &result.findings {
                *counts.entry(finding.severity).or_insert(0) += 1;
            }
        }
        counts
    }
}

/// Truncate a string to a maximum number of characters (UTF-8 safe).
/// Appends "..." if truncated.
pub fn truncate(s: &str, max_chars: usize) -> String {
    let char_count = s.chars().count();
    if char_count <= max_chars {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max_chars).collect();
        format!("{}...", truncated)
    }
}

/// Supported AI agent platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Platform {
    ClaudeCode,
    OpenClaw,
    Cursor,
    Codex,
    Generic,
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Platform::ClaudeCode => write!(f, "claude-code"),
            Platform::OpenClaw => write!(f, "openclaw"),
            Platform::Cursor => write!(f, "cursor"),
            Platform::Codex => write!(f, "codex"),
            Platform::Generic => write!(f, "generic"),
        }
    }
}

impl std::str::FromStr for Platform {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "claude-code" | "claudecode" | "claude" => Ok(Platform::ClaudeCode),
            "openclaw" | "claw" => Ok(Platform::OpenClaw),
            "cursor" => Ok(Platform::Cursor),
            "codex" => Ok(Platform::Codex),
            "generic" | "dir" | "directory" => Ok(Platform::Generic),
            _ => Err(format!("Unknown platform: {}", s)),
        }
    }
}
