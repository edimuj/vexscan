//! Vexscan - Security Scanner for AI Agents
//!
//! A security scanner for AI agent plugins, skills, MCP servers, and configurations.
//!
//! # Features
//!
//! - **Static Analysis**: Pattern-based detection of malicious code
//! - **Encoding Detection**: Recursive decoding of base64, hex, unicode, etc.
//! - **AI Analysis**: Optional AI-powered detection of sophisticated threats
//! - **Multi-Platform**: Support for Claude Code, OpenClaw, Cursor, and more
//!
//! # Quick Start
//!
//! ```no_run
//! use vexscan::{Scanner, ScanConfig};
//! use std::path::PathBuf;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let scanner = Scanner::new()?;
//!     let report = scanner.scan_path(&PathBuf::from("./plugins")).await?;
//!
//!     println!("Found {} issues", report.total_findings());
//!     Ok(())
//! }
//! ```

pub mod adapters;
pub mod analyzers;
pub mod cli;
pub mod config;
pub mod decoders;
pub mod deps;
pub mod reporters;
pub mod rules;
pub mod types;

// Re-exports for convenience
pub use analyzers::{
    AiAnalyzer, AiAnalyzerConfig, AiBackend, AnalyzerConfig, AstAnalyzer, AstAnalyzerConfig,
    StaticAnalyzer,
};
pub use deps::{DependencyAnalyzer, DependencyAnalyzerConfig};
pub use config::Config;
pub use decoders::Decoder;
pub use reporters::{report, OutputFormat};
pub use rules::{
    loader::{
        filter_rules_by_author, filter_rules_by_source, filter_rules_by_tag,
        load_builtin_json_rules, load_rules_from_file, test_all_rules, test_rule,
        test_rules_from_file, RuleTestResult,
    },
    Rule, RuleMetadata, RuleSet, RuleSource, TestCases,
};
pub use types::{truncate, Finding, Platform, ScanReport, ScanResult, Severity};

use adapters::{create_adapter, detect_platform, PlatformAdapter};
use anyhow::Result;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;

/// Configuration for the scanner.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Enable AI-powered analysis.
    pub enable_ai: bool,
    /// AI analyzer configuration.
    pub ai_config: Option<AiAnalyzerConfig>,
    /// Enable AST-based analysis for obfuscation detection.
    pub enable_ast: bool,
    /// AST analyzer configuration.
    pub ast_config: Option<AstAnalyzerConfig>,
    /// Enable dependency scanning (package.json analysis).
    pub enable_deps: bool,
    /// Dependency analyzer configuration.
    pub deps_config: Option<DependencyAnalyzerConfig>,
    /// Static analyzer configuration.
    pub static_config: AnalyzerConfig,
    /// Minimum severity to include in results.
    pub min_severity: Severity,
    /// Platform to scan (auto-detect if None).
    pub platform: Option<Platform>,
    /// Filter configuration (allowlists, trusted packages).
    pub filter_config: Config,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            enable_ai: false,
            ai_config: None,
            enable_ast: false,
            ast_config: None,
            enable_deps: false,
            deps_config: None,
            static_config: AnalyzerConfig::default(),
            min_severity: Severity::Low,
            platform: None,
            filter_config: Config::load_default(),
        }
    }
}

/// The main scanner that coordinates all analysis.
pub struct Scanner {
    config: ScanConfig,
    static_analyzer: StaticAnalyzer,
    ast_analyzer: Option<Mutex<AstAnalyzer>>,
    deps_analyzer: Option<DependencyAnalyzer>,
    ai_analyzer: Option<AiAnalyzer>,
}

impl Scanner {
    /// Create a new scanner with default configuration.
    pub fn new() -> Result<Self> {
        Self::with_config(ScanConfig::default())
    }

    /// Create a scanner with custom configuration.
    pub fn with_config(config: ScanConfig) -> Result<Self> {
        let static_analyzer = StaticAnalyzer::with_config(config.static_config.clone())?;

        let ast_analyzer = if config.enable_ast {
            let ast_config = config.ast_config.clone().unwrap_or_default();
            Some(Mutex::new(AstAnalyzer::with_config(ast_config)?))
        } else {
            None
        };

        let deps_analyzer = if config.enable_deps {
            let deps_config = config.deps_config.clone().unwrap_or_default();
            Some(DependencyAnalyzer::with_config(deps_config)?)
        } else {
            None
        };

        let ai_analyzer = if config.enable_ai {
            config.ai_config.clone().map(AiAnalyzer::new)
        } else {
            None
        };

        Ok(Self {
            config,
            static_analyzer,
            ast_analyzer,
            deps_analyzer,
            ai_analyzer,
        })
    }

    /// Scan a specific path (file or directory).
    pub async fn scan_path(&self, path: &PathBuf) -> Result<ScanReport> {
        let start = Instant::now();
        let mut report = ScanReport::new(path.clone());

        // Determine platform and adapter
        let platform = self.config.platform.or_else(detect_platform);
        report.platform = platform.map(|p| p.to_string());

        let adapter: Box<dyn PlatformAdapter> = match platform {
            Some(p) => create_adapter(p),
            None => create_adapter(Platform::Generic),
        };

        // Discover components
        let components = adapter.discover_at(path)?;

        tracing::info!("Discovered {} components to scan", components.len());

        // Scan each component
        for component in components {
            // Check if path should be skipped
            if self.config.filter_config.should_skip_path(&component.path) {
                tracing::debug!("Skipping (allowlisted): {}", component.path.display());
                continue;
            }

            // If third_party_only mode, skip trusted/official sources
            if self.config.filter_config.third_party_only
                && self.config.filter_config.is_trusted_source(&component.path)
            {
                tracing::debug!("Skipping (trusted source): {}", component.path.display());
                continue;
            }

            tracing::debug!("Scanning: {}", component.path.display());

            match self.static_analyzer.scan_file(&component.path) {
                Ok(mut result) => {
                    // Filter by minimum severity and disabled rules
                    result.findings.retain(|f| {
                        f.severity >= self.config.min_severity
                            && !self.config.filter_config.is_rule_disabled(&f.rule_id)
                    });

                    // Run AST analysis if enabled
                    if let Some(ref ast_analyzer) = self.ast_analyzer {
                        match ast_analyzer.lock().unwrap().analyze_file(&component.path) {
                            Ok(ast_result) => {
                                let mut ast_findings: Vec<_> = ast_result
                                    .findings
                                    .into_iter()
                                    .filter(|f| f.severity >= self.config.min_severity)
                                    .collect();
                                result.findings.append(&mut ast_findings);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "AST analysis failed for {}: {}",
                                    component.path.display(),
                                    e
                                );
                            }
                        }
                    }

                    // Run dependency analysis if enabled and file is package.json
                    if let Some(ref deps_analyzer) = self.deps_analyzer {
                        if component.path.file_name().map(|n| n == "package.json").unwrap_or(false) {
                            match deps_analyzer.analyze_file(&component.path) {
                                Ok(deps_result) => {
                                    let mut deps_findings: Vec<_> = deps_result
                                        .findings
                                        .into_iter()
                                        .filter(|f| f.severity >= self.config.min_severity)
                                        .collect();
                                    result.findings.append(&mut deps_findings);
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "Dependency analysis failed for {}: {}",
                                        component.path.display(),
                                        e
                                    );
                                }
                            }
                        }
                    }

                    // Run AI analysis if enabled
                    if let Some(ref ai_analyzer) = self.ai_analyzer {
                        if let Ok(content) = std::fs::read_to_string(&component.path) {
                            let content_type =
                                analyzers::ContentType::Code; // TODO: infer from component type

                            match ai_analyzer
                                .analyze_content(&content, &component.path, content_type)
                                .await
                            {
                                Ok(ai_findings) => {
                                    result.findings.extend(ai_findings);
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "AI analysis failed for {}: {}",
                                        component.path.display(),
                                        e
                                    );
                                }
                            }
                        }
                    }

                    report.results.push(result);
                }
                Err(e) => {
                    tracing::warn!("Failed to scan {}: {}", component.path.display(), e);
                }
            }
        }

        report.total_time_ms = start.elapsed().as_millis() as u64;
        Ok(report)
    }

    /// Scan all installed components for the detected/specified platform.
    pub async fn scan_platform(&self) -> Result<ScanReport> {
        let platform = self.config.platform.or_else(detect_platform);

        let adapter: Box<dyn PlatformAdapter> = match platform {
            Some(p) => create_adapter(p),
            None => {
                return Err(anyhow::anyhow!(
                    "Could not detect platform. Specify --platform or provide a path."
                ));
            }
        };

        let default_paths = adapter.default_paths();
        if default_paths.is_empty() {
            return Err(anyhow::anyhow!("No default paths for platform"));
        }

        self.scan_path(&default_paths[0]).await
    }
}

impl Default for Scanner {
    fn default() -> Self {
        Self::new().expect("Failed to create default scanner")
    }
}
