//! Vetryx - Security Scanner for AI Agents
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
//! use vetryx::{Scanner, ScanConfig};
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
pub mod reporters;
pub mod rules;
pub mod types;

// Re-exports for convenience
pub use analyzers::{AiAnalyzer, AiAnalyzerConfig, AiBackend, AnalyzerConfig, StaticAnalyzer};
pub use config::Config;
pub use decoders::Decoder;
pub use reporters::{report, OutputFormat};
pub use rules::RuleSet;
pub use types::{Finding, Platform, ScanReport, ScanResult, Severity};

use adapters::{create_adapter, detect_platform, PlatformAdapter};
use anyhow::Result;
use std::path::PathBuf;
use std::time::Instant;

/// Configuration for the scanner.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Enable AI-powered analysis.
    pub enable_ai: bool,
    /// AI analyzer configuration.
    pub ai_config: Option<AiAnalyzerConfig>,
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

        let ai_analyzer = if config.enable_ai {
            config.ai_config.clone().map(AiAnalyzer::new)
        } else {
            None
        };

        Ok(Self {
            config,
            static_analyzer,
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

            tracing::debug!("Scanning: {}", component.path.display());

            match self.static_analyzer.scan_file(&component.path) {
                Ok(mut result) => {
                    // Filter by minimum severity
                    result.findings.retain(|f| f.severity >= self.config.min_severity);

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
