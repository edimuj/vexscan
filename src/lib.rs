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
pub mod baseline;
pub mod cache;
pub mod cli;
pub mod components;
pub mod config;
pub mod decoders;
pub mod deps;
pub mod domains;
pub mod reporters;
pub mod rules;
pub mod scope;
pub mod trace;
pub mod trust;
pub mod types;

// Re-exports for convenience
pub use analyzers::{
    AiAnalyzer, AiAnalyzerConfig, AiBackend, AnalyzerConfig, AstAnalyzer, AstAnalyzerConfig,
    StaticAnalyzer,
};
pub use cache::{ScanCache, ScanProfile};
pub use components::{ComponentIndex, ComponentKind, DetectedComponent};
pub use config::Config;
pub use decoders::Decoder;
pub use deps::{DependencyAnalyzer, DependencyAnalyzerConfig};
pub use reporters::{report, OutputFormat};
pub use rules::{
    loader::{
        filter_rules_by_author, filter_rules_by_source, filter_rules_by_tag,
        load_builtin_json_rules, load_rules_from_file, test_all_rules, test_rule,
        test_rules_from_file, RuleTestResult,
    },
    Rule, RuleMetadata, RuleSet, RuleSource, ScanContext, TestCases,
};
pub use scope::{detect_scope, InstallScope, ScopeMap};
pub use trace::ReferenceGraph;
pub use trust::{TrustEntry, TrustLevel, TrustStore};
pub use types::{truncate, Finding, Platform, ScanReport, ScanResult, Severity};

use adapters::{create_adapter, detect_platform, PlatformAdapter};
use anyhow::Result;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
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
    /// Enable result caching (default true, disabled when AI is on).
    pub enable_cache: bool,
    /// Only scan installed/published files (skip dev-only files entirely).
    pub installed_only: bool,
    /// Scan all files at full severity (disable scope-based severity capping).
    pub include_dev: bool,
    /// Additional directories to load rules from at runtime.
    pub extra_rules_dirs: Vec<PathBuf>,
    /// Max parallel threads for scanning (0 = all CPUs, default = half CPUs).
    pub max_threads: usize,
    /// Scan context for rule filtering (None = all rules fire).
    pub scan_context: Option<rules::ScanContext>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        let filter_config = Config::load_default();
        let extra_rules_dirs = filter_config.resolved_extra_rules_dirs();
        Self {
            enable_ai: false,
            ai_config: None,
            enable_ast: false,
            ast_config: None,
            enable_deps: false,
            deps_config: None,
            static_config: AnalyzerConfig::default(),
            min_severity: Severity::High,
            platform: None,
            filter_config,
            enable_cache: true,
            installed_only: false,
            include_dev: false,
            extra_rules_dirs,
            max_threads: 0,
            scan_context: None,
        }
    }
}

/// Returns a sensible default thread count: half of available CPUs, minimum 1.
pub fn default_thread_count() -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    (cpus / 2).max(1)
}

/// Resolves the configured max_threads to an actual count.
/// 0 means "use default" (half CPUs).
fn resolve_thread_count(max_threads: usize) -> usize {
    if max_threads == 0 {
        default_thread_count()
    } else {
        max_threads
    }
}

/// Progress tracker for large scans. Shows progress on stderr when it's a TTY.
struct ScanProgress {
    total: usize,
    processed: AtomicUsize,
    show_progress: bool,
    start_time: Instant,
    last_update: AtomicUsize, // epoch millis of last update
}

impl ScanProgress {
    fn new(total: usize) -> Self {
        Self {
            total,
            processed: AtomicUsize::new(0),
            show_progress: std::io::stderr().is_terminal(),
            start_time: Instant::now(),
            last_update: AtomicUsize::new(0),
        }
    }

    /// Mark one file as processed and maybe print progress.
    /// Updates every ~500 files or every 2 seconds, whichever comes first.
    fn increment(&self) {
        let count = self.processed.fetch_add(1, Ordering::Relaxed) + 1;
        if !self.show_progress {
            return;
        }

        let elapsed_millis = self.start_time.elapsed().as_millis() as usize;
        let last = self.last_update.load(Ordering::Relaxed);

        // Update if 2 seconds passed OR every 500 files
        let should_update = (elapsed_millis - last >= 2000) || count.is_multiple_of(500);

        if should_update
            && self
                .last_update
                .compare_exchange(last, elapsed_millis, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            eprint!("\rScanning... {}/{} files", count, self.total);
            let _ = std::io::stderr().flush();
        }
    }

    /// Print final summary (always shown, even when not a TTY).
    fn finish(&self) {
        let elapsed = self.start_time.elapsed();
        let count = self.processed.load(Ordering::Relaxed);

        let (time_val, time_unit) = if elapsed.as_secs() < 60 {
            (elapsed.as_secs(), "s")
        } else {
            (elapsed.as_secs() / 60, "m")
        };

        let subsec = if time_unit == "m" {
            format!("{}s", elapsed.as_secs() % 60)
        } else {
            String::new()
        };

        if self.show_progress {
            // Clear progress line with \r, then print summary
            eprintln!(
                "\rScanned {} files in {}{}{}",
                count, time_val, time_unit, subsec
            );
        } else {
            // When piped/not TTY, just print to stderr without \r
            eprintln!(
                "Scanned {} files in {}{}{}",
                count, time_val, time_unit, subsec
            );
        }
    }
}

/// The main scanner that coordinates all analysis.
pub struct Scanner {
    config: ScanConfig,
    static_analyzer: StaticAnalyzer,
    ast_analyzer: Option<AstAnalyzer>,
    deps_analyzer: Option<DependencyAnalyzer>,
    ai_analyzer: Option<AiAnalyzer>,
    cache: Option<ScanCache>,
    trusted_domains: domains::TrustedDomainDb,
}

impl Scanner {
    /// Create a new scanner with default configuration.
    pub fn new() -> Result<Self> {
        Self::with_config(ScanConfig::default())
    }

    /// Create a scanner with custom configuration.
    pub fn with_config(config: ScanConfig) -> Result<Self> {
        let mut static_config = config.static_config.clone();
        // Propagate scan context from top-level config to the static analyzer
        if config.scan_context.is_some() && static_config.scan_context.is_none() {
            static_config.scan_context = config.scan_context;
        }
        // Context filtering happens in the rule matching phase, so cached results
        // (which store unfiltered findings) would bypass it. Disable caching when
        // a context is set to ensure consistent filtering.
        let mut config = config;
        if config.scan_context.is_some() {
            config.enable_cache = false;
        }
        let mut static_analyzer = StaticAnalyzer::with_config(static_config)?;

        // Load external rules from configured directories
        let mut external_rule_count = 0;
        for dir in &config.extra_rules_dirs {
            if dir.is_dir() {
                match static_analyzer.load_external_rules_dir(dir) {
                    Ok(count) => {
                        external_rule_count += count;
                        tracing::debug!("Loaded {} external rules from {}", count, dir.display());
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load rules from {}: {}", dir.display(), e);
                    }
                }
            }
        }
        if external_rule_count > 0 {
            tracing::info!(
                "Loaded {} external rules from {} dir(s)",
                external_rule_count,
                config
                    .extra_rules_dirs
                    .iter()
                    .filter(|d| d.is_dir())
                    .count()
            );
        }

        let ast_analyzer = if config.enable_ast {
            let ast_config = config.ast_config.clone().unwrap_or_default();
            Some(AstAnalyzer::with_config(ast_config)?)
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

        let cache = if config.enable_cache && !config.enable_ai {
            let profile = ScanProfile::from_config(
                config.enable_ast,
                config.enable_deps,
                config.static_config.enable_entropy,
                static_analyzer.rule_count(),
            );
            match ScanCache::new(profile) {
                Ok(c) => Some(c),
                Err(e) => {
                    tracing::warn!("Failed to initialize cache: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let trusted_domains = domains::TrustedDomainDb::load_builtin();

        Ok(Self {
            config,
            static_analyzer,
            ast_analyzer,
            deps_analyzer,
            ai_analyzer,
            cache,
            trusted_domains,
        })
    }

    /// Scan a specific path (file or directory).
    pub async fn scan_path(&self, path: &Path) -> Result<ScanReport> {
        let start = Instant::now();
        let mut report = ScanReport::new(path.to_path_buf());
        report.rule_count = self.static_analyzer.rule_count();
        report.ast_enabled = self.config.enable_ast;
        report.deps_enabled = self.config.enable_deps;

        // Determine platform and adapter
        let platform = self.config.platform.or_else(detect_platform);
        report.platform = platform.map(|p| p.to_string());

        let adapter: Box<dyn PlatformAdapter> = match platform {
            Some(p) => create_adapter(p),
            None => create_adapter(Platform::Generic),
        };

        // Detect logical AI components (skills, MCP servers, plugins, etc.)
        let detected_components = components::detect_components(path);
        report.components = detected_components;
        if !report.components.is_empty() {
            let mut kind_counts: std::collections::HashMap<components::ComponentKind, usize> =
                std::collections::HashMap::new();
            for comp in &report.components {
                *kind_counts.entry(comp.kind).or_insert(0) += 1;
            }
            let breakdown: Vec<String> = kind_counts
                .iter()
                .map(|(k, v)| format!("{} {}", v, k))
                .collect();
            tracing::info!(
                "Detected {} AI components ({})",
                report.components.len(),
                breakdown.join(", ")
            );
        }

        // Discover files to scan
        let components = adapter.discover_at(path)?;

        tracing::info!("Discovered {} components to scan", components.len());

        // Detect installation scope
        let scope_map = scope::detect_scope(path);
        let manifest_based = scope_map.manifest_based;
        tracing::info!(
            "Project type: {:?}, manifest-based: {}",
            scope_map.project_type,
            manifest_based
        );

        // Build agent instruction reference graph
        let ref_graph = trace::build_reference_graph(&components, path);
        if ref_graph.reachable_count() > 0 {
            tracing::info!(
                "Agent trace: {} files reachable from instruction files",
                ref_graph.reachable_count()
            );
        }

        // Filter components and classify scope once (avoids re-classifying in Phase 2)
        let installed_only = self.config.installed_only;
        let scannable: Vec<_> = components
            .into_iter()
            .filter_map(|c| {
                if self.config.filter_config.should_skip_path(&c.path) {
                    tracing::debug!("Skipping (allowlisted): {}", c.path.display());
                    return None;
                }
                if self.config.filter_config.third_party_only
                    && self.config.filter_config.is_trusted_source(&c.path)
                {
                    tracing::debug!("Skipping (trusted source): {}", c.path.display());
                    return None;
                }
                let file_scope = scope_map.classify(&c.path, path);
                // Skip dev-only files when --installed-only is set
                // (but keep agent-reachable files even if dev-only)
                if installed_only
                    && file_scope == scope::InstallScope::DevOnly
                    && !ref_graph.is_agent_reachable(&c.path)
                {
                    tracing::debug!("Skipping (dev-only): {}", c.path.display());
                    return None;
                }
                Some((c, file_scope))
            })
            .collect();

        // Phase 1: Parallel static + AST analysis (CPU-bound, read file once per component)
        // On cache hit, skip analysis entirely and return cached findings.
        let static_analyzer = &self.static_analyzer;
        let ast_analyzer = &self.ast_analyzer;
        let min_severity = self.config.min_severity;
        let filter_config = &self.config.filter_config;
        let cache = &self.cache;

        // Tuple: (component, content, result, cache_hit, file_scope)
        let num_threads = resolve_thread_count(self.config.max_threads);
        tracing::info!("Scanning with {} threads", num_threads);

        let progress = Arc::new(ScanProgress::new(scannable.len()));

        let static_results: Vec<_> = std::thread::scope(|s| {
            // Chunk work across a fixed number of threads instead of one-per-file
            let chunks: Vec<&[(_, _)]> = scannable
                .chunks((scannable.len() / num_threads).max(1))
                .collect();
            let handles: Vec<_> = chunks
                .into_iter()
                .map(|chunk| {
                    let progress = Arc::clone(&progress);
                    s.spawn(move || {
                        let mut results = Vec::with_capacity(chunk.len());
                        for (component, file_scope) in chunk {
                            tracing::debug!("Scanning: {}", component.path.display());
                            progress.increment();
                            let content = match std::fs::read_to_string(&component.path) {
                                Ok(c) => c,
                                Err(e) => {
                                    tracing::warn!(
                                        "Failed to read {}: {}",
                                        component.path.display(),
                                        e
                                    );
                                    continue;
                                }
                            };

                            // Compute content hash for cache lookup
                            let content_hash = {
                                use sha2::{Digest, Sha256};
                                let mut hasher = Sha256::new();
                                hasher.update(content.as_bytes());
                                format!("{:x}", hasher.finalize())
                            };

                            // Check cache
                            if let Some(ref cache) = cache {
                                if let Some(mut cached_findings) = cache.get(&content_hash) {
                                    tracing::debug!(
                                        "Cache hit: {} ({} findings)",
                                        component.path.display(),
                                        cached_findings.len()
                                    );
                                    for finding in &mut cached_findings {
                                        finding.location.file = component.path.clone();
                                    }
                                    let mut result = ScanResult::new(component.path.clone());
                                    result.content_hash = Some(content_hash);
                                    result.findings = cached_findings;
                                    results.push((component, content, result, true, *file_scope));
                                    continue;
                                }
                            }

                            // Cache miss — run static analysis (pass pre-computed hash)
                            let mut result = match static_analyzer.scan_content(
                                &content,
                                &component.path,
                                Some(content_hash),
                            ) {
                                Ok(result) => result,
                                Err(e) => {
                                    tracing::warn!(
                                        "Failed to scan {}: {}",
                                        component.path.display(),
                                        e
                                    );
                                    continue;
                                }
                            };

                            // AST analysis runs in the same thread (per-call parser, no Mutex)
                            if let Some(ref ast) = ast_analyzer {
                                match ast.analyze_content_str(&content, &component.path) {
                                    Ok(ast_result) => {
                                        result.findings.extend(ast_result.findings);
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

                            results.push((component, content, result, false, *file_scope));
                        }
                        results
                    })
                })
                .collect();

            handles
                .into_iter()
                .flat_map(|h| h.join().unwrap_or_default())
                .collect()
        });

        progress.finish();

        // Phase 2: Sequential post-processing (reuses already-read content + pre-computed scope)
        let include_dev = self.config.include_dev;
        let component_index = components::ComponentIndex::new(&report.components);
        for (component, content, mut result, cache_hit, mut file_scope) in static_results {
            // Assign file to nearest AI component (O(path depth) via HashMap)
            result.component_idx = component_index.assign(&component.path);
            // Elevate agent-reachable dev-only files
            let is_agent_reachable = ref_graph.is_agent_reachable(&component.path);
            if is_agent_reachable && file_scope == scope::InstallScope::DevOnly {
                file_scope = scope::InstallScope::Installed;
            }
            result.install_scope = Some(file_scope);

            // Track scope counts
            if is_agent_reachable {
                report.agent_reachable_count += 1;
            }
            match file_scope {
                scope::InstallScope::Installed => report.installed_file_count += 1,
                scope::InstallScope::DevOnly => report.dev_only_file_count += 1,
            }

            // Add agent-reachable metadata to findings
            if is_agent_reachable && !result.findings.is_empty() {
                let refs = ref_graph.referenced_by(&component.path);
                let ref_names: String = refs
                    .iter()
                    .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
                    .collect::<Vec<_>>()
                    .join(", ");
                for finding in &mut result.findings {
                    finding
                        .metadata
                        .insert("agent_reachable".to_string(), "true".to_string());
                    finding
                        .metadata
                        .insert("referenced_by".to_string(), ref_names.clone());
                }
            }

            // Trusted domain downgrade: if a finding's snippet contains a URL
            // to a trusted installer domain, downgrade to Info.
            for finding in &mut result.findings {
                if let Some(domain) = self.trusted_domains.check_snippet(&finding.snippet) {
                    if finding.severity > Severity::Info {
                        finding
                            .metadata
                            .entry("original_severity".to_string())
                            .or_insert_with(|| format!("{}", finding.severity));
                        finding
                            .metadata
                            .insert("trusted_domain".to_string(), domain);
                        finding.severity = Severity::Info;
                    }
                }
            }

            // Injection detector heuristic: downgrade INJECT/AUTH findings
            // that appear inside string literals, security tool files, or files
            // with high injection-pattern density (likely detectors, not attackers).
            let inject_count = result
                .findings
                .iter()
                .filter(|f| analyzers::injection_context::is_injection_rule(&f.rule_id))
                .count();
            for finding in &mut result.findings {
                if finding.severity > Severity::Low
                    && analyzers::injection_context::is_injection_rule(&finding.rule_id)
                {
                    if let Some(reason) = analyzers::injection_context::is_detection_context(
                        &finding.snippet,
                        &component.path,
                        inject_count,
                    ) {
                        finding
                            .metadata
                            .entry("original_severity".to_string())
                            .or_insert_with(|| format!("{}", finding.severity));
                        finding
                            .metadata
                            .insert("injection_context".to_string(), reason.to_string());
                        finding.severity = Severity::Low;
                    }
                }
            }

            // Cap ALL findings to Low on non-instruction, non-agent-reachable
            // markdown/text files. If no agent instruction file or script references
            // this doc, no AI agent will read it — nothing in it is a real threat.
            // This is reference-based scoping, not directory-based heuristics.
            if !is_agent_reachable && !trace::is_instruction_file(&component.path) {
                if let Some(ext) = component.path.extension().and_then(|e| e.to_str()) {
                    if matches!(ext, "md" | "markdown" | "txt") {
                        for finding in &mut result.findings {
                            if finding.severity > Severity::Low {
                                finding.metadata.insert(
                                    "original_severity".to_string(),
                                    format!("{}", finding.severity),
                                );
                                finding
                                    .metadata
                                    .insert("unreferenced_doc".to_string(), "true".to_string());
                                finding.severity = Severity::Low;
                            }
                        }
                    }
                }
            }

            if cache_hit {
                // Apply scope-based severity cap to cached findings
                if file_scope == scope::InstallScope::DevOnly && !include_dev {
                    for finding in &mut result.findings {
                        if finding.severity > Severity::Low
                            && !scope::is_scope_cap_exempt(&finding.rule_id, manifest_based)
                        {
                            finding.metadata.insert(
                                "original_severity".to_string(),
                                format!("{}", finding.severity),
                            );
                            finding
                                .metadata
                                .insert("install_scope".to_string(), "dev_only".to_string());
                            finding.severity = Severity::Low;
                        }
                    }
                }

                // Apply severity/disabled-rule filter to cached findings
                result.findings.retain(|f| {
                    f.severity >= min_severity && !filter_config.is_rule_disabled(&f.rule_id)
                });
                report.results.push(result);
                continue;
            }

            // Cache miss — run remaining analyzers (AST already done in Phase 1)
            if let Some(ref deps_analyzer) = self.deps_analyzer {
                if component
                    .path
                    .file_name()
                    .map(|n| n == "package.json")
                    .unwrap_or(false)
                {
                    match deps_analyzer.analyze_file(&component.path) {
                        Ok(deps_result) => {
                            result.findings.extend(deps_result.findings);
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

            // AI analysis reuses already-read content
            if let Some(ref ai_analyzer) = self.ai_analyzer {
                let content_type = analyzers::ContentType::Code;

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

            // Store unfiltered findings in cache before applying filters
            if let Some(ref cache) = self.cache {
                if let Some(ref hash) = result.content_hash {
                    if let Err(e) = cache.put(hash, &result.findings) {
                        tracing::debug!(
                            "Failed to cache result for {}: {}",
                            component.path.display(),
                            e
                        );
                    }
                }
            }

            // Apply scope-based severity cap (post-cache, like doc-file cap)
            if file_scope == scope::InstallScope::DevOnly && !include_dev {
                for finding in &mut result.findings {
                    if finding.severity > Severity::Low
                        && !scope::is_scope_cap_exempt(&finding.rule_id, manifest_based)
                    {
                        finding
                            .metadata
                            .entry("original_severity".to_string())
                            .or_insert_with(|| format!("{}", finding.severity));
                        finding
                            .metadata
                            .insert("install_scope".to_string(), "dev_only".to_string());
                        finding.severity = Severity::Low;
                    }
                }
            }

            // Now apply severity/disabled-rule filter
            result.findings.retain(|f| {
                f.severity >= min_severity && !filter_config.is_rule_disabled(&f.rule_id)
            });

            report.results.push(result);
        }

        report.total_time_ms = start.elapsed().as_millis() as u64;
        report.risk_score = report.compute_risk_score();
        Ok(report)
    }

    /// Scan all installed components for the detected/specified platform.
    /// Note: re-detects platform even though scan_path() also detects it.
    /// Acceptable — detect_platform() is cheap (directory marker checks).
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
