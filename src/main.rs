//! CLI entry point for the Vexscan security scanner.

use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing_subscriber::EnvFilter;

/// Global quiet flag — suppresses informational stderr output.
static QUIET: AtomicBool = AtomicBool::new(false);

/// Print to stderr unless --quiet is set. Use for informational output only.
/// Errors should always use eprintln! directly.
macro_rules! info {
    ($($arg:tt)*) => {
        if !QUIET.load(Ordering::Relaxed) {
            eprintln!($($arg)*);
        }
    };
}
use vexscan::{
    cli::{CacheSubcommand, Cli, Commands, RulesSubcommand, TrustSubcommand},
    config::{generate_default_config, Config},
    decoders::Decoder,
    filter_rules_by_author, filter_rules_by_source, filter_rules_by_tag, load_builtin_json_rules,
    reporters::{report, OutputFormat},
    test_all_rules, test_rules_from_file, truncate, AiAnalyzerConfig, AiBackend, AnalyzerConfig,
    AstAnalyzer, Platform, RuleSource, ScanCache, ScanConfig, ScanContext, ScanProfile, Scanner,
    Severity, StaticAnalyzer, TrustEntry, TrustLevel, TrustStore,
};

fn parse_scan_context(s: &str) -> Result<ScanContext> {
    match s.to_lowercase().as_str() {
        "code" => Ok(ScanContext::Code),
        "config" => Ok(ScanContext::Config),
        "message" => Ok(ScanContext::Message),
        "skill" => Ok(ScanContext::Skill),
        "plugin" => Ok(ScanContext::Plugin),
        _ => anyhow::bail!(
            "Unknown scan context '{}'. Valid contexts: code, config, message, skill, plugin",
            s
        ),
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{}: {:?}", "Error".bright_red().bold(), e);
        std::process::exit(2);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    QUIET.store(cli.quiet, Ordering::Relaxed);

    // Initialize logging (stderr to avoid interfering with JSON output)
    let log_level = if cli.quiet {
        "warn"
    } else if cli.verbose {
        "debug"
    } else {
        "info"
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| log_level.into()))
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    // Load config file if specified, otherwise use defaults
    let base_config = if let Some(ref config_path) = cli.config {
        Config::load(config_path)?
    } else {
        Config::load_default()
    };

    let scan_context = cli
        .context
        .as_deref()
        .map(parse_scan_context)
        .transpose()?;

    match cli.command {
        Commands::Scan {
            path,
            platform,
            ai,
            ai_backend,
            output,
            min_severity,
            fail_on,
            skip_deps,
            enable_entropy,
            trusted_packages,
            third_party_only,
            ast,
            deps,
            no_cache,
            installed_only,
            include_dev,
            jobs,
            save_baseline,
            diff,
        } => {
            // Parse platform
            let platform: Option<Platform> = platform
                .map(|p| p.parse())
                .transpose()
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            // Parse severity
            let min_severity = parse_severity(&min_severity)?;
            let fail_on_severity = parse_severity(&fail_on)?;

            // Build filter config from base + CLI overrides
            let mut filter_config = base_config;
            if skip_deps {
                filter_config.skip_node_modules = true;
            }
            if third_party_only {
                filter_config.third_party_only = true;
            }
            for pkg in trusted_packages {
                if !filter_config.trusted_packages.contains(&pkg) {
                    filter_config.trusted_packages.push(pkg);
                }
            }

            // Build static analyzer config
            let mut static_config = AnalyzerConfig::default();
            if enable_entropy {
                static_config.enable_entropy = true;
            }

            // Resolve extra rules directories
            let extra_rules_dirs = filter_config.resolved_extra_rules_dirs();

            // Build scan config
            let mut config = ScanConfig {
                enable_ai: ai,
                enable_ast: ast,
                enable_deps: deps,
                enable_cache: !no_cache,
                platform,
                min_severity,
                filter_config,
                static_config,
                installed_only,
                include_dev,
                extra_rules_dirs,
                max_threads: jobs.unwrap_or(0),
                scan_context,
                ..Default::default()
            };

            // Configure AI if enabled
            if ai {
                let backend = match ai_backend.to_lowercase().as_str() {
                    "claude" => AiBackend::Claude,
                    "openai" => AiBackend::OpenAi,
                    "ollama" => AiBackend::Ollama,
                    _ => {
                        return Err(anyhow::anyhow!("Unknown AI backend: {}", ai_backend));
                    }
                };

                let api_key = match backend {
                    AiBackend::Claude => std::env::var("ANTHROPIC_API_KEY").ok(),
                    AiBackend::OpenAi => std::env::var("OPENAI_API_KEY").ok(),
                    AiBackend::Ollama => None,
                    AiBackend::Local => None,
                };

                config.ai_config = Some(AiAnalyzerConfig {
                    backend,
                    api_key,
                    ..Default::default()
                });
            }

            // Run scanner
            let scanner = Scanner::with_config(config)?;
            let mut scan_report = scanner.scan_path(&path).await?;

            // Apply trust store (suppress reviewed findings)
            let trust_store = TrustStore::load().unwrap_or_default();
            let suppressed = trust_store.apply_to_report(&mut scan_report);
            if suppressed > 0 {
                info!(
                    "{} {} finding(s) suppressed by trust store",
                    "Trust:".dimmed(),
                    suppressed
                );
            }

            // Snapshot full report before diff (for --save-baseline)
            let full_report = if save_baseline.is_some() {
                Some(scan_report.clone())
            } else {
                None
            };

            // Apply baseline diff
            if let Some(ref baseline_path) = diff {
                let baseline = vexscan::baseline::load(baseline_path)?;
                let result = vexscan::baseline::diff(scan_report, &baseline);
                info!(
                    "{} {} file(s) unchanged, {} finding(s) suppressed by baseline",
                    "Baseline:".dimmed(),
                    result.files_unchanged,
                    result.findings_suppressed,
                );
                scan_report = result.report;
            }

            // Save baseline (full report, not the diffed one)
            if let Some(ref baseline_path) = save_baseline {
                let to_save = full_report.as_ref().unwrap_or(&scan_report);
                vexscan::baseline::save(to_save, baseline_path)?;
                info!("Baseline saved to: {}", baseline_path.display());
            }

            // Output format
            let format: OutputFormat = cli.format.parse().map_err(|e| anyhow::anyhow!("{}", e))?;

            // Write output
            if let Some(output_path) = output {
                let mut file = std::fs::File::create(&output_path)?;
                report(&scan_report, format, &mut file)?;
                info!("Report written to: {}", output_path.display());
            } else {
                let mut stdout = io::stdout().lock();
                report(&scan_report, format, &mut stdout)?;
            }

            // Hint about additional analyzers
            if !ast && !deps {
                info!(
                    "\n{} Use {} for obfuscation detection and {} for supply chain checks.",
                    "Tip:".dimmed(),
                    "--ast".bold(),
                    "--deps".bold()
                );
            } else if !ast {
                info!(
                    "\n{} Use {} for obfuscation detection.",
                    "Tip:".dimmed(),
                    "--ast".bold()
                );
            } else if !deps {
                info!(
                    "\n{} Use {} for supply chain checks.",
                    "Tip:".dimmed(),
                    "--deps".bold()
                );
            }

            // Check fail condition (ignore suppressed findings)
            if let Some(max_sev) = scan_report.max_active_severity() {
                if max_sev >= fail_on_severity {
                    std::process::exit(1);
                }
            }
        }

        Commands::Watch {
            platform,
            notify: send_notifications,
            third_party_only,
            min_severity,
            watch_paths,
            installed_only,
            include_dev,
        } => {
            use notify::{Config as NotifyConfig, RecommendedWatcher, RecursiveMode, Watcher};
            use std::sync::mpsc::channel;
            use std::time::Duration;

            let platform: Option<Platform> = platform
                .map(|p| p.parse())
                .transpose()
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            let min_severity = parse_severity(&min_severity)?;

            // Build filter config
            let mut filter_config = base_config;
            filter_config.third_party_only = third_party_only;

            // Determine paths to watch
            let paths_to_watch: Vec<PathBuf> = if !watch_paths.is_empty() {
                watch_paths
            } else {
                // Get default paths from platform adapter
                let resolved_platform = platform.or_else(vexscan::adapters::detect_platform);
                match resolved_platform {
                    Some(p) => {
                        let adapter = vexscan::adapters::create_adapter(p);
                        adapter.default_paths()
                    }
                    None => {
                        return Err(anyhow::anyhow!(
                            "Could not detect platform. Use --platform or --path to specify."
                        ));
                    }
                }
            };

            if paths_to_watch.is_empty() {
                return Err(anyhow::anyhow!("No paths to watch."));
            }

            // Print startup info
            info!("{}", "═".repeat(60).bright_blue());
            info!("{}  {} Watch Mode", "👁".bright_blue(), "Vexscan".bold());
            info!("{}", "═".repeat(60).bright_blue());
            info!();
            info!("{}", "Watching for new plugin installations...".cyan());
            for path in &paths_to_watch {
                info!("  {} {}", "→".dimmed(), path.display());
            }
            if third_party_only {
                info!("  {} Only alerting on third-party plugins", "ℹ".blue());
            }
            info!("  {} Minimum severity: {:?}", "ℹ".blue(), min_severity);
            if send_notifications {
                info!("  {} Desktop notifications enabled", "🔔".yellow());
            }
            info!();
            info!("{}", "Press Ctrl+C to stop.".dimmed());
            info!();

            // Create scanner config
            let extra_rules_dirs = filter_config.resolved_extra_rules_dirs();
            let scan_config = ScanConfig {
                enable_ai: false,
                platform,
                min_severity,
                filter_config: filter_config.clone(),
                static_config: AnalyzerConfig::default(),
                installed_only,
                include_dev,
                extra_rules_dirs,
                scan_context,
                ..Default::default()
            };

            let scanner = Scanner::with_config(scan_config)?;

            // Set up file watcher
            let (tx, rx) = channel();

            let mut watcher = RecommendedWatcher::new(
                move |res| {
                    if let Ok(event) = res {
                        let _ = tx.send(event);
                    }
                },
                NotifyConfig::default().with_poll_interval(Duration::from_secs(2)),
            )?;

            // Watch all paths
            for path in &paths_to_watch {
                if path.exists() {
                    watcher.watch(path, RecursiveMode::Recursive)?;
                } else {
                    info!(
                        "{} Path does not exist, skipping: {}",
                        "⚠".yellow(),
                        path.display()
                    );
                }
            }

            // Track seen files to avoid duplicate scans (capped to prevent unbounded growth)
            let mut seen_files: std::collections::HashSet<PathBuf> =
                std::collections::HashSet::new();
            const MAX_SEEN_FILES: usize = 10_000;

            // Event loop
            loop {
                match rx.recv() {
                    Ok(event) => {
                        // Only process Create events
                        if !matches!(
                            event.kind,
                            notify::EventKind::Create(_) | notify::EventKind::Modify(_)
                        ) {
                            continue;
                        }

                        for path in event.paths {
                            // Skip if we've already seen this file
                            if seen_files.contains(&path) {
                                continue;
                            }
                            if seen_files.len() >= MAX_SEEN_FILES {
                                // Evict half instead of clearing everything to reduce duplicate scans
                                let to_remove: Vec<_> = seen_files
                                    .iter()
                                    .take(MAX_SEEN_FILES / 2)
                                    .cloned()
                                    .collect();
                                for key in &to_remove {
                                    seen_files.remove(key);
                                }
                            }
                            seen_files.insert(path.clone());

                            // Skip non-files
                            if !path.is_file() {
                                continue;
                            }

                            // Skip if in trusted source and third_party_only is set
                            if third_party_only && filter_config.is_trusted_source(&path) {
                                continue;
                            }

                            // Skip if should be skipped by normal rules
                            if filter_config.should_skip_path(&path) {
                                continue;
                            }

                            info!("\n{} New file detected: {}", "📄".cyan(), path.display());

                            // Scan the file
                            match scanner.scan_path(&path).await {
                                Ok(scan_report) => {
                                    let findings_count = scan_report.total_findings();

                                    if findings_count > 0 {
                                        let max_sev = scan_report.max_severity();

                                        // Print alert
                                        info!(
                                            "{} {} finding(s) in {}",
                                            "🚨".bright_red(),
                                            findings_count.to_string().bright_red(),
                                            path.file_name()
                                                .map(|n| n.to_string_lossy().to_string())
                                                .unwrap_or_else(|| path.display().to_string())
                                        );

                                        // Show brief summary
                                        for result in &scan_report.results {
                                            for finding in &result.findings {
                                                let sev_icon = match finding.severity {
                                                    Severity::Critical => "▲".bright_red(),
                                                    Severity::High => "▲".red(),
                                                    Severity::Medium => "●".yellow(),
                                                    Severity::Low => "●".blue(),
                                                    Severity::Info => "○".white(),
                                                };
                                                info!(
                                                    "   {} [{}] {}",
                                                    sev_icon,
                                                    finding.rule_id.dimmed(),
                                                    finding.title
                                                );
                                            }
                                        }

                                        // Desktop notification
                                        if send_notifications {
                                            let severity_text = max_sev
                                                .map(|s| format!("{:?}", s))
                                                .unwrap_or_else(|| "Unknown".to_string());

                                            send_desktop_notification(
                                                &format!(
                                                    "Vexscan: {} issue(s) found",
                                                    findings_count
                                                ),
                                                &format!(
                                                    "{} in {}\nMax severity: {}",
                                                    findings_count,
                                                    path.file_name()
                                                        .map(|n| n.to_string_lossy().to_string())
                                                        .unwrap_or_default(),
                                                    severity_text
                                                ),
                                            );
                                        }
                                    } else {
                                        info!("   {} No issues found", "✓".green());
                                    }
                                }
                                Err(e) => {
                                    eprintln!("   {} Failed to scan: {}", "⚠".yellow(), e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Watch error: {}", e);
                        break;
                    }
                }
            }
        }

        Commands::List { platform } => {
            let platform: Option<Platform> = platform
                .map(|p| p.parse())
                .transpose()
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            let resolved_platform = platform.or_else(vexscan::adapters::detect_platform);

            match resolved_platform {
                Some(p) => {
                    let adapter = vexscan::adapters::create_adapter(p);
                    let components = adapter.discover()?;

                    println!("{}", format!("Platform: {}", p).bold());
                    println!("Discovered {} components:\n", components.len());

                    for component in components {
                        println!(
                            "  {} [{}]",
                            component.path.display(),
                            format!("{}", component.component_type).dimmed()
                        );
                    }
                }
                None => {
                    eprintln!("Could not detect platform. Specify --platform.");
                    std::process::exit(1);
                }
            }
        }

        Commands::Rules {
            rule,
            official,
            community,
            external,
            author,
            tag,
            json,
            subcommand,
        } => {
            // Handle subcommands first
            if let Some(subcmd) = subcommand {
                match subcmd {
                    RulesSubcommand::Test {
                        path,
                        filter,
                        verbose,
                    } => {
                        let results = if let Some(p) = path {
                            // Test specific file
                            info!("{} {}", "Testing rules from:".cyan(), p.display());
                            match test_rules_from_file(&p) {
                                Ok(r) => r,
                                Err(e) => {
                                    eprintln!("{} Failed to load rules: {}", "Error:".red(), e);
                                    std::process::exit(1);
                                }
                            }
                        } else {
                            // Test all built-in rules
                            info!("{}", "Testing all built-in rules...".cyan());
                            let rules = load_builtin_json_rules();
                            test_all_rules(&rules)
                        };

                        // Filter results if needed
                        let results: Vec<_> = if let Some(ref f) = filter {
                            results
                                .into_iter()
                                .filter(|r| r.rule_id.to_lowercase().contains(&f.to_lowercase()))
                                .collect()
                        } else {
                            results
                        };

                        // Display results
                        let mut total_passed = 0;
                        let mut total_failed = 0;
                        let mut rules_with_tests = 0;
                        let mut rules_passed = 0;

                        for result in &results {
                            if result.total_tests() == 0 && !verbose {
                                continue;
                            }

                            rules_with_tests += 1;

                            let status_icon = if result.passed {
                                rules_passed += 1;
                                "✓".green()
                            } else {
                                "✗".red()
                            };

                            if result.passed && !verbose {
                                total_passed += result.total_tests();
                                println!(
                                    "{} {} - {} ({} tests)",
                                    status_icon,
                                    result.rule_id.cyan(),
                                    result.rule_title,
                                    result.total_tests()
                                );
                            } else {
                                println!(
                                    "{} {} - {}",
                                    status_icon,
                                    result.rule_id.cyan(),
                                    result.rule_title
                                );

                                if let Some(ref err) = result.error {
                                    println!("  {} {}", "Error:".red(), err);
                                }

                                // Show should_match results
                                for (case, passed) in &result.should_match_passed {
                                    let icon = if *passed {
                                        total_passed += 1;
                                        "✓".green()
                                    } else {
                                        total_failed += 1;
                                        "✗".red()
                                    };
                                    let expected = if *passed { "" } else { " (expected match)" };
                                    println!(
                                        "  {} should_match: \"{}\"{}",
                                        icon,
                                        truncate(case, 50),
                                        expected.red()
                                    );
                                }

                                // Show should_not_match results
                                for (case, passed) in &result.should_not_match_passed {
                                    let icon = if *passed {
                                        total_passed += 1;
                                        "✓".green()
                                    } else {
                                        total_failed += 1;
                                        "✗".red()
                                    };
                                    let expected = if *passed { "" } else { " (unexpected match)" };
                                    println!(
                                        "  {} should_not_match: \"{}\"{}",
                                        icon,
                                        truncate(case, 50),
                                        expected.red()
                                    );
                                }
                            }
                        }

                        // Summary
                        println!();
                        println!("{}", "═".repeat(50));
                        if total_failed == 0 {
                            println!(
                                "{} All tests passed! ({} rules with tests, {} total tests)",
                                "✓".green(),
                                rules_with_tests,
                                total_passed
                            );
                        } else {
                            println!(
                                "{} {} tests passed, {} tests failed ({}/{} rules passed)",
                                "✗".red(),
                                total_passed.to_string().green(),
                                total_failed.to_string().red(),
                                rules_passed,
                                rules_with_tests
                            );
                            std::process::exit(1);
                        }
                    }
                }
                return Ok(());
            }

            // Load built-in rules + external rules from ~/.vexscan/rules/
            let mut all_rules = load_builtin_json_rules();

            // Load external rules
            let extra_dirs = base_config.resolved_extra_rules_dirs();
            for dir in &extra_dirs {
                if dir.is_dir() {
                    match vexscan::rules::loader::load_rules_from_directory_with_source(
                        dir,
                        Some(RuleSource::External),
                    ) {
                        Ok(ext_rules) => all_rules.extend(ext_rules),
                        Err(e) => {
                            eprintln!(
                                "Warning: failed to load rules from {}: {}",
                                dir.display(),
                                e
                            );
                        }
                    }
                }
            }

            // Apply source filter
            let mut rules = if external {
                filter_rules_by_source(&all_rules, RuleSource::External)
            } else if official && !community {
                filter_rules_by_source(&all_rules, RuleSource::Official)
            } else if community && !official {
                filter_rules_by_source(&all_rules, RuleSource::Community)
            } else {
                all_rules
            };

            // Apply author filter
            if let Some(ref auth) = author {
                rules = filter_rules_by_author(&rules, auth);
            }

            // Apply tag filter
            if let Some(ref t) = tag {
                rules = filter_rules_by_tag(&rules, t);
            }

            if let Some(rule_id) = rule {
                // Show specific rule
                if let Some(r) = rules.iter().find(|r| r.id == rule_id) {
                    if json {
                        println!("{}", serde_json::to_string_pretty(r)?);
                    } else {
                        println!("{}", format!("Rule: {}", r.id).bold());
                        println!("Title:       {}", r.title);
                        println!("Severity:    {}", r.severity);
                        println!("Category:    {}", r.category);
                        println!("Source:      {}", r.source);
                        println!("Description: {}", r.description);
                        if r.patterns.len() == 1 {
                            println!("Pattern:     {}", r.patterns[0]);
                        } else {
                            println!("Patterns:");
                            for (i, pat) in r.patterns.iter().enumerate() {
                                println!("  {}. {}", i + 1, pat);
                            }
                        }
                        if !r.file_extensions.is_empty() {
                            println!("Extensions:  {}", r.file_extensions.join(", "));
                        }
                        if let Some(ref rem) = r.remediation {
                            println!("Remediation: {}", rem);
                        }

                        // Show metadata if present
                        if let Some(ref meta) = r.metadata {
                            println!();
                            println!("{}", "Metadata:".bold());
                            if let Some(ref auth) = meta.author {
                                println!("  Author:     {}", auth);
                            }
                            if let Some(ref url) = meta.author_url {
                                println!("  Author URL: {}", url);
                            }
                            if let Some(ref ver) = meta.version {
                                println!("  Version:    {}", ver);
                            }
                            if !meta.tags.is_empty() {
                                println!("  Tags:       {}", meta.tags.join(", "));
                            }
                            if !meta.references.is_empty() {
                                println!("  References:");
                                for ref_url in &meta.references {
                                    println!("    - {}", ref_url);
                                }
                            }
                            if let Some(ref tc) = meta.test_cases {
                                if !tc.should_match.is_empty() || !tc.should_not_match.is_empty() {
                                    println!(
                                        "  Test cases: {} should_match, {} should_not_match",
                                        tc.should_match.len(),
                                        tc.should_not_match.len()
                                    );
                                }
                            }
                        }
                    }
                } else {
                    eprintln!("Rule not found: {}", rule_id);
                    std::process::exit(1);
                }
            } else {
                // List all rules
                if json {
                    println!("{}", serde_json::to_string_pretty(&rules)?);
                } else {
                    let title = if external {
                        "External Rules"
                    } else if official {
                        "Official Rules"
                    } else if community {
                        "Community Rules"
                    } else {
                        "Available Rules"
                    };
                    println!("{}", title.bold().underline());
                    println!();

                    let mut current_category = String::new();
                    let mut sorted_rules = rules.clone();
                    sorted_rules
                        .sort_by(|a, b| format!("{}", a.category).cmp(&format!("{}", b.category)));

                    for r in sorted_rules {
                        let cat = format!("{}", r.category);
                        if cat != current_category {
                            println!("\n{}", cat.bold());
                            current_category = cat;
                        }

                        let severity_color = match r.severity {
                            Severity::Critical => r.severity.to_string().bright_red(),
                            Severity::High => r.severity.to_string().red(),
                            Severity::Medium => r.severity.to_string().yellow(),
                            Severity::Low => r.severity.to_string().blue(),
                            Severity::Info => r.severity.to_string().white(),
                        };

                        let source_badge = match r.source {
                            RuleSource::Community => " [community]".dimmed(),
                            RuleSource::External => " [external]".dimmed(),
                            RuleSource::Official => "".normal(),
                        };

                        let file_constraint = if !r.file_names.is_empty() {
                            format!(" ({})", r.file_names.join(", ")).dimmed()
                        } else {
                            "".normal()
                        };

                        println!(
                            "  {} [{}] - {}{}{}",
                            r.id.bright_cyan(),
                            severity_color,
                            r.title,
                            source_badge,
                            file_constraint
                        );
                    }
                    println!();
                    println!("Total: {} rules", rules.len());
                    if !official && !community {
                        let official_count = rules
                            .iter()
                            .filter(|r| r.source == RuleSource::Official)
                            .count();
                        let community_count = rules
                            .iter()
                            .filter(|r| r.source == RuleSource::Community)
                            .count();
                        let external_count = rules
                            .iter()
                            .filter(|r| r.source == RuleSource::External)
                            .count();
                        if external_count > 0 {
                            println!(
                                "  {} official, {} community, {} external",
                                official_count, community_count, external_count
                            );
                        } else {
                            println!(
                                "  {} official, {} community",
                                official_count, community_count
                            );
                        }
                    }
                }
            }
        }

        Commands::Decode { input, depth } => {
            let decoder = Decoder::new();
            let layers = decoder.decode_recursive(&input, depth);

            if layers.is_empty() {
                println!("No encodings detected in input.");
            } else {
                println!("{}", "Decoded content:".bold());
                for (i, layer) in layers.iter().enumerate() {
                    println!(
                        "\n{}",
                        format!("Layer {} (depth {})", i + 1, i + 1).underline()
                    );
                    for decoded in layer {
                        println!("  Encoding: {}", decoded.encoding.to_string().cyan());
                        println!("  Original: {}", truncate(&decoded.original, 60).dimmed());
                        println!("  Decoded:  {}", decoded.decoded.green());
                    }
                }
            }
        }

        Commands::Init { output } => {
            if output.exists() {
                info!(
                    "{}",
                    format!("Config file already exists: {}", output.display()).yellow()
                );
                info!("Use a different path or remove the existing file.");
                std::process::exit(1);
            }

            std::fs::write(&output, generate_default_config())?;
            println!(
                "{}",
                format!("Created config file: {}", output.display()).green()
            );
            println!("Edit this file to customize allowlists and trusted packages.");
        }

        Commands::Install {
            source,
            install_type,
            name,
            platform,
            force,
            allow_high,
            skip_deps,
            branch,
            dry_run,
            ast,
            deps,
            no_cache,
            installed_only,
            include_dev,
            jobs,
        } => {
            // Validate platform
            if platform != "claude-code" {
                return Err(anyhow::anyhow!(
                    "Currently only 'claude-code' platform is supported for installation"
                ));
            }

            info!("{}", "═".repeat(60).bright_blue());
            info!("{}  {} Install", "📦".bright_blue(), "Vexscan".bold());
            info!("{}", "═".repeat(60).bright_blue());
            info!();

            // Step 1: Fetch the source
            let (scan_path, temp_dir, source_name) = if is_github_url(&source) {
                info!("{} {}", "Fetching:".cyan(), source);
                let temp_dir = clone_github_repo(&source, branch.as_deref())?;
                let repo_name = extract_repo_name(&source);
                (temp_dir.path().to_path_buf(), Some(temp_dir), repo_name)
            } else {
                let path = PathBuf::from(&source);
                if !path.exists() {
                    return Err(anyhow::anyhow!("Path does not exist: {}", source));
                }
                let dir_name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                info!("{} {}", "Source:".cyan(), path.display());
                (path, None, dir_name)
            };

            // Step 2: Detect installation type
            let detected_type = detect_install_type(&scan_path);
            let final_type = install_type.as_deref().unwrap_or(&detected_type);
            let install_name = name.unwrap_or_else(|| source_name.clone());

            info!(
                "{} {} ({})",
                "Component:".cyan(),
                install_name.bright_white(),
                final_type
            );
            info!();

            // Step 3: Security scan
            info!("{}", "Scanning for security issues...".yellow());
            info!();

            let mut filter_config = base_config.clone();
            if skip_deps {
                filter_config.skip_node_modules = true;
            }

            let extra_rules_dirs = filter_config.resolved_extra_rules_dirs();
            let config = ScanConfig {
                enable_ai: false,
                enable_ast: ast,
                enable_deps: deps,
                enable_cache: !no_cache,
                platform: None,
                min_severity: Severity::Low,
                filter_config,
                static_config: AnalyzerConfig::default(),
                installed_only,
                include_dev,
                extra_rules_dirs,
                max_threads: jobs.unwrap_or(0),
                scan_context,
                ..Default::default()
            };

            let scanner = Scanner::with_config(config)?;
            let mut scan_report = scanner.scan_path(&scan_path).await?;

            // Apply trust store
            let trust_store = TrustStore::load().unwrap_or_default();
            let suppressed = trust_store.apply_to_report(&mut scan_report);
            if suppressed > 0 {
                info!(
                    "{} {} finding(s) suppressed by trust store",
                    "Trust:".dimmed(),
                    suppressed
                );
            }

            // Show findings summary (active findings only)
            let (critical, high, medium, low, info_count) = count_active_by_severity(&scan_report);
            let total = critical + high + medium + low + info_count;

            if total > 0 {
                // Show the scan report
                let format: OutputFormat =
                    cli.format.parse().map_err(|e| anyhow::anyhow!("{}", e))?;
                let mut stdout = io::stdout().lock();
                report(&scan_report, format, &mut stdout)?;
                drop(stdout);
                info!();
            }

            // Step 4: Determine if installation should proceed (ignore suppressed)
            let max_sev = scan_report.max_active_severity();
            let can_install = match max_sev {
                Some(Severity::Critical) => {
                    info!(
                        "{} {} - Installation blocked",
                        "🚨 CRITICAL ISSUES FOUND".bright_red().bold(),
                        format!("({} critical)", critical).red()
                    );
                    info!("   This component contains critical security issues and cannot be installed.");
                    info!("   Review the findings above and contact the author.");
                    false
                }
                Some(Severity::High) => {
                    if allow_high {
                        info!(
                            "{} {} - Proceeding (--allow-high)",
                            "⚠️  HIGH SEVERITY ISSUES".red().bold(),
                            format!("({} high)", high).red()
                        );
                        true
                    } else {
                        info!(
                            "{} {} - Installation blocked",
                            "⚠️  HIGH SEVERITY ISSUES".red().bold(),
                            format!("({} high)", high).red()
                        );
                        info!("   Use --allow-high to install anyway (not recommended).");
                        false
                    }
                }
                Some(Severity::Medium) => {
                    if force {
                        info!(
                            "{} {} - Proceeding (--force)",
                            "⚡ WARNINGS FOUND".yellow(),
                            format!("({} medium)", medium).yellow()
                        );
                        true
                    } else {
                        info!(
                            "{} {}",
                            "⚡ WARNINGS FOUND".yellow(),
                            format!("({} medium)", medium).yellow()
                        );
                        info!("   Use --force to install anyway.");
                        false
                    }
                }
                Some(Severity::Low) | Some(Severity::Info) | None => {
                    if total > 0 {
                        info!(
                            "{} ({} low, {} info)",
                            "✓ Minor issues only".green(),
                            low,
                            info_count
                        );
                    } else {
                        info!("{}", "✓ No security issues found".green().bold());
                    }
                    true
                }
            };

            if !can_install {
                info!();
                info!("{}", "Installation aborted.".red());
                std::process::exit(1);
            }

            // Step 5: Install
            info!();

            if dry_run {
                info!("{}", "DRY RUN - Would install to:".yellow().bold());
                let install_path = get_install_path(final_type, &install_name)?;
                info!("   {}", install_path.display());
                info!();
                info!("Run without --dry-run to actually install.");
            } else {
                let install_path = install_component(&scan_path, final_type, &install_name)?;
                info!("{}", "═".repeat(60).green());
                info!(
                    "{} Installed {} to:",
                    "✓".green().bold(),
                    install_name.bright_white()
                );
                info!("   {}", install_path.display().to_string().green());
                info!("{}", "═".repeat(60).green());

                // Show usage hint
                match final_type {
                    "skill" | "command" => {
                        info!();
                        info!("{}  Use with: /{}", "💡".yellow(), install_name);
                    }
                    _ => {}
                }
            }

            // Cleanup temp directory
            if let Some(temp) = temp_dir {
                drop(temp); // Explicitly drop to clean up
            }
        }

        Commands::Vet {
            source,
            output,
            min_severity,
            fail_on,
            skip_deps,
            enable_entropy,
            keep,
            branch,
            ast,
            deps,
            no_cache,
            installed_only,
            include_dev,
            jobs,
        } => {
            // Parse severities
            let min_severity = parse_severity(&min_severity)?;
            let fail_on_severity = parse_severity(&fail_on)?;

            // Determine if source is a URL or local path
            let (scan_path, temp_dir) = if is_github_url(&source) {
                info!("{}", "Fetching from GitHub...".cyan());
                let temp_dir = clone_github_repo(&source, branch.as_deref())?;
                (temp_dir.path().to_path_buf(), Some(temp_dir))
            } else {
                // Local path
                let path = PathBuf::from(&source);
                if !path.exists() {
                    return Err(anyhow::anyhow!("Path does not exist: {}", source));
                }
                (path, None)
            };

            info!("{} {}", "Vetting:".bold(), source.bright_cyan());
            info!();

            // Build filter config
            let mut filter_config = base_config;
            if skip_deps {
                filter_config.skip_node_modules = true;
            }

            // Build static analyzer config
            let mut static_config = AnalyzerConfig::default();
            if enable_entropy {
                static_config.enable_entropy = true;
            }

            // Resolve extra rules directories
            let extra_rules_dirs = filter_config.resolved_extra_rules_dirs();

            // Build scan config
            let config = ScanConfig {
                enable_ai: false,
                enable_ast: ast,
                enable_deps: deps,
                enable_cache: !no_cache,
                platform: None,
                min_severity,
                filter_config,
                static_config,
                installed_only,
                include_dev,
                extra_rules_dirs,
                max_threads: jobs.unwrap_or(0),
                scan_context,
                ..Default::default()
            };

            // Run scanner
            let scanner = Scanner::with_config(config)?;
            let mut scan_report = scanner.scan_path(&scan_path).await?;

            // Apply trust store
            let trust_store = TrustStore::load().unwrap_or_default();
            let suppressed = trust_store.apply_to_report(&mut scan_report);
            if suppressed > 0 {
                info!(
                    "{} {} finding(s) suppressed by trust store",
                    "Trust:".dimmed(),
                    suppressed
                );
            }

            // Output results
            let format: OutputFormat = cli.format.parse().map_err(|e| anyhow::anyhow!("{}", e))?;

            if let Some(output_path) = output {
                let mut file = std::fs::File::create(&output_path)?;
                report(&scan_report, format, &mut file)?;
                info!("Report written to: {}", output_path.display());
            } else {
                let mut stdout = io::stdout().lock();
                report(&scan_report, format, &mut stdout)?;
            }

            // Print verdict
            info!();
            print_verdict(&scan_report, fail_on_severity);

            // Cleanup temp directory (unless --keep)
            if let Some(temp) = temp_dir {
                if keep {
                    let kept_path = temp.path().to_path_buf();
                    // Leak the temp dir so it doesn't get cleaned up
                    std::mem::forget(temp);
                    info!(
                        "\n{} {}",
                        "Repository kept at:".dimmed(),
                        kept_path.display()
                    );
                }
                // If not keep, temp_dir drops and cleans up automatically
            }

            // Exit with appropriate code (ignore suppressed findings)
            if let Some(max_sev) = scan_report.max_active_severity() {
                if max_sev >= fail_on_severity {
                    std::process::exit(1);
                }
            }
        }

        Commands::Check {
            input,
            stdin,
            r#type,
            min_severity,
            fail_on,
            ast,
        } => {
            // Validate: need either positional text or --stdin, not both
            let text = match (input, stdin) {
                (Some(text), false) => text,
                (None, true) => {
                    let text = io::read_to_string(io::stdin())?;
                    if text.trim().is_empty() {
                        eprintln!("{}: No input received on stdin", "Error".bright_red().bold());
                        std::process::exit(1);
                    }
                    text
                }
                (Some(_), true) => {
                    eprintln!(
                        "{}: Cannot use both positional TEXT and --stdin",
                        "Error".bright_red().bold()
                    );
                    std::process::exit(1);
                }
                (None, false) => {
                    eprintln!(
                        "{}: Provide text as argument or use --stdin\n\n  {} vexscan check \"text to scan\"\n  {} echo \"text\" | vexscan check --stdin",
                        "Error".bright_red().bold(),
                        "Usage:".bold(),
                        "      ".bold(),
                    );
                    std::process::exit(1);
                }
            };

            let min_severity = parse_severity(&min_severity)?;
            let fail_on_severity = parse_severity(&fail_on)?;

            // Synthetic path for rule filtering by file extension
            let synthetic_path = PathBuf::from(format!("<stdin>.{}", r#type));

            // Static analysis (with context if provided)
            let analyzer = if let Some(ctx) = scan_context {
                let mut cfg = AnalyzerConfig::default();
                cfg.scan_context = Some(ctx);
                StaticAnalyzer::with_config(cfg)?
            } else {
                StaticAnalyzer::new()?
            };
            let mut result = analyzer.scan_content(&text, &synthetic_path, None)?;

            // AST analysis (if enabled and type is a supported language)
            if ast {
                match AstAnalyzer::new() {
                    Ok(ast_analyzer) => {
                        match ast_analyzer.analyze_content_str(&text, &synthetic_path) {
                            Ok(ast_result) => {
                                result.findings.extend(ast_result.findings);
                            }
                            Err(e) => {
                                tracing::debug!("AST analysis skipped: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!("AST analyzer init failed: {}", e);
                    }
                }
            }

            // Filter by min_severity
            result
                .findings
                .retain(|f| f.severity >= min_severity);

            // Build report
            let mut scan_report = vexscan::ScanReport::new(PathBuf::from("<stdin>"));
            scan_report.results.push(result);
            scan_report.rule_count = analyzer.rule_count();
            scan_report.ast_enabled = ast;
            scan_report.risk_score = scan_report.compute_risk_score();

            // Output
            let format: OutputFormat = cli.format.parse().map_err(|e| anyhow::anyhow!("{}", e))?;
            let mut stdout = io::stdout().lock();
            report(&scan_report, format, &mut stdout)?;

            // Verdict (CLI format only)
            if matches!(format, OutputFormat::Cli) {
                print_verdict(&scan_report, fail_on_severity);
            }

            // Exit code
            if let Some(max_sev) = scan_report.max_severity() {
                if max_sev >= fail_on_severity {
                    std::process::exit(1);
                }
            }
        }

        Commands::Trust { subcommand } => {
            match subcommand {
                TrustSubcommand::Accept { path, rules, notes } => {
                    if rules.is_empty() {
                        eprintln!(
                            "{}: --rules is required. Use 'trust full' to accept all findings.",
                            "Error".bright_red().bold()
                        );
                        std::process::exit(1);
                    }

                    let components = vexscan::components::detect_components(&path);
                    if components.is_empty() {
                        eprintln!(
                            "{}: No AI component detected at {}",
                            "Error".bright_red().bold(),
                            path.display()
                        );
                        std::process::exit(1);
                    }

                    let comp = &components[0];
                    let hash = vexscan::trust::hash_component_dir(&comp.root)?;
                    let kind = vexscan::trust::component_kind_key(comp);

                    let entry = TrustEntry {
                        name: comp.name.clone(),
                        kind: kind.clone(),
                        component_hash: hash,
                        trust_level: TrustLevel::Accepted,
                        accepted_rules: rules.clone(),
                        decided_at: chrono::Utc::now(),
                        scanner_version: env!("CARGO_PKG_VERSION").to_string(),
                        notes,
                    };

                    let key = entry.key();
                    let mut store = TrustStore::load().unwrap_or_default();
                    store.add(entry);
                    store.save()?;

                    println!(
                        "{} Accepted {} for {} (rules: {})",
                        "✓".green().bold(),
                        key.bright_cyan(),
                        comp.name,
                        rules.join(", ")
                    );
                }

                TrustSubcommand::Full { path, notes } => {
                    let components = vexscan::components::detect_components(&path);
                    if components.is_empty() {
                        eprintln!(
                            "{}: No AI component detected at {}",
                            "Error".bright_red().bold(),
                            path.display()
                        );
                        std::process::exit(1);
                    }

                    let comp = &components[0];
                    let hash = vexscan::trust::hash_component_dir(&comp.root)?;
                    let kind = vexscan::trust::component_kind_key(comp);

                    let entry = TrustEntry {
                        name: comp.name.clone(),
                        kind: kind.clone(),
                        component_hash: hash,
                        trust_level: TrustLevel::Accepted,
                        accepted_rules: vec![], // empty = all rules
                        decided_at: chrono::Utc::now(),
                        scanner_version: env!("CARGO_PKG_VERSION").to_string(),
                        notes,
                    };

                    let key = entry.key();
                    let mut store = TrustStore::load().unwrap_or_default();
                    store.add(entry);
                    store.save()?;

                    println!(
                        "{} Fully trusted {} (all findings suppressed)",
                        "✓".green().bold(),
                        key.bright_cyan()
                    );
                }

                TrustSubcommand::Quarantine { path } => {
                    let components = vexscan::components::detect_components(&path);
                    if components.is_empty() {
                        eprintln!(
                            "{}: No AI component detected at {}",
                            "Error".bright_red().bold(),
                            path.display()
                        );
                        std::process::exit(1);
                    }

                    let comp = &components[0];
                    let hash = vexscan::trust::hash_component_dir(&comp.root)?;
                    let kind = vexscan::trust::component_kind_key(comp);

                    let entry = TrustEntry {
                        name: comp.name.clone(),
                        kind: kind.clone(),
                        component_hash: hash,
                        trust_level: TrustLevel::Quarantined,
                        accepted_rules: vec![],
                        decided_at: chrono::Utc::now(),
                        scanner_version: env!("CARGO_PKG_VERSION").to_string(),
                        notes: None,
                    };

                    let key = entry.key();
                    let mut store = TrustStore::load().unwrap_or_default();
                    store.add(entry);
                    store.save()?;

                    println!(
                        "{} Quarantined {} — will inject critical finding on future scans",
                        "🚫".red(),
                        key.bright_cyan()
                    );
                }

                TrustSubcommand::List => {
                    let store = TrustStore::load().unwrap_or_default();

                    if store.entries.is_empty() {
                        println!("Trust store is empty. Use 'vexscan trust accept' or 'trust full' to add entries.");
                        return Ok(());
                    }

                    println!("{}", "Trust Store Entries".bold().underline());
                    println!();

                    let mut keys: Vec<&String> = store.entries.keys().collect();
                    keys.sort();

                    for key in keys {
                        let entry = &store.entries[key];
                        let level_str = match entry.trust_level {
                            TrustLevel::Accepted => "accepted".green().to_string(),
                            TrustLevel::Quarantined => "QUARANTINED".bright_red().bold().to_string(),
                        };

                        let rules_str = if entry.accepted_rules.is_empty() {
                            "all rules".dimmed().to_string()
                        } else {
                            entry.accepted_rules.join(", ")
                        };

                        println!(
                            "  {} [{}] rules: {} | hash: {}.. | {}",
                            key.bright_cyan(),
                            level_str,
                            rules_str,
                            &entry.component_hash[..8],
                            entry.decided_at.format("%Y-%m-%d %H:%M")
                        );

                        if let Some(ref notes) = entry.notes {
                            println!("    {}", format!("Notes: {}", notes).dimmed());
                        }
                    }
                    println!();
                    println!("Total: {} entries", store.entries.len());
                }

                TrustSubcommand::Revoke { name } => {
                    let mut store = TrustStore::load().unwrap_or_default();

                    // Try exact key first, then bare name match
                    let key = if store.entries.contains_key(&name) {
                        name.clone()
                    } else {
                        // Search for bare name match
                        store
                            .entries
                            .keys()
                            .find(|k| k.ends_with(&format!(":{}", name)))
                            .cloned()
                            .unwrap_or(name.clone())
                    };

                    if store.revoke(&key) {
                        store.save()?;
                        println!(
                            "{} Revoked trust for {}",
                            "✓".green().bold(),
                            key.bright_cyan()
                        );
                    } else {
                        eprintln!(
                            "{}: No trust entry found for '{}'",
                            "Error".bright_red().bold(),
                            name
                        );
                        std::process::exit(1);
                    }
                }

                TrustSubcommand::Show { path } => {
                    let components = vexscan::components::detect_components(&path);
                    if components.is_empty() {
                        eprintln!(
                            "{}: No AI component detected at {}",
                            "Error".bright_red().bold(),
                            path.display()
                        );
                        std::process::exit(1);
                    }

                    let store = TrustStore::load().unwrap_or_default();

                    for comp in &components {
                        let kind = vexscan::trust::component_kind_key(comp);
                        let current_hash = vexscan::trust::hash_component_dir(&comp.root)?;

                        println!(
                            "{} {} ({})",
                            "Component:".bold(),
                            comp.name.bright_cyan(),
                            comp.kind
                        );
                        println!("  Path: {}", comp.root.display());
                        println!("  Hash: {}", &current_hash[..16]);

                        match store.get(&kind, &comp.name) {
                            Some(entry) => {
                                let level_str = match entry.trust_level {
                                    TrustLevel::Accepted => "Accepted".green().to_string(),
                                    TrustLevel::Quarantined => {
                                        "QUARANTINED".bright_red().bold().to_string()
                                    }
                                };
                                println!("  Trust: {}", level_str);

                                if current_hash == entry.component_hash {
                                    println!("  Hash:  {} (matches)", "valid".green());
                                } else {
                                    println!(
                                        "  Hash:  {} (stored: {}..)",
                                        "STALE — component changed since trust was granted"
                                            .yellow()
                                            .bold(),
                                        &entry.component_hash[..8]
                                    );
                                }

                                if entry.accepted_rules.is_empty() {
                                    println!("  Rules: all (full trust)");
                                } else {
                                    println!("  Rules: {}", entry.accepted_rules.join(", "));
                                }
                                println!("  Since: {}", entry.decided_at.format("%Y-%m-%d %H:%M"));
                                if let Some(ref notes) = entry.notes {
                                    println!("  Notes: {}", notes);
                                }
                            }
                            None => {
                                println!("  Trust: {} (not in trust store)", "none".dimmed());
                            }
                        }
                        println!();
                    }
                }
            }
        }

        Commands::Cache { subcommand } => {
            // Build a dummy profile just to access the cache directory
            let profile = ScanProfile::from_config(false, false, false, 0);
            let cache = ScanCache::new(profile)?;

            match subcommand {
                CacheSubcommand::Stats => {
                    let count = cache.entry_count();
                    let size = cache.total_size_bytes();
                    let size_str = if size >= 1_048_576 {
                        format!("{:.1} MB", size as f64 / 1_048_576.0)
                    } else if size >= 1024 {
                        format!("{:.1} KB", size as f64 / 1024.0)
                    } else {
                        format!("{} bytes", size)
                    };
                    println!("Cache entries: {}", count);
                    println!("Total size:    {}", size_str);
                }
                CacheSubcommand::Clear => {
                    let removed = cache.clear()?;
                    println!("Cleared {} cache entries.", removed);
                }
            }
        }
    }

    Ok(())
}

/// Check if a string looks like a GitHub URL.
fn is_github_url(s: &str) -> bool {
    s.starts_with("https://github.com/")
        || s.starts_with("http://github.com/")
        || s.starts_with("git@github.com:")
        || s.starts_with("github.com/")
}

/// Clone a GitHub repository to a temporary directory.
fn clone_github_repo(url: &str, branch: Option<&str>) -> Result<tempfile::TempDir> {
    // Normalize URL
    let normalized_url = if url.starts_with("github.com/") {
        format!("https://{}", url)
    } else if url.starts_with("git@github.com:") {
        // Convert SSH to HTTPS
        let path = url.strip_prefix("git@github.com:").unwrap();
        format!("https://github.com/{}", path)
    } else {
        url.to_string()
    };

    // Ensure .git suffix for cloning
    let clone_url = if normalized_url.ends_with(".git") {
        normalized_url
    } else {
        format!("{}.git", normalized_url.trim_end_matches('/'))
    };

    // Create temp directory
    let temp_dir = tempfile::tempdir()?;

    // Clone
    let mut builder = git2::build::RepoBuilder::new();

    if let Some(branch_name) = branch {
        builder.branch(branch_name);
    }

    // Set up fetch options for shallow clone (faster)
    let mut fetch_opts = git2::FetchOptions::new();
    fetch_opts.depth(1);
    builder.fetch_options(fetch_opts);

    info!("  {} {}", "Cloning".dimmed(), clone_url.dimmed());

    builder
        .clone(&clone_url, temp_dir.path())
        .map_err(|e| anyhow::anyhow!("Failed to clone repository: {}", e))?;

    info!("  {} {}", "Cloned to".dimmed(), temp_dir.path().display());

    Ok(temp_dir)
}

/// Print the verdict based on scan results.
fn print_verdict(report: &vexscan::ScanReport, threshold: Severity) {
    let max_sev = report.max_active_severity();

    let (critical, high, medium, low, info_count) = count_active_by_severity(report);

    info!("{}", "═".repeat(60));

    match max_sev {
        Some(sev) if sev >= Severity::Critical => {
            info!(
                "{} {}",
                "VERDICT:".bold(),
                "🚨 DANGEROUS - DO NOT INSTALL".bright_red().bold()
            );
            info!(
                "         Found {} critical issue(s) that may compromise your system.",
                critical.to_string().bright_red()
            );
        }
        Some(sev) if sev >= Severity::High => {
            info!(
                "{} {}",
                "VERDICT:".bold(),
                "⚠️  HIGH RISK - Review carefully before installing"
                    .red()
                    .bold()
            );
            info!(
                "         Found {} high severity issue(s).",
                high.to_string().red()
            );
        }
        Some(sev) if sev >= Severity::Medium => {
            info!(
                "{} {}",
                "VERDICT:".bold(),
                "⚡ WARNINGS - Proceed with caution".yellow().bold()
            );
            info!(
                "         Found {} medium severity issue(s).",
                medium.to_string().yellow()
            );
        }
        Some(sev) if sev >= Severity::Low => {
            info!(
                "{} {}",
                "VERDICT:".bold(),
                "ℹ️  MINOR ISSUES - Generally safe".blue()
            );
            info!(
                "         Found {} low severity and {} info issue(s).",
                low.to_string().blue(),
                info_count.to_string().white()
            );
        }
        Some(_) | None => {
            info!(
                "{} {}",
                "VERDICT:".bold(),
                "✅ CLEAN - No issues found".green().bold()
            );
        }
    }

    // Show summary counts
    if critical + high + medium + low + info_count > 0 {
        info!();
        info!(
            "         Summary: {} critical, {} high, {} medium, {} low, {} info",
            if critical > 0 {
                critical.to_string().bright_red().to_string()
            } else {
                "0".dimmed().to_string()
            },
            if high > 0 {
                high.to_string().red().to_string()
            } else {
                "0".dimmed().to_string()
            },
            if medium > 0 {
                medium.to_string().yellow().to_string()
            } else {
                "0".dimmed().to_string()
            },
            if low > 0 {
                low.to_string().blue().to_string()
            } else {
                "0".dimmed().to_string()
            },
            if info_count > 0 {
                info_count.to_string().white().to_string()
            } else {
                "0".dimmed().to_string()
            },
        );
    }

    // Risk score
    let risk_label = vexscan::ScanReport::risk_label(report.risk_score);
    let risk_colored = match report.risk_score {
        0 => format!("{}/100 ({})", report.risk_score, risk_label)
            .green()
            .bold()
            .to_string(),
        1..=25 => format!("{}/100 ({})", report.risk_score, risk_label)
            .blue()
            .to_string(),
        26..=50 => format!("{}/100 ({})", report.risk_score, risk_label)
            .yellow()
            .to_string(),
        51..=75 => format!("{}/100 ({})", report.risk_score, risk_label)
            .red()
            .to_string(),
        _ => format!("{}/100 ({})", report.risk_score, risk_label)
            .bright_red()
            .bold()
            .to_string(),
    };
    info!("         Risk Score: {}", risk_colored);

    info!("{}", "═".repeat(60));

    // Note about threshold
    if max_sev.map(|s| s >= threshold).unwrap_or(false) {
        info!(
            "\n{} Exit code 1 (findings at {} or above)",
            "Note:".dimmed(),
            format!("{:?}", threshold).to_lowercase()
        );
    }
}

/// Count active (non-suppressed) findings by severity.
fn count_active_by_severity(report: &vexscan::ScanReport) -> (usize, usize, usize, usize, usize) {
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    let mut info = 0;

    for result in &report.results {
        for finding in &result.findings {
            if finding.suppressed_by.is_some() {
                continue;
            }
            match finding.severity {
                Severity::Critical => critical += 1,
                Severity::High => high += 1,
                Severity::Medium => medium += 1,
                Severity::Low => low += 1,
                Severity::Info => info += 1,
            }
        }
    }

    (critical, high, medium, low, info)
}

fn parse_severity(s: &str) -> Result<Severity> {
    match s.to_lowercase().as_str() {
        "info" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" | "med" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" | "crit" => Ok(Severity::Critical),
        _ => Err(anyhow::anyhow!("Unknown severity: {}", s)),
    }
}

/// Send a desktop notification (platform-specific).
fn send_desktop_notification(title: &str, body: &str) {
    #[cfg(target_os = "macos")]
    {
        let script = format!(
            r#"display notification "{}" with title "{}""#,
            body.replace('"', "\\\"").replace('\n', " "),
            title.replace('"', "\\\"")
        );
        let _ = std::process::Command::new("osascript")
            .args(["-e", &script])
            .output();
    }

    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("notify-send")
            .args([title, body])
            .output();
    }

    #[cfg(target_os = "windows")]
    {
        // PowerShell notification (Windows 10+)
        let script = format!(
            r#"[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null; $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); $template.SelectSingleNode('//text[@id=\"1\"]').InnerText = '{}'; $template.SelectSingleNode('//text[@id=\"2\"]').InnerText = '{}'; [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Vexscan').Show([Windows.UI.Notifications.ToastNotification]::new($template))"#,
            title.replace('\'', "''"),
            body.replace('\'', "''").replace('\n', " ")
        );
        let _ = std::process::Command::new("powershell")
            .args(["-Command", &script])
            .output();
    }
}

/// Extract repository name from a GitHub URL.
fn extract_repo_name(url: &str) -> String {
    // Handle various URL formats:
    // https://github.com/user/repo
    // https://github.com/user/repo.git
    // git@github.com:user/repo.git
    let cleaned = url.trim_end_matches('/').trim_end_matches(".git");

    cleaned
        .rsplit('/')
        .next()
        .or_else(|| cleaned.rsplit(':').next())
        .unwrap_or("unknown")
        .to_string()
}

/// Detect the installation type from the source directory.
fn detect_install_type(path: &std::path::Path) -> String {
    // Check for SKILL.md (new skill format)
    if path.join("SKILL.md").exists() {
        return "skill".to_string();
    }

    // Check for a single .md file (legacy command format)
    let md_files: Vec<_> = std::fs::read_dir(path)
        .ok()
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map(|ext| ext == "md").unwrap_or(false))
                .collect()
        })
        .unwrap_or_default();

    if md_files.len() == 1 {
        return "command".to_string();
    }

    // Check for package.json (likely a plugin)
    if path.join("package.json").exists() {
        return "plugin".to_string();
    }

    // Check for hook-like scripts
    let has_hook_scripts = std::fs::read_dir(path)
        .ok()
        .map(|entries| {
            entries.filter_map(|e| e.ok()).any(|e| {
                let path = e.path();
                let ext = path.extension().and_then(|e| e.to_str());
                matches!(ext, Some("sh") | Some("bash") | Some("zsh"))
            })
        })
        .unwrap_or(false);

    if has_hook_scripts {
        return "hook".to_string();
    }

    // Default to skill
    "skill".to_string()
}

/// Get the installation path for a component.
fn get_install_path(install_type: &str, name: &str) -> Result<PathBuf> {
    let home_dir =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?;
    let claude_dir = home_dir.join(".claude");

    let path = match install_type {
        "skill" => claude_dir.join("skills").join(name),
        "command" => claude_dir.join("commands"),
        "plugin" => claude_dir.join("plugins").join(name),
        "hook" => claude_dir.join("hooks").join(name),
        _ => return Err(anyhow::anyhow!("Unknown install type: {}", install_type)),
    };

    Ok(path)
}

/// Install a component to the appropriate directory.
fn install_component(source: &std::path::Path, install_type: &str, name: &str) -> Result<PathBuf> {
    let install_path = get_install_path(install_type, name)?;

    // Create parent directories if needed
    if let Some(parent) = install_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Check if already exists
    if install_path.exists() {
        return Err(anyhow::anyhow!(
            "Component already exists at {}. Remove it first or use a different name.",
            install_path.display()
        ));
    }

    // Copy the source to the destination
    match install_type {
        "command" => {
            // For legacy commands, copy the .md file directly
            let md_file = find_main_file(source, "md")?;
            let dest_file = install_path.join(format!("{}.md", name));
            std::fs::create_dir_all(&install_path)?;
            std::fs::copy(&md_file, &dest_file)?;
            Ok(dest_file)
        }
        "skill" | "plugin" | "hook" => {
            // Copy the entire directory
            copy_dir_recursive(source, &install_path)?;
            Ok(install_path)
        }
        _ => Err(anyhow::anyhow!("Unknown install type: {}", install_type)),
    }
}

/// Find the main file of a specific type in a directory.
fn find_main_file(dir: &std::path::Path, extension: &str) -> Result<PathBuf> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == extension {
                    return Ok(path);
                }
            }
        }
    }
    Err(anyhow::anyhow!(
        "No .{} file found in {}",
        extension,
        dir.display()
    ))
}

/// Recursively copy a directory.
fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;

    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            // Skip common non-essential directories
            let dir_name = entry.file_name();
            let skip_dirs = ["node_modules", ".git", "__pycache__", ".venv", "target"];
            if skip_dirs.iter().any(|&d| dir_name == d) {
                continue;
            }
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }

    Ok(())
}
