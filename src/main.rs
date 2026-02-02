//! CLI entry point for the Vexscan security scanner.

use vexscan::{
    cli::{Cli, Commands, RulesSubcommand},
    config::{generate_default_config, Config},
    decoders::Decoder,
    filter_rules_by_author, filter_rules_by_source, filter_rules_by_tag, load_builtin_json_rules,
    reporters::{report, OutputFormat},
    rules::patterns::builtin_rules,
    test_all_rules, test_rules_from_file, AiAnalyzerConfig, AiBackend, AnalyzerConfig, Platform,
    RuleSource, ScanConfig, Scanner, Severity,
};
use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use std::io;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| log_level.into()))
        .with_target(false)
        .init();

    // Load config file if specified, otherwise use defaults
    let base_config = if let Some(ref config_path) = cli.config {
        Config::load(config_path)?
    } else {
        Config::load_default()
    };

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
        } => {
            // Parse platform
            let platform: Option<Platform> = platform
                .map(|p| p.parse())
                .transpose()
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            // Parse severity
            let min_severity = parse_severity(&min_severity)?;
            let fail_on_severity = fail_on.as_ref().map(|s| parse_severity(s)).transpose()?;

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

            // Build scan config
            let mut config = ScanConfig {
                enable_ai: ai,
                enable_ast: ast,
                enable_deps: deps,
                platform,
                min_severity,
                filter_config,
                static_config,
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
            let scan_report = scanner.scan_path(&path).await?;

            // Output format
            let format: OutputFormat = cli.format.parse().map_err(|e| anyhow::anyhow!("{}", e))?;

            // Write output
            if let Some(output_path) = output {
                let mut file = std::fs::File::create(&output_path)?;
                report(&scan_report, format, &mut file)?;
                eprintln!("Report written to: {}", output_path.display());
            } else {
                let mut stdout = io::stdout().lock();
                report(&scan_report, format, &mut stdout)?;
            }

            // Check fail condition
            if let Some(fail_severity) = fail_on_severity {
                if let Some(max_sev) = scan_report.max_severity() {
                    if max_sev >= fail_severity {
                        std::process::exit(1);
                    }
                }
            }
        }

        Commands::Watch {
            platform,
            notify: send_notifications,
            third_party_only,
            min_severity,
            watch_paths,
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
            eprintln!("{}", "═".repeat(60).bright_blue());
            eprintln!(
                "{}  {} Watch Mode",
                "👁".bright_blue(),
                "Vexscan".bold()
            );
            eprintln!("{}", "═".repeat(60).bright_blue());
            eprintln!();
            eprintln!("{}", "Watching for new plugin installations...".cyan());
            for path in &paths_to_watch {
                eprintln!("  {} {}", "→".dimmed(), path.display());
            }
            if third_party_only {
                eprintln!("  {} Only alerting on third-party plugins", "ℹ".blue());
            }
            eprintln!("  {} Minimum severity: {:?}", "ℹ".blue(), min_severity);
            if send_notifications {
                eprintln!("  {} Desktop notifications enabled", "🔔".yellow());
            }
            eprintln!();
            eprintln!("{}", "Press Ctrl+C to stop.".dimmed());
            eprintln!();

            // Create scanner config
            let scan_config = ScanConfig {
                enable_ai: false,
                platform,
                min_severity,
                filter_config: filter_config.clone(),
                static_config: AnalyzerConfig::default(),
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
                    eprintln!(
                        "{} Path does not exist, skipping: {}",
                        "⚠".yellow(),
                        path.display()
                    );
                }
            }

            // Track seen files to avoid duplicate scans
            let mut seen_files: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

            // Event loop
            loop {
                match rx.recv() {
                    Ok(event) => {
                        // Only process Create events
                        if !matches!(event.kind, notify::EventKind::Create(_)) {
                            continue;
                        }

                        for path in event.paths {
                            // Skip if we've already seen this file
                            if seen_files.contains(&path) {
                                continue;
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

                            eprintln!(
                                "\n{} New file detected: {}",
                                "📄".cyan(),
                                path.display()
                            );

                            // Scan the file
                            match scanner.scan_path(&path).await {
                                Ok(scan_report) => {
                                    let findings_count = scan_report.total_findings();

                                    if findings_count > 0 {
                                        let max_sev = scan_report.max_severity();

                                        // Print alert
                                        eprintln!(
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
                                                eprintln!(
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
                                                &format!("Vexscan: {} issue(s) found", findings_count),
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
                                        eprintln!(
                                            "   {} No issues found",
                                            "✓".green()
                                        );
                                    }
                                }
                                Err(e) => {
                                    eprintln!(
                                        "   {} Failed to scan: {}",
                                        "⚠".yellow(),
                                        e
                                    );
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
                            eprintln!("{} {}", "Testing rules from:".cyan(), p.display());
                            match test_rules_from_file(&p) {
                                Ok(r) => r,
                                Err(e) => {
                                    eprintln!("{} Failed to load rules: {}", "Error:".red(), e);
                                    std::process::exit(1);
                                }
                            }
                        } else {
                            // Test all built-in rules
                            eprintln!("{}", "Testing all built-in rules...".cyan());
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
                                println!(
                                    "{} {} - {} ({} tests)",
                                    status_icon,
                                    result.rule_id.cyan(),
                                    result.rule_title,
                                    result.total_tests()
                                );
                            } else {
                                println!("{} {} - {}", status_icon, result.rule_id.cyan(), result.rule_title);

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

                            if result.passed && result.total_tests() > 0 {
                                total_passed += result.total_tests();
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

            // Load rules based on source filter
            let mut rules = if official && !community {
                filter_rules_by_source(&load_builtin_json_rules(), RuleSource::Official)
            } else if community && !official {
                filter_rules_by_source(&load_builtin_json_rules(), RuleSource::Community)
            } else {
                // Fall back to compiled rules if no JSON rules, or use JSON rules
                let json_rules = load_builtin_json_rules();
                if json_rules.is_empty() {
                    builtin_rules()
                } else {
                    json_rules
                }
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
                        println!("Pattern:     {}", r.pattern);
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
                                    println!("  Test cases: {} should_match, {} should_not_match",
                                        tc.should_match.len(), tc.should_not_match.len());
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
                    let title = if official {
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
                    sorted_rules.sort_by(|a, b| format!("{}", a.category).cmp(&format!("{}", b.category)));

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
                            RuleSource::Official => "".normal(),
                        };

                        println!(
                            "  {} [{}] - {}{}",
                            r.id.bright_cyan(),
                            severity_color,
                            r.title,
                            source_badge
                        );
                    }
                    println!();
                    println!("Total: {} rules", rules.len());
                    if !official && !community {
                        let official_count = rules.iter().filter(|r| r.source == RuleSource::Official).count();
                        let community_count = rules.iter().filter(|r| r.source == RuleSource::Community).count();
                        println!("  {} official, {} community", official_count, community_count);
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
                    println!("\n{}", format!("Layer {} (depth {})", i + 1, i + 1).underline());
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
                eprintln!(
                    "{}",
                    format!("Config file already exists: {}", output.display()).yellow()
                );
                eprintln!("Use a different path or remove the existing file.");
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
        } => {
            // Validate platform
            if platform != "claude-code" {
                return Err(anyhow::anyhow!(
                    "Currently only 'claude-code' platform is supported for installation"
                ));
            }

            eprintln!("{}", "═".repeat(60).bright_blue());
            eprintln!(
                "{}  {} Install",
                "📦".bright_blue(),
                "Vexscan".bold()
            );
            eprintln!("{}", "═".repeat(60).bright_blue());
            eprintln!();

            // Step 1: Fetch the source
            let (scan_path, temp_dir, source_name) = if is_github_url(&source) {
                eprintln!("{} {}", "Fetching:".cyan(), source);
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
                eprintln!("{} {}", "Source:".cyan(), path.display());
                (path, None, dir_name)
            };

            // Step 2: Detect installation type
            let detected_type = detect_install_type(&scan_path);
            let final_type = install_type.as_deref().unwrap_or(&detected_type);
            let install_name = name.unwrap_or_else(|| source_name.clone());

            eprintln!("{} {} ({})", "Component:".cyan(), install_name.bright_white(), final_type);
            eprintln!();

            // Step 3: Security scan
            eprintln!("{}", "Scanning for security issues...".yellow());
            eprintln!();

            let mut filter_config = base_config.clone();
            if skip_deps {
                filter_config.skip_node_modules = true;
            }

            let config = ScanConfig {
                enable_ai: false,
                enable_ast: ast,
                enable_deps: deps,
                platform: None,
                min_severity: Severity::Low,
                filter_config,
                static_config: AnalyzerConfig::default(),
                ..Default::default()
            };

            let scanner = Scanner::with_config(config)?;
            let scan_report = scanner.scan_path(&scan_path).await?;

            // Show findings summary
            let (critical, high, medium, low, info) = count_by_severity(&scan_report);
            let total = critical + high + medium + low + info;

            if total > 0 {
                // Show the scan report
                let format: OutputFormat = cli.format.parse().map_err(|e| anyhow::anyhow!("{}", e))?;
                let mut stdout = io::stdout().lock();
                report(&scan_report, format, &mut stdout)?;
                drop(stdout);
                eprintln!();
            }

            // Step 4: Determine if installation should proceed
            let max_sev = scan_report.max_severity();
            let can_install = match max_sev {
                Some(Severity::Critical) => {
                    eprintln!(
                        "{} {} - Installation blocked",
                        "🚨 CRITICAL ISSUES FOUND".bright_red().bold(),
                        format!("({} critical)", critical).red()
                    );
                    eprintln!("   This component contains critical security issues and cannot be installed.");
                    eprintln!("   Review the findings above and contact the author.");
                    false
                }
                Some(Severity::High) => {
                    if allow_high {
                        eprintln!(
                            "{} {} - Proceeding (--allow-high)",
                            "⚠️  HIGH SEVERITY ISSUES".red().bold(),
                            format!("({} high)", high).red()
                        );
                        true
                    } else {
                        eprintln!(
                            "{} {} - Installation blocked",
                            "⚠️  HIGH SEVERITY ISSUES".red().bold(),
                            format!("({} high)", high).red()
                        );
                        eprintln!("   Use --allow-high to install anyway (not recommended).");
                        false
                    }
                }
                Some(Severity::Medium) => {
                    if force {
                        eprintln!(
                            "{} {} - Proceeding (--force)",
                            "⚡ WARNINGS FOUND".yellow(),
                            format!("({} medium)", medium).yellow()
                        );
                        true
                    } else {
                        eprintln!(
                            "{} {}",
                            "⚡ WARNINGS FOUND".yellow(),
                            format!("({} medium)", medium).yellow()
                        );
                        eprintln!("   Use --force to install anyway.");
                        false
                    }
                }
                Some(Severity::Low) | Some(Severity::Info) | None => {
                    if total > 0 {
                        eprintln!(
                            "{} ({} low, {} info)",
                            "✓ Minor issues only".green(),
                            low, info
                        );
                    } else {
                        eprintln!("{}", "✓ No security issues found".green().bold());
                    }
                    true
                }
            };

            if !can_install {
                eprintln!();
                eprintln!("{}", "Installation aborted.".red());
                std::process::exit(1);
            }

            // Step 5: Install
            eprintln!();

            if dry_run {
                eprintln!("{}", "DRY RUN - Would install to:".yellow().bold());
                let install_path = get_install_path(final_type, &install_name)?;
                eprintln!("   {}", install_path.display());
                eprintln!();
                eprintln!("Run without --dry-run to actually install.");
            } else {
                let install_path = install_component(&scan_path, final_type, &install_name)?;
                eprintln!("{}", "═".repeat(60).green());
                eprintln!(
                    "{} Installed {} to:",
                    "✓".green().bold(),
                    install_name.bright_white()
                );
                eprintln!("   {}", install_path.display().to_string().green());
                eprintln!("{}", "═".repeat(60).green());

                // Show usage hint
                match final_type {
                    "skill" | "command" => {
                        eprintln!();
                        eprintln!("{}  Use with: /{}", "💡".yellow(), install_name);
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
        } => {
            // Parse severities
            let min_severity = parse_severity(&min_severity)?;
            let fail_on_severity = parse_severity(&fail_on)?;

            // Determine if source is a URL or local path
            let (scan_path, temp_dir) = if is_github_url(&source) {
                eprintln!("{}", "Fetching from GitHub...".cyan());
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

            eprintln!(
                "{} {}",
                "Vetting:".bold(),
                source.bright_cyan()
            );
            eprintln!();

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

            // Build scan config
            let config = ScanConfig {
                enable_ai: false,
                enable_ast: ast,
                enable_deps: deps,
                platform: None,
                min_severity,
                filter_config,
                static_config,
                ..Default::default()
            };

            // Run scanner
            let scanner = Scanner::with_config(config)?;
            let scan_report = scanner.scan_path(&scan_path).await?;

            // Output results
            let format: OutputFormat = cli.format.parse().map_err(|e| anyhow::anyhow!("{}", e))?;

            if let Some(output_path) = output {
                let mut file = std::fs::File::create(&output_path)?;
                report(&scan_report, format, &mut file)?;
                eprintln!("Report written to: {}", output_path.display());
            } else {
                let mut stdout = io::stdout().lock();
                report(&scan_report, format, &mut stdout)?;
            }

            // Print verdict
            eprintln!();
            print_verdict(&scan_report, fail_on_severity);

            // Cleanup temp directory (unless --keep)
            if let Some(temp) = temp_dir {
                if keep {
                    let kept_path = temp.path().to_path_buf();
                    // Leak the temp dir so it doesn't get cleaned up
                    std::mem::forget(temp);
                    eprintln!(
                        "\n{} {}",
                        "Repository kept at:".dimmed(),
                        kept_path.display()
                    );
                }
                // If not keep, temp_dir drops and cleans up automatically
            }

            // Exit with appropriate code
            if let Some(max_sev) = scan_report.max_severity() {
                if max_sev >= fail_on_severity {
                    std::process::exit(1);
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

    eprintln!("  {} {}", "Cloning".dimmed(), clone_url.dimmed());

    builder.clone(&clone_url, temp_dir.path()).map_err(|e| {
        anyhow::anyhow!("Failed to clone repository: {}", e)
    })?;

    eprintln!("  {} {}", "Cloned to".dimmed(), temp_dir.path().display());

    Ok(temp_dir)
}

/// Print the verdict based on scan results.
fn print_verdict(report: &vexscan::ScanReport, threshold: Severity) {
    let max_sev = report.max_severity();

    let (critical, high, medium, low, info) = count_by_severity(report);

    eprintln!("{}", "═".repeat(60));

    match max_sev {
        Some(sev) if sev >= Severity::Critical => {
            eprintln!(
                "{} {}",
                "VERDICT:".bold(),
                "🚨 DANGEROUS - DO NOT INSTALL".bright_red().bold()
            );
            eprintln!(
                "         Found {} critical issue(s) that may compromise your system.",
                critical.to_string().bright_red()
            );
        }
        Some(sev) if sev >= Severity::High => {
            eprintln!(
                "{} {}",
                "VERDICT:".bold(),
                "⚠️  HIGH RISK - Review carefully before installing".red().bold()
            );
            eprintln!(
                "         Found {} high severity issue(s).",
                high.to_string().red()
            );
        }
        Some(sev) if sev >= Severity::Medium => {
            eprintln!(
                "{} {}",
                "VERDICT:".bold(),
                "⚡ WARNINGS - Proceed with caution".yellow().bold()
            );
            eprintln!(
                "         Found {} medium severity issue(s).",
                medium.to_string().yellow()
            );
        }
        Some(sev) if sev >= Severity::Low => {
            eprintln!(
                "{} {}",
                "VERDICT:".bold(),
                "ℹ️  MINOR ISSUES - Generally safe".blue()
            );
            eprintln!(
                "         Found {} low severity and {} info issue(s).",
                low.to_string().blue(),
                info.to_string().white()
            );
        }
        Some(_) | None => {
            eprintln!(
                "{} {}",
                "VERDICT:".bold(),
                "✅ CLEAN - No issues found".green().bold()
            );
        }
    }

    // Show summary counts
    if critical + high + medium + low + info > 0 {
        eprintln!();
        eprintln!(
            "         Summary: {} critical, {} high, {} medium, {} low, {} info",
            if critical > 0 { critical.to_string().bright_red().to_string() } else { "0".dimmed().to_string() },
            if high > 0 { high.to_string().red().to_string() } else { "0".dimmed().to_string() },
            if medium > 0 { medium.to_string().yellow().to_string() } else { "0".dimmed().to_string() },
            if low > 0 { low.to_string().blue().to_string() } else { "0".dimmed().to_string() },
            if info > 0 { info.to_string().white().to_string() } else { "0".dimmed().to_string() },
        );
    }

    eprintln!("{}", "═".repeat(60));

    // Note about threshold
    if max_sev.map(|s| s >= threshold).unwrap_or(false) {
        eprintln!(
            "\n{} Exit code 1 (findings at {} or above)",
            "Note:".dimmed(),
            format!("{:?}", threshold).to_lowercase()
        );
    }
}

/// Count findings by severity.
fn count_by_severity(report: &vexscan::ScanReport) -> (usize, usize, usize, usize, usize) {
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    let mut info = 0;

    for result in &report.results {
        for finding in &result.findings {
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

fn truncate(s: &str, max: usize) -> String {
    let char_count = s.chars().count();
    if char_count <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max).collect();
        format!("{}...", truncated)
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
    let cleaned = url
        .trim_end_matches('/')
        .trim_end_matches(".git");

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
                .filter(|e| {
                    e.path()
                        .extension()
                        .map(|ext| ext == "md")
                        .unwrap_or(false)
                })
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
    let home_dir = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not find home directory"))?;
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
    Err(anyhow::anyhow!("No .{} file found in {}", extension, dir.display()))
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
