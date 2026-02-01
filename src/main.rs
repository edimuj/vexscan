//! CLI entry point for the agent-security scanner.

use agent_security::{
    cli::{Cli, Commands},
    config::{generate_default_config, Config},
    decoders::Decoder,
    reporters::{report, OutputFormat},
    rules::patterns::builtin_rules,
    AiAnalyzerConfig, AiBackend, AnalyzerConfig, Platform, ScanConfig, Scanner, Severity,
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

        Commands::Watch { platform, notify } => {
            let platform: Option<Platform> = platform
                .map(|p| p.parse())
                .transpose()
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            eprintln!(
                "{}",
                "Watch mode is not yet implemented.".yellow()
            );
            eprintln!("Platform: {:?}", platform);
            eprintln!("Notify: {}", notify);

            // TODO: Implement file watching with the `notify` crate
        }

        Commands::List { platform } => {
            let platform: Option<Platform> = platform
                .map(|p| p.parse())
                .transpose()
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            let resolved_platform = platform.or_else(agent_security::adapters::detect_platform);

            match resolved_platform {
                Some(p) => {
                    let adapter = agent_security::adapters::create_adapter(p);
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

        Commands::Rules { rule, json } => {
            let rules = builtin_rules();

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
                        println!("Description: {}", r.description);
                        println!("Pattern:     {}", r.pattern);
                        if !r.file_extensions.is_empty() {
                            println!("Extensions:  {}", r.file_extensions.join(", "));
                        }
                        if let Some(ref rem) = r.remediation {
                            println!("Remediation: {}", rem);
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
                    println!("{}", "Available Rules".bold().underline());
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

                        println!(
                            "  {} [{}] - {}",
                            r.id.bright_cyan(),
                            severity_color,
                            r.title
                        );
                    }
                    println!();
                    println!("Total: {} rules", rules.len());
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

        Commands::Vet {
            source,
            output,
            min_severity,
            fail_on,
            skip_deps,
            enable_entropy,
            keep,
            branch,
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
fn print_verdict(report: &agent_security::ScanReport, threshold: Severity) {
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
fn count_by_severity(report: &agent_security::ScanReport) -> (usize, usize, usize, usize, usize) {
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
