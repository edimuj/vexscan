//! Output formatters for scan results.

use crate::components::{ComponentKind, DetectedComponent};
use crate::scope::InstallScope;
use crate::types::{ScanReport, ScanResult, Severity};
use anyhow::Result;
use colored::Colorize;
use std::io::Write;

/// Output format for scan results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    #[default]
    Cli,
    Json,
    Sarif,
    Markdown,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "cli" | "terminal" | "console" => Ok(OutputFormat::Cli),
            "json" => Ok(OutputFormat::Json),
            "sarif" => Ok(OutputFormat::Sarif),
            "md" | "markdown" => Ok(OutputFormat::Markdown),
            _ => Err(format!("Unknown output format: {}", s)),
        }
    }
}

/// Report the scan results in the specified format.
pub fn report<W: Write>(report: &ScanReport, format: OutputFormat, writer: &mut W) -> Result<()> {
    match format {
        OutputFormat::Cli => report_cli(report, writer),
        OutputFormat::Json => report_json(report, writer),
        OutputFormat::Sarif => report_sarif(report, writer),
        OutputFormat::Markdown => report_markdown(report, writer),
    }
}

/// CLI-formatted output with colors.
fn report_cli<W: Write>(report: &ScanReport, writer: &mut W) -> Result<()> {
    writeln!(writer)?;
    writeln!(
        writer,
        "{}",
        "═══════════════════════════════════════════════════════════════".bright_blue()
    )?;
    writeln!(
        writer,
        "{}  Vexscan Security Scan Report",
        "🔒".bright_blue()
    )?;
    writeln!(
        writer,
        "{}",
        "═══════════════════════════════════════════════════════════════".bright_blue()
    )?;
    writeln!(writer)?;

    // Summary
    writeln!(writer, "{}", "Summary".bold().underline())?;
    writeln!(writer, "  Scan root:    {}", report.scan_root.display())?;
    if let Some(ref platform) = report.platform {
        writeln!(writer, "  Platform:     {}", platform)?;
    }
    if report.installed_file_count > 0 || report.dev_only_file_count > 0 {
        let agent_tag = if report.agent_reachable_count > 0 {
            format!(", {} agent-reachable", report.agent_reachable_count)
        } else {
            String::new()
        };
        writeln!(
            writer,
            "  Files scanned: {} ({} installed, {} dev-only{})",
            report.results.len(),
            report.installed_file_count,
            report.dev_only_file_count,
            agent_tag
        )?;
    } else {
        writeln!(writer, "  Files scanned: {}", report.results.len())?;
    }
    let total_active = report
        .results
        .iter()
        .flat_map(|r| &r.findings)
        .filter(|f| f.suppressed_by.is_none())
        .count();
    let total_suppressed = report.total_findings() - total_active;
    if total_suppressed > 0 {
        writeln!(
            writer,
            "  Total findings: {} ({} suppressed)",
            total_active, total_suppressed
        )?;
    } else {
        writeln!(writer, "  Total findings: {}", total_active)?;
    }
    writeln!(
        writer,
        "  Rules active:  {} (AST: {}, Deps: {})",
        report.rule_count,
        if report.ast_enabled { "on" } else { "off" },
        if report.deps_enabled { "on" } else { "off" }
    )?;
    let risk_label = ScanReport::risk_label(report.risk_score);
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
    writeln!(writer, "  Risk score:   {}", risk_colored)?;
    writeln!(writer, "  Scan time:    {}ms", report.total_time_ms)?;

    // Component summary
    if !report.components.is_empty() {
        let mut kind_counts: std::collections::HashMap<ComponentKind, usize> =
            std::collections::HashMap::new();
        for comp in &report.components {
            *kind_counts.entry(comp.kind).or_insert(0) += 1;
        }
        let breakdown: Vec<String> = kind_counts
            .iter()
            .map(|(k, v)| {
                let label = match k {
                    ComponentKind::Skill => "skill",
                    ComponentKind::McpServer => "MCP server",
                    ComponentKind::Plugin => "plugin",
                    ComponentKind::NpmPackage => "npm package",
                    ComponentKind::RustCrate => "Rust crate",
                };
                if *v == 1 {
                    format!("{} {}", v, label)
                } else {
                    format!("{} {}s", v, label)
                }
            })
            .collect();
        writeln!(
            writer,
            "  Components:   {} detected ({})",
            report.components.len(),
            breakdown.join(", ")
        )?;
    }
    writeln!(writer)?;

    // Findings by severity (count only active, non-suppressed findings)
    let counts = {
        let mut c = std::collections::HashMap::new();
        for result in &report.results {
            for finding in &result.findings {
                if finding.suppressed_by.is_none() {
                    *c.entry(finding.severity).or_insert(0usize) += 1;
                }
            }
        }
        c
    };
    writeln!(writer, "{}", "Findings by Severity".bold().underline())?;
    writeln!(
        writer,
        "  {} Critical: {}",
        "●".bright_red(),
        counts.get(&Severity::Critical).unwrap_or(&0)
    )?;
    writeln!(
        writer,
        "  {} High:     {}",
        "●".red(),
        counts.get(&Severity::High).unwrap_or(&0)
    )?;
    writeln!(
        writer,
        "  {} Medium:   {}",
        "●".yellow(),
        counts.get(&Severity::Medium).unwrap_or(&0)
    )?;
    writeln!(
        writer,
        "  {} Low:      {}",
        "●".blue(),
        counts.get(&Severity::Low).unwrap_or(&0)
    )?;
    writeln!(
        writer,
        "  {} Info:     {}",
        "●".white(),
        counts.get(&Severity::Info).unwrap_or(&0)
    )?;
    writeln!(writer)?;

    // Detailed findings
    if report.total_findings() > 0 {
        writeln!(writer, "{}", "Detailed Findings".bold().underline())?;
        writeln!(writer)?;

        if report.components.is_empty() {
            // No components detected — flat output (original behavior)
            for result in &report.results {
                if result.findings.is_empty() {
                    continue;
                }
                write_result_findings(result, &report.scan_root, writer)?;
            }
        } else {
            // Group findings by component
            for (comp_idx, comp) in report.components.iter().enumerate() {
                let comp_results: Vec<&ScanResult> = report
                    .results
                    .iter()
                    .filter(|r| r.component_idx == Some(comp_idx) && !r.findings.is_empty())
                    .collect();

                if comp_results.is_empty() {
                    continue;
                }

                let file_count = report
                    .results
                    .iter()
                    .filter(|r| r.component_idx == Some(comp_idx))
                    .count();
                let finding_count: usize = comp_results.iter().map(|r| r.findings.len()).sum();
                let comp_max_sev = comp_results.iter().filter_map(|r| r.max_severity()).max();
                let risk_tag = comp_max_sev
                    .map(|s| format!("{}", s).to_uppercase())
                    .unwrap_or_else(|| "CLEAN".to_string());

                write_component_header(comp, file_count, finding_count, &risk_tag, writer)?;

                let rel_root = comp
                    .root
                    .strip_prefix(&report.scan_root)
                    .unwrap_or(&comp.root);
                writeln!(writer, "   Path: {}/", rel_root.display())?;
                writeln!(writer)?;

                for result in comp_results {
                    write_result_findings(result, &comp.root, writer)?;
                }
            }

            // "Other files" bucket
            let other_results: Vec<&ScanResult> = report
                .results
                .iter()
                .filter(|r| r.component_idx.is_none() && !r.findings.is_empty())
                .collect();

            if !other_results.is_empty() {
                writeln!(
                    writer,
                    "{}",
                    "── Other files ─────────────────────────────────".bright_black()
                )?;
                writeln!(writer)?;

                for result in other_results {
                    write_result_findings(result, &report.scan_root, writer)?;
                }
            }
        }
    }

    // Exit status indicator (based on non-suppressed findings only)
    writeln!(writer)?;
    if let Some(max_sev) = report.max_active_severity() {
        if max_sev >= Severity::High {
            writeln!(
                writer,
                "{}",
                "⚠️  Security issues detected! Review findings above."
                    .bright_red()
                    .bold()
            )?;
        } else {
            writeln!(
                writer,
                "{}",
                "⚡ Some potential issues found. Review recommended.".yellow()
            )?;
        }
    } else {
        writeln!(
            writer,
            "{}",
            "✅ No security issues detected.".green().bold()
        )?;
    }
    writeln!(writer)?;

    Ok(())
}

/// Write the component section header.
fn write_component_header<W: Write>(
    comp: &DetectedComponent,
    file_count: usize,
    finding_count: usize,
    risk_tag: &str,
    writer: &mut W,
) -> Result<()> {
    let header = format!("── {}: {} ──", comp.kind, comp.name);
    let colored_header = match risk_tag {
        "CRITICAL" => header.bright_red().bold().to_string(),
        "HIGH" => header.red().bold().to_string(),
        "MEDIUM" => header.yellow().bold().to_string(),
        _ => header.bright_blue().to_string(),
    };
    writeln!(writer, "{}", colored_header)?;
    writeln!(
        writer,
        "   Files: {} | Findings: {} | Risk: {}",
        file_count, finding_count, risk_tag
    )?;
    Ok(())
}

/// Write findings for a single scan result (one file).
fn write_result_findings<W: Write>(
    result: &ScanResult,
    strip_prefix: &std::path::Path,
    writer: &mut W,
) -> Result<()> {
    let display_path = result
        .path
        .strip_prefix(strip_prefix)
        .unwrap_or(&result.path);

    let has_agent_reachable = result.findings.iter().any(|f| {
        f.metadata
            .get("agent_reachable")
            .map(|v| v == "true")
            .unwrap_or(false)
    });
    let scope_tag = if has_agent_reachable {
        format!(" {}", "[agent-reachable]".yellow())
    } else if result.install_scope == Some(InstallScope::DevOnly) {
        format!(" {}", "[dev-only]".dimmed())
    } else {
        String::new()
    };
    writeln!(
        writer,
        "{}{}",
        format!("   ── {} ──", display_path.display()).bright_blue(),
        scope_tag
    )?;

    let mut suppressed_count = 0usize;
    for finding in &result.findings {
        if finding.suppressed_by.is_some() {
            suppressed_count += 1;
            continue;
        }

        let severity_indicator = match finding.severity {
            Severity::Critical => "▲ CRITICAL".bright_red().bold(),
            Severity::High => "▲ HIGH".red().bold(),
            Severity::Medium => "● MEDIUM".yellow().bold(),
            Severity::Low => "● LOW".blue(),
            Severity::Info => "○ INFO".white(),
        };

        let scope_tag = if finding
            .metadata
            .get("agent_reachable")
            .map(|v| v == "true")
            .unwrap_or(false)
        {
            let via = finding
                .metadata
                .get("referenced_by")
                .map(|refs| format!(" {}", format!("(via {})", refs).dimmed()))
                .unwrap_or_default();
            format!(" {}{}", "[agent-reachable]".yellow(), via)
        } else if finding.metadata.get("install_scope").map(|s| s.as_str()) == Some("dev_only") {
            format!(" {}", "[dev-only]".dimmed())
        } else {
            String::new()
        };

        writeln!(writer)?;
        writeln!(
            writer,
            "     {} [{}]{}",
            severity_indicator, finding.rule_id, scope_tag
        )?;
        writeln!(writer, "     {}", finding.title.bold())?;
        writeln!(
            writer,
            "     Location: line {}-{}",
            finding.location.start_line, finding.location.end_line
        )?;
        writeln!(writer, "     {}", finding.description.dimmed())?;

        let snippet = if finding.snippet.chars().count() > 100 {
            let truncated: String = finding.snippet.chars().take(100).collect();
            format!("{}...", truncated)
        } else {
            finding.snippet.clone()
        };
        writeln!(writer, "     Code: {}", snippet.bright_black())?;

        if let Some(ref remediation) = finding.remediation {
            writeln!(writer, "     Fix: {}", remediation.green())?;
        }
    }
    if suppressed_count > 0 {
        writeln!(
            writer,
            "     {}",
            format!("({} suppressed by trust store)", suppressed_count).dimmed()
        )?;
    }
    writeln!(writer)?;
    Ok(())
}

/// JSON output format.
fn report_json<W: Write>(report: &ScanReport, writer: &mut W) -> Result<()> {
    serde_json::to_writer_pretty(writer, report)?;
    Ok(())
}

/// SARIF format for GitHub integration.
fn report_sarif<W: Write>(report: &ScanReport, writer: &mut W) -> Result<()> {
    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "vexscan",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/edimuj/vexscan",
                    "rules": collect_rules(report)
                }
            },
            "results": collect_sarif_results(report)
        }]
    });

    serde_json::to_writer_pretty(writer, &sarif)?;
    Ok(())
}

fn collect_rules(report: &ScanReport) -> Vec<serde_json::Value> {
    let mut rules = std::collections::HashMap::new();

    for result in &report.results {
        for finding in &result.findings {
            rules.entry(finding.rule_id.clone()).or_insert_with(|| {
                serde_json::json!({
                    "id": finding.rule_id,
                    "name": finding.title,
                    "shortDescription": {
                        "text": finding.title
                    },
                    "fullDescription": {
                        "text": finding.description
                    },
                    "defaultConfiguration": {
                        "level": severity_to_sarif_level(finding.severity)
                    }
                })
            });
        }
    }

    rules.into_values().collect()
}

fn collect_sarif_results(report: &ScanReport) -> Vec<serde_json::Value> {
    let mut results = Vec::new();

    for scan_result in &report.results {
        for finding in &scan_result.findings {
            let mut region = serde_json::json!({
                "startLine": finding.location.start_line,
                "endLine": finding.location.end_line
            });
            if let Some(col) = finding.location.start_column {
                region["startColumn"] = serde_json::json!(col);
            }
            if let Some(col) = finding.location.end_column {
                region["endColumn"] = serde_json::json!(col);
            }

            results.push(serde_json::json!({
                "ruleId": finding.rule_id,
                "level": severity_to_sarif_level(finding.severity),
                "message": {
                    "text": finding.description
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.location.file
                                .strip_prefix(&report.scan_root)
                                .unwrap_or(&finding.location.file)
                                .display()
                                .to_string()
                        },
                        "region": region
                    }
                }]
            }));
        }
    }

    results
}

fn severity_to_sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// Markdown output format.
fn report_markdown<W: Write>(report: &ScanReport, writer: &mut W) -> Result<()> {
    writeln!(writer, "# Agent Security Scan Report")?;
    writeln!(writer)?;
    writeln!(writer, "## Summary")?;
    writeln!(writer)?;
    writeln!(writer, "| Metric | Value |")?;
    writeln!(writer, "|--------|-------|")?;
    writeln!(writer, "| Scan Root | `{}` |", report.scan_root.display())?;
    if let Some(ref platform) = report.platform {
        writeln!(writer, "| Platform | {} |", platform)?;
    }
    if report.installed_file_count > 0 || report.dev_only_file_count > 0 {
        let agent_tag = if report.agent_reachable_count > 0 {
            format!(", {} agent-reachable", report.agent_reachable_count)
        } else {
            String::new()
        };
        writeln!(
            writer,
            "| Files Scanned | {} ({} installed, {} dev-only{}) |",
            report.results.len(),
            report.installed_file_count,
            report.dev_only_file_count,
            agent_tag
        )?;
    } else {
        writeln!(writer, "| Files Scanned | {} |", report.results.len())?;
    }
    writeln!(writer, "| Total Findings | {} |", report.total_findings())?;
    writeln!(
        writer,
        "| Risk Score | {}/100 ({}) |",
        report.risk_score,
        ScanReport::risk_label(report.risk_score)
    )?;
    writeln!(writer, "| Scan Time | {}ms |", report.total_time_ms)?;
    writeln!(writer)?;

    let counts = report.findings_count_by_severity();
    writeln!(writer, "## Findings by Severity")?;
    writeln!(writer)?;
    writeln!(
        writer,
        "- 🔴 Critical: {}",
        counts.get(&Severity::Critical).unwrap_or(&0)
    )?;
    writeln!(
        writer,
        "- 🟠 High: {}",
        counts.get(&Severity::High).unwrap_or(&0)
    )?;
    writeln!(
        writer,
        "- 🟡 Medium: {}",
        counts.get(&Severity::Medium).unwrap_or(&0)
    )?;
    writeln!(
        writer,
        "- 🔵 Low: {}",
        counts.get(&Severity::Low).unwrap_or(&0)
    )?;
    writeln!(
        writer,
        "- ⚪ Info: {}",
        counts.get(&Severity::Info).unwrap_or(&0)
    )?;
    writeln!(writer)?;

    if report.total_findings() > 0 {
        writeln!(writer, "## Detailed Findings")?;
        writeln!(writer)?;

        for result in &report.results {
            if result.findings.is_empty() {
                continue;
            }

            writeln!(writer, "### `{}`", result.path.display())?;
            writeln!(writer)?;

            for finding in &result.findings {
                let severity_emoji = match finding.severity {
                    Severity::Critical => "🔴",
                    Severity::High => "🟠",
                    Severity::Medium => "🟡",
                    Severity::Low => "🔵",
                    Severity::Info => "⚪",
                };

                writeln!(
                    writer,
                    "#### {} {} [{}]",
                    severity_emoji, finding.title, finding.rule_id
                )?;
                writeln!(writer)?;
                writeln!(
                    writer,
                    "**Location:** Line {}-{}",
                    finding.location.start_line, finding.location.end_line
                )?;
                writeln!(writer)?;
                writeln!(writer, "{}", finding.description)?;
                writeln!(writer)?;
                writeln!(writer, "```")?;
                writeln!(writer, "{}", finding.snippet)?;
                writeln!(writer, "```")?;
                writeln!(writer)?;

                if let Some(ref remediation) = finding.remediation {
                    writeln!(writer, "**Remediation:** {}", remediation)?;
                    writeln!(writer)?;
                }
            }
        }
    }

    Ok(())
}
