//! Output formatters for scan results.

use crate::types::{ScanReport, Severity};
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
        "{}  Vetryx Security Scan Report",
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
    writeln!(writer, "  Files scanned: {}", report.results.len())?;
    writeln!(writer, "  Total findings: {}", report.total_findings())?;
    writeln!(writer, "  Scan time:    {}ms", report.total_time_ms)?;
    writeln!(writer)?;

    // Findings by severity
    let counts = report.findings_count_by_severity();
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

        for result in &report.results {
            if result.findings.is_empty() {
                continue;
            }

            writeln!(
                writer,
                "{}",
                format!("── {} ──", result.path.display()).bright_blue()
            )?;

            for finding in &result.findings {
                let severity_indicator = match finding.severity {
                    Severity::Critical => "▲ CRITICAL".bright_red().bold(),
                    Severity::High => "▲ HIGH".red().bold(),
                    Severity::Medium => "● MEDIUM".yellow().bold(),
                    Severity::Low => "● LOW".blue(),
                    Severity::Info => "○ INFO".white(),
                };

                writeln!(writer)?;
                writeln!(writer, "  {} [{}]", severity_indicator, finding.rule_id)?;
                writeln!(writer, "  {}", finding.title.bold())?;
                writeln!(
                    writer,
                    "  Location: line {}-{}",
                    finding.location.start_line, finding.location.end_line
                )?;
                writeln!(writer, "  {}", finding.description.dimmed())?;

                // Show snippet (truncated, UTF-8 safe)
                let snippet = if finding.snippet.chars().count() > 100 {
                    let truncated: String = finding.snippet.chars().take(100).collect();
                    format!("{}...", truncated)
                } else {
                    finding.snippet.clone()
                };
                writeln!(writer, "  Code: {}", snippet.bright_black())?;

                if let Some(ref remediation) = finding.remediation {
                    writeln!(writer, "  Fix: {}", remediation.green())?;
                }
            }
            writeln!(writer)?;
        }
    }

    // Exit status indicator
    writeln!(writer)?;
    if let Some(max_sev) = report.max_severity() {
        if max_sev >= Severity::High {
            writeln!(
                writer,
                "{}",
                "⚠️  Security issues detected! Review findings above.".bright_red().bold()
            )?;
        } else {
            writeln!(
                writer,
                "{}",
                "⚡ Some potential issues found. Review recommended.".yellow()
            )?;
        }
    } else {
        writeln!(writer, "{}", "✅ No security issues detected.".green().bold())?;
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
                    "name": "vetryx",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/yourusername/vetryx",
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
            results.push(serde_json::json!({
                "ruleId": finding.rule_id,
                "level": severity_to_sarif_level(finding.severity),
                "message": {
                    "text": finding.description
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.location.file.display().to_string()
                        },
                        "region": {
                            "startLine": finding.location.start_line,
                            "endLine": finding.location.end_line,
                            "startColumn": finding.location.start_column,
                            "endColumn": finding.location.end_column
                        }
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
    writeln!(writer, "| Files Scanned | {} |", report.results.len())?;
    writeln!(writer, "| Total Findings | {} |", report.total_findings())?;
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
