//! Command-line interface for the security scanner.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Subcommands for the `cache` command
#[derive(Subcommand, Debug)]
pub enum CacheSubcommand {
    /// Show cache statistics
    Stats,
    /// Clear all cached scan results
    Clear,
}

/// Subcommands for the `rules` command
#[derive(Subcommand, Debug)]
pub enum RulesSubcommand {
    /// Test rules against their test cases
    Test {
        /// Path to a specific rule file to test (tests all rules if not specified)
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,

        /// Only run tests for rules matching this ID pattern
        #[arg(long)]
        filter: Option<String>,

        /// Show detailed test output even for passing tests
        #[arg(long)]
        verbose: bool,
    },
}

/// Security scanner for AI agent plugins, skills, and MCP servers.
#[derive(Parser, Debug)]
#[command(name = "vexscan")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Suppress informational output (only show results and errors)
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Output format
    #[arg(short = 'f', long, global = true, default_value = "cli")]
    pub format: String,

    /// Config file path
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Scan a path or platform for security issues
    Scan {
        /// Path to scan (file or directory)
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Platform to scan (auto-detects if not specified)
        #[arg(short, long)]
        platform: Option<String>,

        /// Enable AI-powered analysis
        #[arg(long)]
        ai: bool,

        /// AI backend to use (claude, openai, ollama)
        #[arg(long, default_value = "claude")]
        ai_backend: String,

        /// Output file (writes to stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Minimum severity to report (info, low, medium, high, critical)
        #[arg(long, default_value = "high")]
        min_severity: String,

        /// Fail with exit code 1 if any findings at this severity or above
        #[arg(long, default_value = "high")]
        fail_on: String,

        /// Skip node_modules directories entirely (focus on actual code)
        #[arg(long)]
        skip_deps: bool,

        /// Enable entropy analysis (disabled by default due to false positives)
        #[arg(long)]
        enable_entropy: bool,

        /// Additional packages to trust (can be used multiple times)
        #[arg(long = "trust", value_name = "PACKAGE")]
        trusted_packages: Vec<String>,

        /// Only scan third-party/unknown plugins (skip official and trusted sources)
        #[arg(long)]
        third_party_only: bool,

        /// Enable AST-based analysis for obfuscation detection (catches patterns like window['eval'])
        #[arg(long)]
        ast: bool,

        /// Enable dependency scanning (check package.json for malicious packages)
        #[arg(long)]
        deps: bool,

        /// Disable result caching (rescan everything)
        #[arg(long)]
        no_cache: bool,

        /// Only scan installed/published files (skip tests, examples, docs)
        #[arg(long)]
        installed_only: bool,

        /// Scan all files at full severity (disable scope-based severity capping)
        #[arg(long)]
        include_dev: bool,

        /// Max parallel threads (default: half of available CPUs, 0 = all CPUs)
        #[arg(short = 'j', long, value_name = "N")]
        jobs: Option<usize>,
    },

    /// Watch for new plugin/skill installations and scan automatically
    Watch {
        /// Platform to watch (auto-detects if not specified)
        #[arg(short, long)]
        platform: Option<String>,

        /// Send desktop notifications on findings
        #[arg(long)]
        notify: bool,

        /// Only alert on third-party/untrusted plugins
        #[arg(long)]
        third_party_only: bool,

        /// Minimum severity to alert on (info, low, medium, high, critical)
        #[arg(long, default_value = "medium")]
        min_severity: String,

        /// Custom paths to watch (can be used multiple times)
        #[arg(long = "path", value_name = "PATH")]
        watch_paths: Vec<std::path::PathBuf>,

        /// Only scan installed/published files (skip tests, examples, docs)
        #[arg(long)]
        installed_only: bool,

        /// Scan all files at full severity (disable scope-based severity capping)
        #[arg(long)]
        include_dev: bool,
    },

    /// List all discovered components for a platform
    List {
        /// Platform to list (auto-detects if not specified)
        #[arg(short, long)]
        platform: Option<String>,
    },

    /// Show information about available rules
    Rules {
        /// Show details for a specific rule ID
        #[arg(short, long)]
        rule: Option<String>,

        /// Show only official rules
        #[arg(long)]
        official: bool,

        /// Show only community rules
        #[arg(long)]
        community: bool,

        /// Show only external (user-loaded) rules
        #[arg(long)]
        external: bool,

        /// Filter rules by author (partial match)
        #[arg(long)]
        author: Option<String>,

        /// Filter rules by tag
        #[arg(long)]
        tag: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,

        #[command(subcommand)]
        subcommand: Option<RulesSubcommand>,
    },

    /// Decode and analyze an encoded string
    Decode {
        /// The encoded string to analyze
        input: String,

        /// Maximum decode depth
        #[arg(short, long, default_value = "5")]
        depth: usize,
    },

    /// Generate a default configuration file
    Init {
        /// Output path for config file
        #[arg(default_value = "vexscan.toml")]
        output: PathBuf,
    },

    /// Vet and install a plugin/skill (scan first, install if clean)
    Install {
        /// GitHub URL or local path to install
        /// Examples:
        ///   https://github.com/user/claude-skill
        ///   ./my-local-skill/
        source: String,

        /// Installation type (auto-detected if not specified)
        /// Options: skill, command, plugin, hook
        #[arg(short = 't', long, value_name = "TYPE")]
        install_type: Option<String>,

        /// Custom name for the installed component (default: repo/directory name)
        #[arg(short, long)]
        name: Option<String>,

        /// Platform to install to (default: claude-code)
        #[arg(short, long, default_value = "claude-code")]
        platform: String,

        /// Force install even with medium severity findings (still blocks critical/high)
        #[arg(long)]
        force: bool,

        /// Install even with high severity findings (DANGEROUS - use with caution)
        #[arg(long)]
        allow_high: bool,

        /// Skip dependencies (node_modules, etc.) during scan
        #[arg(long)]
        skip_deps: bool,

        /// Branch to checkout (default: default branch)
        #[arg(short, long)]
        branch: Option<String>,

        /// Dry run - scan and show what would be installed without actually installing
        #[arg(long)]
        dry_run: bool,

        /// Enable AST-based analysis for obfuscation detection
        #[arg(long)]
        ast: bool,

        /// Enable dependency scanning (check package.json for malicious packages)
        #[arg(long)]
        deps: bool,

        /// Disable result caching (rescan everything)
        #[arg(long)]
        no_cache: bool,

        /// Only scan installed/published files (skip tests, examples, docs)
        #[arg(long)]
        installed_only: bool,

        /// Scan all files at full severity (disable scope-based severity capping)
        #[arg(long)]
        include_dev: bool,

        /// Max parallel threads (default: half of available CPUs, 0 = all CPUs)
        #[arg(short = 'j', long, value_name = "N")]
        jobs: Option<usize>,
    },

    /// Vet a plugin/skill before installation (scan from GitHub URL or local path)
    Vet {
        /// GitHub URL or local path to vet
        /// Examples:
        ///   https://github.com/user/claude-plugin
        ///   ./downloaded-plugin/
        source: String,

        /// Output file (writes to stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Minimum severity to report (info, low, medium, high, critical)
        #[arg(long, default_value = "high")]
        min_severity: String,

        /// Fail with exit code 1 if any findings at this severity or above
        #[arg(long, default_value = "high")]
        fail_on: String,

        /// Skip dependencies (node_modules, etc.)
        #[arg(long)]
        skip_deps: bool,

        /// Enable entropy analysis
        #[arg(long)]
        enable_entropy: bool,

        /// Keep cloned repository after vetting (don't delete temp dir)
        #[arg(long)]
        keep: bool,

        /// Branch to checkout (default: default branch)
        #[arg(short, long)]
        branch: Option<String>,

        /// Enable AST-based analysis for obfuscation detection
        #[arg(long)]
        ast: bool,

        /// Enable dependency scanning (check package.json for malicious packages)
        #[arg(long)]
        deps: bool,

        /// Disable result caching (rescan everything)
        #[arg(long)]
        no_cache: bool,

        /// Only scan installed/published files (skip tests, examples, docs)
        #[arg(long)]
        installed_only: bool,

        /// Scan all files at full severity (disable scope-based severity capping)
        #[arg(long)]
        include_dev: bool,

        /// Max parallel threads (default: half of available CPUs, 0 = all CPUs)
        #[arg(short = 'j', long, value_name = "N")]
        jobs: Option<usize>,
    },

    /// Check text for security patterns (prompt injection, exfiltration, etc.)
    Check {
        /// Text to check (reads from stdin if --stdin is used)
        #[arg(value_name = "TEXT")]
        input: Option<String>,

        /// Read input from stdin instead of argument
        #[arg(long)]
        stdin: bool,

        /// File type hint for rule filtering (default: md)
        /// Controls which rules apply. Examples: md, js, ts, py, sh, json
        #[arg(long, default_value = "md", value_name = "TYPE")]
        r#type: String,

        /// Minimum severity to report (info, low, medium, high, critical)
        #[arg(long, default_value = "low")]
        min_severity: String,

        /// Fail with exit code 1 if findings at this severity or above
        #[arg(long, default_value = "high")]
        fail_on: String,

        /// Enable AST-based analysis for obfuscation detection
        #[arg(long)]
        ast: bool,
    },

    /// Manage the trust store (suppress reviewed findings)
    Trust {
        #[command(subcommand)]
        subcommand: TrustSubcommand,
    },

    /// Manage the scan result cache
    Cache {
        #[command(subcommand)]
        subcommand: CacheSubcommand,
    },
}

/// Subcommands for the `trust` command
#[derive(Subcommand, Debug)]
pub enum TrustSubcommand {
    /// Accept specific findings for a component (suppress on future scans)
    Accept {
        /// Path to the component directory
        path: PathBuf,

        /// Comma-separated rule IDs to accept (e.g., INJECT-001,EXEC-002)
        #[arg(long, value_delimiter = ',')]
        rules: Vec<String>,

        /// Optional notes about why this was accepted
        #[arg(long)]
        notes: Option<String>,
    },

    /// Accept ALL findings for a component (full trust)
    Full {
        /// Path to the component directory
        path: PathBuf,

        /// Optional notes about why this was fully trusted
        #[arg(long)]
        notes: Option<String>,
    },

    /// Quarantine a component (inject critical finding on future scans)
    Quarantine {
        /// Path to the component directory
        path: PathBuf,
    },

    /// List all trust store entries
    List,

    /// Revoke trust for a component
    Revoke {
        /// Component name or key (e.g., "my-plugin" or "skill:my-plugin")
        name: String,
    },

    /// Show trust status for a component
    Show {
        /// Path to the component directory
        path: PathBuf,
    },
}
