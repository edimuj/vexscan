//! Command-line interface for the security scanner.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Security scanner for AI agent plugins, skills, and MCP servers.
#[derive(Parser, Debug)]
#[command(name = "vetryx")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

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
        #[arg(long, default_value = "low")]
        min_severity: String,

        /// Fail with exit code 1 if any findings at this severity or above
        #[arg(long)]
        fail_on: Option<String>,

        /// Skip node_modules directories entirely (focus on actual code)
        #[arg(long)]
        skip_deps: bool,

        /// Enable entropy analysis (disabled by default due to false positives)
        #[arg(long)]
        enable_entropy: bool,

        /// Additional packages to trust (can be used multiple times)
        #[arg(long = "trust", value_name = "PACKAGE")]
        trusted_packages: Vec<String>,
    },

    /// Watch for new plugin/skill installations and scan automatically
    Watch {
        /// Platform to watch
        #[arg(short, long)]
        platform: Option<String>,

        /// Send desktop notifications on findings
        #[arg(long)]
        notify: bool,
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

        /// Output as JSON
        #[arg(long)]
        json: bool,
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
        #[arg(default_value = "vetryx.toml")]
        output: PathBuf,
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
        #[arg(long, default_value = "low")]
        min_severity: String,

        /// Fail with exit code 1 if any findings at this severity or above
        #[arg(long, default_value = "medium")]
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
    },
}
