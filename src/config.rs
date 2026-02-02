//! Configuration for the scanner, including allowlists and trusted packages.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Extensions that are executable and should NEVER be skipped, regardless of filename.
const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "js", "mjs", "cjs", "ts", "tsx", "jsx", // JavaScript/TypeScript
    "py", "pyw", "pyc", "pyo",              // Python
    "sh", "bash", "zsh", "fish",            // Shell
    "rb", "erb",                            // Ruby
    "pl", "pm",                             // Perl
    "php", "phtml",                         // PHP
    "lua",                                  // Lua
    "ps1", "psm1", "psd1",                  // PowerShell
    "bat", "cmd",                           // Windows batch
    "jar", "class",                         // Java
    "exe", "dll", "so", "dylib",            // Binaries
    "wasm",                                 // WebAssembly
];

/// Extensions that are safe to skip (documentation/data only).
const SAFE_DOC_EXTENSIONS: &[&str] = &[
    "md", "markdown", "txt", "rst", "adoc", // Documentation
    "log",                                   // Log files
    "json", "yaml", "yml", "toml",          // Config (but be careful)
];

/// Scanner configuration that can be loaded from a file.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// Paths to skip (glob patterns).
    #[serde(default)]
    pub skip_paths: Vec<String>,

    /// Trusted npm packages (won't be scanned).
    #[serde(default)]
    pub trusted_packages: Vec<String>,

    /// Skip all node_modules directories.
    #[serde(default)]
    pub skip_node_modules: bool,

    /// Skip all __pycache__ and .venv directories.
    #[serde(default)]
    pub skip_python_cache: bool,

    /// Minimum entropy threshold (higher = fewer false positives).
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f64,

    /// Rule IDs to disable.
    #[serde(default)]
    pub disabled_rules: Vec<String>,

    /// Only scan third-party/unknown sources (skip official and trusted).
    #[serde(default)]
    pub third_party_only: bool,
}

fn default_entropy_threshold() -> f64 {
    5.5
}

impl Config {
    /// Load config from a TOML file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Load config from default locations, or return default config.
    pub fn load_default() -> Self {
        // Try current directory
        if let Ok(config) = Self::load(Path::new("vexscan.toml")) {
            return config;
        }

        // Try home directory
        if let Some(home) = dirs::home_dir() {
            if let Ok(config) = Self::load(&home.join(".vexscan.toml")) {
                return config;
            }
        }

        // Return default with sensible built-in allowlists
        Self::with_defaults()
    }

    /// Create config with sensible defaults for reducing noise.
    pub fn with_defaults() -> Self {
        Self {
            skip_paths: vec![
                // === DIRECTORIES (safe to skip entirely) ===
                "**/node_modules/.cache/**".to_string(),
                "**/.git/**".to_string(),
                "**/__pycache__/**".to_string(),
                "**/.venv/**".to_string(),
                "**/venv/**".to_string(),
                "**/target/**".to_string(), // Rust build
                // System package managers
                "**/homebrew/**".to_string(),
                "**/Homebrew/**".to_string(),
                "**/Cellar/**".to_string(),
                // Cache directories (but executable check still applies)
                "**/cache/**".to_string(),
                "**/Cache/**".to_string(),
                "**/Caches/**".to_string(),
                "**/.cache/**".to_string(),
                // Official Claude plugins (Anthropic-reviewed)
                "**/claude-plugins-official/**".to_string(),
                // === SPECIFIC FILES (extension-restricted) ===
                // Lock files - only actual lock file extensions
                "**/package-lock.json".to_string(),
                "**/yarn.lock".to_string(),
                "**/pnpm-lock.yaml".to_string(),
                "**/Cargo.lock".to_string(),
                "**/Gemfile.lock".to_string(),
                "**/poetry.lock".to_string(),
                "**/composer.lock".to_string(),
                "**/*.lock".to_string(),
                // Changelog/history - ONLY documentation extensions
                "**/CHANGELOG.md".to_string(),
                "**/CHANGELOG.txt".to_string(),
                "**/CHANGELOG.rst".to_string(),
                "**/HISTORY.md".to_string(),
                "**/HISTORY.txt".to_string(),
                "**/CHANGES.md".to_string(),
                "**/CHANGES.txt".to_string(),
                "**/RELEASES.md".to_string(),
                "**/RELEASES.txt".to_string(),
                "**/NEWS.md".to_string(),
                "**/NEWS.txt".to_string(),
            ],
            trusted_packages: vec![
                // Validation libraries (use atob/base64 legitimately)
                "zod".to_string(),
                "ajv".to_string(),
                "joi".to_string(),
                "yup".to_string(),
                // Official SDKs
                "@anthropic-ai".to_string(),
                "@openai".to_string(),
                // Build tools
                "node-gyp".to_string(),
                "esbuild".to_string(),
                "webpack".to_string(),
                "rollup".to_string(),
                "vite".to_string(),
                // Crypto/encoding (legitimate use)
                "@sigstore".to_string(),
                "jose".to_string(),
                "jsonwebtoken".to_string(),
                // Common utilities
                "lodash".to_string(),
                "underscore".to_string(),
                "axios".to_string(),
                "node-fetch".to_string(),
            ],
            skip_node_modules: false,
            skip_python_cache: true,
            entropy_threshold: 5.5,
            disabled_rules: vec![],
            third_party_only: false,
        }
    }

    /// Check if a path should be skipped.
    ///
    /// SECURITY: Files with executable extensions are only skipped in TRUSTED contexts
    /// (trusted packages, official plugins). Generic skip patterns (like CHANGELOG*)
    /// will NOT skip executable files to prevent bypass attacks.
    pub fn should_skip_path(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        let is_executable = self.has_executable_extension(path);

        // === FULLY TRUSTED CONTEXTS (can skip even executables) ===
        // These are system/IDE caches and official plugins that are vetted

        // System package manager caches (Homebrew, etc.)
        if path_str.contains("/Homebrew/")
            || path_str.contains("/homebrew/")
            || path_str.contains("/Cellar/")
        {
            return true;
        }

        // IDE caches (JetBrains, VS Code, etc.)
        if path_str.contains("/JetBrains/") || path_str.contains("/.vscode/") {
            return true;
        }

        // Official Claude plugins (both marketplace and cache locations)
        if path_str.contains("claude-plugins-official") {
            return true;
        }

        // Check skip_node_modules flag (user explicitly trusts all node_modules)
        if self.skip_node_modules && path_str.contains("node_modules") {
            return true;
        }

        // Check skip_python_cache flag (compiled bytecode, not source)
        if self.skip_python_cache
            && (path_str.contains("__pycache__") || path_str.contains(".venv"))
        {
            return true;
        }

        // Check trusted packages (in node_modules) - vetted by user
        if path_str.contains("node_modules") {
            for pkg in &self.trusted_packages {
                // Match both scoped (@org/pkg) and unscoped packages
                if path_str.contains(&format!("node_modules/{}/", pkg))
                    || path_str.contains(&format!("node_modules/{}\\", pkg))
                {
                    return true;
                }
            }
        }

        // === PATTERN-BASED SKIPS (NEVER skip executables) ===

        // SECURITY: Don't skip executable files based on patterns alone!
        // This prevents bypass attacks like "CHANGELOG.js" or "cache/evil.py"
        if is_executable {
            return false;
        }

        // Check glob patterns (only for non-executable files)
        for pattern in &self.skip_paths {
            if let Ok(glob) = globset::Glob::new(pattern) {
                let matcher = glob.compile_matcher();
                if matcher.is_match(path) {
                    return true;
                }
            }
        }

        false
    }

    /// Check if a file has an executable extension that should never be skipped.
    fn has_executable_extension(&self, path: &Path) -> bool {
        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase());

        match extension {
            Some(ext) => EXECUTABLE_EXTENSIONS.contains(&ext.as_str()),
            None => false,
        }
    }

    /// Check if a file has a safe documentation extension.
    #[allow(dead_code)]
    fn has_safe_doc_extension(&self, path: &Path) -> bool {
        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase());

        match extension {
            Some(ext) => SAFE_DOC_EXTENSIONS.contains(&ext.as_str()),
            None => false,
        }
    }

    /// Check if a rule is disabled.
    pub fn is_rule_disabled(&self, rule_id: &str) -> bool {
        self.disabled_rules.iter().any(|r| r == rule_id)
    }

    /// Check if a path is from a trusted/official source.
    /// Used with --third-party-only to skip these and only scan unknown plugins.
    pub fn is_trusted_source(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        // Official Claude plugins
        if path_str.contains("claude-plugins-official") {
            return true;
        }

        // Official Anthropic packages/plugins
        if path_str.contains("@anthropic-ai")
            || path_str.contains("anthropic-ai")
            || path_str.contains("/anthropic/")
        {
            return true;
        }

        // Official OpenAI packages
        if path_str.contains("@openai") || path_str.contains("/openai/") {
            return true;
        }

        // System package managers (not user-installed plugins)
        if path_str.contains("/Homebrew/")
            || path_str.contains("/homebrew/")
            || path_str.contains("/Cellar/")
        {
            return true;
        }

        // IDE extensions/caches
        if path_str.contains("/JetBrains/")
            || path_str.contains("/.vscode/")
            || path_str.contains("/VSCode/")
        {
            return true;
        }

        // Check trusted packages list
        if path_str.contains("node_modules") {
            for pkg in &self.trusted_packages {
                if path_str.contains(&format!("node_modules/{}/", pkg))
                    || path_str.contains(&format!("node_modules/{}\\", pkg))
                {
                    return true;
                }
            }
        }

        false
    }
}

/// Generate a default config file content.
pub fn generate_default_config() -> String {
    r#"# Vexscan Configuration
# Place this file at ./vexscan.toml or ~/.vexscan.toml

# SECURITY NOTE: Files with executable extensions (.js, .py, .sh, etc.) are
# NEVER skipped by pattern matching, even if they match these patterns.
# This prevents attackers from evading detection with names like "CHANGELOG.js".
# Only trusted packages and explicitly safe directories skip executables.

# Skip these path patterns (glob syntax)
skip_paths = [
    # Directories (safe to skip entirely)
    "**/node_modules/.cache/**",
    "**/.git/**",
    "**/__pycache__/**",
    "**/.venv/**",
    "**/target/**",
    "**/homebrew/**",
    "**/Homebrew/**",
    "**/Cellar/**",
    "**/cache/**",
    "**/Cache/**",
    "**/Caches/**",
    "**/.cache/**",
    # Specific safe files (only doc extensions are actually skipped)
    "**/package-lock.json",
    "**/yarn.lock",
    "**/pnpm-lock.yaml",
    "**/Cargo.lock",
    "**/Gemfile.lock",
    "**/poetry.lock",
    "**/*.lock",
    "**/CHANGELOG.md",
    "**/CHANGELOG.txt",
    "**/HISTORY.md",
    "**/CHANGES.md",
]

# Trusted npm packages - these won't be scanned
# Add packages you trust and don't want flagged
trusted_packages = [
    # Validation libraries (legitimately use base64)
    "zod",
    "ajv",
    "joi",
    "yup",
    # Official SDKs
    "@anthropic-ai",
    "@openai",
    # Build tools
    "node-gyp",
    "esbuild",
    "webpack",
    "rollup",
    "vite",
    # Crypto/encoding
    "@sigstore",
    "jose",
    "jsonwebtoken",
]

# Skip all node_modules directories entirely
# Set to true for fastest scans (only scans actual plugin code)
skip_node_modules = false

# Skip Python cache directories
skip_python_cache = true

# Entropy threshold for flagging suspicious strings
# Higher = fewer false positives (default: 5.5)
entropy_threshold = 5.5

# Disable specific rules by ID
disabled_rules = [
    # "ENTROPY-001",  # Uncomment to disable entropy checks
]
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_skip_trusted_package() {
        let config = Config::with_defaults();

        assert!(config.should_skip_path(Path::new(
            "/project/node_modules/zod/lib/index.js"
        )));
        assert!(config.should_skip_path(Path::new(
            "/project/node_modules/@anthropic-ai/sdk/index.js"
        )));
        assert!(!config.should_skip_path(Path::new(
            "/project/node_modules/suspicious-pkg/evil.js"
        )));
    }

    #[test]
    fn test_skip_node_modules() {
        let mut config = Config::with_defaults();
        config.skip_node_modules = true;

        assert!(config.should_skip_path(Path::new(
            "/project/node_modules/anything/file.js"
        )));
    }

    #[test]
    fn test_bypass_protection_executables_not_skipped() {
        let config = Config::with_defaults();

        // Attacker tries to evade by naming malicious file like a changelog
        assert!(
            !config.should_skip_path(Path::new("/project/CHANGELOG.js")),
            "CHANGELOG.js should NOT be skipped - executable extension!"
        );
        assert!(
            !config.should_skip_path(Path::new("/project/CHANGELOG.py")),
            "CHANGELOG.py should NOT be skipped - executable extension!"
        );
        assert!(
            !config.should_skip_path(Path::new("/project/HISTORY.sh")),
            "HISTORY.sh should NOT be skipped - executable extension!"
        );

        // Attacker tries to hide in cache directory
        assert!(
            !config.should_skip_path(Path::new("/project/cache/evil.js")),
            "cache/evil.js should NOT be skipped - executable extension!"
        );
        assert!(
            !config.should_skip_path(Path::new("/project/.cache/payload.py")),
            ".cache/payload.py should NOT be skipped - executable extension!"
        );

        // Attacker creates a CHANGELOG directory with code inside
        assert!(
            !config.should_skip_path(Path::new("/project/CHANGELOG/malware.js")),
            "CHANGELOG/malware.js should NOT be skipped - executable extension!"
        );
    }

    #[test]
    fn test_safe_files_still_skipped() {
        let config = Config::with_defaults();

        // Legitimate documentation files should still be skipped
        assert!(
            config.should_skip_path(Path::new("/project/CHANGELOG.md")),
            "CHANGELOG.md should be skipped - safe doc extension"
        );
        assert!(
            config.should_skip_path(Path::new("/project/CHANGELOG.txt")),
            "CHANGELOG.txt should be skipped - safe doc extension"
        );

        // Git directory should be skipped
        assert!(config.should_skip_path(Path::new("/project/.git/config")));
        assert!(config.should_skip_path(Path::new("/project/.git/objects/pack/file")));
    }

    #[test]
    fn test_executable_extensions() {
        let config = Config::with_defaults();

        // Test various executable extensions are detected
        assert!(config.has_executable_extension(Path::new("file.js")));
        assert!(config.has_executable_extension(Path::new("file.py")));
        assert!(config.has_executable_extension(Path::new("file.sh")));
        assert!(config.has_executable_extension(Path::new("file.ts")));
        assert!(config.has_executable_extension(Path::new("file.exe")));
        assert!(config.has_executable_extension(Path::new("file.PS1"))); // case insensitive

        // Non-executable extensions
        assert!(!config.has_executable_extension(Path::new("file.md")));
        assert!(!config.has_executable_extension(Path::new("file.txt")));
        assert!(!config.has_executable_extension(Path::new("file.json")));
        assert!(!config.has_executable_extension(Path::new("file.lock")));
    }
}
