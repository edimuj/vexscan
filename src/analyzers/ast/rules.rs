//! Externalized AST detection rules loaded from JSON.
//!
//! Keeps detection *strategies* in Rust while moving *data* (dangerous lists,
//! rule metadata) to `rules/ast/ast-rules.json`, mirroring the static-analysis
//! pattern already used for regex rules.

use crate::types::{FindingCategory, Severity};
use anyhow::Result;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// Compile-time embedded AST rules JSON.
const BUILTIN_AST_RULES: &str = include_str!("../../../rules/ast/ast-rules.json");

/// Root configuration loaded from `ast-rules.json`.
#[derive(Debug, Clone, Deserialize)]
pub struct AstRulesConfig {
    pub version: String,
    pub dangerous_lists: DangerousLists,
    pub detectors: Vec<AstRuleEntry>,
}

/// Lists of dangerous globals, functions, and module exports.
#[derive(Debug, Clone, Deserialize)]
pub struct DangerousLists {
    pub globals: Vec<String>,
    pub functions: Vec<String>,
    pub modules: HashMap<String, Vec<String>>,

    /// Pre-built lookup sets (populated after deserialization).
    #[serde(skip)]
    globals_set: HashSet<String>,
    #[serde(skip)]
    functions_set: HashSet<String>,
}

impl DangerousLists {
    /// Build fast lookup sets from the deserialized vecs. Must be called after loading.
    pub fn build_lookups(&mut self) {
        self.globals_set = self.globals.iter().cloned().collect();
        self.functions_set = self.functions.iter().cloned().collect();
    }

    pub fn is_dangerous_global(&self, name: &str) -> bool {
        self.globals_set.contains(name)
    }

    pub fn is_dangerous_function(&self, name: &str) -> bool {
        self.functions_set.contains(name)
    }

    /// Check if a module name appears in the dangerous modules map (regardless of exports).
    pub fn is_dangerous_module(&self, module: &str) -> bool {
        self.modules.contains_key(module)
    }

    /// Check if a specific export from a module is dangerous.
    pub fn is_dangerous_export(&self, module: &str, export: &str) -> bool {
        self.modules
            .get(module)
            .map_or(false, |exports| exports.iter().any(|e| e == export))
    }
}

/// A single AST detection rule entry.
#[derive(Debug, Clone, Deserialize)]
pub struct AstRuleEntry {
    pub id: String,
    pub strategy: DetectionStrategy,
    pub title: String,
    pub description: String,
    pub severity: SeverityStr,
    pub category: CategoryStr,
    pub enabled: bool,
    pub remediation: String,
}

impl AstRuleEntry {
    pub fn severity(&self) -> Severity {
        self.severity.into_severity()
    }

    pub fn category(&self) -> FindingCategory {
        self.category.into_category()
    }
}

/// Detection strategy — maps to a specific Rust detector implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionStrategy {
    ComputedAccess,
    VariableAliasing,
    StringConcat,
    EscapeSequences,
    CommaOperator,
    DestructuredAlias,
}

/// Severity as it appears in JSON.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeverityStr {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityStr {
    pub fn into_severity(self) -> Severity {
        match self {
            Self::Info => Severity::Info,
            Self::Low => Severity::Low,
            Self::Medium => Severity::Medium,
            Self::High => Severity::High,
            Self::Critical => Severity::Critical,
        }
    }
}

/// Finding category as it appears in JSON.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CategoryStr {
    CodeExecution,
    ShellExecution,
    SensitiveFileAccess,
    DataExfiltration,
    Obfuscation,
    PromptInjection,
    AuthorityImpersonation,
    CredentialAccess,
    PrivilegeEscalation,
    SuspiciousDependency,
    HiddenInstructions,
}

impl CategoryStr {
    pub fn into_category(self) -> FindingCategory {
        match self {
            Self::CodeExecution => FindingCategory::CodeExecution,
            Self::ShellExecution => FindingCategory::ShellExecution,
            Self::SensitiveFileAccess => FindingCategory::SensitiveFileAccess,
            Self::DataExfiltration => FindingCategory::DataExfiltration,
            Self::Obfuscation => FindingCategory::Obfuscation,
            Self::PromptInjection => FindingCategory::PromptInjection,
            Self::AuthorityImpersonation => FindingCategory::AuthorityImpersonation,
            Self::CredentialAccess => FindingCategory::CredentialAccess,
            Self::PrivilegeEscalation => FindingCategory::PrivilegeEscalation,
            Self::SuspiciousDependency => FindingCategory::SuspiciousDependency,
            Self::HiddenInstructions => FindingCategory::HiddenInstructions,
        }
    }
}

/// Load the built-in AST rules (embedded at compile time).
pub fn load_builtin_ast_rules() -> Result<AstRulesConfig> {
    let mut config: AstRulesConfig = serde_json::from_str(BUILTIN_AST_RULES)?;
    config.dangerous_lists.build_lookups();
    Ok(config)
}

/// Load AST rules, building an `Arc<DangerousLists>` for shared use.
pub fn load_ast_rules() -> Result<(Vec<AstRuleEntry>, Arc<DangerousLists>)> {
    let config = load_builtin_ast_rules()?;
    let lists = Arc::new(config.dangerous_lists);
    let detectors: Vec<AstRuleEntry> = config
        .detectors
        .into_iter()
        .filter(|d| d.enabled)
        .collect();
    Ok((detectors, lists))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_builtin_rules() {
        let config = load_builtin_ast_rules().unwrap();
        assert_eq!(config.version, "1.0");
        assert_eq!(config.detectors.len(), 6);
        assert!(config.dangerous_lists.is_dangerous_function("eval"));
        assert!(config.dangerous_lists.is_dangerous_global("window"));
        assert!(config.dangerous_lists.is_dangerous_module("child_process"));
        assert!(config
            .dangerous_lists
            .is_dangerous_export("child_process", "exec"));
        assert!(!config
            .dangerous_lists
            .is_dangerous_export("os", "platform"));
    }

    #[test]
    fn test_all_strategies_present() {
        let config = load_builtin_ast_rules().unwrap();
        let strategies: Vec<_> = config.detectors.iter().map(|d| d.strategy).collect();
        assert!(strategies.contains(&DetectionStrategy::ComputedAccess));
        assert!(strategies.contains(&DetectionStrategy::VariableAliasing));
        assert!(strategies.contains(&DetectionStrategy::StringConcat));
        assert!(strategies.contains(&DetectionStrategy::EscapeSequences));
        assert!(strategies.contains(&DetectionStrategy::CommaOperator));
        assert!(strategies.contains(&DetectionStrategy::DestructuredAlias));
    }
}
