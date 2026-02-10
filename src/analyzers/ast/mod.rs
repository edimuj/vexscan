//! AST-based analysis for detecting obfuscated malicious patterns.
//!
//! This module uses tree-sitter to parse JavaScript, TypeScript, and Python
//! files and detect patterns that regex-based scanning cannot catch:
//!
//! - `window['eval'](code)` - computed property access
//! - `const e = eval; e(code)` - variable aliasing
//! - `window['ev'+'al']()` - string concatenation
//! - `window["\x65\x76\x61\x6c"]()` - escape sequences
//! - `(0, eval)(code)` - comma operator indirect call
//! - `const {exec: run} = require('child_process')` - destructured aliases

pub mod config;
pub mod detectors;
pub mod rules;
pub mod scope;

pub use config::AstAnalyzerConfig;
use detectors::DetectorSet;
use rules::DangerousLists;
use scope::{ResolvedValue, ScopeTracker};

use crate::types::{Finding, ScanResult};
use anyhow::Result;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tree_sitter::{Node, Parser};

/// AST-based analyzer for detecting obfuscated malicious patterns.
///
/// Holds only immutable shared data (detectors, dangerous lists, config).
/// Parsers are created per-call since tree-sitter `Parser` is `!Send`.
/// This makes `AstAnalyzer` `Send + Sync`, enabling parallel AST analysis.
pub struct AstAnalyzer {
    config: AstAnalyzerConfig,
    detectors: DetectorSet,
    lists: Arc<DangerousLists>,
}

impl AstAnalyzer {
    /// Create a new AST analyzer with default configuration.
    pub fn new() -> Result<Self> {
        Self::with_config(AstAnalyzerConfig::default())
    }

    /// Create an AST analyzer with custom configuration.
    pub fn with_config(config: AstAnalyzerConfig) -> Result<Self> {
        let (rule_entries, lists) = rules::load_ast_rules()?;
        let detectors = DetectorSet::from_rules(&rule_entries, lists.clone());

        Ok(Self {
            config,
            detectors,
            lists,
        })
    }

    /// Analyze a file and return findings.
    pub fn analyze_file(&self, path: &Path) -> Result<ScanResult> {
        let content = std::fs::read_to_string(path)?;
        self.analyze_content_str(&content, path)
    }

    /// Analyze pre-read content and return findings.
    pub fn analyze_content_str(&self, content: &str, path: &Path) -> Result<ScanResult> {
        let start = Instant::now();
        let mut result = ScanResult::new(path.to_path_buf());

        // Check file size
        if content.len() > self.config.max_file_size {
            tracing::warn!(
                "File {} exceeds max size for AST analysis ({} > {}), skipping",
                path.display(),
                content.len(),
                self.config.max_file_size
            );
            return Ok(result);
        }

        // Determine file type from extension
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        // Create only the parser needed for this file type (cheap: ~2μs)
        let findings = match ext {
            "js" | "mjs" | "cjs" | "jsx" if self.config.enable_javascript => {
                let mut parser = Parser::new();
                parser.set_language(&tree_sitter_javascript::LANGUAGE.into())?;
                self.analyze_with_parser(&mut parser, content, path)?
            }
            "ts" | "tsx" | "mts" | "cts" if self.config.enable_javascript => {
                let mut parser = Parser::new();
                parser.set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())?;
                self.analyze_with_parser(&mut parser, content, path)?
            }
            "py" if self.config.enable_python => {
                let mut parser = Parser::new();
                parser.set_language(&tree_sitter_python::LANGUAGE.into())?;
                self.analyze_with_parser(&mut parser, content, path)?
            }
            _ => Vec::new(),
        };

        result.findings = findings;
        result.scan_time_ms = start.elapsed().as_millis() as u64;

        Ok(result)
    }

    /// Parse content with the given parser and run detectors.
    fn analyze_with_parser(
        &self,
        parser: &mut Parser,
        content: &str,
        path: &Path,
    ) -> Result<Vec<Finding>> {
        let tree = match parser.parse(content, None) {
            Some(t) => t,
            None => return Ok(Vec::new()),
        };

        self.analyze_tree(tree.root_node(), content, path)
    }

    /// Walk the AST and run detectors on each node.
    fn analyze_tree(&self, root: Node, source: &str, path: &Path) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        let mut scope_tracker = ScopeTracker::new(self.config.max_scope_depth, self.lists.clone());

        self.walk_tree(root, source, path, &mut scope_tracker, &mut findings);

        Ok(findings)
    }

    /// Recursively walk the tree, tracking scopes and running detectors.
    fn walk_tree(
        &self,
        node: Node,
        source: &str,
        path: &Path,
        scope_tracker: &mut ScopeTracker,
        findings: &mut Vec<Finding>,
    ) {
        let node_type = node.kind();

        // Track scope changes
        let is_scope_boundary = matches!(
            node_type,
            "function_declaration"
                | "function_expression"
                | "arrow_function"
                | "method_definition"
                | "class_declaration"
                | "class_expression"
                | "block"
        );

        if is_scope_boundary {
            scope_tracker.push_scope();
        }

        // Track variable bindings for aliasing detection
        self.track_bindings(node, source, scope_tracker);

        // Run all detectors that handle this node type (zero-alloc lookup)
        for &idx in self.detectors.for_node_type(node_type) {
            let detector_findings =
                self.detectors
                    .get(idx)
                    .analyze(node, source, path, scope_tracker);
            findings.extend(detector_findings);
        }

        // Recursively process children
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            self.walk_tree(child, source, path, scope_tracker, findings);
        }

        // Pop scope on exit
        if is_scope_boundary {
            scope_tracker.pop_scope();
        }
    }

    /// Track variable bindings for aliasing detection.
    fn track_bindings(&self, node: Node, source: &str, scope_tracker: &mut ScopeTracker) {
        // Handle variable declarations: const e = eval
        if node.kind() == "variable_declarator" {
            self.track_variable_declarator(node, source, scope_tracker);
        }
    }

    /// Track a variable declarator node.
    fn track_variable_declarator(
        &self,
        node: Node,
        source: &str,
        scope_tracker: &mut ScopeTracker,
    ) {
        // Get the name (left side)
        let name_node = match node.child_by_field_name("name") {
            Some(n) => n,
            None => return,
        };

        // Only handle simple identifier names for now
        if name_node.kind() != "identifier" {
            // Object patterns (destructuring) are handled by DestructuredAliasDetector
            return;
        }

        let name = match name_node.utf8_text(source.as_bytes()) {
            Ok(text) => text.to_string(),
            Err(_) => return,
        };

        // Get the value (right side)
        let value_node = match node.child_by_field_name("value") {
            Some(v) => v,
            None => return,
        };

        let line = node.start_position().row + 1;

        // Determine what the variable points to
        match value_node.kind() {
            "identifier" => {
                let value_name = match value_node.utf8_text(source.as_bytes()) {
                    Ok(text) => text,
                    Err(_) => return,
                };

                if self.lists.is_dangerous_function(value_name) {
                    scope_tracker.add_binding(
                        name,
                        ResolvedValue::DangerousFunction(value_name.to_string()),
                        line,
                    );
                } else {
                    scope_tracker.add_binding(
                        name,
                        ResolvedValue::Alias(value_name.to_string()),
                        line,
                    );
                }
            }
            "call_expression" => {
                // Check for require() calls
                self.track_require_binding(name, value_node, source, line, scope_tracker);
            }
            _ => {
                scope_tracker.add_binding(name, ResolvedValue::Unknown, line);
            }
        }
    }

    /// Track a require() binding.
    fn track_require_binding(
        &self,
        name: String,
        call_node: Node,
        source: &str,
        line: usize,
        scope_tracker: &mut ScopeTracker,
    ) {
        let func = match call_node.child_by_field_name("function") {
            Some(f) => f,
            None => return,
        };

        let func_name = match func.utf8_text(source.as_bytes()) {
            Ok(text) => text,
            Err(_) => return,
        };

        if func_name != "require" {
            return;
        }

        let args = match call_node.child_by_field_name("arguments") {
            Some(a) => a,
            None => return,
        };

        let first_arg = match args.named_child(0) {
            Some(a) => a,
            None => return,
        };

        if first_arg.kind() != "string" {
            return;
        }

        let arg_text = match first_arg.utf8_text(source.as_bytes()) {
            Ok(text) => text,
            Err(_) => return,
        };

        // Extract module name from quoted string
        let module = if (arg_text.starts_with('"') && arg_text.ends_with('"'))
            || (arg_text.starts_with('\'') && arg_text.ends_with('\''))
        {
            arg_text[1..arg_text.len() - 1].to_string()
        } else {
            return;
        };

        scope_tracker.add_binding(
            name,
            ResolvedValue::ImportResult {
                module,
                export: None,
            },
            line,
        );
    }
}

impl Default for AstAnalyzer {
    fn default() -> Self {
        Self::new().expect("Failed to create default AST analyzer")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_temp_file(content: &str, ext: &str) -> NamedTempFile {
        let mut file = tempfile::Builder::new().suffix(ext).tempfile().unwrap();
        writeln!(file, "{}", content).unwrap();
        file
    }

    #[test]
    fn test_computed_access_detection() {
        let mut analyzer = AstAnalyzer::new().unwrap();
        let file = create_temp_file("window['eval']('alert(1)')", ".js");

        let result = analyzer.analyze_file(file.path()).unwrap();
        assert!(!result.findings.is_empty());
        assert!(result.findings.iter().any(|f| f.rule_id == "AST-EXEC-001"));
    }

    #[test]
    fn test_variable_aliasing_detection() {
        let mut analyzer = AstAnalyzer::new().unwrap();
        let file = create_temp_file(
            r#"
            const e = eval;
            e('alert(1)');
            "#,
            ".js",
        );

        let result = analyzer.analyze_file(file.path()).unwrap();
        assert!(!result.findings.is_empty());
        assert!(result.findings.iter().any(|f| f.rule_id == "AST-EXEC-002"));
    }

    #[test]
    fn test_string_concat_detection() {
        let mut analyzer = AstAnalyzer::new().unwrap();
        let file = create_temp_file("window['ev' + 'al']('alert(1)')", ".js");

        let result = analyzer.analyze_file(file.path()).unwrap();
        assert!(!result.findings.is_empty());
        assert!(result.findings.iter().any(|f| f.rule_id == "AST-EXEC-003"));
    }

    #[test]
    fn test_comma_operator_detection() {
        let mut analyzer = AstAnalyzer::new().unwrap();
        let file = create_temp_file("(0, eval)('alert(1)')", ".js");

        let result = analyzer.analyze_file(file.path()).unwrap();
        assert!(!result.findings.is_empty());
        assert!(result.findings.iter().any(|f| f.rule_id == "AST-EXEC-005"));
    }

    #[test]
    fn test_escape_sequence_detection() {
        let mut analyzer = AstAnalyzer::new().unwrap();
        // \x65\x76\x61\x6c = "eval"
        let file = create_temp_file(r#"window["\x65\x76\x61\x6c"]('alert(1)')"#, ".js");

        let result = analyzer.analyze_file(file.path()).unwrap();
        assert!(!result.findings.is_empty());
        assert!(result.findings.iter().any(|f| f.rule_id == "AST-EXEC-004"));
    }

    #[test]
    fn test_destructured_alias_detection() {
        let mut analyzer = AstAnalyzer::new().unwrap();
        let file = create_temp_file(
            r#"const {exec: run} = require('child_process'); run('ls')"#,
            ".js",
        );

        let result = analyzer.analyze_file(file.path()).unwrap();
        assert!(!result.findings.is_empty());
        assert!(result.findings.iter().any(|f| f.rule_id == "AST-SHELL-001"));
    }

    #[test]
    fn test_typescript_support() {
        let mut analyzer = AstAnalyzer::new().unwrap();
        let file = create_temp_file(
            r#"
            const e: typeof eval = eval;
            e('alert(1)');
            "#,
            ".ts",
        );

        let result = analyzer.analyze_file(file.path()).unwrap();
        assert!(!result.findings.is_empty());
    }

    #[test]
    fn test_no_false_positives_for_safe_code() {
        let mut analyzer = AstAnalyzer::new().unwrap();
        let file = create_temp_file(
            r#"
            const obj = { foo: 'bar' };
            console.log(obj['foo']);
            const x = 'a' + 'b';
            "#,
            ".js",
        );

        let result = analyzer.analyze_file(file.path()).unwrap();
        assert!(result.findings.is_empty());
    }
}
