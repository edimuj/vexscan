//! Detector for variable aliasing of dangerous functions.
//!
//! Detects patterns like:
//! - `const e = eval; e(code)`
//! - `let fn = Function; fn('return alert(1)')()`
//! - `var exec = eval; exec(input)`

use super::Detector;
use crate::analyzers::ast::rules::{AstRuleEntry, DangerousLists};
use crate::analyzers::ast::scope::{ResolvedValue, ScopeTracker};
use crate::types::{Finding, FindingCategory, Location, Severity};
use std::path::Path;
use std::sync::Arc;
use tree_sitter::Node;

pub struct VariableAliasingDetector {
    rule: AstRuleEntry,
    lists: Arc<DangerousLists>,
}

impl VariableAliasingDetector {
    pub fn new(rule: AstRuleEntry, lists: Arc<DangerousLists>) -> Self {
        Self { rule, lists }
    }
}

impl Detector for VariableAliasingDetector {
    fn rule_id(&self) -> &str {
        &self.rule.id
    }

    fn title(&self) -> &str {
        &self.rule.title
    }

    fn handles_node_type(&self, node_type: &str) -> bool {
        node_type == "call_expression"
    }

    fn analyze(
        &self,
        node: Node,
        source: &str,
        path: &Path,
        scope_tracker: &ScopeTracker,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        if node.kind() != "call_expression" {
            return findings;
        }

        let callee = match node.child_by_field_name("function") {
            Some(c) => c,
            None => return findings,
        };

        if callee.kind() != "identifier" {
            return findings;
        }

        let callee_name = match callee.utf8_text(source.as_bytes()) {
            Ok(text) => text,
            Err(_) => return findings,
        };

        match scope_tracker.resolve(callee_name) {
            ResolvedValue::DangerousFunction(func_name) => {
                if callee_name != func_name {
                    let snippet = node.utf8_text(source.as_bytes()).unwrap_or("").to_string();

                    let start_line = node.start_position().row + 1;
                    let end_line = node.end_position().row + 1;

                    findings.push(
                        Finding::new(
                            self.rule_id(),
                            self.title(),
                            format!(
                                "Variable '{}' is an alias for '{}'. Calling it executes arbitrary code. \
                                This pattern is used to evade regex-based detection.",
                                callee_name, func_name
                            ),
                            self.rule.severity(),
                            self.rule.category(),
                            Location::new(path.to_path_buf(), start_line, end_line)
                                .with_columns(callee.start_position().column + 1, callee.end_position().column + 1),
                            snippet,
                        )
                        .with_remediation(&self.rule.remediation)
                        .with_metadata("technique", "variable_aliasing")
                        .with_metadata("alias", callee_name.to_string())
                        .with_metadata("target_function", func_name)
                        .with_metadata("ast_analyzed", "true"),
                    );
                }
            }
            ResolvedValue::ImportResult { module, export } => {
                if self.lists.is_dangerous_module(&module) {
                    if let Some(ref exp) = export {
                        if self.lists.is_dangerous_export(&module, exp) {
                            let snippet =
                                node.utf8_text(source.as_bytes()).unwrap_or("").to_string();

                            let start_line = node.start_position().row + 1;
                            let end_line = node.end_position().row + 1;

                            findings.push(
                                Finding::new(
                                    "AST-SHELL-001",
                                    "Aliased shell execution function call",
                                    format!(
                                        "Variable '{}' is an alias for '{}.{}'. Calling it executes shell commands.",
                                        callee_name, module, exp
                                    ),
                                    Severity::High,
                                    FindingCategory::ShellExecution,
                                    Location::new(path.to_path_buf(), start_line, end_line)
                                        .with_columns(callee.start_position().column + 1, callee.end_position().column + 1),
                                    snippet,
                                )
                                .with_remediation("Review the shell command execution and ensure user input is properly sanitized.")
                                .with_metadata("technique", "import_aliasing")
                                .with_metadata("alias", callee_name.to_string())
                                .with_metadata("module", module)
                                .with_metadata("export", exp.clone())
                                .with_metadata("ast_analyzed", "true"),
                            );
                        }
                    }
                }
            }
            _ => {}
        }

        findings
    }
}
