//! Detector for comma operator indirect calls.
//!
//! Detects patterns like:
//! - `(0, eval)(code)` - indirect eval call
//! - `(1, Function)('return this')()` - indirect Function constructor
//!
//! The comma operator trick is used to change the `this` binding
//! and evade detection of direct calls.

use super::Detector;
use crate::analyzers::ast::rules::{AstRuleEntry, DangerousLists};
use crate::analyzers::ast::scope::ScopeTracker;
use crate::types::{Finding, Location};
use std::path::Path;
use std::sync::Arc;
use tree_sitter::Node;

pub struct CommaOperatorDetector {
    rule: AstRuleEntry,
    lists: Arc<DangerousLists>,
}

impl CommaOperatorDetector {
    pub fn new(rule: AstRuleEntry, lists: Arc<DangerousLists>) -> Self {
        Self { rule, lists }
    }
}

impl Detector for CommaOperatorDetector {
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
        _scope_tracker: &ScopeTracker,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        if node.kind() != "call_expression" {
            return findings;
        }

        let callee = match node.child_by_field_name("function") {
            Some(c) => c,
            None => return findings,
        };

        if callee.kind() != "parenthesized_expression" {
            return findings;
        }

        let inner = match callee.named_child(0) {
            Some(i) => i,
            None => return findings,
        };

        if inner.kind() != "sequence_expression" {
            return findings;
        }

        let mut cursor = inner.walk();
        let named_children: Vec<_> = inner.named_children(&mut cursor).collect();

        let target = match named_children.last() {
            Some(t) => *t,
            None => return findings,
        };

        if target.kind() != "identifier" {
            return findings;
        }

        let target_name = match target.utf8_text(source.as_bytes()) {
            Ok(text) => text,
            Err(_) => return findings,
        };

        if self.lists.is_dangerous_function(target_name) {
            let snippet = node.utf8_text(source.as_bytes()).unwrap_or("").to_string();

            let start_line = node.start_position().row + 1;
            let end_line = node.end_position().row + 1;

            findings.push(
                Finding::new(
                    self.rule_id(),
                    self.title(),
                    format!(
                        "Comma operator pattern '(expr, {})()' is used to call '{}' indirectly. \
                        This technique changes the 'this' binding and evades direct call detection.",
                        target_name, target_name
                    ),
                    self.rule.severity(),
                    self.rule.category(),
                    Location::new(path.to_path_buf(), start_line, end_line)
                        .with_columns(callee.start_position().column + 1, callee.end_position().column + 1),
                    snippet,
                )
                .with_remediation(&self.rule.remediation)
                .with_metadata("technique", "comma_operator_indirect_call")
                .with_metadata("function", target_name.to_string())
                .with_metadata("ast_analyzed", "true"),
            );
        }

        findings
    }
}
