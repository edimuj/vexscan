//! Detector for computed property access to dangerous functions.
//!
//! Detects patterns like:
//! - `window['eval'](code)`
//! - `globalThis["eval"](code)`
//! - `global['Function'](code)`

use super::Detector;
use crate::analyzers::ast::rules::{AstRuleEntry, DangerousLists};
use crate::analyzers::ast::scope::ScopeTracker;
use crate::types::{Finding, Location};
use std::path::Path;
use std::sync::Arc;
use tree_sitter::Node;

pub struct ComputedAccessDetector {
    rule: AstRuleEntry,
    lists: Arc<DangerousLists>,
}

impl ComputedAccessDetector {
    pub fn new(rule: AstRuleEntry, lists: Arc<DangerousLists>) -> Self {
        Self { rule, lists }
    }

    fn get_string_value(node: Node, source: &str) -> Option<String> {
        let text = node.utf8_text(source.as_bytes()).ok()?;
        if (text.starts_with('"') && text.ends_with('"'))
            || (text.starts_with('\'') && text.ends_with('\''))
        {
            Some(text[1..text.len() - 1].to_string())
        } else if text.starts_with('`') && text.ends_with('`') {
            Some(text[1..text.len() - 1].to_string())
        } else {
            None
        }
    }
}

impl Detector for ComputedAccessDetector {
    fn rule_id(&self) -> &str {
        &self.rule.id
    }

    fn title(&self) -> &str {
        &self.rule.title
    }

    fn handles_node_type(&self, node_type: &str) -> bool {
        node_type == "subscript_expression" || node_type == "call_expression"
    }

    fn analyze(
        &self,
        node: Node,
        source: &str,
        path: &Path,
        _scope_tracker: &ScopeTracker,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        if node.kind() == "call_expression" {
            if let Some(callee) = node.child_by_field_name("function") {
                if callee.kind() == "subscript_expression" {
                    findings.extend(self.check_subscript(callee, source, path));
                }
            }
            return findings;
        }

        if node.kind() == "subscript_expression" {
            findings.extend(self.check_subscript(node, source, path));
        }

        findings
    }
}

impl ComputedAccessDetector {
    fn check_subscript(&self, node: Node, source: &str, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();

        let object = match node.child_by_field_name("object") {
            Some(obj) => obj,
            None => return findings,
        };

        let object_text = match object.utf8_text(source.as_bytes()) {
            Ok(text) => text,
            Err(_) => return findings,
        };

        if !self.lists.is_dangerous_global(object_text) {
            return findings;
        }

        let index = match node.child_by_field_name("index") {
            Some(idx) => idx,
            None => return findings,
        };

        if index.kind() != "string" {
            return findings;
        }

        let property = match Self::get_string_value(index, source) {
            Some(s) => s,
            None => return findings,
        };

        if self.lists.is_dangerous_function(&property) {
            let snippet = node
                .utf8_text(source.as_bytes())
                .unwrap_or("")
                .to_string();

            let start_line = node.start_position().row + 1;
            let end_line = node.end_position().row + 1;

            findings.push(
                Finding::new(
                    self.rule_id(),
                    self.title(),
                    format!(
                        "Computed property access to '{}' on '{}' can execute arbitrary code. \
                        This pattern is often used to evade regex-based detection.",
                        property, object_text
                    ),
                    self.rule.severity(),
                    self.rule.category(),
                    Location::new(path.to_path_buf(), start_line, end_line)
                        .with_columns(node.start_position().column + 1, node.end_position().column + 1),
                    snippet,
                )
                .with_remediation(&self.rule.remediation)
                .with_metadata("technique", "computed_property_access")
                .with_metadata("function", property)
                .with_metadata("ast_analyzed", "true"),
            );
        }

        findings
    }
}
