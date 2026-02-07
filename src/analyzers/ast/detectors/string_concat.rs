//! Detector for string concatenation in property access.
//!
//! Detects patterns like:
//! - `window['ev' + 'al'](code)`
//! - `window["Fu" + "nct" + "ion"](code)`

use super::Detector;
use crate::analyzers::ast::rules::{AstRuleEntry, DangerousLists};
use crate::analyzers::ast::scope::ScopeTracker;
use crate::types::{Finding, Location};
use std::path::Path;
use std::sync::Arc;
use tree_sitter::Node;

pub struct StringConcatDetector {
    rule: AstRuleEntry,
    lists: Arc<DangerousLists>,
    max_depth: usize,
}

impl StringConcatDetector {
    pub fn new(rule: AstRuleEntry, lists: Arc<DangerousLists>) -> Self {
        Self {
            rule,
            lists,
            max_depth: 10,
        }
    }

    fn resolve_concat(&self, node: Node, source: &str, depth: usize) -> Option<String> {
        if depth > self.max_depth {
            return None;
        }

        match node.kind() {
            "string" => {
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
            "binary_expression" => {
                let operator = node.child_by_field_name("operator")?;
                let op_text = operator.utf8_text(source.as_bytes()).ok()?;
                if op_text != "+" {
                    return None;
                }

                let left = node.child_by_field_name("left")?;
                let right = node.child_by_field_name("right")?;

                let left_val = self.resolve_concat(left, source, depth + 1)?;
                let right_val = self.resolve_concat(right, source, depth + 1)?;

                Some(format!("{}{}", left_val, right_val))
            }
            "parenthesized_expression" => {
                let inner = node.named_child(0)?;
                self.resolve_concat(inner, source, depth + 1)
            }
            _ => None,
        }
    }
}

impl Detector for StringConcatDetector {
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

        let subscript = if node.kind() == "call_expression" {
            match node.child_by_field_name("function") {
                Some(callee) if callee.kind() == "subscript_expression" => callee,
                _ => return findings,
            }
        } else if node.kind() == "subscript_expression" {
            node
        } else {
            return findings;
        };

        let object = match subscript.child_by_field_name("object") {
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

        let index = match subscript.child_by_field_name("index") {
            Some(idx) => idx,
            None => return findings,
        };

        if index.kind() != "binary_expression" {
            return findings;
        }

        if let Some(resolved) = self.resolve_concat(index, source, 0) {
            if self.lists.is_dangerous_function(&resolved) {
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
                            "String concatenation resolves to '{}' on '{}'. \
                            This pattern is used to evade regex-based detection by splitting dangerous function names.",
                            resolved, object_text
                        ),
                        self.rule.severity(),
                        self.rule.category(),
                        Location::new(path.to_path_buf(), start_line, end_line)
                            .with_columns(index.start_position().column + 1, index.end_position().column + 1),
                        snippet,
                    )
                    .with_remediation(&self.rule.remediation)
                    .with_metadata("technique", "string_concatenation")
                    .with_metadata("resolved_function", resolved)
                    .with_metadata("ast_analyzed", "true"),
                );
            }
        }

        findings
    }
}
