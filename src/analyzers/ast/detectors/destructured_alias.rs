//! Detector for destructured and aliased imports.
//!
//! Detects patterns like:
//! - `const {exec: run} = require('child_process'); run(cmd)`
//! - `const {execSync: e} = require('child_process'); e(cmd)`
//! - `import {exec as run} from 'child_process'; run(cmd)`

use super::Detector;
use crate::analyzers::ast::rules::{AstRuleEntry, DangerousLists};
use crate::analyzers::ast::scope::ScopeTracker;
use crate::types::{Finding, Location};
use std::path::Path;
use std::sync::Arc;
use tree_sitter::Node;

pub struct DestructuredAliasDetector {
    rule: AstRuleEntry,
    lists: Arc<DangerousLists>,
}

impl DestructuredAliasDetector {
    pub fn new(rule: AstRuleEntry, lists: Arc<DangerousLists>) -> Self {
        Self { rule, lists }
    }

    fn get_string_value(node: Node, source: &str) -> Option<String> {
        let text = node.utf8_text(source.as_bytes()).ok()?;
        if (text.starts_with('"') && text.ends_with('"'))
            || (text.starts_with('\'') && text.ends_with('\''))
        {
            Some(text[1..text.len() - 1].to_string())
        } else {
            None
        }
    }
}

impl Detector for DestructuredAliasDetector {
    fn rule_id(&self) -> &str {
        &self.rule.id
    }

    fn title(&self) -> &str {
        &self.rule.title
    }

    fn handles_node_type(&self, node_type: &str) -> bool {
        node_type == "variable_declarator" || node_type == "import_specifier"
    }

    fn analyze(
        &self,
        node: Node,
        source: &str,
        path: &Path,
        _scope_tracker: &ScopeTracker,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        match node.kind() {
            "variable_declarator" => {
                findings.extend(self.analyze_require_destructure(node, source, path));
            }
            "import_specifier" => {
                findings.extend(self.analyze_import_alias(node, source, path));
            }
            _ => {}
        }

        findings
    }
}

impl DestructuredAliasDetector {
    fn analyze_require_destructure(&self, node: Node, source: &str, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();

        let name = match node.child_by_field_name("name") {
            Some(n) => n,
            None => return findings,
        };

        if name.kind() != "object_pattern" {
            return findings;
        }

        let value = match node.child_by_field_name("value") {
            Some(v) => v,
            None => return findings,
        };

        if value.kind() != "call_expression" {
            return findings;
        }

        let func = match value.child_by_field_name("function") {
            Some(f) => f,
            None => return findings,
        };

        let func_name = match func.utf8_text(source.as_bytes()) {
            Ok(text) => text,
            Err(_) => return findings,
        };

        if func_name != "require" {
            return findings;
        }

        let args = match value.child_by_field_name("arguments") {
            Some(a) => a,
            None => return findings,
        };

        let first_arg = match args.named_child(0) {
            Some(a) => a,
            None => return findings,
        };

        let module = if first_arg.kind() == "string" {
            match Self::get_string_value(first_arg, source) {
                Some(m) => m,
                None => return findings,
            }
        } else {
            return findings;
        };

        if !self.lists.is_dangerous_module(&module) {
            return findings;
        }

        let mut cursor = name.walk();
        for child in name.named_children(&mut cursor) {
            if child.kind() == "shorthand_property_identifier_pattern" {
                let prop_name = match child.utf8_text(source.as_bytes()) {
                    Ok(text) => text,
                    Err(_) => continue,
                };

                if self.lists.is_dangerous_export(&module, prop_name) {
                    continue;
                }
            } else if child.kind() == "pair_pattern" {
                let key = match child.child_by_field_name("key") {
                    Some(k) => k,
                    None => continue,
                };

                let value_node = match child.child_by_field_name("value") {
                    Some(v) => v,
                    None => continue,
                };

                let original_name = match key.utf8_text(source.as_bytes()) {
                    Ok(text) => text,
                    Err(_) => continue,
                };

                let alias_name = match value_node.utf8_text(source.as_bytes()) {
                    Ok(text) => text,
                    Err(_) => continue,
                };

                if self.lists.is_dangerous_export(&module, original_name)
                    && original_name != alias_name
                {
                    let snippet = node.utf8_text(source.as_bytes()).unwrap_or("").to_string();

                    let start_line = child.start_position().row + 1;
                    let end_line = child.end_position().row + 1;

                    findings.push(
                        Finding::new(
                            self.rule_id(),
                            self.title(),
                            format!(
                                "Destructuring aliases '{}' to '{}' from '{}'. \
                                Using '{}()' will execute shell commands while evading detection.",
                                original_name, alias_name, module, alias_name
                            ),
                            self.rule.severity(),
                            self.rule.category(),
                            Location::new(path.to_path_buf(), start_line, end_line).with_columns(
                                child.start_position().column + 1,
                                child.end_position().column + 1,
                            ),
                            snippet,
                        )
                        .with_remediation(&self.rule.remediation)
                        .with_metadata("technique", "destructured_aliasing")
                        .with_metadata("original", original_name.to_string())
                        .with_metadata("alias", alias_name.to_string())
                        .with_metadata("module", module.clone())
                        .with_metadata("ast_analyzed", "true"),
                    );
                }
            }
        }

        findings
    }

    fn analyze_import_alias(&self, node: Node, source: &str, path: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();

        let name = match node.child_by_field_name("name") {
            Some(n) => n,
            None => return findings,
        };

        let alias = match node.child_by_field_name("alias") {
            Some(a) => a,
            None => return findings,
        };

        let original_name = match name.utf8_text(source.as_bytes()) {
            Ok(text) => text,
            Err(_) => return findings,
        };

        let alias_name = match alias.utf8_text(source.as_bytes()) {
            Ok(text) => text,
            Err(_) => return findings,
        };

        if original_name == alias_name {
            return findings;
        }

        // Walk up to find the import_statement and get the source
        let mut parent = node.parent();
        while let Some(p) = parent {
            if p.kind() == "import_statement" {
                if let Some(source_node) = p.child_by_field_name("source") {
                    if let Some(module) = Self::get_string_value(source_node, source) {
                        if self.lists.is_dangerous_module(&module)
                            && self.lists.is_dangerous_export(&module, original_name)
                        {
                            let snippet = p.utf8_text(source.as_bytes()).unwrap_or("").to_string();

                            let start_line = node.start_position().row + 1;
                            let end_line = node.end_position().row + 1;

                            findings.push(
                                Finding::new(
                                    self.rule_id(),
                                    self.title(),
                                    format!(
                                        "Import aliases '{}' to '{}' from '{}'. \
                                        Using '{}()' will execute shell commands while evading detection.",
                                        original_name, alias_name, module, alias_name
                                    ),
                                    self.rule.severity(),
                                    self.rule.category(),
                                    Location::new(path.to_path_buf(), start_line, end_line)
                                        .with_columns(node.start_position().column + 1, node.end_position().column + 1),
                                    snippet,
                                )
                                .with_remediation(&self.rule.remediation)
                                .with_metadata("technique", "import_aliasing")
                                .with_metadata("original", original_name.to_string())
                                .with_metadata("alias", alias_name.to_string())
                                .with_metadata("module", module)
                                .with_metadata("ast_analyzed", "true"),
                            );
                        }
                    }
                }
                break;
            }
            parent = p.parent();
        }

        findings
    }
}
