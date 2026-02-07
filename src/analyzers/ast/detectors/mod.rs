//! Detection patterns for obfuscated malicious code.
//!
//! Each detector analyzes specific AST node types to find patterns that
//! regex-based scanning cannot catch.

mod computed_access;
mod variable_aliasing;
mod string_concat;
mod escape_sequences;
mod comma_operator;
mod destructured_alias;

pub use computed_access::ComputedAccessDetector;
pub use variable_aliasing::VariableAliasingDetector;
pub use string_concat::StringConcatDetector;
pub use escape_sequences::EscapeSequenceDetector;
pub use comma_operator::CommaOperatorDetector;
pub use destructured_alias::DestructuredAliasDetector;

use crate::types::Finding;
use std::path::Path;
use std::sync::Arc;
use tree_sitter::Node;

use super::rules::{AstRuleEntry, DangerousLists, DetectionStrategy};
use super::scope::ScopeTracker;

/// A detector that analyzes AST nodes for specific malicious patterns.
pub trait Detector: Send + Sync {
    /// Returns the unique rule ID for this detector.
    fn rule_id(&self) -> &str;

    /// Returns the human-readable title for findings from this detector.
    fn title(&self) -> &str;

    /// Check if this detector should analyze a given node type.
    fn handles_node_type(&self, node_type: &str) -> bool;

    /// Analyze a node and return any findings.
    fn analyze(
        &self,
        node: Node,
        source: &str,
        path: &Path,
        scope_tracker: &ScopeTracker,
    ) -> Vec<Finding>;
}

/// Collection of all detectors.
pub struct DetectorSet {
    detectors: Vec<Box<dyn Detector>>,
}

impl DetectorSet {
    /// Create a detector set from externalized AST rules.
    pub fn from_rules(rules: &[AstRuleEntry], lists: Arc<DangerousLists>) -> Self {
        let detectors: Vec<Box<dyn Detector>> = rules
            .iter()
            .map(|rule| -> Box<dyn Detector> {
                match rule.strategy {
                    DetectionStrategy::ComputedAccess => {
                        Box::new(ComputedAccessDetector::new(rule.clone(), lists.clone()))
                    }
                    DetectionStrategy::VariableAliasing => {
                        Box::new(VariableAliasingDetector::new(rule.clone(), lists.clone()))
                    }
                    DetectionStrategy::StringConcat => {
                        Box::new(StringConcatDetector::new(rule.clone(), lists.clone()))
                    }
                    DetectionStrategy::EscapeSequences => {
                        Box::new(EscapeSequenceDetector::new(rule.clone(), lists.clone()))
                    }
                    DetectionStrategy::CommaOperator => {
                        Box::new(CommaOperatorDetector::new(rule.clone(), lists.clone()))
                    }
                    DetectionStrategy::DestructuredAlias => {
                        Box::new(DestructuredAliasDetector::new(rule.clone(), lists.clone()))
                    }
                }
            })
            .collect();

        Self { detectors }
    }

    /// Get all detectors that handle a specific node type.
    pub fn for_node_type(&self, node_type: &str) -> Vec<&dyn Detector> {
        self.detectors
            .iter()
            .filter(|d| d.handles_node_type(node_type))
            .map(|d| d.as_ref())
            .collect()
    }

    /// Get all detectors.
    pub fn all(&self) -> &[Box<dyn Detector>] {
        &self.detectors
    }
}
