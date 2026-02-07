//! Scope tracking for variable aliasing resolution.
//!
//! This module tracks variable bindings across scopes to detect patterns like:
//! - `const e = eval; e(code)` - variable aliasing
//! - `const {exec: run} = require('child_process'); run(cmd)` - destructuring aliases

use std::collections::HashMap;
use std::sync::Arc;

use super::rules::DangerousLists;

/// A resolved value that a variable binding points to.
#[derive(Debug, Clone, PartialEq)]
pub enum ResolvedValue {
    /// Points to a dangerous function (e.g., "eval", "exec", "Function").
    DangerousFunction(String),
    /// Points to another variable name (alias chain).
    Alias(String),
    /// Result of an import/require.
    ImportResult {
        /// Module name (e.g., "child_process", "fs").
        module: String,
        /// Specific export (e.g., "exec", "readFile"). None means default export.
        export: Option<String>,
    },
    /// Unknown or untracked value.
    Unknown,
}

/// A variable binding in a scope.
#[derive(Debug, Clone)]
pub struct Binding {
    /// Variable name.
    pub name: String,
    /// What the variable points to.
    pub points_to: ResolvedValue,
    /// Line number where the binding was created.
    pub line: usize,
}

/// A single scope level (function, block, etc.).
#[derive(Debug, Clone, Default)]
pub struct Scope {
    /// Variable bindings in this scope.
    bindings: HashMap<String, Binding>,
}

impl Scope {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_binding(&mut self, name: String, points_to: ResolvedValue, line: usize) {
        self.bindings.insert(
            name.clone(),
            Binding {
                name,
                points_to,
                line,
            },
        );
    }

    pub fn get_binding(&self, name: &str) -> Option<&Binding> {
        self.bindings.get(name)
    }
}

/// Tracks variable scopes for aliasing resolution.
#[derive(Debug)]
pub struct ScopeTracker {
    /// Stack of scopes (innermost is last).
    scopes: Vec<Scope>,
    /// Maximum depth to follow alias chains.
    max_alias_depth: usize,
    /// Shared dangerous lists from JSON config.
    lists: Arc<DangerousLists>,
}

impl ScopeTracker {
    pub fn new(max_alias_depth: usize, lists: Arc<DangerousLists>) -> Self {
        Self {
            scopes: vec![Scope::new()], // Start with global scope
            max_alias_depth,
            lists,
        }
    }

    /// Enter a new scope (function, block, etc.).
    pub fn push_scope(&mut self) {
        self.scopes.push(Scope::new());
    }

    /// Exit the current scope.
    pub fn pop_scope(&mut self) {
        if self.scopes.len() > 1 {
            self.scopes.pop();
        }
    }

    /// Add a binding to the current scope.
    pub fn add_binding(&mut self, name: String, points_to: ResolvedValue, line: usize) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.add_binding(name, points_to, line);
        }
    }

    /// Look up a variable, searching from innermost to outermost scope.
    pub fn lookup(&self, name: &str) -> Option<&Binding> {
        for scope in self.scopes.iter().rev() {
            if let Some(binding) = scope.get_binding(name) {
                return Some(binding);
            }
        }
        None
    }

    /// Resolve a variable name to its ultimate value, following alias chains.
    pub fn resolve(&self, name: &str) -> ResolvedValue {
        self.resolve_with_depth(name, 0)
    }

    fn resolve_with_depth(&self, name: &str, depth: usize) -> ResolvedValue {
        if depth > self.max_alias_depth {
            return ResolvedValue::Unknown;
        }

        if let Some(binding) = self.lookup(name) {
            match &binding.points_to {
                ResolvedValue::Alias(target) => {
                    // Follow the alias chain
                    self.resolve_with_depth(target, depth + 1)
                }
                other => other.clone(),
            }
        } else {
            // Check if it's a global dangerous function
            if self.lists.is_dangerous_function(name) {
                ResolvedValue::DangerousFunction(name.to_string())
            } else {
                ResolvedValue::Unknown
            }
        }
    }

    /// Get access to the dangerous lists.
    pub fn lists(&self) -> &DangerousLists {
        &self.lists
    }

    /// Clear all scopes and reset to initial state.
    pub fn reset(&mut self) {
        self.scopes.clear();
        self.scopes.push(Scope::new());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_lists() -> Arc<DangerousLists> {
        use crate::analyzers::ast::rules::load_builtin_ast_rules;
        let config = load_builtin_ast_rules().unwrap();
        Arc::new(config.dangerous_lists)
    }

    #[test]
    fn test_simple_alias() {
        let mut tracker = ScopeTracker::new(10, test_lists());
        tracker.add_binding(
            "e".to_string(),
            ResolvedValue::DangerousFunction("eval".to_string()),
            1,
        );

        match tracker.resolve("e") {
            ResolvedValue::DangerousFunction(name) => assert_eq!(name, "eval"),
            _ => panic!("Expected DangerousFunction"),
        }
    }

    #[test]
    fn test_alias_chain() {
        let mut tracker = ScopeTracker::new(10, test_lists());
        tracker.add_binding(
            "e".to_string(),
            ResolvedValue::DangerousFunction("eval".to_string()),
            1,
        );
        tracker.add_binding("f".to_string(), ResolvedValue::Alias("e".to_string()), 2);
        tracker.add_binding("g".to_string(), ResolvedValue::Alias("f".to_string()), 3);

        match tracker.resolve("g") {
            ResolvedValue::DangerousFunction(name) => assert_eq!(name, "eval"),
            _ => panic!("Expected DangerousFunction"),
        }
    }

    #[test]
    fn test_scope_shadowing() {
        let mut tracker = ScopeTracker::new(10, test_lists());
        tracker.add_binding(
            "x".to_string(),
            ResolvedValue::DangerousFunction("eval".to_string()),
            1,
        );

        tracker.push_scope();
        tracker.add_binding("x".to_string(), ResolvedValue::Unknown, 5);

        // Inner scope shadows outer
        assert!(matches!(tracker.resolve("x"), ResolvedValue::Unknown));

        tracker.pop_scope();

        // After popping, should see outer scope again
        match tracker.resolve("x") {
            ResolvedValue::DangerousFunction(name) => assert_eq!(name, "eval"),
            _ => panic!("Expected DangerousFunction"),
        }
    }

    #[test]
    fn test_global_dangerous_functions() {
        let tracker = ScopeTracker::new(10, test_lists());

        match tracker.resolve("eval") {
            ResolvedValue::DangerousFunction(name) => assert_eq!(name, "eval"),
            _ => panic!("Expected DangerousFunction for eval"),
        }

        match tracker.resolve("Function") {
            ResolvedValue::DangerousFunction(name) => assert_eq!(name, "Function"),
            _ => panic!("Expected DangerousFunction for Function"),
        }
    }
}
