//! Detector for escape sequence obfuscation in property access.
//!
//! Detects patterns like:
//! - `window["\x65\x76\x61\x6c"]()` - hex escapes for "eval"
//! - `window["\u0065\u0076\u0061\u006c"]()` - unicode escapes for "eval"

use super::Detector;
use crate::analyzers::ast::rules::{AstRuleEntry, DangerousLists};
use crate::analyzers::ast::scope::ScopeTracker;
use crate::types::{Finding, Location};
use std::path::Path;
use std::sync::Arc;
use tree_sitter::Node;

pub struct EscapeSequenceDetector {
    rule: AstRuleEntry,
    lists: Arc<DangerousLists>,
}

impl EscapeSequenceDetector {
    pub fn new(rule: AstRuleEntry, lists: Arc<DangerousLists>) -> Self {
        Self { rule, lists }
    }

    fn decode_escapes(s: &str) -> Option<String> {
        let mut result = String::new();
        let mut chars = s.chars().peekable();
        let mut has_escapes = false;

        while let Some(c) = chars.next() {
            if c == '\\' {
                has_escapes = true;
                match chars.next() {
                    Some('x') => {
                        let mut hex = String::new();
                        for _ in 0..2 {
                            if let Some(&ch) = chars.peek() {
                                if ch.is_ascii_hexdigit() {
                                    hex.push(chars.next().unwrap());
                                } else {
                                    break;
                                }
                            }
                        }
                        if hex.len() == 2 {
                            if let Ok(code) = u8::from_str_radix(&hex, 16) {
                                result.push(code as char);
                            }
                        }
                    }
                    Some('u') => {
                        if chars.peek() == Some(&'{') {
                            chars.next();
                            let mut hex = String::new();
                            while let Some(&ch) = chars.peek() {
                                if ch == '}' {
                                    chars.next();
                                    break;
                                }
                                if ch.is_ascii_hexdigit() {
                                    hex.push(chars.next().unwrap());
                                } else {
                                    break;
                                }
                            }
                            if let Ok(code) = u32::from_str_radix(&hex, 16) {
                                if let Some(ch) = char::from_u32(code) {
                                    result.push(ch);
                                }
                            }
                        } else {
                            let mut hex = String::new();
                            for _ in 0..4 {
                                if let Some(&ch) = chars.peek() {
                                    if ch.is_ascii_hexdigit() {
                                        hex.push(chars.next().unwrap());
                                    } else {
                                        break;
                                    }
                                }
                            }
                            if hex.len() == 4 {
                                if let Ok(code) = u16::from_str_radix(&hex, 16) {
                                    result.push(char::from_u32(code as u32).unwrap_or('?'));
                                }
                            }
                        }
                    }
                    Some('n') => result.push('\n'),
                    Some('r') => result.push('\r'),
                    Some('t') => result.push('\t'),
                    Some('\\') => result.push('\\'),
                    Some('"') => result.push('"'),
                    Some('\'') => result.push('\''),
                    Some(other) => {
                        result.push('\\');
                        result.push(other);
                    }
                    None => result.push('\\'),
                }
            } else {
                result.push(c);
            }
        }

        if has_escapes {
            Some(result)
        } else {
            None
        }
    }

    fn get_raw_string_content(node: Node, source: &str) -> Option<String> {
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

impl Detector for EscapeSequenceDetector {
    fn rule_id(&self) -> &str {
        &self.rule.id
    }

    fn title(&self) -> &str {
        &self.rule.title
    }

    fn handled_node_types(&self) -> &'static [&'static str] {
        &["subscript_expression", "call_expression"]
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

        if index.kind() != "string" {
            return findings;
        }

        let raw = match Self::get_raw_string_content(index, source) {
            Some(s) => s,
            None => return findings,
        };

        if let Some(decoded) = Self::decode_escapes(&raw) {
            if self.lists.is_dangerous_function(&decoded) {
                let snippet = node.utf8_text(source.as_bytes()).unwrap_or("").to_string();

                let start_line = node.start_position().row + 1;
                let end_line = node.end_position().row + 1;

                findings.push(
                    Finding::new(
                        self.rule_id(),
                        self.title(),
                        format!(
                            "Escape sequences decode to '{}' on '{}'. \
                            This pattern uses character escapes (\\x, \\u) to hide dangerous function names.",
                            decoded, object_text
                        ),
                        self.rule.severity(),
                        self.rule.category(),
                        Location::new(path.to_path_buf(), start_line, end_line)
                            .with_columns(index.start_position().column + 1, index.end_position().column + 1),
                        snippet,
                    )
                    .with_remediation(&self.rule.remediation)
                    .with_metadata("technique", "escape_sequence_obfuscation")
                    .with_metadata("decoded_function", decoded)
                    .with_metadata("ast_analyzed", "true"),
                );
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_hex_escapes() {
        let decoded = EscapeSequenceDetector::decode_escapes(r"\x65\x76\x61\x6c");
        assert_eq!(decoded, Some("eval".to_string()));
    }

    #[test]
    fn test_decode_unicode_escapes() {
        let decoded = EscapeSequenceDetector::decode_escapes(r"\u0065\u0076\u0061\u006c");
        assert_eq!(decoded, Some("eval".to_string()));
    }

    #[test]
    fn test_no_escapes_returns_none() {
        let decoded = EscapeSequenceDetector::decode_escapes("eval");
        assert_eq!(decoded, None);
    }

    #[test]
    fn test_mixed_escapes() {
        let decoded = EscapeSequenceDetector::decode_escapes(r"ev\x61l");
        assert_eq!(decoded, Some("eval".to_string()));
    }
}
