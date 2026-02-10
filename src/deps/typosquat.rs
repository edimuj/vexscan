//! Typosquatting detection for npm packages.
//!
//! Popular package list is externalized to `data/popular-packages.json`
//! and embedded at compile time via `include_str!()`.

use serde::Deserialize;
use std::collections::{HashMap, HashSet};

/// Embedded JSON list of popular packages.
const POPULAR_JSON: &str = include_str!("../../data/popular-packages.json");

/// JSON file wrapper.
#[derive(Debug, Deserialize)]
struct PopularPackageFile {
    packages: Vec<String>,
}

/// Detector for typosquatting attempts.
pub struct TyposquatDetector {
    /// Original popular package names (for return values).
    popular_original: Vec<String>,
    /// Pre-lowercased popular package names (parallel to popular_original).
    popular_lower: Vec<String>,
    /// O(1) exact-match guard (lowercased).
    popular_set: HashSet<String>,
    /// Pre-computed pattern variants → index into popular arrays.
    /// Covers suffix additions, hyphen removal, underscore swap.
    pattern_variants: HashMap<String, usize>,
    /// Maximum Levenshtein distance to consider as typosquatting.
    threshold: usize,
}

impl TyposquatDetector {
    /// Create a new typosquatting detector.
    pub fn new(threshold: usize) -> Self {
        let file: PopularPackageFile = serde_json::from_str(POPULAR_JSON)
            .expect("Failed to parse embedded popular-packages.json");

        let popular_lower: Vec<String> = file.packages.iter().map(|p| p.to_lowercase()).collect();
        let popular_set: HashSet<String> = popular_lower.iter().cloned().collect();

        // Pre-compute all pattern variants at construction time
        let suffixes = ["-js", ".js", "-node", "-npm", "-lib", "-pkg", "js", "node"];
        let mut pattern_variants: HashMap<String, usize> = HashMap::new();

        for (idx, lower) in popular_lower.iter().enumerate() {
            // Suffix additions: "lodash-js", "lodash-node", etc.
            for suffix in &suffixes {
                let with_suffix = format!("{}{}", lower, suffix);
                pattern_variants.entry(with_suffix).or_insert(idx);
                // Reverse: if popular is "lodash-js", match "lodash"
                if let Some(stripped) = lower.strip_suffix(suffix) {
                    pattern_variants.entry(stripped.to_string()).or_insert(idx);
                }
            }

            // Hyphen removal: "cross-env" → "crossenv"
            if lower.contains('-') {
                let no_hyphen = lower.replace('-', "");
                pattern_variants.entry(no_hyphen).or_insert(idx);
            }

            // Underscore swap: "cross-env" → "cross_env"
            if lower.contains('-') {
                let underscored = lower.replace('-', "_");
                pattern_variants.entry(underscored).or_insert(idx);
            }
        }

        Self {
            popular_original: file.packages,
            popular_lower,
            popular_set,
            pattern_variants,
            threshold,
        }
    }

    /// Check if a package name looks like a typosquat of a popular package.
    /// Returns Some((popular_name, distance)) if it's suspicious.
    pub fn check(&self, name: &str) -> Option<(String, usize)> {
        let name_lower = name.to_lowercase();

        // O(1) exact-match guard
        if self.popular_set.contains(&name_lower) {
            return None;
        }

        // O(1) pattern variant check (suffix, hyphen, underscore)
        if let Some(&idx) = self.pattern_variants.get(&name_lower) {
            return Some((self.popular_original[idx].clone(), 1));
        }

        // Doubled letter check + Levenshtein (still O(n) but no allocations per-package)
        for (idx, popular_lower) in self.popular_lower.iter().enumerate() {
            // Skip if lengths are too different for Levenshtein
            let len_diff = (name.len() as isize - popular_lower.len() as isize).unsigned_abs();
            if len_diff > self.threshold {
                // But still check doubled letters (adds exactly 1 char)
                if len_diff == 1 && contains_doubled_letter(&name_lower, popular_lower) {
                    return Some((self.popular_original[idx].clone(), 1));
                }
                continue;
            }

            // Doubled letter check
            if contains_doubled_letter(&name_lower, popular_lower) {
                return Some((self.popular_original[idx].clone(), 1));
            }

            // Levenshtein distance (both already lowercased)
            let distance = levenshtein(&name_lower, popular_lower);
            if distance > 0 && distance <= self.threshold {
                return Some((self.popular_original[idx].clone(), distance));
            }
        }

        None
    }
}

/// Calculate Levenshtein distance between two strings.
/// Uses two-row algorithm: O(min(m,n)) memory instead of O(m*n).
fn levenshtein(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();

    let a_len = a_chars.len();
    let b_len = b_chars.len();

    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    // Ensure b is the shorter string for minimal memory usage
    let (a_chars, b_chars, a_len, b_len) = if a_len < b_len {
        (&b_chars, &a_chars, b_len, a_len)
    } else {
        (&a_chars, &b_chars, a_len, b_len)
    };

    let mut prev = (0..=b_len).collect::<Vec<_>>();
    let mut curr = vec![0; b_len + 1];

    for i in 1..=a_len {
        curr[0] = i;
        for j in 1..=b_len {
            let cost = if a_chars[i - 1] == b_chars[j - 1] {
                0
            } else {
                1
            };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[b_len]
}

/// Check if name has a doubled letter compared to popular.
fn contains_doubled_letter(name: &str, popular: &str) -> bool {
    let name_chars: Vec<char> = name.chars().collect();
    let popular_chars: Vec<char> = popular.chars().collect();

    if name_chars.len() != popular_chars.len() + 1 {
        return false;
    }

    let mut i = 0;
    let mut j = 0;
    let mut found_double = false;

    while i < name_chars.len() && j < popular_chars.len() {
        if name_chars[i] == popular_chars[j] {
            i += 1;
            j += 1;
        } else if !found_double && i + 1 < name_chars.len() && name_chars[i] == name_chars[i + 1] {
            found_double = true;
            i += 1;
        } else {
            return false;
        }
    }

    // Handle trailing doubled letter
    if i < name_chars.len()
        && !found_double
        && i + 1 == name_chars.len()
        && i > 0
        && name_chars[i] == name_chars[i - 1]
    {
        return true;
    }

    found_double && j == popular_chars.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match_not_typosquat() {
        let detector = TyposquatDetector::new(2);
        assert!(detector.check("lodash").is_none());
        assert!(detector.check("express").is_none());
        assert!(detector.check("react").is_none());
    }

    #[test]
    fn test_detect_typosquat() {
        let detector = TyposquatDetector::new(2);

        // lodahs -> lodash (swapped letters)
        let result = detector.check("lodahs");
        assert!(result.is_some());
        let (popular, _) = result.unwrap();
        assert_eq!(popular, "lodash");

        // expresss -> express (extra s)
        let result = detector.check("expresss");
        assert!(result.is_some());
        let (popular, _) = result.unwrap();
        assert_eq!(popular, "express");
    }

    #[test]
    fn test_suffix_pattern() {
        let detector = TyposquatDetector::new(2);

        // lodash-js is suspicious
        let result = detector.check("lodash-js");
        assert!(result.is_some());

        // express-node is suspicious
        let result = detector.check("express-node");
        assert!(result.is_some());
    }

    #[test]
    fn test_not_similar_enough() {
        let detector = TyposquatDetector::new(2);

        // Completely different package
        assert!(detector.check("my-unique-package-name").is_none());

        // Too different to be a typosquat
        assert!(detector.check("expressway").is_none());
    }

    #[test]
    fn test_levenshtein() {
        assert_eq!(levenshtein("kitten", "sitting"), 3);
        assert_eq!(levenshtein("saturday", "sunday"), 3);
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("abc", ""), 3);
        assert_eq!(levenshtein("abc", "abc"), 0);
        assert_eq!(levenshtein("lodash", "lodahs"), 2);
        assert_eq!(levenshtein("express", "expresss"), 1);
    }

    #[test]
    fn test_hyphen_removal() {
        let detector = TyposquatDetector::new(2);

        // "crossenv" is similar to "cross-env"
        let result = detector.check("crossenv");
        assert!(result.is_some());
    }
}
