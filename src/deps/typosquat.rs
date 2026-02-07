//! Typosquatting detection for npm packages.
//!
//! Popular package list is externalized to `data/popular-packages.json`
//! and embedded at compile time via `include_str!()`.

use serde::Deserialize;

/// Embedded JSON list of popular packages.
const POPULAR_JSON: &str = include_str!("../../data/popular-packages.json");

/// JSON file wrapper.
#[derive(Debug, Deserialize)]
struct PopularPackageFile {
    packages: Vec<String>,
}

/// Detector for typosquatting attempts.
pub struct TyposquatDetector {
    /// List of popular packages to check against.
    popular_packages: Vec<String>,
    /// Maximum Levenshtein distance to consider as typosquatting.
    threshold: usize,
}

impl TyposquatDetector {
    /// Create a new typosquatting detector.
    pub fn new(threshold: usize) -> Self {
        let file: PopularPackageFile = serde_json::from_str(POPULAR_JSON)
            .expect("Failed to parse embedded popular-packages.json");
        Self {
            popular_packages: file.packages,
            threshold,
        }
    }

    /// Check if a package name looks like a typosquat of a popular package.
    /// Returns Some((popular_name, distance)) if it's suspicious.
    pub fn check(&self, name: &str) -> Option<(String, usize)> {
        let name_lower = name.to_lowercase();

        // If the package itself is a popular package, it's not a typosquat
        if self
            .popular_packages
            .iter()
            .any(|p| p.to_lowercase() == name_lower)
        {
            return None;
        }

        for popular in &self.popular_packages {
            let popular_lower = popular.to_lowercase();

            // Skip if it's an exact match (not a typosquat)
            if name_lower == popular_lower {
                return None;
            }

            // First check for common typosquatting patterns (suffix additions etc)
            // These are checked before length filtering since they can add significant length
            if is_typosquat_pattern(&name_lower, &popular_lower) {
                return Some((popular.to_string(), 1));
            }

            // Skip if lengths are too different for Levenshtein check
            let len_diff = (name.len() as isize - popular.len() as isize).unsigned_abs();
            if len_diff > self.threshold {
                continue;
            }

            // Calculate Levenshtein distance
            let distance = levenshtein(&name_lower, &popular_lower);

            if distance > 0 && distance <= self.threshold {
                return Some((popular.to_string(), distance));
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

/// Check for common typosquatting patterns beyond Levenshtein distance.
fn is_typosquat_pattern(name: &str, popular: &str) -> bool {
    // Pattern: adding -js, .js, -node, -npm suffix
    let suffixes = ["-js", ".js", "-node", "-npm", "-lib", "-pkg", "js", "node"];
    for suffix in &suffixes {
        if name == format!("{}{}", popular, suffix) {
            return true;
        }
        if popular == format!("{}{}", name, suffix) {
            return true;
        }
    }

    // Pattern: removing hyphens
    let no_hyphen = popular.replace('-', "");
    if name == no_hyphen && name != popular {
        return true;
    }

    // Pattern: replacing hyphens with underscores or vice versa
    let swapped = popular.replace('-', "_");
    if name == swapped && name != popular {
        return true;
    }

    // Pattern: doubling letters
    if contains_doubled_letter(name, popular) {
        return true;
    }

    false
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
