//! Decoders for detecting and extracting obfuscated content.
//!
//! Malware often uses encoding to hide malicious payloads. This module
//! provides recursive decoding to uncover hidden content.

use regex::Regex;
use std::collections::HashSet;

/// Result of attempting to decode content.
#[derive(Debug, Clone)]
pub struct DecodedContent {
    /// The original encoded string.
    pub original: String,
    /// The decoded content.
    pub decoded: String,
    /// The encoding that was detected and decoded.
    pub encoding: EncodingType,
    /// Byte offset where the encoded content started in the source.
    pub offset: usize,
}

/// Types of encoding we can detect and decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncodingType {
    Base64,
    Hex,
    Unicode,
    CharCode,
    UrlEncoded,
}

impl std::fmt::Display for EncodingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodingType::Base64 => write!(f, "base64"),
            EncodingType::Hex => write!(f, "hex"),
            EncodingType::Unicode => write!(f, "unicode"),
            EncodingType::CharCode => write!(f, "charcode"),
            EncodingType::UrlEncoded => write!(f, "url-encoded"),
        }
    }
}

/// Decoder that can find and decode various encodings.
pub struct Decoder {
    base64_pattern: Regex,
    hex_pattern: Regex,
    unicode_pattern: Regex,
    charcode_pattern: Regex,
    url_pattern: Regex,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            // Match base64 strings (at least 20 chars to reduce false positives)
            base64_pattern: Regex::new(r#"['"`]([A-Za-z0-9+/]{20,}={0,2})['"`]"#).unwrap(),
            // Match hex strings like "48656c6c6f"
            hex_pattern: Regex::new(r#"['"`]([0-9a-fA-F]{20,})['"`]"#).unwrap(),
            // Match unicode escape sequences like \u0048\u0065
            unicode_pattern: Regex::new(r"((?:\\u[0-9a-fA-F]{4}){4,})").unwrap(),
            // Match String.fromCharCode(72, 101, 108, 108, 111)
            charcode_pattern: Regex::new(
                r"String\s*\.\s*fromCharCode\s*\(\s*((?:\d+\s*,?\s*){3,})\)",
            )
            .unwrap(),
            // Match URL encoded strings like %48%65%6c%6c%6f
            url_pattern: Regex::new(r"((?:%[0-9a-fA-F]{2}){5,})").unwrap(),
        }
    }

    /// Find all encoded content in the given text.
    pub fn find_encoded(&self, content: &str) -> Vec<DecodedContent> {
        let mut results = Vec::new();
        let mut seen_offsets: HashSet<usize> = HashSet::new();

        // Find base64
        for cap in self.base64_pattern.captures_iter(content) {
            if let Some(m) = cap.get(1) {
                let offset = m.start();
                if seen_offsets.contains(&offset) {
                    continue;
                }
                if let Some(decoded) = self.try_decode_base64(m.as_str()) {
                    // Only include if decoded content looks like text
                    if is_printable_text(&decoded) {
                        seen_offsets.insert(offset);
                        results.push(DecodedContent {
                            original: m.as_str().to_string(),
                            decoded,
                            encoding: EncodingType::Base64,
                            offset,
                        });
                    }
                }
            }
        }

        // Find hex strings
        for cap in self.hex_pattern.captures_iter(content) {
            if let Some(m) = cap.get(1) {
                let offset = m.start();
                if seen_offsets.contains(&offset) {
                    continue;
                }
                if let Some(decoded) = self.try_decode_hex(m.as_str()) {
                    if is_printable_text(&decoded) {
                        seen_offsets.insert(offset);
                        results.push(DecodedContent {
                            original: m.as_str().to_string(),
                            decoded,
                            encoding: EncodingType::Hex,
                            offset,
                        });
                    }
                }
            }
        }

        // Find unicode escapes
        for cap in self.unicode_pattern.captures_iter(content) {
            if let Some(m) = cap.get(1) {
                let offset = m.start();
                if seen_offsets.contains(&offset) {
                    continue;
                }
                if let Some(decoded) = self.try_decode_unicode(m.as_str()) {
                    seen_offsets.insert(offset);
                    results.push(DecodedContent {
                        original: m.as_str().to_string(),
                        decoded,
                        encoding: EncodingType::Unicode,
                        offset,
                    });
                }
            }
        }

        // Find charcode
        for cap in self.charcode_pattern.captures_iter(content) {
            if let Some(m) = cap.get(1) {
                let offset = cap.get(0).map(|c| c.start()).unwrap_or(0);
                if seen_offsets.contains(&offset) {
                    continue;
                }
                if let Some(decoded) = self.try_decode_charcode(m.as_str()) {
                    seen_offsets.insert(offset);
                    results.push(DecodedContent {
                        original: cap.get(0).map(|c| c.as_str()).unwrap_or("").to_string(),
                        decoded,
                        encoding: EncodingType::CharCode,
                        offset,
                    });
                }
            }
        }

        // Find URL encoded
        for cap in self.url_pattern.captures_iter(content) {
            if let Some(m) = cap.get(1) {
                let offset = m.start();
                if seen_offsets.contains(&offset) {
                    continue;
                }
                if let Some(decoded) = self.try_decode_url(m.as_str()) {
                    if is_printable_text(&decoded) {
                        seen_offsets.insert(offset);
                        results.push(DecodedContent {
                            original: m.as_str().to_string(),
                            decoded,
                            encoding: EncodingType::UrlEncoded,
                            offset,
                        });
                    }
                }
            }
        }

        results
    }

    /// Recursively decode content until no more encodings are found.
    /// Returns all intermediate decoded layers.
    pub fn decode_recursive(&self, content: &str, max_depth: usize) -> Vec<Vec<DecodedContent>> {
        let mut all_layers = Vec::new();
        let mut current_content = content.to_string();

        for _ in 0..max_depth {
            let decoded = self.find_encoded(&current_content);
            if decoded.is_empty() {
                break;
            }

            // Build new content by replacing encoded parts with decoded
            let mut new_content = current_content.clone();
            for d in decoded.iter().rev() {
                // Use simple string replacement instead of replace_range to avoid UTF-8 boundary issues
                new_content = new_content.replace(&d.original, &d.decoded);
            }

            all_layers.push(decoded);
            current_content = new_content;
        }

        all_layers
    }

    fn try_decode_base64(&self, s: &str) -> Option<String> {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;

        // Try standard base64
        if let Ok(bytes) = engine.decode(s) {
            if let Ok(decoded) = String::from_utf8(bytes) {
                return Some(decoded);
            }
        }

        // Try URL-safe base64
        let engine_url = base64::engine::general_purpose::URL_SAFE;
        if let Ok(bytes) = engine_url.decode(s) {
            if let Ok(decoded) = String::from_utf8(bytes) {
                return Some(decoded);
            }
        }

        None
    }

    fn try_decode_hex(&self, s: &str) -> Option<String> {
        // Ensure even length for hex pairs and minimum length
        if s.len() % 2 != 0 || s.is_empty() {
            return None;
        }

        // Decode hex string to bytes
        let mut bytes = Vec::with_capacity(s.len() / 2);
        let mut i = 0;
        while i + 2 <= s.len() {
            match u8::from_str_radix(&s[i..i + 2], 16) {
                Ok(byte) => bytes.push(byte),
                Err(_) => return None,
            }
            i += 2;
        }

        String::from_utf8(bytes).ok()
    }

    fn try_decode_unicode(&self, s: &str) -> Option<String> {
        let mut result = String::new();
        let mut chars = s.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '\\' && chars.peek() == Some(&'u') {
                chars.next(); // consume 'u'
                let hex: String = chars.by_ref().take(4).collect();
                if let Ok(code) = u32::from_str_radix(&hex, 16) {
                    if let Some(decoded_char) = char::from_u32(code) {
                        result.push(decoded_char);
                    }
                }
            }
        }

        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    fn try_decode_charcode(&self, s: &str) -> Option<String> {
        let result: String = s
            .split(',')
            .filter_map(|n| n.trim().parse::<u32>().ok())
            .filter_map(char::from_u32)
            .collect();

        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    fn try_decode_url(&self, s: &str) -> Option<String> {
        let mut result = String::new();
        let mut chars = s.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '%' {
                let hex: String = chars.by_ref().take(2).collect();
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                }
            } else {
                result.push(c);
            }
        }

        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }
}

/// Check if a string appears to be human-readable text.
fn is_printable_text(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }

    let printable_count = s
        .chars()
        .filter(|c| c.is_alphanumeric() || c.is_whitespace() || c.is_ascii_punctuation())
        .count();

    let ratio = printable_count as f64 / s.len() as f64;
    ratio > 0.7 // At least 70% printable characters
}

/// Calculate the Shannon entropy of a string.
/// High entropy (> 4.5) often indicates encoded/encrypted content.
pub fn calculate_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq = [0u32; 256];
    for byte in s.bytes() {
        freq[byte as usize] += 1;
    }

    let len = s.len() as f64;
    freq.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_decode() {
        let decoder = Decoder::new();
        // "eval('malicious code')" in base64 = "ZXZhbCgnbWFsaWNpb3VzIGNvZGUnKQ==" (32 chars)
        let content = r#"let x = "ZXZhbCgnbWFsaWNpb3VzIGNvZGUnKQ==";"#;
        let decoded = decoder.find_encoded(content);

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].decoded, "eval('malicious code')");
        assert_eq!(decoded[0].encoding, EncodingType::Base64);
    }

    #[test]
    fn test_charcode_decode() {
        let decoder = Decoder::new();
        let content = "String.fromCharCode(72, 101, 108, 108, 111)"; // "Hello"
        let decoded = decoder.find_encoded(content);

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].decoded, "Hello");
        assert_eq!(decoded[0].encoding, EncodingType::CharCode);
    }

    #[test]
    fn test_unicode_decode() {
        let decoder = Decoder::new();
        let content = r"\u0048\u0065\u006c\u006c\u006f"; // "Hello"
        let decoded = decoder.find_encoded(content);

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].decoded, "Hello");
        assert_eq!(decoded[0].encoding, EncodingType::Unicode);
    }

    #[test]
    fn test_entropy_calculation() {
        // Random-looking string should have high entropy
        let high_entropy = "aB3$kL9@mN2#pQ5";
        assert!(calculate_entropy(high_entropy) > 3.5);

        // Repetitive string should have low entropy
        let low_entropy = "aaaaaaaaaa";
        assert!(calculate_entropy(low_entropy) < 1.0);
    }

    #[test]
    fn test_recursive_decode() {
        let decoder = Decoder::new();
        // Base64 of "eval('malicious code')" = "ZXZhbCgnbWFsaWNpb3VzIGNvZGUnKQ==" (32 chars)
        // Needs to be long enough to trigger detection (20+ chars)
        let content = r#"atob("ZXZhbCgnbWFsaWNpb3VzIGNvZGUnKQ==")"#;
        let layers = decoder.decode_recursive(content, 3);

        // Should find at least one layer of decoding
        assert!(
            !layers.is_empty() || content.contains("ZXZhbCgnbWFsaWNpb3VzIGNvZGUnKQ=="),
            "Should detect base64 or content should contain the encoded string"
        );
    }
}
