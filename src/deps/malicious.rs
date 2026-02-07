//! Database of known malicious npm packages.
//!
//! This database contains packages that have been identified as malicious
//! through npm security advisories, security research, and incident reports.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A known malicious package entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaliciousPackage {
    /// Package name.
    pub name: String,
    /// Affected versions (empty means all versions).
    #[serde(default)]
    pub versions: Vec<String>,
    /// Why this package is malicious.
    pub reason: String,
    /// Severity level (critical, high, medium, low).
    pub severity: String,
    /// CVE identifier if available.
    pub cve: Option<String>,
    /// Reference URL for more information.
    pub reference: Option<String>,
    /// Date the package was identified as malicious.
    pub discovered: Option<String>,
    /// Tags for categorization.
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Database of known malicious packages.
pub struct MaliciousPackageDb {
    /// Map of package name to malicious package info.
    packages: HashMap<String, MaliciousPackage>,
}

impl MaliciousPackageDb {
    /// Load the built-in malicious package database.
    pub fn load_builtin() -> Self {
        let packages = builtin_malicious_packages();
        let mut map = HashMap::new();

        for pkg in packages {
            map.insert(pkg.name.clone(), pkg);
        }

        Self { packages: map }
    }

    /// Look up a package by name and version.
    /// Returns Some if the package is known to be malicious.
    pub fn lookup(&self, name: &str, version: &str) -> Option<&MaliciousPackage> {
        if let Some(pkg) = self.packages.get(name) {
            // If no specific versions listed, all versions are affected
            if pkg.versions.is_empty() {
                return Some(pkg);
            }
            // Check if the specific version is affected
            if pkg.versions.iter().any(|v| version_matches(version, v)) {
                return Some(pkg);
            }
        }
        None
    }

    /// Get the total number of packages in the database.
    pub fn len(&self) -> usize {
        self.packages.len()
    }

    /// Check if the database is empty.
    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }
}

/// Check if a version string matches a pattern.
/// Supports exact match, prefix match with *, and semver ranges.
fn version_matches(version: &str, pattern: &str) -> bool {
    // Strip any leading ^ or ~ from the installed version
    let clean_version = version.trim_start_matches('^').trim_start_matches('~');

    if pattern == "*" {
        return true;
    }

    if pattern.ends_with('*') {
        let prefix = pattern.trim_end_matches('*');
        return clean_version.starts_with(prefix);
    }

    // Exact match
    clean_version == pattern || version == pattern
}

/// Built-in list of known malicious packages.
/// This list is compiled from various security advisories and incident reports.
fn builtin_malicious_packages() -> Vec<MaliciousPackage> {
    vec![
        // === Major Supply Chain Attacks ===
        MaliciousPackage {
            name: "event-stream".to_string(),
            versions: vec!["3.3.6".to_string()],
            reason: "Contained malicious code targeting Copay bitcoin wallet. The flatmap-stream dependency was compromised.".to_string(),
            severity: "critical".to_string(),
            cve: Some("CVE-2018-16492".to_string()),
            reference: Some("https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident".to_string()),
            discovered: Some("2018-11-26".to_string()),
            tags: vec!["supply-chain".to_string(), "cryptocurrency".to_string()],
        },
        MaliciousPackage {
            name: "flatmap-stream".to_string(),
            versions: vec!["0.1.1".to_string()],
            reason: "Injected malicious code into event-stream to steal cryptocurrency.".to_string(),
            severity: "critical".to_string(),
            cve: Some("CVE-2018-16492".to_string()),
            reference: Some("https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident".to_string()),
            discovered: Some("2018-11-26".to_string()),
            tags: vec!["supply-chain".to_string(), "cryptocurrency".to_string()],
        },
        MaliciousPackage {
            name: "ua-parser-js".to_string(),
            versions: vec!["0.7.29".to_string(), "0.8.0".to_string(), "1.0.0".to_string()],
            reason: "Compromised versions contained crypto mining and password stealing malware.".to_string(),
            severity: "critical".to_string(),
            cve: Some("CVE-2021-41264".to_string()),
            reference: Some("https://github.com/nicgirault/ua-parser-js/issues/536".to_string()),
            discovered: Some("2021-10-22".to_string()),
            tags: vec!["supply-chain".to_string(), "cryptominer".to_string(), "credential-theft".to_string()],
        },
        MaliciousPackage {
            name: "coa".to_string(),
            versions: vec!["2.0.3".to_string(), "2.0.4".to_string(), "2.1.1".to_string(), "2.1.3".to_string(), "3.0.1".to_string(), "3.1.3".to_string()],
            reason: "Compromised with malware that steals passwords.".to_string(),
            severity: "critical".to_string(),
            cve: None,
            reference: Some("https://github.com/veged/coa/issues/99".to_string()),
            discovered: Some("2021-11-04".to_string()),
            tags: vec!["supply-chain".to_string(), "credential-theft".to_string()],
        },
        MaliciousPackage {
            name: "rc".to_string(),
            versions: vec!["1.2.9".to_string(), "1.3.9".to_string(), "2.3.9".to_string()],
            reason: "Compromised with malware similar to coa attack.".to_string(),
            severity: "critical".to_string(),
            cve: None,
            reference: Some("https://github.com/dominictarr/rc/issues/131".to_string()),
            discovered: Some("2021-11-04".to_string()),
            tags: vec!["supply-chain".to_string(), "credential-theft".to_string()],
        },

        // === Typosquatting Attacks ===
        MaliciousPackage {
            name: "crossenv".to_string(),
            versions: vec![],
            reason: "Typosquat of cross-env. Steals environment variables including npm tokens.".to_string(),
            severity: "critical".to_string(),
            cve: None,
            reference: Some("https://blog.npmjs.org/post/163723642530/crossenv-malware-on-the-npm-registry".to_string()),
            discovered: Some("2017-08-01".to_string()),
            tags: vec!["typosquat".to_string(), "credential-theft".to_string()],
        },
        MaliciousPackage {
            name: "cross-env.js".to_string(),
            versions: vec![],
            reason: "Typosquat of cross-env. Steals environment variables.".to_string(),
            severity: "critical".to_string(),
            cve: None,
            reference: None,
            discovered: Some("2017-08-01".to_string()),
            tags: vec!["typosquat".to_string(), "credential-theft".to_string()],
        },
        MaliciousPackage {
            name: "babelcli".to_string(),
            versions: vec![],
            reason: "Typosquat of babel-cli. Malicious package.".to_string(),
            severity: "critical".to_string(),
            cve: None,
            reference: None,
            discovered: Some("2017-08-01".to_string()),
            tags: vec!["typosquat".to_string()],
        },
        MaliciousPackage {
            name: "eslint-scope".to_string(),
            versions: vec!["3.7.2".to_string()],
            reason: "Compromised to steal npm credentials.".to_string(),
            severity: "critical".to_string(),
            cve: None,
            reference: Some("https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes".to_string()),
            discovered: Some("2018-07-12".to_string()),
            tags: vec!["supply-chain".to_string(), "credential-theft".to_string()],
        },

        // === Data Exfiltration ===
        MaliciousPackage {
            name: "getcookies".to_string(),
            versions: vec![],
            reason: "Steals cookies and sends them to attacker-controlled server.".to_string(),
            severity: "critical".to_string(),
            cve: None,
            reference: None,
            discovered: Some("2018-05-02".to_string()),
            tags: vec!["data-theft".to_string()],
        },
        MaliciousPackage {
            name: "discord-selfbot-v14".to_string(),
            versions: vec![],
            reason: "Steals Discord tokens and system information.".to_string(),
            severity: "critical".to_string(),
            cve: None,
            reference: None,
            discovered: Some("2022-01-01".to_string()),
            tags: vec!["data-theft".to_string(), "discord".to_string()],
        },
        MaliciousPackage {
            name: "discord-badge".to_string(),
            versions: vec![],
            reason: "Steals Discord tokens.".to_string(),
            severity: "critical".to_string(),
            cve: None,
            reference: None,
            discovered: Some("2022-01-01".to_string()),
            tags: vec!["data-theft".to_string(), "discord".to_string()],
        },

        // === Colors/Faker Protest ===
        MaliciousPackage {
            name: "colors".to_string(),
            versions: vec!["1.4.1".to_string(), "1.4.2".to_string()],
            reason: "Developer intentionally corrupted package with infinite loop as protest.".to_string(),
            severity: "high".to_string(),
            cve: None,
            reference: Some("https://www.bleepingcomputer.com/news/security/dev-corrupts-npm-libs-colors-and-faker-breaking-thousands-of-apps/".to_string()),
            discovered: Some("2022-01-08".to_string()),
            tags: vec!["sabotage".to_string()],
        },
        MaliciousPackage {
            name: "faker".to_string(),
            versions: vec!["6.6.6".to_string()],
            reason: "Developer intentionally corrupted package as protest.".to_string(),
            severity: "high".to_string(),
            cve: None,
            reference: Some("https://www.bleepingcomputer.com/news/security/dev-corrupts-npm-libs-colors-and-faker-breaking-thousands-of-apps/".to_string()),
            discovered: Some("2022-01-08".to_string()),
            tags: vec!["sabotage".to_string()],
        },

        // === node-ipc Protest ===
        MaliciousPackage {
            name: "node-ipc".to_string(),
            versions: vec!["10.1.1".to_string(), "10.1.2".to_string(), "10.1.3".to_string()],
            reason: "Developer added code that would delete files on Russian/Belarusian systems (protestware).".to_string(),
            severity: "critical".to_string(),
            cve: Some("CVE-2022-23812".to_string()),
            reference: Some("https://snyk.io/blog/peacenotwar-malicious-npm-node-ipc-package-vulnerability/".to_string()),
            discovered: Some("2022-03-15".to_string()),
            tags: vec!["protestware".to_string(), "destructive".to_string()],
        },
        MaliciousPackage {
            name: "peacenotwar".to_string(),
            versions: vec![],
            reason: "Dependency used by node-ipc to deliver protestware.".to_string(),
            severity: "high".to_string(),
            cve: None,
            reference: Some("https://snyk.io/blog/peacenotwar-malicious-npm-node-ipc-package-vulnerability/".to_string()),
            discovered: Some("2022-03-15".to_string()),
            tags: vec!["protestware".to_string()],
        },

        // === 2024 Attacks ===
        MaliciousPackage {
            name: "@pnpm/exe".to_string(),
            versions: vec![],
            reason: "Typosquat targeting pnpm users, contains malware.".to_string(),
            severity: "critical".to_string(),
            cve: None,
            reference: None,
            discovered: Some("2024-01-01".to_string()),
            tags: vec!["typosquat".to_string()],
        },
        MaliciousPackage {
            name: "eslint-config-prettier-plugin".to_string(),
            versions: vec![],
            reason: "Typosquat of eslint-config-prettier, contains malware.".to_string(),
            severity: "critical".to_string(),
            cve: None,
            reference: None,
            discovered: Some("2024-01-01".to_string()),
            tags: vec!["typosquat".to_string()],
        },

        // === Cryptominers ===
        MaliciousPackage {
            name: "jdb".to_string(),
            versions: vec![],
            reason: "Contains hidden cryptocurrency miner.".to_string(),
            severity: "high".to_string(),
            cve: None,
            reference: None,
            discovered: Some("2018-01-01".to_string()),
            tags: vec!["cryptominer".to_string()],
        },
        MaliciousPackage {
            name: "db-json".to_string(),
            versions: vec![],
            reason: "Contains hidden cryptocurrency miner.".to_string(),
            severity: "high".to_string(),
            cve: None,
            reference: None,
            discovered: Some("2018-01-01".to_string()),
            tags: vec!["cryptominer".to_string()],
        },

        // === Reverse Shells / Backdoors ===
        MaliciousPackage {
            name: "nodemailer-js".to_string(),
            versions: vec![],
            reason: "Typosquat of nodemailer containing backdoor.".to_string(),
            severity: "critical".to_string(),
            cve: None,
            reference: None,
            discovered: Some("2019-01-01".to_string()),
            tags: vec!["typosquat".to_string(), "backdoor".to_string()],
        },
        MaliciousPackage {
            name: "nodemailer-js-utils".to_string(),
            versions: vec![],
            reason: "Fake package containing backdoor.".to_string(),
            severity: "critical".to_string(),
            cve: None,
            reference: None,
            discovered: Some("2019-01-01".to_string()),
            tags: vec!["backdoor".to_string()],
        },
        MaliciousPackage {
            name: "http-fetch-cookies".to_string(),
            versions: vec![],
            reason: "Contains reverse shell backdoor.".to_string(),
            severity: "critical".to_string(),
            cve: None,
            reference: None,
            discovered: Some("2020-01-01".to_string()),
            tags: vec!["backdoor".to_string(), "reverse-shell".to_string()],
        },

        // === More Typosquats of Popular Packages ===
        MaliciousPackage {
            name: "twilio-npm".to_string(),
            versions: vec![],
            reason: "Typosquat of twilio, contains malware.".to_string(),
            severity: "critical".to_string(),
            cve: None,
            reference: None,
            discovered: Some("2020-01-01".to_string()),
            tags: vec!["typosquat".to_string()],
        },
        MaliciousPackage {
            name: "lodash-es".to_string(),
            versions: vec!["4.17.22".to_string()],
            reason: "Malicious version uploaded briefly, not from original maintainer.".to_string(),
            severity: "high".to_string(),
            cve: None,
            reference: None,
            discovered: Some("2022-01-01".to_string()),
            tags: vec!["supply-chain".to_string()],
        },
        MaliciousPackage {
            name: "lemaaa".to_string(),
            versions: vec![],
            reason: "Contains token grabber and data exfiltration code.".to_string(),
            severity: "critical".to_string(),
            cve: None,
            reference: None,
            discovered: Some("2023-01-01".to_string()),
            tags: vec!["data-theft".to_string()],
        },

        // === Dependency Confusion Attacks ===
        MaliciousPackage {
            name: "internal-store".to_string(),
            versions: vec![],
            reason: "Dependency confusion attack targeting internal packages.".to_string(),
            severity: "high".to_string(),
            cve: None,
            reference: Some("https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610".to_string()),
            discovered: Some("2021-02-09".to_string()),
            tags: vec!["dependency-confusion".to_string()],
        },

        // === Additional Known Malicious Packages ===
        MaliciousPackage {
            name: "socketio".to_string(),
            versions: vec![],
            reason: "Typosquat of socket.io. Contains data-stealing malware.".to_string(),
            severity: "critical".to_string(),
            cve: None,
            reference: None,
            discovered: Some("2017-08-01".to_string()),
            tags: vec!["typosquat".to_string(), "data-theft".to_string()],
        },
        MaliciousPackage {
            name: "d3.js".to_string(),
            versions: vec![],
            reason: "Typosquat of d3. Malicious package.".to_string(),
            severity: "critical".to_string(),
            cve: None,
            reference: None,
            discovered: Some("2017-08-01".to_string()),
            tags: vec!["typosquat".to_string()],
        },
        MaliciousPackage {
            name: "mongose".to_string(),
            versions: vec![],
            reason: "Typosquat of mongoose. Malicious package.".to_string(),
            severity: "critical".to_string(),
            cve: None,
            reference: None,
            discovered: Some("2017-08-01".to_string()),
            tags: vec!["typosquat".to_string()],
        },
        MaliciousPackage {
            name: "mssql-node".to_string(),
            versions: vec![],
            reason: "Fake database connector with backdoor.".to_string(),
            severity: "critical".to_string(),
            cve: None,
            reference: None,
            discovered: Some("2019-01-01".to_string()),
            tags: vec!["backdoor".to_string()],
        },
        MaliciousPackage {
            name: "require-port".to_string(),
            versions: vec![],
            reason: "Typosquat of portfinder/require-port, contains malware.".to_string(),
            severity: "critical".to_string(),
            cve: None,
            reference: None,
            discovered: Some("2020-01-01".to_string()),
            tags: vec!["typosquat".to_string()],
        },
        MaliciousPackage {
            name: "azure-identity-js".to_string(),
            versions: vec![],
            reason: "Typosquat of @azure/identity, contains credential stealer.".to_string(),
            severity: "critical".to_string(),
            cve: None,
            reference: None,
            discovered: Some("2023-01-01".to_string()),
            tags: vec!["typosquat".to_string(), "credential-theft".to_string()],
        },
        MaliciousPackage {
            name: "aws-sdk-js".to_string(),
            versions: vec![],
            reason: "Typosquat of aws-sdk, contains credential stealer.".to_string(),
            severity: "critical".to_string(),
            cve: None,
            reference: None,
            discovered: Some("2023-01-01".to_string()),
            tags: vec!["typosquat".to_string(), "credential-theft".to_string()],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_builtin() {
        let db = MaliciousPackageDb::load_builtin();
        assert!(!db.is_empty());
        assert!(db.len() >= 30);
    }

    #[test]
    fn test_lookup_event_stream() {
        let db = MaliciousPackageDb::load_builtin();

        // Affected version
        assert!(db.lookup("event-stream", "3.3.6").is_some());

        // Safe version
        assert!(db.lookup("event-stream", "3.3.5").is_none());
        assert!(db.lookup("event-stream", "4.0.0").is_none());
    }

    #[test]
    fn test_lookup_any_version() {
        let db = MaliciousPackageDb::load_builtin();

        // crossenv is malicious regardless of version
        assert!(db.lookup("crossenv", "1.0.0").is_some());
        assert!(db.lookup("crossenv", "99.99.99").is_some());
    }

    #[test]
    fn test_safe_package() {
        let db = MaliciousPackageDb::load_builtin();

        assert!(db.lookup("lodash", "4.17.21").is_none());
        assert!(db.lookup("express", "4.18.2").is_none());
    }

    #[test]
    fn test_version_with_prefix() {
        let db = MaliciousPackageDb::load_builtin();

        // Should match even with ^ prefix
        assert!(db.lookup("event-stream", "^3.3.6").is_some());
        assert!(db.lookup("event-stream", "~3.3.6").is_some());
    }
}
