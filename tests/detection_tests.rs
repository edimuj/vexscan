//! Integration tests for malicious pattern detection.
//!
//! These tests ensure Vexscan catches real-world malicious patterns
//! across different threat categories.

use std::path::PathBuf;
use std::process::Command;

/// Run vexscan scan on a sample and return the number of findings
fn scan_sample(path: &str) -> (i32, String) {
    let output = Command::new("cargo")
        .args(["run", "--quiet", "--", "scan", path, "-f", "json"])
        .env("RUST_LOG", "error")
        .output()
        .expect("Failed to run vexscan");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    // Find the JSON object in the output (skip any log lines)
    let json_start = stdout.find('{');
    let json_str = if let Some(start) = json_start {
        &stdout[start..]
    } else {
        &stdout
    };

    // Parse JSON to get finding count
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(json_str) {
        let count = json
            .get("results")
            .and_then(|r| r.as_array())
            .map(|results| {
                results
                    .iter()
                    .filter_map(|r| r.get("findings").and_then(|f| f.as_array()))
                    .map(|f| f.len() as i32)
                    .sum()
            })
            .unwrap_or(0);
        (count, stdout)
    } else {
        eprintln!("Failed to parse output: {}", stdout);
        eprintln!("Stderr: {}", stderr);
        (0, stdout)
    }
}

/// Scan a directory and ensure at least `min_findings` are found
fn assert_detects(dir: &str, min_findings: i32, description: &str) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/samples")
        .join(dir);

    let (count, _output) = scan_sample(path.to_str().unwrap());

    assert!(
        count >= min_findings,
        "{}: Expected at least {} findings, got {}",
        description,
        min_findings,
        count
    );
}

// ============================================================================
// PROMPT INJECTION TESTS
// ============================================================================

#[test]
fn test_detects_prompt_injection_basic_override() {
    assert_detects(
        "prompt-injection/basic-override.md",
        2,
        "Basic 'ignore all previous instructions' pattern",
    );
}

#[test]
fn test_detects_prompt_injection_system_tag() {
    assert_detects(
        "prompt-injection/hidden-system-tag.md",
        3,
        "Hidden <system> tag injection",
    );
}

#[test]
fn test_detects_prompt_injection_role_hijack() {
    assert_detects(
        "prompt-injection/role-hijack.md",
        3,
        "Identity hijacking attempt (INJECT-005)",
    );
}

#[test]
fn test_detects_prompt_injection_admin_impersonation() {
    assert_detects(
        "prompt-injection/admin-impersonation.md",
        1,
        "Authority claim from company (AUTH-003)",
    );
}

// ============================================================================
// CODE EXECUTION TESTS
// ============================================================================

#[test]
fn test_detects_code_execution_eval() {
    assert_detects(
        "code-execution/eval-user-input.js",
        2,
        "eval() and new Function() patterns",
    );
}

#[test]
fn test_detects_code_execution_dynamic_import() {
    assert_detects(
        "code-execution/dynamic-import.js",
        1,
        "Dynamic require/import patterns",
    );
}

#[test]
fn test_detects_code_execution_python_exec() {
    assert_detects(
        "code-execution/python-exec.py",
        2,
        "Python exec() and eval() patterns",
    );
}

// ============================================================================
// DATA EXFILTRATION TESTS
// ============================================================================

#[test]
fn test_detects_exfil_discord_webhook() {
    assert_detects(
        "data-exfiltration/discord-webhook.js",
        2,
        "Discord webhook exfiltration",
    );
}

#[test]
fn test_detects_exfil_external_post() {
    assert_detects(
        "data-exfiltration/external-post.js",
        2,
        "External POST with sensitive data",
    );
}

#[test]
fn test_detects_exfil_telegram_bot() {
    assert_detects(
        "data-exfiltration/telegram-bot.py",
        4,
        "Telegram bot exfiltration",
    );
}

// ============================================================================
// OBFUSCATION TESTS
// ============================================================================

#[test]
fn test_detects_obfuscation_base64() {
    assert_detects(
        "obfuscation/base64-payload.js",
        6,
        "Base64 encoded payload with eval",
    );
}

#[test]
fn test_detects_obfuscation_charcode() {
    assert_detects(
        "obfuscation/charcode-exec.js",
        4,
        "String.fromCharCode obfuscation",
    );
}

#[test]
fn test_detects_obfuscation_multi_layer() {
    assert_detects(
        "obfuscation/multi-layer.js",
        6,
        "Multi-layer base64 obfuscation",
    );
}

// ============================================================================
// CREDENTIAL THEFT TESTS
// ============================================================================

#[test]
fn test_detects_credential_theft_ssh() {
    assert_detects(
        "credential-theft/ssh-keys.js",
        1,
        "SSH key theft (.ssh/id_rsa)",
    );
}

#[test]
fn test_detects_credential_theft_aws() {
    assert_detects(
        "credential-theft/aws-creds.py",
        2,
        "Python Path sensitive directory access (CRED-005)",
    );
}

#[test]
fn test_detects_credential_theft_env() {
    assert_detects(
        "credential-theft/env-dump.js",
        3,
        "Environment variable dumping",
    );
}

// ============================================================================
// SHELL INJECTION TESTS
// ============================================================================

#[test]
fn test_detects_shell_injection_child_process() {
    assert_detects(
        "shell-injection/child-process.js",
        4,
        "child_process exec/spawn patterns",
    );
}

#[test]
fn test_detects_shell_injection_python_subprocess() {
    assert_detects(
        "shell-injection/python-subprocess.py",
        5,
        "Python subprocess/os.system patterns",
    );
}

#[test]
fn test_detects_shell_injection_reverse_shell() {
    assert_detects(
        "shell-injection/reverse-shell.sh",
        5,
        "Reverse shell patterns",
    );
}

// ============================================================================
// BACKDOOR DETECTION TESTS
// ============================================================================

#[test]
fn test_detects_backdoor_production_conditional() {
    assert_detects(
        "backdoor/production-backdoor.js",
        5,
        "Production-only backdoor, hostname check, time bomb, C2 (BACK-001 through BACK-005)",
    );
}

// ============================================================================
// DANGEROUS OPERATIONS TESTS
// ============================================================================

#[test]
fn test_detects_dangerous_ops_system_destruction() {
    assert_detects(
        "dangerous-ops/system-destruction.sh",
        8,
        "rm -rf, chmod 777, sudo, dd, suid, system dir writes (DANGER-001 through DANGER-006)",
    );
}

// ============================================================================
// PACKAGE MANAGEMENT TESTS
// ============================================================================

#[test]
fn test_detects_package_management_abuse() {
    assert_detects(
        "package-management/malicious-install.sh",
        8,
        "Global installs, sudo pip, force reinstall, URL installs (PKG-001 through PKG-005)",
    );
}

// ============================================================================
// HARDCODED SECRETS TESTS
// ============================================================================

#[test]
fn test_detects_hardcoded_secrets() {
    assert_detects(
        "hardcoded-secrets/leaked-keys.py",
        8,
        "SECRET-001 through SECRET-008: AWS, Stripe, Google, GitHub, JWT, private key, password, DB conn string",
    );
}

// ============================================================================
// RESOURCE ABUSE TESTS
// ============================================================================

#[test]
fn test_detects_resource_abuse() {
    assert_detects(
        "resource-abuse",
        3,
        "RESOURCE-001 through RESOURCE-003: infinite loop, fork bomb, excessive memory",
    );
}

// ============================================================================
// SQL INJECTION TESTS
// ============================================================================

#[test]
fn test_detects_sql_injection() {
    assert_detects(
        "code-execution/sql-injection.py",
        2,
        "EXEC-007: SQL injection via f-string and .format()",
    );
}

// ============================================================================
// PROMPT INJECTION EXTENDED TESTS
// ============================================================================

#[test]
fn test_detects_prompt_injection_system_reveal() {
    assert_detects(
        "prompt-injection/system-reveal.md",
        2,
        "INJECT-006 and INJECT-007: system prompt reveal and action concealment",
    );
}

// ============================================================================
// AGGREGATE TESTS
// ============================================================================

#[test]
fn test_all_samples_detected() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/samples");
    let (count, _) = scan_sample(path.to_str().unwrap());

    // 25 sample files across 11 categories, ~105+ total findings
    // Minimum expected: 95 (allowing some margin for rule changes)
    assert!(
        count >= 95,
        "Expected at least 95 total findings across all samples, got {}",
        count
    );
}
