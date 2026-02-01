//! Built-in detection patterns for common security issues.

use super::Rule;
use crate::types::{FindingCategory, Severity};

/// Returns all built-in security rules.
pub fn builtin_rules() -> Vec<Rule> {
    let mut rules = Vec::new();

    // ==================== CODE EXECUTION ====================

    rules.push(Rule {
        id: "EXEC-001".to_string(),
        title: "Direct eval() usage".to_string(),
        description: "eval() executes arbitrary code and is commonly used in malware to run obfuscated payloads.".to_string(),
        severity: Severity::Critical,
        category: FindingCategory::CodeExecution,
        pattern: r"\beval\s*\(".to_string(),
        file_extensions: vec!["js".into(), "ts".into(), "mjs".into(), "cjs".into()],
        remediation: Some("Replace eval() with safer alternatives like JSON.parse() for data or explicit function calls.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "EXEC-002".to_string(),
        title: "Function constructor".to_string(),
        description: "new Function() is equivalent to eval() and can execute arbitrary code.".to_string(),
        severity: Severity::Critical,
        category: FindingCategory::CodeExecution,
        pattern: r"\bnew\s+Function\s*\(".to_string(),
        file_extensions: vec!["js".into(), "ts".into(), "mjs".into(), "cjs".into()],
        remediation: Some("Avoid dynamic code generation. Use explicit function definitions.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "EXEC-003".to_string(),
        title: "VM code execution".to_string(),
        description: "Node.js vm module can execute arbitrary code with various isolation levels.".to_string(),
        severity: Severity::High,
        category: FindingCategory::CodeExecution,
        pattern: r"\bvm\s*\.\s*(runInContext|runInNewContext|runInThisContext|compileFunction)\s*\(".to_string(),
        file_extensions: vec!["js".into(), "ts".into(), "mjs".into(), "cjs".into()],
        remediation: Some("Ensure VM usage is intentional and inputs are strictly validated.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "EXEC-004".to_string(),
        title: "Python exec/eval".to_string(),
        description: "exec() and eval() execute arbitrary Python code.".to_string(),
        severity: Severity::Critical,
        category: FindingCategory::CodeExecution,
        pattern: r"\b(exec|eval)\s*\(".to_string(),
        file_extensions: vec!["py".into()],
        remediation: Some("Use ast.literal_eval() for safe evaluation of literals, or avoid dynamic execution entirely.".to_string()),
        enabled: true,
    });

    // ==================== SHELL EXECUTION ====================

    rules.push(Rule {
        id: "SHELL-001".to_string(),
        title: "Child process spawn/exec".to_string(),
        description: "Spawning shell processes can execute arbitrary system commands.".to_string(),
        severity: Severity::High,
        category: FindingCategory::ShellExecution,
        pattern: r#"\b(child_process|require\s*\(\s*['"]child_process['"]\s*\))\s*\.\s*(exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\s*\("#.to_string(),
        file_extensions: vec!["js".into(), "ts".into(), "mjs".into(), "cjs".into()],
        remediation: Some("Validate all inputs passed to shell commands. Prefer execFile over exec when possible.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "SHELL-002".to_string(),
        title: "Shell execution via execa/shelljs".to_string(),
        description: "Popular shell execution libraries that can run arbitrary commands.".to_string(),
        severity: Severity::High,
        category: FindingCategory::ShellExecution,
        pattern: r"\b(execa|shelljs|\$`|shell\.exec)\s*\(".to_string(),
        file_extensions: vec!["js".into(), "ts".into(), "mjs".into(), "cjs".into()],
        remediation: Some("Audit all shell commands being executed and validate inputs.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "SHELL-003".to_string(),
        title: "Python subprocess execution".to_string(),
        description: "subprocess module can execute arbitrary system commands.".to_string(),
        severity: Severity::High,
        category: FindingCategory::ShellExecution,
        pattern: r"\bsubprocess\s*\.\s*(run|call|Popen|check_output|check_call|getoutput|getstatusoutput)\s*\(".to_string(),
        file_extensions: vec!["py".into()],
        remediation: Some("Use shell=False and pass arguments as a list. Validate all inputs.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "SHELL-004".to_string(),
        title: "Python os.system/popen".to_string(),
        description: "os.system() and os.popen() execute shell commands.".to_string(),
        severity: Severity::High,
        category: FindingCategory::ShellExecution,
        pattern: r"\bos\s*\.\s*(system|popen)\s*\(".to_string(),
        file_extensions: vec!["py".into()],
        remediation: Some("Use subprocess module with shell=False instead.".to_string()),
        enabled: true,
    });

    // ==================== BASE64 / OBFUSCATION ====================

    rules.push(Rule {
        id: "OBFUSC-001".to_string(),
        title: "Base64 decode (atob)".to_string(),
        description: "atob() decodes base64 strings, commonly used to hide malicious payloads.".to_string(),
        severity: Severity::Medium,
        category: FindingCategory::Obfuscation,
        pattern: r"\batob\s*\(".to_string(),
        file_extensions: vec!["js".into(), "ts".into(), "mjs".into(), "cjs".into()],
        remediation: Some("Review what is being decoded. Legitimate uses should have clear, documented purposes.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "OBFUSC-002".to_string(),
        title: "Buffer.from base64".to_string(),
        description: "Buffer.from with base64 encoding is used to decode hidden content.".to_string(),
        severity: Severity::Medium,
        category: FindingCategory::Obfuscation,
        pattern: r#"Buffer\s*\.\s*from\s*\([^)]*['"](base64|hex)['"]"#.to_string(),
        file_extensions: vec!["js".into(), "ts".into(), "mjs".into(), "cjs".into()],
        remediation: Some("Review what is being decoded and ensure it's not hiding malicious content.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "OBFUSC-003".to_string(),
        title: "Long base64 string literal".to_string(),
        description: "Long base64-encoded strings may contain hidden code or data.".to_string(),
        severity: Severity::Medium,
        category: FindingCategory::Obfuscation,
        pattern: r#"['"`][A-Za-z0-9+/=]{100,}['"`]"#.to_string(),
        file_extensions: vec![],  // All files
        remediation: Some("Decode and review the content of long encoded strings.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "OBFUSC-004".to_string(),
        title: "String.fromCharCode obfuscation".to_string(),
        description: "String.fromCharCode can be used to build strings that evade pattern matching.".to_string(),
        severity: Severity::Medium,
        category: FindingCategory::Obfuscation,
        pattern: r"String\s*\.\s*fromCharCode\s*\([^)]{10,}\)".to_string(),
        file_extensions: vec!["js".into(), "ts".into(), "mjs".into(), "cjs".into()],
        remediation: Some("Review what string is being constructed.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "OBFUSC-005".to_string(),
        title: "Hex escape sequence string".to_string(),
        description: "Strings with many hex escapes may be obfuscating content.".to_string(),
        severity: Severity::Low,
        category: FindingCategory::Obfuscation,
        pattern: r#"['"]((\\x[0-9a-fA-F]{2})){5,}['"]"#.to_string(),
        file_extensions: vec!["js".into(), "ts".into(), "mjs".into(), "cjs".into(), "py".into()],
        remediation: Some("Convert hex escapes to readable text and review.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "OBFUSC-006".to_string(),
        title: "Python base64 decode".to_string(),
        description: "base64.b64decode() is commonly used to hide malicious payloads.".to_string(),
        severity: Severity::Medium,
        category: FindingCategory::Obfuscation,
        pattern: r"\bbase64\s*\.\s*(b64decode|decodebytes|decodestring)\s*\(".to_string(),
        file_extensions: vec!["py".into()],
        remediation: Some("Review what is being decoded.".to_string()),
        enabled: true,
    });

    // ==================== SENSITIVE FILE ACCESS ====================

    rules.push(Rule {
        id: "FILE-001".to_string(),
        title: "SSH key access".to_string(),
        description: "Accessing SSH keys could lead to unauthorized access to systems.".to_string(),
        severity: Severity::Critical,
        category: FindingCategory::SensitiveFileAccess,
        pattern: r#"['"](~/)?\.ssh/(id_rsa|id_ed25519|id_ecdsa|known_hosts|authorized_keys|config)['"]"#.to_string(),
        file_extensions: vec![],
        remediation: Some("SSH key access should be strictly audited and justified.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "FILE-002".to_string(),
        title: "AWS credentials access".to_string(),
        description: "Accessing AWS credentials could lead to cloud infrastructure compromise.".to_string(),
        severity: Severity::Critical,
        category: FindingCategory::SensitiveFileAccess,
        pattern: r#"['"](~/)?\.aws/(credentials|config)['"]"#.to_string(),
        file_extensions: vec![],
        remediation: Some("AWS credential access must be carefully reviewed.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "FILE-003".to_string(),
        title: "Environment file access".to_string(),
        description: ".env files often contain secrets and API keys.".to_string(),
        severity: Severity::High,
        category: FindingCategory::SensitiveFileAccess,
        pattern: r#"['"]\.env(\.(local|development|production|test))?['"]"#.to_string(),
        file_extensions: vec![],
        remediation: Some("Review why .env files are being accessed.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "FILE-004".to_string(),
        title: "Browser data access".to_string(),
        description: "Accessing browser storage may expose cookies, passwords, or history.".to_string(),
        severity: Severity::Critical,
        category: FindingCategory::SensitiveFileAccess,
        pattern: r#"['"].*/(Chrome|Firefox|Safari|Edge)/.*(Cookies|Login Data|History|Local Storage)['"]"#.to_string(),
        file_extensions: vec![],
        remediation: Some("Browser data access is highly sensitive and suspicious.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "FILE-005".to_string(),
        title: "Keychain/credential store access".to_string(),
        description: "Accessing system credential stores is highly suspicious.".to_string(),
        severity: Severity::Critical,
        category: FindingCategory::CredentialAccess,
        pattern: r#"['"].*(keychain|credential-store|gnome-keyring|kwallet)['"]"#.to_string(),
        file_extensions: vec![],
        remediation: Some("Credential store access must be justified and audited.".to_string()),
        enabled: true,
    });

    // ==================== DATA EXFILTRATION ====================

    rules.push(Rule {
        id: "EXFIL-001".to_string(),
        title: "Webhook/external POST".to_string(),
        description: "POST requests to external URLs may be exfiltrating data.".to_string(),
        severity: Severity::Medium,
        category: FindingCategory::DataExfiltration,
        pattern: r#"(fetch|axios|request|got|http\.request)\s*\([^)]*['"]https?://[^'"]+['"][^)]*['"](POST|post)['"]"#.to_string(),
        file_extensions: vec!["js".into(), "ts".into(), "mjs".into(), "cjs".into()],
        remediation: Some("Audit external network requests and ensure they are expected.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "EXFIL-002".to_string(),
        title: "Discord/Slack webhook".to_string(),
        description: "Webhooks to chat services are commonly used for data exfiltration.".to_string(),
        severity: Severity::High,
        category: FindingCategory::DataExfiltration,
        pattern: r#"['"]https://(discord\.com/api/webhooks|hooks\.slack\.com|api\.telegram\.org)/[^'"]+['"]"#.to_string(),
        file_extensions: vec![],
        remediation: Some("Webhook URLs should be reviewed for legitimacy.".to_string()),
        enabled: true,
    });

    // ==================== PROMPT INJECTION ====================

    rules.push(Rule {
        id: "INJECT-001".to_string(),
        title: "Ignore instructions pattern".to_string(),
        description: "Classic prompt injection attempting to override system instructions.".to_string(),
        severity: Severity::Critical,
        category: FindingCategory::PromptInjection,
        pattern: r"(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|guidelines|constraints)".to_string(),
        file_extensions: vec!["md".into(), "txt".into(), "json".into(), "yaml".into(), "yml".into()],
        remediation: Some("Remove prompt injection attempts from content.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "INJECT-002".to_string(),
        title: "System message injection".to_string(),
        description: "Attempting to inject fake system messages.".to_string(),
        severity: Severity::Critical,
        category: FindingCategory::PromptInjection,
        // More specific: requires XML-style tags, brackets, or colon prefix - not camelCase
        pattern: r"(?i)(<\s*system\s*>|\[SYSTEM\]|^SYSTEM\s*:|---\s*system\s*---|<<\s*system\s*>>)".to_string(),
        file_extensions: vec!["md".into(), "txt".into(), "json".into(), "yaml".into(), "yml".into()],
        remediation: Some("Remove fake system message injections.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "INJECT-003".to_string(),
        title: "Role/mode override".to_string(),
        description: "Attempting to change AI role or enable special modes.".to_string(),
        severity: Severity::High,
        category: FindingCategory::PromptInjection,
        // More specific: requires "you are now" or known jailbreak terms, not generic "enable developer mode"
        pattern: r"(?i)(you\s+are\s+now\s+(in\s+)?(developer|admin|debug|root|jailbreak|DAN|unrestricted)|switch\s+to\s+(developer|admin|debug|jailbreak|DAN|unrestricted)\s+mode|enter\s+(jailbreak|DAN|unrestricted)\s+mode|activate\s+(jailbreak|DAN|unrestricted))".to_string(),
        file_extensions: vec!["md".into(), "txt".into(), "json".into(), "yaml".into(), "yml".into()],
        remediation: Some("Remove role/mode override attempts.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "INJECT-004".to_string(),
        title: "Pre-authorization claim".to_string(),
        description: "Claiming user has already authorized an action.".to_string(),
        severity: Severity::High,
        category: FindingCategory::PromptInjection,
        pattern: r"(?i)(user\s+has\s+(already\s+)?(authorized|approved|confirmed|granted|consented)|pre-?authorized|implicit\s+consent)".to_string(),
        file_extensions: vec!["md".into(), "txt".into(), "json".into(), "yaml".into(), "yml".into()],
        remediation: Some("Remove false authorization claims.".to_string()),
        enabled: true,
    });

    // ==================== AUTHORITY IMPERSONATION ====================

    rules.push(Rule {
        id: "AUTH-001".to_string(),
        title: "Admin/developer impersonation".to_string(),
        description: "Claiming to be an administrator or developer to override instructions.".to_string(),
        severity: Severity::High,
        category: FindingCategory::AuthorityImpersonation,
        // More specific: requires context suggesting override/instruction
        pattern: r"(?i)(this\s+is\s+(a\s+)?(message\s+from|instruction\s+from)|I\s+am\s+(the|an?)\s+(system\s+)?administrator|official\s+(message|instruction)\s+from\s+(anthropic|openai|the\s+system))".to_string(),
        file_extensions: vec!["md".into(), "txt".into(), "json".into(), "yaml".into(), "yml".into()],
        remediation: Some("Remove authority impersonation attempts.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "AUTH-002".to_string(),
        title: "Emergency/urgent override".to_string(),
        description: "Using urgency to bypass normal security checks.".to_string(),
        severity: Severity::Medium,
        category: FindingCategory::AuthorityImpersonation,
        pattern: r"(?i)(emergency|urgent|critical|immediately)\s+(override|bypass|skip|ignore)\s+(security|verification|confirmation)".to_string(),
        file_extensions: vec!["md".into(), "txt".into(), "json".into(), "yaml".into(), "yml".into()],
        remediation: Some("Remove urgency-based override attempts.".to_string()),
        enabled: true,
    });

    // ==================== HIDDEN INSTRUCTIONS ====================

    rules.push(Rule {
        id: "HIDDEN-001".to_string(),
        title: "Zero-width characters".to_string(),
        description: "Zero-width characters can hide instructions in seemingly empty text.".to_string(),
        severity: Severity::High,
        category: FindingCategory::HiddenInstructions,
        pattern: r"[\u200B\u200C\u200D\u2060\uFEFF]{3,}".to_string(),
        file_extensions: vec![],
        remediation: Some("Remove zero-width characters that may hide content.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "HIDDEN-002".to_string(),
        title: "HTML comment instructions".to_string(),
        description: "Potential prompt injection hidden in HTML comments.".to_string(),
        severity: Severity::Medium,
        category: FindingCategory::HiddenInstructions,
        // More specific: requires injection-like context, not just metadata comments
        pattern: r"(?i)<!--\s*(ignore\s+(all\s+)?(previous|prior)|execute\s+(this|the\s+following)|you\s+(must|should|are)|do\s+not\s+tell|secretly|hidden\s+instruction)".to_string(),
        file_extensions: vec!["html".into(), "htm".into(), "md".into()],
        remediation: Some("Review HTML comments for hidden instructions.".to_string()),
        enabled: true,
    });

    // ==================== NETWORK/CRYPTO ====================

    rules.push(Rule {
        id: "NET-001".to_string(),
        title: "Crypto mining indicators".to_string(),
        description: "Patterns associated with cryptocurrency mining.".to_string(),
        severity: Severity::Critical,
        category: FindingCategory::Other("Cryptomining".to_string()),
        pattern: r"(?i)(coinhive|cryptonight|stratum\+tcp|xmrig|minergate|hashrate|nonce\s*[:=])".to_string(),
        file_extensions: vec![],
        remediation: Some("Remove cryptocurrency mining code.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "NET-002".to_string(),
        title: "Suspicious IP address".to_string(),
        description: "Hard-coded IP addresses may indicate C2 communication.".to_string(),
        severity: Severity::Low,
        category: FindingCategory::DataExfiltration,
        pattern: r#"['"]([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]+)?['"]"#.to_string(),
        file_extensions: vec![],
        remediation: Some("Review hard-coded IP addresses for legitimacy.".to_string()),
        enabled: true,
    });

    // ==================== MARKDOWN CODE BLOCKS ====================
    // Dangerous code embedded in markdown can be extracted and executed by plugins

    rules.push(Rule {
        id: "MDCODE-001".to_string(),
        title: "Shell commands in markdown".to_string(),
        description: "Markdown code block contains potentially dangerous shell commands that could be extracted and executed.".to_string(),
        severity: Severity::High,
        category: FindingCategory::CodeExecution,
        pattern: r"```(?:bash|sh|shell|zsh)\s*\n[^`]*(rm\s+-rf|curl\s+[^|]*\|\s*(ba)?sh|wget\s+[^|]*\|\s*(ba)?sh|chmod\s+[+0-7]*x|>\s*/etc/|mkfs\.|dd\s+if=)[^`]*```".to_string(),
        file_extensions: vec!["md".into(), "markdown".into()],
        remediation: Some("Review shell commands in markdown for malicious intent.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "MDCODE-002".to_string(),
        title: "Eval/exec in markdown code block".to_string(),
        description: "Markdown code block contains eval/exec which could be extracted and executed.".to_string(),
        severity: Severity::High,
        category: FindingCategory::CodeExecution,
        pattern: r"```(?:python|py)\s*\n[^`]*(exec\s*\(|eval\s*\()[^`]*```".to_string(),
        file_extensions: vec!["md".into(), "markdown".into()],
        remediation: Some("Review Python code in markdown for malicious intent.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "MDCODE-003".to_string(),
        title: "JavaScript eval in markdown".to_string(),
        description: "Markdown code block contains JavaScript eval which could be extracted and executed.".to_string(),
        severity: Severity::High,
        category: FindingCategory::CodeExecution,
        pattern: r"```(?:javascript|js|typescript|ts)\s*\n[^`]*(\beval\s*\(|\bnew\s+Function\s*\()[^`]*```".to_string(),
        file_extensions: vec!["md".into(), "markdown".into()],
        remediation: Some("Review JavaScript code in markdown for malicious intent.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "MDCODE-004".to_string(),
        title: "Curl/wget piped to shell in markdown".to_string(),
        description: "Classic 'curl | bash' attack pattern in markdown code block.".to_string(),
        severity: Severity::Critical,
        category: FindingCategory::CodeExecution,
        pattern: r"```[^`]*(curl|wget)\s+[^\n]*\|\s*(sudo\s+)?(ba)?sh[^`]*```".to_string(),
        file_extensions: vec!["md".into(), "markdown".into()],
        remediation: Some("Never pipe remote content directly to shell. Download and inspect first.".to_string()),
        enabled: true,
    });

    // ==================== ADDITIONAL SHELL PATTERNS ====================

    rules.push(Rule {
        id: "SHELL-005".to_string(),
        title: "Destructured child_process import".to_string(),
        description: "Importing exec/spawn from child_process enables shell command execution.".to_string(),
        severity: Severity::High,
        category: FindingCategory::ShellExecution,
        pattern: r#"(const|let|var)\s*\{\s*(exec|execSync|spawn|spawnSync|execFile|fork)[^}]*\}\s*=\s*require\s*\(\s*['"]child_process['"]\s*\)"#.to_string(),
        file_extensions: vec!["js".into(), "ts".into(), "mjs".into(), "cjs".into()],
        remediation: Some("Review shell command usage for security issues.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "SHELL-006".to_string(),
        title: "Direct exec/execSync call".to_string(),
        description: "Direct exec() or execSync() calls execute shell commands.".to_string(),
        severity: Severity::High,
        category: FindingCategory::ShellExecution,
        pattern: r#"\b(exec|execSync)\s*\(\s*['"`]"#.to_string(),
        file_extensions: vec!["js".into(), "ts".into(), "mjs".into(), "cjs".into()],
        remediation: Some("Validate all shell command inputs.".to_string()),
        enabled: true,
    });

    // ==================== SHELL SCRIPT PATTERNS ====================

    rules.push(Rule {
        id: "SCRIPT-001".to_string(),
        title: "Reverse shell pattern".to_string(),
        description: "Bash reverse shell connects back to attacker-controlled server.".to_string(),
        severity: Severity::Critical,
        category: FindingCategory::ShellExecution,
        pattern: r"(bash\s+-i\s+>&\s*/dev/tcp/|nc\s+(-e|--exec)\s+/bin/(ba)?sh|/dev/tcp/[^/]+/[0-9]+)".to_string(),
        file_extensions: vec!["sh".into(), "bash".into(), "zsh".into()],
        remediation: Some("Remove reverse shell code immediately.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "SCRIPT-002".to_string(),
        title: "Curl/wget pipe to shell".to_string(),
        description: "Downloading and executing remote scripts is extremely dangerous.".to_string(),
        severity: Severity::Critical,
        category: FindingCategory::ShellExecution,
        pattern: r"(curl|wget)\s+[^\n|]*\|\s*(sudo\s+)?(ba)?sh".to_string(),
        file_extensions: vec!["sh".into(), "bash".into(), "zsh".into()],
        remediation: Some("Download scripts and review before executing.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "SCRIPT-003".to_string(),
        title: "Python reverse shell".to_string(),
        description: "Python one-liner reverse shell pattern.".to_string(),
        severity: Severity::Critical,
        category: FindingCategory::ShellExecution,
        pattern: r"python[23]?\s+-c\s+.import\s+socket".to_string(),
        file_extensions: vec!["sh".into(), "bash".into(), "zsh".into()],
        remediation: Some("Remove reverse shell code.".to_string()),
        enabled: true,
    });

    // ==================== ENHANCED CREDENTIAL ACCESS ====================

    rules.push(Rule {
        id: "CRED-001".to_string(),
        title: "SSH directory access pattern".to_string(),
        description: "Accessing .ssh directory contents suggests credential theft.".to_string(),
        severity: Severity::Critical,
        category: FindingCategory::CredentialAccess,
        pattern: r"(\.ssh[/\\]|homedir\(\)[^)]*\.ssh|HOME[^)]*\.ssh)".to_string(),
        file_extensions: vec![],
        remediation: Some("SSH key access must be strictly justified.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "CRED-002".to_string(),
        title: "AWS directory access pattern".to_string(),
        description: "Accessing .aws directory suggests cloud credential theft.".to_string(),
        severity: Severity::Critical,
        category: FindingCategory::CredentialAccess,
        pattern: r"(\.aws[/\\]|homedir\(\)[^)]*\.aws|HOME[^)]*\.aws)".to_string(),
        file_extensions: vec![],
        remediation: Some("AWS credential access must be justified.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "CRED-003".to_string(),
        title: "Environment variable harvesting".to_string(),
        description: "Bulk access to process.env may be harvesting secrets.".to_string(),
        severity: Severity::High,
        category: FindingCategory::CredentialAccess,
        pattern: r"(process\.env\s*[,\}]|JSON\.stringify\s*\([^)]*process\.env|Object\.(keys|entries|values)\s*\(\s*process\.env)".to_string(),
        file_extensions: vec!["js".into(), "ts".into(), "mjs".into(), "cjs".into()],
        remediation: Some("Avoid bulk access to environment variables.".to_string()),
        enabled: true,
    });

    rules.push(Rule {
        id: "CRED-004".to_string(),
        title: "Python environment harvesting".to_string(),
        description: "Bulk access to os.environ may be harvesting secrets.".to_string(),
        severity: Severity::High,
        category: FindingCategory::CredentialAccess,
        pattern: r"(dict\s*\(\s*os\.environ\)|os\.environ\.(copy|items|keys)|json\.dumps\s*\([^)]*os\.environ)".to_string(),
        file_extensions: vec!["py".into()],
        remediation: Some("Avoid bulk access to environment variables.".to_string()),
        enabled: true,
    });

    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_rules_compile() {
        let rules = builtin_rules();
        for rule in rules {
            assert!(
                rule.compile().is_ok(),
                "Rule {} failed to compile: {}",
                rule.id,
                rule.pattern
            );
        }
    }

    #[test]
    fn test_eval_detection() {
        let rules = builtin_rules();
        let eval_rule = rules.iter().find(|r| r.id == "EXEC-001").unwrap();
        let compiled = eval_rule.compile().unwrap();

        assert!(compiled.regex.is_match("eval(code)"));
        assert!(compiled.regex.is_match("eval (dangerous)"));
        assert!(compiled.regex.is_match("  eval('test')"));
        assert!(!compiled.regex.is_match("evaluate(x)"));
    }

    #[test]
    fn test_prompt_injection_detection() {
        let rules = builtin_rules();
        let inject_rule = rules.iter().find(|r| r.id == "INJECT-001").unwrap();
        let compiled = inject_rule.compile().unwrap();

        assert!(compiled.regex.is_match("ignore all previous instructions"));
        assert!(compiled.regex.is_match("IGNORE PREVIOUS INSTRUCTIONS"));
        assert!(compiled.regex.is_match("disregard prior rules"));
        assert!(compiled.regex.is_match("Forget all earlier guidelines"));
    }

    #[test]
    fn test_base64_detection() {
        let rules = builtin_rules();
        let b64_rule = rules.iter().find(|r| r.id == "OBFUSC-003").unwrap();
        let compiled = b64_rule.compile().unwrap();

        // Long base64 string (100+ chars)
        let long_b64 = format!("\"{}\"", "A".repeat(150));
        assert!(compiled.regex.is_match(&long_b64));

        // Short string should not match
        assert!(!compiled.regex.is_match("\"short\""));
    }
}
