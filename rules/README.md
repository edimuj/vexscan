# Vexscan Detection Rules

This directory contains security detection rules for the Vexscan scanner. Rules are organized into two categories:

## Directory Structure

```
rules/
├── official/           # Maintained by the Vexscan team
│   ├── code-execution.json
│   ├── shell-execution.json
│   ├── prompt-injection.json
│   ├── credential-access.json
│   ├── obfuscation.json
│   ├── data-exfiltration.json
│   └── hidden-content.json
├── community/          # Community-contributed rules
│   └── cloud-security.json
├── rule-schema.json    # JSON Schema for validation
├── CONTRIBUTING.md     # How to contribute rules
└── README.md           # This file
```

## Official Rules

Official rules are maintained by the Vexscan team and cover core security patterns:

| Category | Description | Rule Count |
|----------|-------------|------------|
| Code Execution | eval(), Function(), vm execution | 4 |
| Shell Execution | child_process, subprocess, system | 10 |
| Prompt Injection | Instruction override, role hijacking | 4 |
| Credential Access | SSH keys, AWS creds, env harvesting | 9 |
| Obfuscation | Base64, charcode, hex encoding | 6 |
| Data Exfiltration | Webhooks, external requests | 5 |
| Hidden Content | Zero-width chars, HTML comments | 2 |

## Community Rules

Community rules extend coverage to additional platforms, services, and threat patterns. They are contributed by the community and reviewed for quality.

Current community rules:
- **Cloud Security**: AWS access keys, GCP service accounts

## Using Rules

### List All Rules

```bash
# Show all rules
vexscan rules

# Show only official rules
vexscan rules --official

# Show only community rules
vexscan rules --community

# Filter by tag
vexscan rules --tag aws

# Filter by author
vexscan rules --author username
```

### View Rule Details

```bash
vexscan rules --rule EXEC-001
vexscan rules --rule COMM-001
```

### Test Rules

```bash
# Test all rules against their test cases
vexscan rules test

# Test a specific file
vexscan rules test rules/community/cloud-security.json

# Filter by rule ID pattern
vexscan rules test --filter COMM
```

### Scan with Rules

```bash
# Scan using all rules (default)
vexscan scan ./path

# Output includes rule IDs for each finding
vexscan scan ./path -f json
```

## Writing Rules

See [CONTRIBUTING.md](./CONTRIBUTING.md) for detailed instructions on:

- Rule structure and required fields
- Writing effective regex patterns
- Severity guidelines
- Test case requirements
- Submission process

## Rule Schema

All rules must conform to [rule-schema.json](./rule-schema.json). Key fields:

```json
{
  "id": "COMM-001",           // Unique ID (COMM- prefix for community)
  "title": "Short title",     // < 60 characters
  "description": "Details",   // What it detects and why
  "severity": "high",         // critical|high|medium|low|info
  "pattern": "regex",         // Valid Rust regex
  "test_cases": {             // Validation examples
    "should_match": [...],
    "should_not_match": [...]
  }
}
```

## Validation

Rules are automatically validated on PR:

1. **JSON Schema**: Must match rule-schema.json
2. **Regex Compilation**: Pattern must be valid
3. **Test Cases**: All tests must pass
4. **Unique IDs**: No duplicate rule IDs
5. **Naming**: Community rules must use COMM- prefix

Run validation locally:

```bash
cargo run -- rules test
```

## Severity Levels

| Level | Description | Example |
|-------|-------------|---------|
| Critical | Immediate danger, likely malicious | eval() with external input, credential theft |
| High | Serious security risk | Shell execution, sensitive file access |
| Medium | Concerning, needs review | Obfuscation, suspicious encoding |
| Low | Suspicious but often benign | Hardcoded IPs, base64 usage |
| Info | Informational | Patterns worth noting |

## Contributing

We welcome community contributions! See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

Quick start:
1. Create a JSON file in `rules/community/`
2. Use the `COMM-XXX` ID prefix
3. Add test cases
4. Run `vexscan rules test`
5. Submit a PR
