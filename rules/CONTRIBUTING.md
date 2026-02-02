# Contributing Detection Rules to Vexscan

Thank you for your interest in contributing detection rules to Vexscan! Community rules help expand coverage for emerging threats and platform-specific security issues.

## Rule Structure

Rules are defined in JSON files within the `rules/community/` directory. Each file contains a category and an array of rules:

```json
{
  "$schema": "../rule-schema.json",
  "category": "Your Category Name",
  "source": "community",
  "rules": [
    {
      "id": "COMM-001",
      "title": "Short descriptive title",
      "description": "Detailed explanation of what this rule detects and why it's dangerous",
      "severity": "high",
      "pattern": "regex_pattern_here",
      "file_extensions": ["js", "ts"],
      "remediation": "How to fix or mitigate this issue",
      "author": "your-github-username",
      "author_url": "https://github.com/your-github-username",
      "version": "1.0.0",
      "created": "2026-02-02",
      "tags": ["category", "relevant", "tags"],
      "references": [
        "https://link-to-documentation-or-cve.com"
      ],
      "test_cases": {
        "should_match": [
          "example code that should trigger this rule"
        ],
        "should_not_match": [
          "similar but benign code that should NOT trigger"
        ]
      }
    }
  ]
}
```

## Required Fields

| Field | Description |
|-------|-------------|
| `id` | Unique identifier. **Community rules MUST use `COMM-XXX` prefix** |
| `title` | Short title (< 60 characters) |
| `description` | What the rule detects and why it's a security concern |
| `severity` | One of: `critical`, `high`, `medium`, `low`, `info` |
| `pattern` | Regular expression pattern (must be valid Rust regex) |

## Recommended Fields

| Field | Description |
|-------|-------------|
| `file_extensions` | Array of file extensions to check (empty = all files) |
| `remediation` | Guidance on how to fix the issue |
| `author` | Your GitHub username |
| `author_url` | Link to your profile |
| `version` | Semantic version (start with `1.0.0`) |
| `created` | Date created (YYYY-MM-DD) |
| `tags` | Searchable keywords |
| `references` | Links to CVEs, documentation, or security advisories |
| `test_cases` | **Strongly recommended** - examples that should/shouldn't match |

## Writing Good Patterns

### Regex Tips

- Use `\b` for word boundaries to avoid partial matches
- Use `\s*` or `\s+` for flexible whitespace matching
- Escape special regex characters: `\.`, `\(`, `\)`, `\[`, `\]`
- Use non-capturing groups `(?:...)` when you don't need captures
- Test patterns at [regex101.com](https://regex101.com/) (select Rust flavor)

### Example Patterns

```regex
# Match function call with flexible whitespace
\beval\s*\(

# Match string literal (single or double quotes)
['"]dangerous_string['"]

# Case-insensitive match
(?i)password\s*=

# Match either of two patterns
\b(exec|spawn)\s*\(

# Match with lookahead (not followed by)
api_key(?!_example)
```

### Avoid These Mistakes

- **Too broad**: `password` matches comments and variable names
- **Too narrow**: `password="secret"` misses `password = 'secret'`
- **Missing word boundaries**: `exec` matches `execute` and `execSync`
- **Not escaping special chars**: `eval()` should be `eval\(\)`

## Severity Guidelines

| Severity | When to Use |
|----------|-------------|
| `critical` | Immediate danger: credential theft, RCE, data exfiltration |
| `high` | Serious risk: shell execution, sensitive file access |
| `medium` | Concerning: obfuscation, suspicious patterns that need review |
| `low` | Suspicious but likely benign: hardcoded IPs, base64 usage |
| `info` | Informational: patterns worth noting but not necessarily dangerous |

## Test Cases

Test cases help validate your rule and prevent regressions:

```json
"test_cases": {
  "should_match": [
    "eval(userInput)",
    "eval ( code )",
    "window.eval(x)"
  ],
  "should_not_match": [
    "// eval is dangerous",
    "evaluate(x)",
    "\"eval\""
  ]
}
```

Run tests locally with:
```bash
cargo run -- rules test
```

## Submission Process

1. **Fork** the repository
2. **Create** your rule file in `rules/community/`
3. **Validate** your rules:
   ```bash
   cargo run -- rules test rules/community/your-rules.json
   ```
4. **Submit** a Pull Request with:
   - Clear description of what your rules detect
   - Why these patterns are security-relevant
   - Any references or CVEs related to the threats

## Review Criteria

Rules will be reviewed for:

- [ ] Valid JSON and schema compliance
- [ ] Regex pattern compiles without errors
- [ ] Pattern specificity (avoids excessive false positives)
- [ ] Appropriate severity level
- [ ] Clear, helpful description and remediation
- [ ] Test cases provided and passing
- [ ] Uses `COMM-` prefix for rule IDs
- [ ] No duplicate rule IDs

## Categories

You can create rules in existing categories or define new ones:

**Existing Categories:**
- Code Execution
- Shell Execution
- Prompt Injection
- Credential Access
- Data Exfiltration
- Obfuscation
- Hidden Content
- Cloud Security

**Creating New Categories:**
Simply use a descriptive `"category"` name in your rule file.

## Questions?

- Open an issue for questions about rule writing
- Check existing rules in `rules/official/` for examples
- See the [rule schema](./rule-schema.json) for all available fields

## License

By contributing rules, you agree to license them under the same license as Vexscan.
