# Vexscan Documentation

Vexscan is a security scanner for AI agent plugins, skills, MCP servers, and configurations. It detects malicious
patterns, supply chain attacks, and prompt injection attempts before they can harm your system.

## Quick Start

```bash
# Scan a directory
vexscan scan ./plugins

# Scan with all features
vexscan scan ./plugins --ast --deps

# Output as JSON for CI integration
vexscan scan ./plugins -f json --fail-on critical
```

## Security Features

| Feature                                         | Flag      | Description                                     |
|-------------------------------------------------|-----------|-------------------------------------------------|
| [Static Analysis](./static-analysis.md)         | (default) | Regex-based pattern matching for known threats  |
| [AST Analysis](./ast-analysis.md)               | `--ast`   | Tree-sitter based detection for obfuscated code |
| [Dependency Scanning](./dependency-scanning.md) | `--deps`  | npm supply chain attack detection               |
| [AI Analysis](./ai-analysis.md)                 | `--ai`    | LLM-powered semantic threat detection           |
| [Encoding Detection](./encoding-detection.md)   | (default) | Automatic decoding of obfuscated payloads       |

## What Vexscan Detects

### Code Execution Threats

- Direct `eval()` and `new Function()` usage
- Shell command execution via `child_process`
- Obfuscated execution patterns (computed access, variable aliasing)

### Supply Chain Attacks

- Known malicious npm packages (event-stream, ua-parser-js, etc.)
- Typosquatting attempts (lodahs → lodash)
- Suspicious install scripts (postinstall curl|bash)

### Prompt Injection

- Instruction override attempts ("ignore previous instructions")
- Authority impersonation ("I am the system administrator")
- Hidden instructions (zero-width characters, HTML comments)

### Data Exfiltration

- Webhook URLs (Discord, Slack, Telegram)
- Credential harvesting (SSH keys, AWS credentials, .env files)
- Environment variable exfiltration

## Platforms

Vexscan supports multiple AI agent platforms:

- [Claude Code](./platforms/claude-code.md) - Plugins, skills, hooks, MCP servers
- [OpenClaw](./platforms/openclaw.md) - Tools, skills, CLI extensions
- Generic - Any directory of code files

## Rule Reference

See [Rules Reference](./rules/reference.md) for a complete list of detection rules.

## Integration

### CI/CD Pipeline

```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    vexscan scan ./src --deps --fail-on high -f sarif > results.sarif
```

### Pre-commit Hook

```bash
vexscan scan --changed-only --fail-on critical
```

## Further Reading

- [Static Analysis](./static-analysis.md) - How regex-based detection works
- [AST Analysis](./ast-analysis.md) - Detecting obfuscated threats
- [Dependency Scanning](./dependency-scanning.md) - Protecting against supply chain attacks
- [AI Analysis](./ai-analysis.md) - Using LLMs for threat detection
- [Contributing Rules](../CONTRIBUTING.md) - Adding community detection rules
