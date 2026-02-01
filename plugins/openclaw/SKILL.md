# Vetryx Security Scanner

Vetryx scans extensions, skills, and code for security threats. Use it when:

- User wants to install a new extension or skill
- User asks about security of their OpenClaw setup
- User mentions suspicious behavior from an extension
- User wants to audit installed extensions
- Before recommending any third-party extension

## When to use Vetryx

| User intent                          | Use Vetryx?                         |
|--------------------------------------|-------------------------------------|
| "Install this extension from GitHub" | Yes — vet before installing         |
| "Is my setup secure?"                | Yes — scan all extensions           |
| "This extension is acting weird"     | Yes — scan for malicious patterns   |
| "Show me my installed extensions"    | No — use OpenClaw's built-in list   |
| "What does this code do?"            | Maybe — scan if it looks suspicious |

## Basic usage

### Scan installed extensions

```json
{
  "action": "scan",
  "path": "~/.openclaw/extensions"
}
```

Returns:

```json
{
  "ok": true,
  "findings": 3,
  "maxSeverity": "medium",
  "summary": {
    "critical": 0,
    "high": 0,
    "medium": 3,
    "low": 1,
    "info": 2
  }
}
```

### Vet before installing

When user wants to install an extension, **always vet first**:

```json
{
  "action": "vet",
  "source": "https://github.com/user/cool-extension"
}
```

Returns verdict:

```json
{
  "ok": true,
  "verdict": "clean",
  "findings": 0,
  "message": "No security issues found"
}
```

Or if issues found:

```json
{
  "ok": true,
  "verdict": "warnings",
  "findings": 2,
  "maxSeverity": "medium",
  "message": "Found 2 medium-severity issues"
}
```

## Verdicts

| Verdict     | Meaning              | Recommendation              |
|-------------|----------------------|-----------------------------|
| `clean`     | No issues found      | Safe to install             |
| `warnings`  | Low/medium issues    | Review findings, usually OK |
| `high_risk` | High severity issues | Warn user, review carefully |
| `dangerous` | Critical issues      | Do NOT recommend installing |

## Important

- **Always vet** extensions before recommending installation
- If verdict is `high_risk` or `dangerous`, explain the specific threats found
- Scanning is fast — prefer caution over speed
- Third-party extensions are higher risk than official ones
