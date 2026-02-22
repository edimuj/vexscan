# Vexscan Security Scanner

Scans extensions, skills, and code for security threats: prompt injection, malicious code, obfuscation, data exfiltration. Also scans inbound messages for injection patterns automatically.

Use it when:
- User wants to install a new extension or skill
- User asks about security of their setup
- User mentions suspicious behavior from an extension
- User wants to audit installed extensions
- User asks about or wants to manage trust decisions
- Before recommending any third-party extension

## Action routing

| User intent | Action |
|---|---|
| "Install this extension from GitHub" | **install** — vets then installs |
| "Is this extension safe?" | **vet** — scan without installing |
| "Is my setup secure?" | **scan** — scan all extensions |
| "This extension is acting weird" | **scan** on that extension's path |
| "Check this text for injection" | **check** — stdin text scanning (not yet exposed as tool action; use `/check` slash command) |
| "What's trusted?" / "Show trust entries" | **trust_list** |
| "Stop trusting X" | **trust_revoke** |

## Install (vet + install in one step)

**Always prefer install over vet** when the user wants to add an extension.

```json
{ "action": "install", "source": "https://github.com/user/extension" }
```

Success: `{ "ok": true, "action": "installed", "findings": 0, "message": "..." }`
Blocked: `{ "ok": false, "action": "install_blocked", "verdict": "high_risk", "findings": 3, "maxSeverity": "high", "reason": "..." }`

### Severity gates

| Max severity | Default | Override |
|---|---|---|
| Critical | **Blocked** | Cannot override |
| High | **Blocked** | `"allowHigh": true` |
| Medium | **Blocked** | `"force": true` |
| Low / Info | Allowed | — |

**Never set `allowHigh` or `force` without explaining the risks to the user first.**

## Scan

```json
{ "action": "scan", "path": "~/.openclaw/extensions" }
```

Path defaults to `~/.openclaw/extensions` if omitted. Returns findings count, max severity, and breakdown by severity level.

## Vet

```json
{ "action": "vet", "source": "https://github.com/user/extension" }
```

Returns verdict + findings without installing anything.

## Trust store

Manage suppression of reviewed findings. Findings suppressed by trust still exist but don't count toward severity or risk score.

| Action | Parameters | Use when |
|---|---|---|
| `trust_list` | — | Show all trust entries |
| `trust_show` | `path` | Check trust status of a component |
| `trust_accept` | `path`, `rules` (comma-separated IDs), optional `notes` | Accept specific known-safe rule matches |
| `trust_full` | `path`, optional `notes` | Trust everything in a component |
| `trust_revoke` | `name` (component name or trust key) | Remove trust |
| `trust_quarantine` | `path` | Mark component as quarantined |

Example — accept specific rules after review:
```json
{ "action": "trust_accept", "path": "/path/to/skill", "rules": "EXEC-001,REMOTE-002", "notes": "Reviewed: legitimate API calls" }
```

## Verdicts

| Verdict | Meaning | Recommendation |
|---|---|---|
| `clean` | No issues found | Safe to install |
| `warnings` | Low/medium issues | Review findings, usually OK |
| `high_risk` | High severity issues | Warn user, review carefully |
| `dangerous` | Critical issues | Do NOT recommend installing |

## Slash commands

These run instantly without LLM involvement:

| Command | Purpose |
|---|---|
| `/scan [path]` | Quick security scan (defaults to extensions dir) |
| `/vet <source>` | Vet a plugin/skill by URL or path |
| `/check <text>` | Check text for prompt injection patterns |
| `/trust [subcommand]` | Manage trust store (list/show/accept/full/revoke/quarantine) |

## Background behavior

When `scanMessages` is enabled (default), the plugin:
1. Scans every inbound message for prompt injection patterns
2. If injection detected, stores a security alert
3. On next agent start, injects a heightened security warning into agent context
4. If no alerts, injects a baseline security policy reminder

This is automatic — no tool call needed.

## Context-aware scanning

All 160+ rules are annotated with scan contexts. When scanning messages, code-only rules are automatically excluded (86% noise reduction). The plugin uses `--context message` for inbound message scanning.

Available contexts: `code`, `config`, `message`, `skill`, `plugin`.

## Important

- **Always use install** (not raw `openclaw plugins install`) so extensions are vetted first
- If install is blocked, explain the specific threats found
- Never override severity gates without user consent
- Third-party extensions are higher risk than official ones
- Trust decisions are auditable — prefer `trust_accept` with specific rules over `trust_full`
