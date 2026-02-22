<p align="center">
  <img src="https://raw.githubusercontent.com/edimuj/vexscan/main/assets/sir-clawsalot-256.png" alt="Sir Clawsalot" width="180">
</p>

<h1 align="center">Vexscan Plugin for OpenClaw</h1>

<p align="center">
  <strong>Security scanner plugin that protects your OpenClaw environment from malicious extensions and skills.</strong>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@exelerus/openclaw-vexscan"><img src="https://img.shields.io/npm/v/@exelerus/openclaw-vexscan?style=flat-square&color=blue" alt="npm"></a>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-green?style=flat-square" alt="License"></a>
</p>

## Features

- **Automatic Scanning**: Scans third-party extensions on startup
- **Pre-Install Vetting**: Vet extensions before installing with `openclaw vexscan vet`
- **Message Scanning**: Scans inbound messages for prompt injection in real-time
- **Trust Store**: Suppress reviewed findings with auditable trust decisions
- **Context-Aware Rules**: 160+ rules annotated with scan contexts to reduce false positives
- **Baseline/Diff**: Save scan baselines and see only new findings on re-scans
- **AI-Integrated**: The AI assistant can scan code on your behalf
- **Slash Commands**: `/scan`, `/vet`, `/check`, `/trust` for instant operations

## Installation

### Install the Plugin

```bash
# From npm
openclaw plugins install @exelerus/openclaw-vexscan

# From local path
openclaw plugins install ./plugins/openclaw

# Development (symlink)
openclaw plugins install -l ./plugins/openclaw
```

### CLI Installation (Optional)

The plugin will **auto-install** the Vexscan CLI on first run. For manual installation:

```bash
# Quick install (macOS/Linux)
curl -fsSL https://raw.githubusercontent.com/edimuj/vexscan/main/install.sh | bash

# Or from source
git clone https://github.com/edimuj/vexscan && cd vexscan && cargo install --path .
```

## Usage

### CLI Commands

```bash
# Scan installed extensions
openclaw vexscan scan

# Vet before installing
openclaw vexscan vet https://github.com/user/cool-extension

# Vet and install in one step (blocked if critical/high findings)
openclaw vexscan install https://github.com/user/cool-extension

# Install with overrides
openclaw vexscan install ./local-extension --link       # symlink for dev
openclaw vexscan install @org/extension --force         # allow medium findings
openclaw vexscan install @org/extension --dry-run       # vet only, don't install

# Trust store
openclaw vexscan trust list
openclaw vexscan trust show /path/to/extension
openclaw vexscan trust accept /path/to/ext --rules EXEC-001,REMOTE-002
openclaw vexscan trust revoke my-extension

# List detection rules
openclaw vexscan rules
```

### Slash Commands

```bash
/scan                    # Quick scan of extensions directory
/scan /path/to/dir       # Scan specific path
/vet https://github.com/user/ext   # Vet a plugin
/check "some suspicious text"      # Check text for injection patterns
/trust                   # List trust entries
/trust show /path        # Show trust status
```

### AI Tool Actions

The AI assistant can use Vexscan directly through tool calls:

- `scan` — Scan a path for security issues
- `vet` — Vet an extension before installing
- `install` — Vet and install in one step
- `trust_list` / `trust_show` / `trust_accept` / `trust_full` / `trust_revoke` / `trust_quarantine` — Manage trust store
- `status` — Check plugin status and config

## Configuration

Configure in your `openclaw.json`:

```json
{
  "plugins": {
    "vexscan": {
      "enabled": true,
      "scanOnInstall": true,
      "minSeverity": "medium",
      "thirdPartyOnly": true,
      "skipDeps": true
    }
  }
}
```

| Option           | Default  | Description                                        |
|------------------|----------|----------------------------------------------------|
| `enabled`        | `true`   | Enable security scanning                           |
| `scanOnInstall`  | `true`   | Scan on startup                                    |
| `scanMessages`   | `true`   | Scan inbound messages for prompt injection         |
| `minSeverity`    | `medium` | Minimum severity to report                         |
| `thirdPartyOnly` | `true`   | Only scan non-official extensions                  |
| `skipDeps`       | `true`   | Skip node_modules to reduce false positives        |
| `ast`            | `true`   | AST analysis for obfuscation detection             |
| `deps`           | `true`   | Dependency scanning for supply chain attacks       |
| `cliPath`        | (auto)   | Path to vexscan binary                             |

## What It Detects

| Category             | Examples                                        |
|----------------------|-------------------------------------------------|
| Code Execution       | `eval()`, `new Function()`, `exec()`, SQL injection |
| Shell Injection      | `child_process`, `subprocess`, reverse shells   |
| Data Exfiltration    | Discord webhooks, external POST                 |
| Credential Access    | SSH keys, AWS credentials                       |
| Hardcoded Secrets    | API keys, tokens, passwords, connection strings |
| Prompt Injection     | Instruction override, system prompt reveal      |
| Obfuscation          | Base64, hex encoding                            |
| Backdoor Detection   | Time bombs, C2 callbacks                        |
| Dangerous Operations | `rm -rf`, `chmod 777`, `sudo`                   |
| Resource Abuse       | Fork bombs, infinite loops                      |

## Development

```bash
cd plugins/openclaw
npm install
npm run build
```

## License

Apache 2.0
