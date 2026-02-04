<p align="center">
  <img src="https://raw.githubusercontent.com/edimuj/vexscan/main/assets/sir-clawsalot-256.png" alt="Sir Clawsalot" width="180">
</p>

<h1 align="center">Vexscan Plugin for OpenClaw</h1>

<p align="center">
  <strong>Security scanner plugin that protects your OpenClaw environment from malicious extensions and skills.</strong>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@exelerus/vexscan-openclaw"><img src="https://img.shields.io/npm/v/@exelerus/vexscan-openclaw?style=flat-square&color=blue" alt="npm"></a>
  <a href="../../LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-green?style=flat-square" alt="License"></a>
</p>

## Features

- **Automatic Scanning**: Scans third-party extensions on startup
- **Pre-Install Vetting**: Vet extensions before installing with `openclaw vexscan vet`
- **AI-Integrated**: The AI assistant can scan code on your behalf
- **Smart Filtering**: Skips official extensions, focuses on untrusted code

## Installation

### Install the Plugin

```bash
# From npm
openclaw plugins install @exelerus/vexscan-openclaw

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

# Scan specific path
openclaw vexscan scan ~/.openclaw/extensions

# Vet before installing
openclaw vexscan vet https://github.com/user/cool-extension

# List detection rules
openclaw vexscan rules
```

### AI Tool Usage

The AI assistant can use Vexscan directly:

```
User: "Is this extension safe? https://github.com/user/extension"
AI: *uses vexscan tool to vet the extension*
```

```
User: "Check my extensions for security issues"
AI: *uses vexscan tool to scan ~/.openclaw/extensions*
```

## Configuration

Configure in your OpenClaw settings:

```yaml
plugins:
  vexscan:
    enabled: true
    scanOnInstall: true
    minSeverity: medium
    thirdPartyOnly: true
    skipDeps: true
    # cliPath: /custom/path/to/vexscan  # Optional
```

| Option           | Default  | Description                                 |
|------------------|----------|---------------------------------------------|
| `enabled`        | `true`   | Enable security scanning                    |
| `scanOnInstall`  | `true`   | Scan on startup                             |
| `minSeverity`    | `medium` | Minimum severity to report                  |
| `thirdPartyOnly` | `true`   | Only scan non-official extensions           |
| `skipDeps`       | `true`   | Skip node_modules to reduce false positives |
| `cliPath`        | (auto)   | Path to vexscan binary                      |

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
