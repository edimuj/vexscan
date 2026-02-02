# Vexscan Plugin for OpenClaw

Security scanner plugin that protects your OpenClaw environment from malicious extensions and skills.

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
    # cliPath: /custom/path/to/vexscan  # Optional
```

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `true` | Enable security scanning |
| `scanOnInstall` | `true` | Scan on startup |
| `minSeverity` | `medium` | Minimum severity to report |
| `thirdPartyOnly` | `true` | Only scan non-official extensions |
| `cliPath` | (auto) | Path to vexscan binary |

## What It Detects

| Category | Examples |
|----------|----------|
| Code Execution | `eval()`, `new Function()`, `exec()` |
| Shell Injection | `child_process`, `subprocess` |
| Data Exfiltration | Discord webhooks, external POST |
| Credential Access | SSH keys, AWS credentials |
| Prompt Injection | Instruction override attempts |
| Obfuscation | Base64, hex encoding |

## Development

```bash
cd plugins/openclaw
npm install
npm run build
```

## License

Apache 2.0
