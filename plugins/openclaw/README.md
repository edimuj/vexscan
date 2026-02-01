# Vetryx Plugin for OpenClaw

Security scanner plugin that protects your OpenClaw environment from malicious extensions and skills.

## Features

- **Automatic Scanning**: Scans third-party extensions on startup
- **Pre-Install Vetting**: Vet extensions before installing with `openclaw vetryx vet`
- **AI-Integrated**: The AI assistant can scan code on your behalf
- **Smart Filtering**: Skips official extensions, focuses on untrusted code

## Installation

### Install the Plugin

```bash
# From npm (when published)
openclaw plugins install @vetryx/openclaw-plugin

# From local path
openclaw plugins install ./plugins/openclaw

# Development (symlink)
openclaw plugins install -l ./plugins/openclaw
```

### CLI Installation (Optional)

The plugin will **auto-install** the Vetryx CLI on first run. For manual installation:

```bash
# Quick install (macOS/Linux)
curl -fsSL https://raw.githubusercontent.com/edimuj/vetryx/main/install.sh | bash

# Or from source
git clone https://github.com/edimuj/vetryx && cd vetryx && cargo install --path .
```

## Usage

### CLI Commands

```bash
# Scan installed extensions
openclaw vetryx scan

# Scan specific path
openclaw vetryx scan ~/.openclaw/extensions

# Vet before installing
openclaw vetryx vet https://github.com/user/cool-extension

# List detection rules
openclaw vetryx rules
```

### AI Tool Usage

The AI assistant can use Vetryx directly:

```
User: "Is this extension safe? https://github.com/user/extension"
AI: *uses vetryx tool to vet the extension*
```

```
User: "Check my extensions for security issues"
AI: *uses vetryx tool to scan ~/.openclaw/extensions*
```

## Configuration

Configure in your OpenClaw settings:

```yaml
plugins:
  vetryx:
    enabled: true
    scanOnInstall: true
    minSeverity: medium
    thirdPartyOnly: true
    # cliPath: /custom/path/to/vetryx  # Optional
```

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | `true` | Enable security scanning |
| `scanOnInstall` | `true` | Scan on startup |
| `minSeverity` | `medium` | Minimum severity to report |
| `thirdPartyOnly` | `true` | Only scan non-official extensions |
| `cliPath` | (auto) | Path to vetryx binary |

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
