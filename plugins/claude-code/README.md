# Vetryx Plugin for Claude Code

Security scanner plugin that automatically protects your Claude Code environment.

## Features

- **Automatic Scanning**: Scans third-party plugins on every session start
- **On-Demand Scanning**: `/vetryx:scan` command for manual scans
- **Pre-Install Vetting**: `/vetryx:vet` to check plugins before installing
- **Smart Filtering**: Skips official Anthropic plugins, focuses on untrusted code
- **AI-Powered Analysis**: Uses your Claude subscription to analyze findings — no extra API keys needed

## Installation

### Install the Plugin

```bash
# In Claude Code, run:
/plugin install vetryx
```

Or add the marketplace:

```bash
/plugin marketplace add edimuj/vetryx
/plugin install vetryx@edimuj-vetryx
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

### Automatic Protection

Once installed, Vetryx automatically scans your plugins when you start a Claude Code session. If issues are found,
you'll see a security alert.

### Manual Commands

```
/vetryx:scan                    # Scan all plugins
/vetryx:scan ~/.claude/plugins  # Scan specific path
/vetryx:vet https://github.com/user/plugin  # Vet before install
```

## How It Works

1. **CLI Scan**: The Vetryx CLI runs static analysis and produces findings
2. **AI Analysis**: A Claude subagent analyzes each finding to determine if it's a real threat or false positive
3. **Smart Summary**: You get a concise report with only actionable findings

The AI analysis uses your existing Claude subscription — no separate API keys or costs. This gives you the power of AI-assisted security analysis for free.

## What It Detects

| Category          | Examples                             |
|-------------------|--------------------------------------|
| Code Execution    | `eval()`, `new Function()`, `exec()` |
| Shell Injection   | `child_process`, `subprocess`        |
| Data Exfiltration | Discord webhooks, external POST      |
| Credential Access | SSH keys, AWS credentials            |
| Prompt Injection  | Instruction override attempts        |
| Obfuscation       | Base64, hex encoding                 |

## Configuration

The plugin uses Vetryx's default configuration. To customize, create `~/.vetryx.toml`:

```toml
# Trust additional packages
trusted_packages = ["my-trusted-plugin"]

# Adjust sensitivity
entropy_threshold = 5.5
```

## License

Apache 2.0
