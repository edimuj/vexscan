# Vexscan Plugin for Claude Code

Security scanner plugin that automatically protects your Claude Code environment.

## Features

- **Automatic Scanning**: Scans third-party plugins on every session start
- **On-Demand Scanning**: `/vexscan:scan` command for manual scans
- **Pre-Install Vetting**: `/vexscan:vet` to check plugins before installing
- **Smart Filtering**: Skips official Anthropic plugins, focuses on untrusted code
- **AI-Powered Analysis**: Uses your Claude subscription to analyze findings — no extra API keys needed

## Installation

### Install the Plugin

```bash
# In Claude Code, run:
/plugin marketplace add edimuj/vexscan
/plugin install vexscan@edimuj-vexscan
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

### Automatic Protection

Once installed, Vexscan automatically scans your plugins when you start a Claude Code session. If issues are found,
you'll see a security alert.

### Manual Commands

```
/vexscan:scan                    # Scan all plugins
/vexscan:scan ~/.claude/plugins  # Scan specific path
/vexscan:vet https://github.com/user/plugin  # Vet before install
```

## How It Works

1. **CLI Scan**: The Vexscan CLI runs static analysis and produces findings
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

The plugin uses Vexscan's default configuration. To customize, create `~/.vexscan.toml`:

```toml
# Trust additional packages
trusted_packages = ["my-trusted-plugin"]

# Adjust sensitivity
entropy_threshold = 5.5
```

## License

Apache 2.0
