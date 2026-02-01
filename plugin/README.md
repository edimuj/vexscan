# Vetryx Plugin for Claude Code

Security scanner plugin that automatically protects your Claude Code environment.

## Features

- **Automatic Scanning**: Scans third-party plugins on every session start
- **On-Demand Scanning**: `/vetryx:scan` command for manual scans
- **Pre-Install Vetting**: `/vetryx:vet` to check plugins before installing
- **Smart Filtering**: Skips official Anthropic plugins, focuses on untrusted code

## Installation

### Prerequisites

Install the Vetryx CLI first:

```bash
# From source
git clone https://github.com/edimuj/vetryx
cd vetryx
cargo install --path .

# Or download pre-built binary (coming soon)
```

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

## Usage

### Automatic Protection

Once installed, Vetryx automatically scans your plugins when you start a Claude Code session. If issues are found, you'll see a security alert.

### Manual Commands

```
/vetryx:scan                    # Scan all plugins
/vetryx:scan ~/.claude/plugins  # Scan specific path
/vetryx:vet https://github.com/user/plugin  # Vet before install
```

## What It Detects

| Category | Examples |
|----------|----------|
| Code Execution | `eval()`, `new Function()`, `exec()` |
| Shell Injection | `child_process`, `subprocess` |
| Data Exfiltration | Discord webhooks, external POST |
| Credential Access | SSH keys, AWS credentials |
| Prompt Injection | Instruction override attempts |
| Obfuscation | Base64, hex encoding |

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
