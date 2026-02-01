# Vetryx Plugins

Platform-specific plugins for Vetryx security scanner integration.

## Available Plugins

| Plugin | Platform | Status |
|--------|----------|--------|
| [claude-code](./claude-code/) | Claude Code | Ready |
| [openclaw](./openclaw/) | OpenClaw | Ready |
| codex | OpenAI Codex | Planned |
| cursor | Cursor IDE | Planned |

## Plugin Architecture

Each plugin provides:
- **Automatic scanning** on session start
- **On-demand commands** for manual scans
- **Pre-install vetting** to check before installing extensions

All plugins use the same Vetryx CLI backend.

## Installation

See individual plugin directories for installation instructions.
