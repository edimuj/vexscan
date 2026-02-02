#!/bin/bash
# Vexscan Session Start Security Scan
# Runs automatically when Claude Code session starts

set -e

# Read hook input (JSON from stdin)
HOOK_INPUT=$(cat)

# Paths to scan
CLAUDE_DIR="$HOME/.claude"
INSTALL_DIR="$HOME/.local/bin"

# Find vexscan binary
find_vexscan() {
    # Check PATH first
    if command -v vexscan &> /dev/null; then
        echo "vexscan"
        return 0
    fi

    # Check common install locations
    local locations=(
        "$INSTALL_DIR/vexscan"
        "$HOME/.cargo/bin/vexscan"
        "/usr/local/bin/vexscan"
        "/opt/homebrew/bin/vexscan"
    )

    for loc in "${locations[@]}"; do
        if [ -x "$loc" ]; then
            echo "$loc"
            return 0
        fi
    done

    return 1
}

# Auto-install vexscan if not found
auto_install() {
    local repo="edimuj/vexscan"
    local os arch asset_name version download_url

    # Detect platform
    case "$(uname -s)" in
        Darwin) os="macos" ;;
        Linux) os="linux" ;;
        *) return 1 ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64) arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *) return 1 ;;
    esac

    asset_name="vexscan-${os}-${arch}"

    # Get latest version
    version=$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null | \
        grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || echo "")

    if [ -z "$version" ]; then
        return 1
    fi

    download_url="https://github.com/${repo}/releases/download/${version}/${asset_name}"

    # Download and install
    mkdir -p "$INSTALL_DIR"
    if curl -fsSL "$download_url" -o "${INSTALL_DIR}/vexscan" 2>/dev/null; then
        chmod +x "${INSTALL_DIR}/vexscan"
        echo "${INSTALL_DIR}/vexscan"
        return 0
    fi

    return 1
}

# Try to find or install vexscan
VEXSCAN=$(find_vexscan)

if [ -z "$VEXSCAN" ]; then
    # Try auto-install
    VEXSCAN=$(auto_install 2>/dev/null || echo "")

    if [ -z "$VEXSCAN" ]; then
        # Give helpful install message
        echo '{"userMessage": "[Vexscan] CLI not found. Install with: curl -fsSL https://raw.githubusercontent.com/edimuj/vexscan/main/install.sh | bash", "systemMessage": "[Vexscan] CLI not found. Install with: curl -fsSL https://raw.githubusercontent.com/edimuj/vexscan/main/install.sh | bash"}'
        exit 0
    fi
fi

# Run scan on Claude directory (plugins, skills, hooks, configs)
# Uses --third-party-only to skip official Anthropic components
# Uses --skip-deps to avoid false positives from node_modules
SCAN_OUTPUT=$($VEXSCAN scan "$CLAUDE_DIR" --platform claude-code --third-party-only --skip-deps --min-severity medium -f json 2>/dev/null || true)

# Parse results
TOTAL_FINDINGS=$(echo "$SCAN_OUTPUT" | jq -r '.results | map(.findings | length) | add // 0' 2>/dev/null || echo "0")
MAX_SEVERITY=$(echo "$SCAN_OUTPUT" | jq -r '.results | map(.findings[].severity) | unique | if any(. == "critical") then "critical" elif any(. == "high") then "high" elif any(. == "medium") then "medium" else "none" end' 2>/dev/null || echo "none")

# Only report if issues found
if [ "$TOTAL_FINDINGS" != "0" ] && [ "$TOTAL_FINDINGS" != "null" ]; then
    # Build summary
    CRITICAL=$(echo "$SCAN_OUTPUT" | jq '[.results[].findings[] | select(.severity == "critical")] | length' 2>/dev/null || echo "0")
    HIGH=$(echo "$SCAN_OUTPUT" | jq '[.results[].findings[] | select(.severity == "high")] | length' 2>/dev/null || echo "0")
    MEDIUM=$(echo "$SCAN_OUTPUT" | jq '[.results[].findings[] | select(.severity == "medium")] | length' 2>/dev/null || echo "0")

    # Format message based on severity
    if [ "$MAX_SEVERITY" = "critical" ]; then
        MESSAGE="[Vexscan] SECURITY ALERT: Found $CRITICAL critical, $HIGH high, $MEDIUM medium issue(s) in plugins/skills. Run /vexscan:scan for AI-powered analysis."
    elif [ "$MAX_SEVERITY" = "high" ]; then
        MESSAGE="[Vexscan] Security Warning: Found $HIGH high, $MEDIUM medium issue(s) in plugins/skills. Run /vexscan:scan to review."
    else
        MESSAGE="[Vexscan] Security Notice: Found $MEDIUM medium issue(s) in plugins/skills. Run /vexscan:scan for details."
    fi

    # Output for Claude Code - both user and system messages
    echo "{\"userMessage\": \"$MESSAGE\", \"systemMessage\": \"$MESSAGE\"}"
fi

exit 0
