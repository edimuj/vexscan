#!/bin/bash
# Vexscan CLI Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/edimuj/vexscan/main/install.sh | bash

set -e

REPO="edimuj/vexscan"
INSTALL_DIR="${VEXSCAN_INSTALL_DIR:-$HOME/.local/bin}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() { echo -e "${BLUE}[info]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

# Detect OS and architecture
detect_platform() {
    local os arch

    case "$(uname -s)" in
        Darwin) os="macos" ;;
        Linux) os="linux" ;;
        MINGW*|MSYS*|CYGWIN*) os="windows" ;;
        *) error "Unsupported operating system: $(uname -s)" ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64) arch="x86_64" ;;
        aarch64|arm64) arch="aarch64" ;;
        *) error "Unsupported architecture: $(uname -m)" ;;
    esac

    # Adjust for available binaries
    if [ "$os" = "linux" ] && [ "$arch" = "aarch64" ]; then
        error "Linux ARM64 binaries not yet available. Please build from source."
    fi

    if [ "$os" = "windows" ]; then
        echo "vexscan-windows-x86_64.exe"
    else
        echo "vexscan-${os}-${arch}"
    fi
}

# Get latest release version
get_latest_version() {
    curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | \
        grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
}

# Download and install
install() {
    local asset_name version download_url

    info "Detecting platform..."
    asset_name=$(detect_platform)
    success "Platform: $asset_name"

    info "Fetching latest version..."
    version=$(get_latest_version)
    if [ -z "$version" ]; then
        error "Could not determine latest version. No releases found."
    fi
    success "Version: $version"

    download_url="https://github.com/${REPO}/releases/download/${version}/${asset_name}"

    info "Downloading from $download_url..."

    # Create install directory if needed
    mkdir -p "$INSTALL_DIR"

    # Download
    if command -v curl &> /dev/null; then
        curl -fsSL "$download_url" -o "${INSTALL_DIR}/vexscan"
    elif command -v wget &> /dev/null; then
        wget -q "$download_url" -O "${INSTALL_DIR}/vexscan"
    else
        error "Neither curl nor wget found. Please install one of them."
    fi

    # Make executable
    chmod +x "${INSTALL_DIR}/vexscan"

    success "Installed to ${INSTALL_DIR}/vexscan"

    # Check if in PATH
    if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
        warn "Add ${INSTALL_DIR} to your PATH:"
        echo ""
        echo "  export PATH=\"\$PATH:${INSTALL_DIR}\""
        echo ""
        echo "Add this line to your ~/.bashrc, ~/.zshrc, or shell config."
    fi

    # Verify installation
    if [ -x "${INSTALL_DIR}/vexscan" ]; then
        success "Installation complete!"
        echo ""
        "${INSTALL_DIR}/vexscan" --version 2>/dev/null || true
    else
        error "Installation failed"
    fi
}

# Check if already installed
check_existing() {
    if command -v vexscan &> /dev/null; then
        local current_version
        current_version=$(vexscan --version 2>/dev/null | head -1 || echo "unknown")
        warn "Vexscan is already installed: $current_version"
        read -p "Do you want to reinstall/update? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            info "Skipping installation."
            exit 0
        fi
    fi
}

main() {
    echo ""
    echo "  ╦  ╦┌─┐┌┬┐┬─┐┬ ┬─┐ ┬"
    echo "  ╚╗╔╝├┤  │ ├┬┘└┬┘┌┴┬┘"
    echo "   ╚╝ └─┘ ┴ ┴└─ ┴ ┴ └─"
    echo "  Security Scanner for AI Agents"
    echo ""

    check_existing
    install
}

main "$@"
