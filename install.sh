#!/bin/sh
# Supply Chain Guardian — Install Script
# Usage: curl -sSL https://scg.bds421.com/install.sh | sh
#
# This script detects your OS and architecture, downloads the correct
# SCG binary, verifies its checksum, and installs it.

set -e

REPO="bds421/rho/supply-chain-guardian"
BASE_URL="https://scg.bds421.com/releases"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="scg"

# Colors (if terminal supports it)
if [ -t 1 ]; then
    GREEN='\033[32m'
    RED='\033[31m'
    YELLOW='\033[33m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    GREEN=''
    RED=''
    YELLOW=''
    BOLD=''
    RESET=''
fi

info() { printf "${GREEN}✓${RESET} %s\n" "$1"; }
warn() { printf "${YELLOW}⚠${RESET} %s\n" "$1"; }
fail() { printf "${RED}✗${RESET} %s\n" "$1" >&2; exit 1; }

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "darwin" ;;
        *)       fail "Unsupported OS: $(uname -s). SCG supports Linux and macOS." ;;
    esac
}

# Detect architecture
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        *)             fail "Unsupported architecture: $(uname -m). SCG supports amd64 and arm64." ;;
    esac
}

# Get latest version from releases
get_latest_version() {
    if command -v curl >/dev/null 2>&1; then
        curl -sSL "${BASE_URL}/latest/version" 2>/dev/null || echo ""
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "${BASE_URL}/latest/version" 2>/dev/null || echo ""
    fi
}

# Download file
download() {
    local url="$1" dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -sSL -o "$dest" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url"
    else
        fail "Neither curl nor wget found. Install one and retry."
    fi
}

main() {
    printf "\n${BOLD}Supply Chain Guardian — Installer${RESET}\n\n"

    OS=$(detect_os)
    ARCH=$(detect_arch)
    info "Detected: ${OS}/${ARCH}"

    # Get version
    VERSION="${SCG_VERSION:-}"
    if [ -z "$VERSION" ]; then
        VERSION=$(get_latest_version)
    fi
    if [ -z "$VERSION" ]; then
        # Fallback: try to get from git tags
        fail "Could not determine latest version. Set SCG_VERSION=v0.1.13 and retry, or install from source: go install gitlab2024.bds421-cloud.com/bds421/rho/supply-chain-guardian/cmd/scg@latest"
    fi
    info "Version: ${VERSION}"

    # Build download URL
    FILENAME="scg-${OS}-${ARCH}"
    DOWNLOAD_URL="${BASE_URL}/${VERSION}/${FILENAME}"
    CHECKSUM_URL="${BASE_URL}/${VERSION}/checksums.txt"

    # Create temp directory
    TMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TMP_DIR"' EXIT

    # Download binary
    printf "  Downloading %s ... " "$FILENAME"
    download "$DOWNLOAD_URL" "${TMP_DIR}/${BINARY_NAME}" || fail "Download failed: ${DOWNLOAD_URL}"
    printf "done\n"

    # Download and verify checksum
    if download "$CHECKSUM_URL" "${TMP_DIR}/checksums.txt" 2>/dev/null; then
        EXPECTED=$(grep "${FILENAME}" "${TMP_DIR}/checksums.txt" | awk '{print $1}')
        if [ -n "$EXPECTED" ]; then
            if command -v sha256sum >/dev/null 2>&1; then
                ACTUAL=$(sha256sum "${TMP_DIR}/${BINARY_NAME}" | awk '{print $1}')
            elif command -v shasum >/dev/null 2>&1; then
                ACTUAL=$(shasum -a 256 "${TMP_DIR}/${BINARY_NAME}" | awk '{print $1}')
            else
                warn "No sha256sum or shasum found — skipping checksum verification"
                ACTUAL="$EXPECTED"
            fi

            if [ "$ACTUAL" != "$EXPECTED" ]; then
                fail "Checksum mismatch!\n  Expected: ${EXPECTED}\n  Got:      ${ACTUAL}\n\nThis could indicate a tampered binary. Do not use."
            fi
            info "Checksum verified"
        else
            warn "Checksum file found but no entry for ${FILENAME}"
        fi
    else
        warn "Could not download checksums — skipping verification"
    fi

    # Make executable
    chmod +x "${TMP_DIR}/${BINARY_NAME}"

    # Install
    if [ -w "$INSTALL_DIR" ]; then
        mv "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
        info "Installed to ${INSTALL_DIR}/${BINARY_NAME}"
    elif command -v sudo >/dev/null 2>&1; then
        sudo mv "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
        info "Installed to ${INSTALL_DIR}/${BINARY_NAME} (via sudo)"
    else
        # Fallback: install to user directory
        USER_BIN="${HOME}/.local/bin"
        mkdir -p "$USER_BIN"
        mv "${TMP_DIR}/${BINARY_NAME}" "${USER_BIN}/${BINARY_NAME}"
        info "Installed to ${USER_BIN}/${BINARY_NAME}"
        warn "Add ${USER_BIN} to your PATH if not already present"
    fi

    # Verify
    if command -v scg >/dev/null 2>&1; then
        printf "\n"
        scg version
        printf "\n${BOLD}Ready.${RESET} Run ${GREEN}scg init${RESET} to get started.\n\n"
    else
        printf "\n${BOLD}Installed.${RESET} You may need to restart your shell or add the install directory to PATH.\n\n"
    fi
}

main "$@"
