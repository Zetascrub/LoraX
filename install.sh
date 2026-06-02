#!/usr/bin/env bash
# LORAX installer — auto-detects OS and architecture
# curl -s https://raw.githubusercontent.com/Zetascrub/LoraX/main/install.sh | bash

set -e

REPO="Zetascrub/LoraX"

# Detect OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
    linux)  OS="linux"  ;;
    darwin) OS="darwin" ;;
    *)
        echo "[-] Unsupported OS: $OS" >&2
        exit 1
        ;;
esac

# Detect and normalise architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)         ARCH="x86_64" ;;
    aarch64|arm64)  ARCH="arm64"  ;;
    armv7l|armv7)   ARCH="armv7"  ;;
    *)
        echo "[-] Unsupported architecture: $ARCH" >&2
        exit 1
        ;;
esac

BINARY="lorax-${OS}-${ARCH}"
echo "[*] Detected: ${OS}/${ARCH} — looking for ${BINARY}"

# Resolve download URL from latest release
DOWNLOAD_URL=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep "browser_download_url" \
    | grep "${BINARY}" \
    | cut -d '"' -f 4 \
    || true)

if [ -z "$DOWNLOAD_URL" ]; then
    echo "[-] No release found for ${BINARY}" >&2
    echo "[-] Available builds: https://github.com/${REPO}/releases" >&2
    exit 1
fi

# Use home dir if /tmp is mounted noexec
if mount | grep -q "on /tmp.*noexec"; then
    DEST="${HOME}/.lorax"
else
    DEST="/tmp/lorax"
fi

curl -sL "$DOWNLOAD_URL" -o "$DEST" && chmod +x "$DEST"
echo "[+] Ready: ${DEST} — run: ${DEST} --mode scan"
