#!/usr/bin/env bash
# LORAX installer
# curl -s https://raw.githubusercontent.com/<USERNAME>/LoraX/main/install.sh | bash

set -e

REPO="<USERNAME>/LoraX"
BINARY="lorax"

DOWNLOAD_URL=$(curl -s "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep "browser_download_url" \
    | grep "${BINARY}" \
    | cut -d '"' -f 4)

if [ -z "$DOWNLOAD_URL" ]; then
    echo "[-] Could not resolve release URL" >&2
    exit 1
fi

# Use home dir if /tmp is mounted noexec
if mount | grep -q "on /tmp.*noexec"; then
    DEST="${HOME}/.${BINARY}"
else
    DEST="/tmp/${BINARY}"
fi

curl -sL "$DOWNLOAD_URL" -o "$DEST" && chmod +x "$DEST"
echo "[+] Ready: ${DEST}"
