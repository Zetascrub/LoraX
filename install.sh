#!/usr/bin/env bash
# LORAX installer — fetches the binary from the latest GitHub release
# Usage (public repo):   curl -s https://raw.githubusercontent.com/<USER>/LoraX/main/install.sh | bash
# Usage (private repo):  curl -H "Authorization: token <TOKEN>" -s https://raw.githubusercontent.com/<USER>/LoraX/main/install.sh | bash

set -e

REPO="<USERNAME>/LoraX"
BINARY="lorax"
RELEASE_URL="https://api.github.com/repos/${REPO}/releases/latest"

# Resolve download URL from latest release
if [ -n "$GITHUB_TOKEN" ]; then
    AUTH_HEADER="-H \"Authorization: token ${GITHUB_TOKEN}\""
fi

DOWNLOAD_URL=$(curl -s ${AUTH_HEADER} "${RELEASE_URL}" \
    | grep "browser_download_url" \
    | grep "${BINARY}" \
    | cut -d '"' -f 4)

if [ -z "$DOWNLOAD_URL" ]; then
    echo "[-] Could not resolve release URL. Set GITHUB_TOKEN for private repos." >&2
    exit 1
fi

# Write to home dir if /tmp is noexec, otherwise /tmp
if mount | grep -q "on /tmp.*noexec"; then
    DEST="${HOME}/.${BINARY}"
else
    DEST="/tmp/${BINARY}"
fi

curl -s ${AUTH_HEADER} -L "$DOWNLOAD_URL" -o "$DEST"
chmod +x "$DEST"
echo "[+] LORAX installed to ${DEST}"
echo "[+] Run: ${DEST} --mode scan"
