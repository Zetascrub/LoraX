#!/usr/bin/env bash
# Build LORAX binaries for all supported Linux targets using Docker buildx.
# Requires: docker buildx with QEMU binfmt support
#   docker run --privileged --rm tonistiigi/binfmt --install all
#
# Usage: ./build.sh

set -e

mkdir -p dist

PLATFORMS=(
    "linux/amd64   lorax-linux-x86_64"
    "linux/arm64   lorax-linux-arm64"
    "linux/arm/v7  lorax-linux-armv7"
)

for entry in "${PLATFORMS[@]}"; do
    PLATFORM=$(echo "$entry" | awk '{print $1}')
    OUTPUT=$(echo "$entry" | awk '{print $2}')

    echo "[*] Building ${OUTPUT} (${PLATFORM})..."
    docker build \
        --platform "$PLATFORM" \
        -f Dockerfile.build \
        -t "lorax-builder-${OUTPUT}" \
        --load \
        . 2>&1 | grep -E "^\[|error|Error" || true

    docker run --rm \
        -v "$(pwd)/dist:/out" \
        "lorax-builder-${OUTPUT}" \
        cp /build/dist/lorax "/out/${OUTPUT}"

    echo "[+] ${OUTPUT} → dist/${OUTPUT} ($(du -sh "dist/${OUTPUT}" | cut -f1))"
done

echo ""
echo "[+] All builds complete:"
ls -lh dist/lorax-linux-*
