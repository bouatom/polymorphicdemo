#!/usr/bin/env bash
# build.sh — Cross-compile polymorphic-demo.exe from macOS/Linux → Windows x64
#
# Prerequisites:
#   brew install go     (or install from https://go.dev/dl/)
#   go version should be 1.21+
#
# Usage:
#   chmod +x build.sh && ./build.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GO_SRC="$SCRIPT_DIR/go"
OUTPUT="$SCRIPT_DIR/polymorphic-demo.exe"

echo ""
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║  Polymorphic Demo — Windows x64 Build                    ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo ""

# Check Go is installed
if ! command -v go &>/dev/null; then
    echo "[ERROR] Go is not installed."
    echo "        Install: brew install go  OR  https://go.dev/dl/"
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}')
echo "[*] Go version : $GO_VERSION"
echo "[*] Source     : $GO_SRC"
echo "[*] Output     : $OUTPUT"
echo ""

cd "$GO_SRC"

echo "[*] Downloading dependencies..."
go mod tidy

echo "[*] Cross-compiling for Windows x64..."
GOOS=windows GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -o "$OUTPUT" \
    .

echo ""
echo "[+] Build complete: $OUTPUT"
echo ""
echo "Next steps:"
echo "  1. Copy polymorphic-demo.exe to the Windows test machine"
echo "  2. Ensure Trend Micro agent is enrolled and reporting to Vision One"
echo "  3. Run as Administrator for full injection module support:"
echo "       polymorphic-demo.exe"
echo ""
echo "  Options:"
echo "       polymorphic-demo.exe -no-inject          # skip injection (non-admin)"
echo "       polymorphic-demo.exe -interval 15        # faster beacon (15s)"
echo "       polymorphic-demo.exe -c2 192.168.1.100   # custom C2 target"
echo "       polymorphic-demo.exe -cleanup            # remove all artifacts"
echo ""
echo "  PowerShell version (also available):"
echo "       powershell.exe -ExecutionPolicy Bypass -File polymorphic-demo.ps1"
echo ""
