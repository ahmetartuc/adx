#!/usr/bin/env bash
# Build adX release binaries for every supported OS/arch. Static, no cgo.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-dev}"
OUT="dist"
rm -rf "$OUT" && mkdir -p "$OUT"

# Both the GUI (adx) and the collector (adx-collector) build for every target.
TARGETS="darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64 windows/386"

export CGO_ENABLED=0
for target in $TARGETS; do
  os="${target%/*}"; arch="${target#*/}"
  ext=""; [ "$os" = "windows" ] && ext=".exe"
  echo "building adx + adx-collector for $os/$arch"
  GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$OUT/adx-$os-$arch$ext" .
  GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$OUT/adx-collector-$os-$arch$ext" ./cmd/adx-collector
done

echo
echo "artifacts:"
ls -lh "$OUT"
