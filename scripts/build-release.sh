#!/usr/bin/env sh
# Build StackSentry release binaries and a SHA-256 checksum file into ./dist.
# Usage: scripts/build-release.sh v0.1.0
set -eu

VERSION="${1:?usage: $0 <version tag, e.g. v0.1.0>}"
PKG="github.com/6-SlX-6/stacksentry"
COMMIT="$(git rev-parse --short=12 HEAD 2>/dev/null || true)"
# Use the commit time so that repeated builds of the same commit are identical.
DATE="$(TZ=UTC git log -1 --format=%cd --date=format-local:%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)"
LDFLAGS="-s -w -X ${PKG}/internal/version.Version=${VERSION#v} -X ${PKG}/internal/version.Commit=${COMMIT} -X ${PKG}/internal/version.Date=${DATE}"
TARGETS="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64"

rm -rf dist
mkdir -p dist

for target in $TARGETS; do
  goos="${target%/*}"
  goarch="${target#*/}"
  name="stacksentry-${VERSION}-${goos}-${goarch}"
  [ "$goos" = "windows" ] && name="${name}.exe"
  echo "building ${name}"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags "$LDFLAGS" -o "dist/${name}" ./cmd/stacksentry
done

cd dist
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum stacksentry-* > checksums.txt
else
  shasum -a 256 stacksentry-* > checksums.txt
fi
cat checksums.txt
