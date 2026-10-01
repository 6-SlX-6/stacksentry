#!/usr/bin/env sh
# Install a StackSentry release binary after verifying its SHA-256 checksum.
#
#   sh install.sh                    # latest release into ~/.local/bin
#   VERSION=v0.1.0 sh install.sh     # specific release
#   INSTALL_DIR=/usr/local/bin sh install.sh
#
# The script never uses sudo. Choose an INSTALL_DIR you can write to.
set -eu

REPO="6-SlX-6/stacksentry"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${VERSION:-}"

say() { printf '%s\n' "$*"; }
fail() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"; }
need curl
need uname

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) fail "unsupported operating system $(uname -s); download a binary from https://github.com/${REPO}/releases" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) fail "unsupported architecture $(uname -m)" ;;
esac

if [ -z "$VERSION" ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" |
    sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)"
  [ -n "$VERSION" ] || fail "could not determine the latest release; set VERSION=vX.Y.Z"
fi

asset="stacksentry-${VERSION}-${os}-${arch}"
base="https://github.com/${REPO}/releases/download/${VERSION}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "Downloading ${asset}"
curl -fsSL -o "${tmp}/${asset}" "${base}/${asset}"
curl -fsSL -o "${tmp}/checksums.txt" "${base}/checksums.txt"

expected="$(awk -v f="$asset" '$2 == f || $2 == "*"f { print $1 }' "${tmp}/checksums.txt")"
[ -n "$expected" ] || fail "no checksum for ${asset} in checksums.txt"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "${tmp}/${asset}" | awk '{ print $1 }')"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "${tmp}/${asset}" | awk '{ print $1 }')"
else
  fail "sha256sum or shasum is required to verify the download"
fi
[ "$expected" = "$actual" ] || fail "checksum mismatch for ${asset}: expected ${expected}, got ${actual}"
say "Checksum verified"

mkdir -p "$INSTALL_DIR"
install -m 0755 "${tmp}/${asset}" "${INSTALL_DIR}/stacksentry" 2>/dev/null ||
  { cp "${tmp}/${asset}" "${INSTALL_DIR}/stacksentry" && chmod 0755 "${INSTALL_DIR}/stacksentry"; }
say "Installed ${INSTALL_DIR}/stacksentry (${VERSION})"

case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *) say "Note: ${INSTALL_DIR} is not in your PATH. Add it, for example: export PATH=\"${INSTALL_DIR}:\$PATH\"" ;;
esac
