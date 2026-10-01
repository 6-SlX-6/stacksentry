#!/usr/bin/env sh
# Run the commands shown in the README and docs against the bundled fixtures
# and check their exit codes. Usage: scripts/verify-examples.sh ./bin/stacksentry
set -u

BIN="${1:-./bin/stacksentry}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
failures=0

expect() {
  want="$1"
  shift
  "$@" >"$TMP/stdout" 2>"$TMP/stderr"
  got=$?
  if [ "$got" -eq "$want" ]; then
    echo "ok   (exit $got) $*"
  else
    echo "FAIL (exit $got, want $want) $*"
    sed 's/^/     | /' "$TMP/stderr"
    failures=$((failures + 1))
  fi
}

expect 0 "$BIN" version
expect 0 "$BIN" rules list
expect 0 "$BIN" rules show SST-SEC-001
expect 0 "$BIN" completion bash
expect 0 "$BIN" scan compose examples/insecure-compose.yaml
expect 0 "$BIN" scan compose examples/n8n-postgres-compose.yaml --format markdown --output "$TMP/report.md"
expect 1 "$BIN" scan compose examples/insecure-compose.yaml --fail-on high
expect 0 "$BIN" scan compose examples/reasonably-secure-compose.yaml --fail-on medium
expect 0 "$BIN" scan compose examples/insecure-compose.yaml --exclude SST-SEC-001,SST-OPS-003
expect 0 "$BIN" scan compose testdata/compose/project-dir
expect 0 "$BIN" scan compose examples/insecure-compose.yaml --format json --output "$TMP/report.json"
expect 2 "$BIN" scan compose testdata/compose/does-not-exist.yaml
expect 2 "$BIN" scan compose testdata/compose/invalid-yaml.yaml
expect 2 "$BIN" scan compose testdata/compose/services-list.yaml
expect 2 "$BIN" scan compose examples/insecure-compose.yaml --format xml
expect 2 "$BIN" scan compose examples/insecure-compose.yaml --only SST-NOPE-001
expect 2 env DOCKER_HOST=tcp://127.0.0.1:1 "$BIN" scan host

for f in "$TMP/report.md" "$TMP/report.json"; do
  if [ ! -s "$f" ]; then
    echo "FAIL report file $f was not written"
    failures=$((failures + 1))
  fi
done
if grep -q "Winter2024!" "$TMP/report.json" "$TMP/report.md"; then
  echo "FAIL secret value leaked into a report"
  failures=$((failures + 1))
fi

# The host scan needs a reachable Docker daemon; it is optional locally.
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  expect 0 "$BIN" scan host --format json --output "$TMP/host.json"
else
  echo "skip scan host (no reachable Docker daemon)"
fi

if [ "$failures" -ne 0 ]; then
  echo "$failures check(s) failed"
  exit 1
fi
echo "all example commands behaved as documented"
