# StackSentry

A local-first CLI that checks Docker Compose stacks and Docker hosts for security, reliability, and operational readiness issues before deployment.

[![CI](https://github.com/6-SlX-6/stacksentry/actions/workflows/ci.yml/badge.svg)](https://github.com/6-SlX-6/stacksentry/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/6-SlX-6/stacksentry?sort=semver)](https://github.com/6-SlX-6/stacksentry/releases)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go version](https://img.shields.io/github/go-mod/go-version/6-SlX-6/stacksentry)](go.mod)

## Why StackSentry?

Docker Compose makes it easy to get a stack running, and just as easy to ship
configuration that works today but causes trouble later: a database port open
to the internet, the Docker socket mounted into a web app, a password committed
in plain text, a container that never restarts after a reboot, logs that fill
the disk, or data that disappears with the next `docker compose down`.

These problems rarely show up in a quick test. StackSentry reads your Compose
files (and optionally your local Docker daemon) and tells you, before you
deploy, what is insecure, fragile, outdated or incomplete, why it matters, and
exactly how to fix it.

## Features

- **Static Compose analysis** with 27 rules covering security, secrets,
  networking, storage, reliability, resource limits and image pinning. No
  Docker installation needed.
- **Read-only Docker host inspection** with 10 rules: privileged containers,
  Docker socket mounts, host networking, restart policies, unencrypted API
  listeners, mutable images, dangling images and disk usage.
- **Actionable findings:** every finding has a stable rule ID, severity,
  category, confidence, the exact evidence, why it matters and how to fix it.
- **Three output formats:** readable terminal tables (with color on TTYs),
  JSON with a [documented, versioned schema](docs/json-report.md), and Markdown
  reports for issues, change requests and audits.
- **CI-friendly:** `--fail-on` exit codes, `--severity` filtering, `--only` /
  `--exclude`, and per-service documented exceptions with `x-stacksentry`.
- **Safe by default:** secrets are always masked; nothing is modified; no
  telemetry; deterministic output.
- **Understands real Compose files:** multiple files and override files,
  `extends`, profiles, anchors and interpolation, using the official
  compose-go library.
- Single static binary for Linux, macOS and Windows.

## Quick start

### Install with Go

```sh
go install github.com/6-SlX-6/stacksentry/cmd/stacksentry@latest
```

Requires Go 1.26 or newer.

### Download a release binary

Binaries for `linux-amd64`, `linux-arm64`, `darwin-amd64`, `darwin-arm64` and
`windows-amd64` are attached to each
[GitHub release](https://github.com/6-SlX-6/stacksentry/releases) together with
a `checksums.txt` file.

```sh
VERSION=v0.1.0
curl -fsSLO "https://github.com/6-SlX-6/stacksentry/releases/download/${VERSION}/stacksentry-${VERSION}-linux-amd64"
curl -fsSLO "https://github.com/6-SlX-6/stacksentry/releases/download/${VERSION}/checksums.txt"
sha256sum --check --ignore-missing checksums.txt
install -m 0755 "stacksentry-${VERSION}-linux-amd64" ~/.local/bin/stacksentry
```

Or use the installer script, which performs the same steps including checksum
verification (review it before running it):

```sh
curl -fsSL https://raw.githubusercontent.com/6-SlX-6/stacksentry/main/scripts/install.sh -o install.sh
less install.sh
sh install.sh            # installs to ~/.local/bin; set INSTALL_DIR to change
```

### Run with Docker (build locally)

A Dockerfile is included for environments without Go. No image is published
yet; build it yourself:

```sh
docker build -t stacksentry:local .
docker run --rm -v "$PWD:/work:ro" stacksentry:local scan compose /work/compose.yaml
```

Running the host scan inside a container would require mounting the Docker
socket, which StackSentry itself flags as critical. Run `scan host` with the
native binary instead.

### Build from source

```sh
git clone https://github.com/6-SlX-6/stacksentry.git
cd stacksentry
make build        # produces ./bin/stacksentry
```

## Usage

```sh
# Scan a Compose file (or a directory containing compose.yaml / docker-compose.yml)
stacksentry scan compose ./docker-compose.yml

# Merge several files, like docker compose -f a -f b
stacksentry scan compose compose.yaml compose.prod.yaml

# Write a Markdown report
stacksentry scan compose ./compose.yaml --format markdown --output report.md

# Fail CI when high or critical findings exist
stacksentry scan compose ./docker-compose.yml --fail-on high

# Show only medium and above; skip rules that do not apply to you
stacksentry scan compose ./docker-compose.yml --severity medium --exclude SST-SEC-001,SST-OPS-003

# Inspect the local Docker daemon (read-only)
stacksentry scan host
stacksentry scan host --format json --output stacksentry-host-report.json

# Explore the rules
stacksentry rules list
stacksentry rules show SST-SEC-001

# Shell completion
stacksentry completion bash|zsh|fish|powershell
```

| Flag (`scan compose`, `scan host`) | Description |
|---|---|
| `-f, --format table\|json\|markdown` | Output format (default `table`). |
| `-o, --output <file>` | Write the report to a file instead of stdout. |
| `--severity info\|low\|medium\|high\|critical` | Show only findings at or above this severity (default `info`, i.e. all). |
| `--fail-on low\|medium\|high\|critical` | Exit with code 1 if a finding at or above this severity exists. |
| `--exclude <id[,id...]>` | Skip these rules. |
| `--only <id[,id...]>` | Run only these rules. |
| `--no-color` | Disable colors (colors are also off when stdout is not a terminal or `NO_COLOR` is set). |
| `-q, --quiet` | Print only findings in table output and no status messages. |

`--severity` affects only what is shown; `--fail-on` always considers every
finding of the rules that ran, so hiding low findings can never make a failing
pipeline pass. The report says how many findings were hidden.

Variables in Compose files are interpolated deterministically: StackSentry does
not read your shell environment or `.env` files. Defaults written in the file
are used and variables without a default are reported by SST-CFG-001.

## Example output

```console
$ stacksentry scan compose examples/insecure-compose.yaml
StackSentry v0.1.0
Target: examples/insecure-compose.yaml (project "insecure-demo")
Scan time: 2026-10-01T12:00:00Z
Rules evaluated: 27 of 27
Services analyzed: 3
Findings: 2 critical, 5 high, 13 medium, 13 low, 2 info

CRITICAL  SST-SEC-001  manager  (examples/insecure-compose.yaml:7)
  The Docker daemon socket is mounted into the container.
  Evidence: /var/run/docker.sock:/var/run/docker.sock
  Why this matters: Access to the Docker socket can effectively grant host-level control: anyone who
    can talk to it can start privileged containers and mount the host filesystem. Mounting it
    read-only (:ro) does not restrict API calls.
  Fix: Remove the mount unless this service explicitly requires Docker daemon access. If it does
    (for example a reverse proxy reading container labels), put a filtering socket proxy in front of
    the socket that only allows the required read-only API endpoints.

HIGH  SST-NET-001  db  (examples/insecure-compose.yaml:23)
  A database port is published on all host interfaces.
  Evidence: 5432:5432/tcp (PostgreSQL port published on all host interfaces)
  ...

HIGH  SST-SEC-011  db  (examples/insecure-compose.yaml:23)
  An environment variable that looks like a credential has an inline value in the Compose file.
  Evidence: POSTGRES_PASSWORD=********
  ...

MEDIUM  SST-SEC-008  manager  (examples/insecure-compose.yaml:7)
  No user is configured, so the container runs as the image's default user, which is root for many
  images.
  Evidence: user is not set
  ...
```

Complete reports for the bundled examples, in all three formats, are in
[`examples/reports/`](examples/reports).

## Supported checks

| Area | Rules |
|---|---|
| Container isolation | Docker socket mounts, privileged mode, host networking, dangerous capabilities, capability dropping, writable and sensitive host mounts, non-root user, read-only root filesystem, unencrypted Docker API |
| Secrets and configuration | Inline secrets (masked), env files, variables without defaults |
| Networking | Published database ports, missing network segmentation, broadly published admin interfaces |
| Reliability and operations | Healthchecks, restart policies, container names, stop grace periods, persistent database volumes |
| Supply chain | Mutable image tags, missing digests |
| Resources | Memory and CPU limits, log rotation |
| Docker host | Daemon reachability, TCP API listeners, privileged containers, socket mounts, host networking, restart policies, stopped containers, dangling images, disk usage, mutable images |

See **[docs/rules.md](docs/rules.md)** for every rule's detection logic,
rationale, remediation and known limitations, or run `stacksentry rules list`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed; no finding at or above `--fail-on` (or `--fail-on` not set). |
| `1` | Scan completed; at least one finding at or above `--fail-on`. |
| `2` | Error: invalid input or flags, unreadable or invalid Compose file, or Docker daemon unavailable for `scan host`. |

Details and CI examples: [docs/exit-codes.md](docs/exit-codes.md).

## Security and privacy

- **No telemetry.** StackSentry does not collect usage data or phone home.
- **No cloud dependency.** No account, API key or online service is needed.
- **No external data transmission.** Compose scans make no network
  connections. Host scans talk only to the Docker daemon you point them at.
- **Local analysis only.** All rules run on your machine against your files
  and your Docker API.
- **No destructive remediation in v0.1.0.** StackSentry never modifies Compose
  files, containers, images, volumes, networks or daemon settings.
- **Secrets stay secret.** Values of credential-like variables are masked in
  every output format.

Use StackSentry only on systems you own or are authorized to assess. Findings
support, but do not replace, a full security review. See
[docs/security-model.md](docs/security-model.md) for the threat model and data
handling, and [SECURITY.md](SECURITY.md) to report vulnerabilities.

## Documentation

- [Rule reference](docs/rules.md)
- [Examples](docs/examples.md): n8n stack, Markdown reports, GitHub Actions, exceptions, host scans
- [Exit codes and CI/CD](docs/exit-codes.md)
- [JSON report format](docs/json-report.md) and [JSON Schema](docs/report.schema.json)
- [Architecture](docs/architecture.md)
- [Security model](docs/security-model.md)

## Project status

v0.1.0 is an early but usable release. The rule set is deliberately
conservative and every rule is covered by tests, but you will find false
positives and gaps. Please
[open an issue](https://github.com/6-SlX-6/stacksentry/issues) with a minimal
Compose snippet (without real secrets) when a finding is wrong, unclear or
missing. Planned rules are listed at the end of [docs/rules.md](docs/rules.md).

## Contributing

Contributions are welcome: new rules, better detection, documentation and bug
reports. Read [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup,
rule design standards and pull request expectations, and follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## License

StackSentry is licensed under the [Apache License 2.0](LICENSE).
