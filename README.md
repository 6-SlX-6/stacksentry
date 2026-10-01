# StackSentry: Docker Compose Security Scanner and Preflight Checker

**Find insecure, fragile and incomplete Docker Compose configuration before you deploy.**
Free and open source (Apache-2.0), local-first, no telemetry, single binary for Linux, macOS and Windows.

[![CI](https://github.com/6-SlX-6/stacksentry/actions/workflows/ci.yml/badge.svg)](https://github.com/6-SlX-6/stacksentry/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/6-SlX-6/stacksentry?sort=semver)](https://github.com/6-SlX-6/stacksentry/releases)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go version](https://img.shields.io/github/go-mod/go-version/6-SlX-6/stacksentry)](go.mod)

**StackSentry** is a command-line tool that scans `docker-compose.yml` and `compose.yaml` files, and optionally the local Docker daemon, for security, reliability and operational-readiness problems. For every finding it shows the exact evidence, explains why it matters and tells you how to fix it. It runs entirely on your machine and never sends data anywhere.

```sh
stacksentry scan compose ./docker-compose.yml
```

[Quick start](#quick-start) · [What it checks](#what-stacksentry-checks) · [CI/CD](#use-stacksentry-in-cicd) · [FAQ](#faq) · [Rule reference](docs/rules.md)

## At a glance

| | |
|---|---|
| **What it is** | Docker Compose security scanner, linter and preflight checker, plus a read-only Docker host audit |
| **What it checks** | 37 rules: 27 for Compose files, 10 for a running Docker host |
| **Typical findings** | Docker socket mounts, privileged containers, published database ports, plaintext secrets, missing restart policies and healthchecks, `latest` tags, missing volumes, unbounded logs |
| **Output** | Terminal table, JSON (with a [JSON Schema](docs/report.schema.json)) and Markdown audit reports |
| **CI/CD** | `--fail-on <severity>` exit codes for GitHub Actions, GitLab CI or any pipeline |
| **Requirements** | None for Compose scans (no Docker needed); a reachable Docker daemon for host scans |
| **Privacy** | Local analysis only: no telemetry, no cloud service, no account, no API key |
| **Platforms** | Linux, macOS, Windows (amd64 and arm64 where applicable) |
| **Language and license** | Go, Apache License 2.0 |
| **Current version** | v0.1.0 |

## Table of contents

- [What is StackSentry?](#what-is-stacksentry)
- [Why scan Docker Compose files?](#why-scan-docker-compose-files)
- [Features](#features)
- [Who is StackSentry for?](#who-is-stacksentry-for)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Example output](#example-output)
- [What StackSentry checks](#what-stacksentry-checks)
- [How it works](#how-it-works)
- [Use StackSentry in CI/CD](#use-stacksentry-in-cicd)
- [Output formats](#output-formats)
- [Documenting intentional exceptions](#documenting-intentional-exceptions)
- [Exit codes](#exit-codes)
- [How StackSentry fits next to other tools](#how-stacksentry-fits-next-to-other-tools)
- [Security and privacy](#security-and-privacy)
- [FAQ](#faq)
- [Documentation](#documentation)
- [Project status and roadmap](#project-status-and-roadmap)
- [Contributing](#contributing)
- [License](#license)

## What is StackSentry?

StackSentry is a **Docker Compose security and best-practice checker**. It reads your Compose files the same way Docker Compose does (using the official [compose-go](https://github.com/compose-spec/compose-go) library) and applies deterministic, documented rules to every service. It can also connect to the local Docker daemon through the official Docker Engine API and audit the containers that are actually running.

Every finding has:

- a stable **rule ID** (for example `SST-SEC-001`) and a **severity** (`critical`, `high`, `medium`, `low` or `info`);
- the **evidence** from your configuration, such as the exact volume mount or port mapping;
- a plain-language explanation of **why it matters**;
- a concrete **fix**, often with a Compose snippet.

StackSentry does not modify anything. It reports; you decide.

## Why scan Docker Compose files?

Docker Compose makes it easy to get a stack running and just as easy to ship configuration that works today but causes trouble later:

- **The Docker socket mounted into a container** (`/var/run/docker.sock`) gives that container control over the host, even when mounted read-only.
- **Database ports published as `5432:5432`** are reachable from the network and often bypass host firewalls such as UFW, because Docker manages its own iptables rules.
- **Passwords written directly into `environment:`** end up in Git, backups and `docker inspect` output.
- **Missing `restart:` policies** mean services stay down after a crash or reboot.
- **No volume for the database** means data disappears with the next `docker compose down`.
- **Default json-file logging without rotation** slowly fills the disk.
- **`image: something:latest`** makes deployments non-reproducible.

These problems rarely show up in a quick test. StackSentry finds them in seconds, before deployment, and works as a **Docker Compose security checklist** you can automate.

## Features

- **Static Docker Compose analysis** with 27 rules covering container isolation, secrets, networking, storage, reliability, resource limits and image pinning. No Docker installation needed.
- **Read-only Docker host audit** with 10 rules: privileged containers, Docker socket mounts, host networking, restart policies, unencrypted Docker API listeners, mutable images, dangling images and disk usage.
- **Actionable findings** with rule ID, severity, category, confidence, evidence, rationale and remediation.
- **Secrets stay secret:** values of credential-like variables are always masked as `********` in every output format.
- **Three output formats:** colored terminal tables, JSON with a versioned schema, and Markdown reports for issues, change requests and audits.
- **CI-friendly:** `--fail-on` exit codes, `--severity` filtering, `--only` / `--exclude` rule selection.
- **Documented exceptions** per service with `x-stacksentry.ignore`, including a reason.
- **Understands real-world Compose files:** multiple files and override files, directory discovery, `extends`, profiles, YAML anchors, variable interpolation and line numbers in findings.
- **Deterministic and reproducible:** the same input always produces the same findings in the same order.
- **Single static binary** for Linux, macOS and Windows, plus shell completion for bash, zsh, fish and PowerShell.

## Who is StackSentry for?

- **Self-hosters and homelab users** running stacks such as n8n, Gitea, Grafana, Nextcloud or Vaultwarden who want a quick security review before exposing a service.
- **Linux system administrators** who inherit Compose files and need to know what is risky.
- **DevOps and platform engineers** who want a security and reliability gate in CI/CD pipelines.
- **Developers** deploying Docker Compose stacks to servers or VMs.
- **Small companies** with Docker-based internal infrastructure that need audit-ready reports.
- **Security-conscious teams** reviewing changes to Compose files in pull requests.

## Quick start

### Install with Go

```sh
go install github.com/6-SlX-6/stacksentry/cmd/stacksentry@latest
```

Requires Go 1.26 or newer.

### Download a release binary

Binaries for `linux-amd64`, `linux-arm64`, `darwin-amd64`, `darwin-arm64` and `windows-amd64` are attached to each [GitHub release](https://github.com/6-SlX-6/stacksentry/releases), together with a `checksums.txt` file.

```sh
VERSION=v0.1.0
curl -fsSLO "https://github.com/6-SlX-6/stacksentry/releases/download/${VERSION}/stacksentry-${VERSION}-linux-amd64"
curl -fsSLO "https://github.com/6-SlX-6/stacksentry/releases/download/${VERSION}/checksums.txt"
sha256sum --check --ignore-missing checksums.txt
install -m 0755 "stacksentry-${VERSION}-linux-amd64" ~/.local/bin/stacksentry
```

Or use the installer script, which performs the same steps including checksum verification. Review it before running it:

```sh
curl -fsSL https://raw.githubusercontent.com/6-SlX-6/stacksentry/main/scripts/install.sh -o install.sh
less install.sh
sh install.sh            # installs to ~/.local/bin; set INSTALL_DIR to change
```

### Run with Docker

A Dockerfile is included. No image is published yet, so build it locally:

```sh
docker build -t stacksentry:local .
docker run --rm -v "$PWD:/work:ro" stacksentry:local scan compose /work/compose.yaml
```

Run `scan host` with the native binary: running it inside a container would require mounting the Docker socket, which StackSentry itself flags as critical.

### Build from source

```sh
git clone https://github.com/6-SlX-6/stacksentry.git
cd stacksentry
make build        # produces ./bin/stacksentry
```

### Your first scan

```sh
stacksentry scan compose ./docker-compose.yml
```

Pass a directory instead of a file and StackSentry picks `compose.yaml`, `compose.yml`, `docker-compose.yaml` or `docker-compose.yml` plus a matching override file, just like Docker Compose.

## Usage

```sh
# Scan a Compose file or a directory
stacksentry scan compose ./docker-compose.yml

# Merge several files, like docker compose -f a -f b
stacksentry scan compose compose.yaml compose.prod.yaml

# Write a Markdown audit report
stacksentry scan compose ./compose.yaml --format markdown --output report.md

# Fail CI when high or critical findings exist
stacksentry scan compose ./docker-compose.yml --fail-on high

# Show only medium and above; skip rules that do not apply to you
stacksentry scan compose ./docker-compose.yml --severity medium --exclude SST-SEC-001,SST-OPS-003

# Audit the local Docker daemon (read-only)
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
| `--no-color` | Disable colors. Colors are also off when stdout is not a terminal or `NO_COLOR` is set. |
| `-q, --quiet` | Print only findings in table output and no status messages. |

`--severity` affects only what is shown. `--fail-on` always considers every finding of the rules that ran, so hiding low-severity findings can never make a failing pipeline pass. The report states how many findings were hidden.

Variables in Compose files are interpolated deterministically: StackSentry does not read your shell environment or `.env` files. Defaults written in the file are used, and variables without a default are reported by `SST-CFG-001`.

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

Complete reports for the bundled examples, in all three formats, are in [`examples/reports/`](examples/reports).

## What StackSentry checks

StackSentry ships 37 rules. Each rule is documented with its detection logic, rationale, remediation and known false positives in the [rule reference](docs/rules.md), and is available offline with `stacksentry rules show <rule-id>`.

<!-- BEGIN GENERATED RULE TABLES: run `make docs` to update -->

### Docker Compose rules (27)

| Rule ID | Severity | Category | Title |
|---|---|---|---|
| [SST-CFG-001](docs/rules.md#sst-cfg-001) | medium | operations | Required environment variable may be missing |
| [SST-NET-001](docs/rules.md#sst-net-001) | high | networking | Publicly published database port |
| [SST-NET-002](docs/rules.md#sst-net-002) | low | networking | No explicit network segmentation |
| [SST-NET-003](docs/rules.md#sst-net-003) | medium | networking | Admin interface likely published broadly |
| [SST-OPS-001](docs/rules.md#sst-ops-001) | medium | reliability | No healthcheck configured |
| [SST-OPS-002](docs/rules.md#sst-ops-002) | medium | reliability | Healthcheck disabled |
| [SST-OPS-003](docs/rules.md#sst-ops-003) | high | reliability | No restart policy configured |
| [SST-OPS-004](docs/rules.md#sst-ops-004) | low | maintainability | Container name explicitly hardcoded |
| [SST-OPS-005](docs/rules.md#sst-ops-005) | medium | supply-chain | Mutable image tag |
| [SST-OPS-006](docs/rules.md#sst-ops-006) | low | supply-chain | Image digest not pinned |
| [SST-OPS-007](docs/rules.md#sst-ops-007) | low | reliability | No stop grace period |
| [SST-RES-001](docs/rules.md#sst-res-001) | low | resource-management | No memory limit configured |
| [SST-RES-002](docs/rules.md#sst-res-002) | low | resource-management | No CPU limit configured |
| [SST-RES-003](docs/rules.md#sst-res-003) | medium | resource-management | No log rotation configured |
| [SST-SEC-001](docs/rules.md#sst-sec-001) | critical | security | Docker socket mount detected |
| [SST-SEC-002](docs/rules.md#sst-sec-002) | critical | security | Privileged container detected |
| [SST-SEC-003](docs/rules.md#sst-sec-003) | high | security | Host network mode detected |
| [SST-SEC-004](docs/rules.md#sst-sec-004) | high | security | Dangerous Linux capabilities added |
| [SST-SEC-005](docs/rules.md#sst-sec-005) | low | security | Linux capabilities not dropped |
| [SST-SEC-006](docs/rules.md#sst-sec-006) | medium | security | Writable host bind mount |
| [SST-SEC-007](docs/rules.md#sst-sec-007) | high | security | Sensitive host path mounted |
| [SST-SEC-008](docs/rules.md#sst-sec-008) | medium | security | No explicit non-root user |
| [SST-SEC-009](docs/rules.md#sst-sec-009) | low | security | Read-only root filesystem not enabled |
| [SST-SEC-010](docs/rules.md#sst-sec-010) | critical | security | Insecure Docker API exposure |
| [SST-SEC-011](docs/rules.md#sst-sec-011) | high | secrets | Likely secret in environment variable |
| [SST-SEC-012](docs/rules.md#sst-sec-012) | medium | secrets | Environment file potentially tracked |
| [SST-STO-001](docs/rules.md#sst-sto-001) | high | storage | Database service without persistent volume |

### Docker host rules (10)

| Rule ID | Severity | Category | Title |
|---|---|---|---|
| [SST-HOST-001](docs/rules.md#sst-host-001) | info | operations | Docker daemon reachable |
| [SST-HOST-002](docs/rules.md#sst-host-002) | high | security | Docker daemon TCP listener |
| [SST-HOST-003](docs/rules.md#sst-host-003) | critical | security | Privileged container running |
| [SST-HOST-004](docs/rules.md#sst-host-004) | critical | security | Container mounts Docker socket |
| [SST-HOST-005](docs/rules.md#sst-host-005) | high | security | Container uses host network |
| [SST-HOST-006](docs/rules.md#sst-host-006) | high | reliability | Container without restart policy |
| [SST-HOST-007](docs/rules.md#sst-host-007) | info | maintainability | Stopped containers present |
| [SST-HOST-008](docs/rules.md#sst-host-008) | low | resource-management | Dangling images |
| [SST-HOST-009](docs/rules.md#sst-host-009) | medium | resource-management | Docker disk usage pressure |
| [SST-HOST-010](docs/rules.md#sst-host-010) | medium | supply-chain | Running container uses mutable image reference |

<!-- END GENERATED RULE TABLES -->

Planned checks, such as `pid: host`, unconfined seccomp profiles and secrets in build arguments, are listed at the end of the [rule reference](docs/rules.md#planned-rules).

## How it works

1. **Load.** Compose files are parsed and merged with compose-go, the library behind Docker Compose. A raw YAML pass records line numbers and interpolation variables.
2. **Normalize.** Services are converted into a small internal model: mounts, ports with exposure classification, environment, healthchecks, restart policies, limits, logging and dependencies.
3. **Evaluate.** Each enabled rule checks the model and reports issues with evidence. The engine adds rule metadata, a stable fingerprint and the scan time, isolates failing rules and sorts findings deterministically.
4. **Report.** Findings are filtered for display, secrets are redacted as a final safety net, and the report is rendered as a table, JSON or Markdown.

For host scans, step 1 is replaced by read-only Docker Engine API calls (version, info, containers, images, disk usage) and, on Linux, by reading `/etc/docker/daemon.json` and `/proc` to detect TCP API listeners. No shell commands are executed. Details are in [docs/architecture.md](docs/architecture.md).

## Use StackSentry in CI/CD

### GitHub Actions

```yaml
name: compose-preflight
on: [pull_request]

permissions:
  contents: read

jobs:
  stacksentry:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: actions/setup-go@v7
        with:
          go-version: stable
      - run: go install github.com/6-SlX-6/stacksentry/cmd/stacksentry@v0.1.0
      - name: Docker Compose security check
        run: stacksentry scan compose compose.yaml --fail-on high --format markdown --output stacksentry.md
      - name: Add report to the job summary
        if: always()
        run: cat stacksentry.md >> "$GITHUB_STEP_SUMMARY"
```

### GitLab CI

```yaml
stacksentry:
  image: golang:1.27
  script:
    - go install github.com/6-SlX-6/stacksentry/cmd/stacksentry@v0.1.0
    - stacksentry scan compose compose.yaml --fail-on high --format json --output stacksentry.json
  artifacts:
    when: always
    paths: [stacksentry.json]
```

More pipeline examples are in [docs/exit-codes.md](docs/exit-codes.md) and [docs/examples.md](docs/examples.md).

## Output formats

- **Table** (default): readable in an 80–120 column terminal, with severity colors on interactive terminals.
- **JSON** (`--format json`): stable, versioned structure for automation, documented in [docs/json-report.md](docs/json-report.md) and validated against [docs/report.schema.json](docs/report.schema.json).
- **Markdown** (`--format markdown`): a self-contained audit report with scan summary, statistics, detailed findings, scan limitations and remediation priorities, ready for GitHub issues, change requests or internal documentation.

```sh
# Rule IDs and services of all high and critical findings
stacksentry scan compose compose.yaml --format json \
  | jq -r '.findings[] | select(.severity == "critical" or .severity == "high") | "\(.rule_id) \(.target_name)"'
```

## Documenting intentional exceptions

Some findings are expected. A reverse proxy such as Traefik may need Docker API access. Document the exception next to the service instead of silencing the rule everywhere:

```yaml
services:
  traefik:
    image: traefik:v3.1.6
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    x-stacksentry:
      ignore:
        - rule: SST-SEC-001
          reason: Traefik discovers containers via labels; access is limited to this host.
```

Suppressed findings are listed in the report with their reason, are not counted in the totals and never trigger `--fail-on`. Docker Compose ignores `x-` keys, so the file stays valid. To skip a rule for the whole scan, use `--exclude`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed; no finding at or above `--fail-on` (or `--fail-on` not set). |
| `1` | Scan completed; at least one finding at or above `--fail-on`. |
| `2` | Error: invalid input or flags, unreadable or invalid Compose file, or Docker daemon unavailable for `scan host`. |

Details: [docs/exit-codes.md](docs/exit-codes.md).

## How StackSentry fits next to other tools

StackSentry focuses on **how containers are configured and run**. It complements, and does not replace, tools that look at other layers:

| Tool type | Typical question | Where StackSentry fits |
|---|---|---|
| Image vulnerability scanners | Does this image contain packages with known CVEs? | StackSentry does not scan image contents; use both. |
| Dockerfile linters | Is this Dockerfile written well? | StackSentry checks the Compose file that runs the image, not the build. |
| `docker compose config` | Is this Compose file syntactically valid? | StackSentry validates too, then checks security, reliability and operations. |
| General infrastructure-as-code scanners | Are my cloud and Kubernetes resources configured securely? | StackSentry is specialized in Docker Compose and single Docker hosts, with explanations aimed at self-hosters and small teams. |

## Security and privacy

- **No telemetry.** StackSentry does not collect usage data or phone home.
- **No cloud dependency.** No account, API key or online service is needed.
- **No external data transmission.** Compose scans make no network connections. Host scans talk only to the Docker daemon you point them at.
- **Local analysis only.** All rules run on your machine against your files and your Docker API.
- **No destructive remediation.** StackSentry never modifies Compose files, containers, images, volumes, networks or daemon settings.
- **Secrets stay secret.** Values of credential-like variables are masked in every output format.

Use StackSentry only on systems you own or are authorized to assess. Findings support, but do not replace, a full security review. See [docs/security-model.md](docs/security-model.md) for the threat model and data handling, and [SECURITY.md](SECURITY.md) to report vulnerabilities.

## FAQ

### How do I check a docker-compose.yml file for security issues?

Run `stacksentry scan compose docker-compose.yml`. StackSentry lists every finding with severity, evidence and a fix. Add `--severity medium` to focus on the important ones, or `--format markdown --output report.md` to get a shareable report.

### Does StackSentry need Docker to be installed?

No, not for Compose scans. `stacksentry scan compose` only reads files. Docker is needed only for `stacksentry scan host`, which audits a running Docker daemon.

### Does StackSentry upload my Compose files or secrets?

No. StackSentry works entirely offline, has no telemetry and never transmits data. Secret values found in Compose files are masked as `********` in all reports.

### Is it safe to mount `/var/run/docker.sock` read-only?

No. A read-only (`:ro`) mount only prevents changing the socket file; it does not restrict Docker API calls. Anyone with access to the socket can start privileged containers and effectively control the host. StackSentry reports this as `SST-SEC-001` (critical) and recommends a filtering socket proxy if API access is really needed.

### Why is a published database port a problem if I have a firewall?

On many Linux hosts, ports published by Docker bypass host firewalls such as UFW or firewalld, because Docker manages its own iptables rules. Bind database ports to `127.0.0.1` (for example `"127.0.0.1:5432:5432"`) or remove them if only other containers need access. StackSentry reports this as `SST-NET-001`.

### Does StackSentry read my `.env` file?

No. To keep results reproducible and avoid reading secrets, variables are interpolated without your shell environment or `.env` files. Defaults written in the Compose file are used; variables without a default are reported by `SST-CFG-001` so you can document them or add `${VAR:?error}` to make Compose fail fast.

### Can I use StackSentry in GitHub Actions or GitLab CI?

Yes. Use `--fail-on high` (or another severity) to fail the pipeline, and `--format markdown` or `--format json` to publish the report. See [Use StackSentry in CI/CD](#use-stacksentry-in-cicd).

### How do I ignore a finding that is intentional?

Add an `x-stacksentry.ignore` entry with a reason to the service (see [Documenting intentional exceptions](#documenting-intentional-exceptions)), or skip a rule for the whole scan with `--exclude SST-XXX-000`.

### Does it support old Compose files with `version: "3.8"`?

Yes. The obsolete `version` attribute is ignored, as in current Docker Compose, and StackSentry adds a warning that it can be removed. Multiple files, override files, `extends`, profiles and YAML anchors are supported.

### Is StackSentry a vulnerability scanner?

No. StackSentry checks configuration: how containers are run, exposed and connected. It does not scan images for CVEs. Use an image vulnerability scanner in addition.

### Does StackSentry use AI?

No. All findings come from deterministic, documented, unit-tested rules, so results are reproducible and explainable. AI integrations are out of scope for v0.1.0.

### Which platforms are supported?

Linux, macOS and Windows. Release binaries are provided for linux-amd64, linux-arm64, darwin-amd64, darwin-arm64 and windows-amd64. Detection of TCP Docker API listeners through `/proc` and `daemon.json` is Linux-only; other host checks work on all platforms.

## Documentation

- [Rule reference](docs/rules.md): every rule with detection logic, rationale, remediation and limitations
- [Examples](docs/examples.md): n8n stack, Markdown reports, GitHub Actions, exceptions, host scans
- [Exit codes and CI/CD](docs/exit-codes.md)
- [JSON report format](docs/json-report.md) and [JSON Schema](docs/report.schema.json)
- [Architecture](docs/architecture.md)
- [Security model](docs/security-model.md)

## Project status and roadmap

v0.1.0 is an early but usable release. The rule set is deliberately conservative and every rule is covered by tests, but you will find false positives and gaps. Please [open an issue](https://github.com/6-SlX-6/stacksentry/issues) with a minimal Compose snippet (without real secrets) when a finding is wrong, unclear or missing.

Planned work includes more isolation checks (`pid: host`, `security_opt`, devices), secret detection in build arguments and labels, analysis of `include:` files and additional Docker daemon checks. See [planned rules](docs/rules.md#planned-rules).

## Contributing

Contributions are welcome: new rules, better detection, documentation and bug reports. Read [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, rule design standards and pull request expectations, and follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

StackSentry is licensed under the [Apache License 2.0](LICENSE).
