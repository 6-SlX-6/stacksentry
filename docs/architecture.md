# Architecture

StackSentry is a single, statically linked Go binary. All analysis happens
locally and deterministically: the same input always produces the same
findings, in the same order.

```
                    ┌──────────────┐
   argv ──────────▶ │ internal/cli │  Cobra commands, flag validation, exit codes
                    └──────┬───────┘
                           ▼
                    ┌──────────────┐
                    │ internal/app │  scan workflows, rule selection, suppressions
                    └──┬────────┬──┘
           compose scan│        │host scan
                       ▼        ▼
   ┌──────────────────────┐  ┌──────────────────────────┐
   │ internal/compose     │  │ internal/docker          │
   │ load + normalize     │  │ read-only API + /proc     │
   │ → compose.Project    │  │ → docker.Snapshot         │
   └──────────┬───────────┘  └────────────┬─────────────┘
              ▼                           ▼
   ┌──────────────────────┐  ┌──────────────────────────┐
   │ internal/rules/compose│ │ internal/rules/host       │
   └──────────┬───────────┘  └────────────┬─────────────┘
              └────────────┬──────────────┘
                           ▼
                    ┌────────────────┐
                    │ internal/engine│  registry, selection, run, finding model
                    └──────┬─────────┘
                           ▼
                    ┌────────────────┐
                    │ internal/report│  summary, filters, table / JSON / Markdown
                    └────────────────┘
```

## Packages

| Package | Responsibility |
|---|---|
| `cmd/stacksentry` | `main`: signal handling and process exit code. |
| `internal/cli` | Cobra command tree, flag parsing and validation, terminal detection, mapping errors to exit codes, `rules` output. |
| `internal/app` | The two scan workflows. Validates `--only`/`--exclude`, runs the engine, applies `x-stacksentry` suppressions, builds and redacts the report. |
| `internal/compose` | Loads Compose files with [compose-go](https://github.com/compose-spec/compose-go) and normalizes them into `compose.Project`. Also performs a raw YAML pass for line numbers and interpolation variables. |
| `internal/docker` | Connects to the Docker daemon with the official Docker Engine API client (`github.com/moby/moby/client`), collects a `docker.Snapshot` and probes for TCP listeners. |
| `internal/rules/compose`, `internal/rules/host` | Rule implementations and their metadata. |
| `internal/engine` | Rule interface, registry, selection, execution (with panic isolation and de-duplication) and conversion of rule issues into findings. |
| `internal/findings` | Finding model, severities, confidence, categories, counting and deterministic sorting. |
| `internal/imageref` | Offline parsing and classification of image references (digest, version, channel, latest, untagged). |
| `internal/report` | Report model, `--severity`/`--fail-on` evaluation, redaction and the three renderers. |
| `internal/version` | Build metadata injected at link time. |

There is no plugin system in v0.1.0. Rules are compiled in, which keeps the
binary self-contained and makes behavior reproducible for a given version.

## CLI flow

1. `cli.Execute` builds the command tree and runs Cobra.
2. Scan flags are validated before any work starts (format, severities, rule
   IDs). Invalid input returns a `usageError` and exit code 2.
3. The `app` layer validates rule IDs against the full catalog. Unknown IDs are
   errors (with "did you mean" suggestions); IDs of the other scan mode are
   ignored with a warning so that one exclusion list can serve both modes.
4. The scan produces a `report.Report` containing *all* findings of the
   evaluated rules. `--severity` decides which findings are displayed and
   `--fail-on` is evaluated against all findings, so the exit code never
   depends on presentation options.
5. The report is rendered to stdout or written atomically to `--output`.
6. `cli.Execute` maps the result to exit code 0, 1 or 2
   (see [exit-codes.md](exit-codes.md)).

## Compose parsing

`compose.Load` accepts one or more files, or a directory (in which case
`compose.yaml`, `compose.yml`, `docker-compose.yaml` or `docker-compose.yml`
plus a matching override file are used, as Docker Compose does).

1. **Raw pass.** Each file is parsed with `go.yaml.in/yaml/v3` into a node tree.
   This rejects invalid YAML with a line number, rejects structures that cannot
   be Compose (for example `services` as a list), records the line of every
   service definition and extracts interpolation expressions without defaults
   for SST-CFG-001. It also notes obsolete `version` keys and `include`
   directives.
2. **compose-go.** The files are merged and validated against the Compose
   specification schema by compose-go. Options are chosen for safe, offline,
   deterministic analysis:
   - interpolation uses an *empty* environment: shell variables and `.env`
     files are never read; defaults in the file apply; missing required
     variables (`${VAR:?err}`) resolve to empty instead of failing;
   - `env_file` and `label_file` contents are not read;
   - paths are not resolved, so evidence shows paths as written;
   - all profiles are enabled so that every service is analyzed;
   - `include` is not followed (reported as a scan limitation);
   - compose-go's log output is captured and turned into report warnings.
3. **Normalization.** compose-go's types are converted into the small
   `compose.Project` model the rules use (mounts, ports with exposure
   classification, environment, healthcheck, restart, limits, logging,
   dependencies, `x-stacksentry` exceptions). Rules never import compose-go.

## Rule registry and scanning engine

A rule implements `engine.Rule[T]`:

```go
type Rule[T any] interface {
    Metadata() Metadata         // ID, title, category, default severity, texts
    Check(target T) []Issue      // what was found, with evidence
}
```

`T` is `*compose.Project` for Compose rules and `*docker.Snapshot` for host
rules. Rules return `Issue` values that contain only what is specific to the
finding (target, evidence, optional severity/confidence/description
overrides). `engine.Run` turns them into complete `findings.Finding` values by
adding the rule metadata, a stable fingerprint ID, the rule version, the
documentation link, the scan timestamp and the scanner version. It also:

- recovers from panics inside a rule and reports them as warnings instead of
  crashing;
- drops duplicate findings with the same fingerprint;
- moves findings matched by `x-stacksentry.ignore` into the suppressed list;
- sorts findings by severity (descending), rule ID, target name, location and
  evidence.

`engine.NewRegistry` validates every rule's metadata (ID format, category,
severity, required texts, scope) and rejects duplicate IDs. A unit test fails
if any registered rule lacks a table-driven test, and another keeps
[rules.md](rules.md) in sync with the compiled-in metadata.

## Host inspection

`docker.Connect` creates a client from the standard environment variables
(`DOCKER_HOST`, `DOCKER_CERT_PATH`, `DOCKER_TLS_VERIFY`, `DOCKER_API_VERSION`)
and pings the daemon. Failures are classified (permission denied, not
reachable, timeout) into an actionable `docker.UnavailableError`.

`docker.Inspector` then calls only read-only endpoints: version, info,
container list and inspect (running containers only), image list
(`dangling=true`) and disk usage. Each failing call becomes a scan limitation
instead of an error. On Linux, with a local daemon, it also reads
`/etc/docker/daemon.json`, the `dockerd` command line from `/proc` and the
kernel socket tables `/proc/net/tcp{,6}` to find TCP listeners. No shell
commands are executed and nothing on the host is modified.

## Report rendering

`report.Build` assembles the renderer-independent `report.Report`: scanner and
scan metadata, target metadata, summary counts (including findings hidden by
`--severity`), displayed findings, suppressed findings, skipped rules,
limitations and warnings. `report.Redact` then replaces known secret values in
every text field as a defense in depth.

- **Table** (`table.go`): human-oriented, wrapped to 100 columns, ANSI colors
  only when stdout is a terminal and neither `--no-color` nor `NO_COLOR` is set.
- **JSON** (`json.go`): stable schema, documented in
  [json-report.md](json-report.md) and [report.schema.json](report.schema.json);
  tests validate output against the schema.
- **Markdown** (`markdown.go`): report for issues, change requests and audits,
  with escaping of user-controlled text.

## Why deterministic rules instead of AI in v0.1.0

- **Trust and reproducibility.** A preflight check that gates deployments must
  give the same answer for the same input. Rule-based findings are
  reproducible, reviewable and testable.
- **Privacy.** Compose files contain hostnames, network layouts and sometimes
  credentials. StackSentry must work offline and never send them anywhere.
- **Explainability.** Every finding cites concrete evidence from the file or
  the Docker API and links to documented detection logic and limitations.
- **No hallucinated results.** Findings are only produced from parsed
  configuration or actual API data.

The architecture leaves room for an optional, *local* explanation layer (for
example a future integration with a local Ollama model) that could consume the
JSON report and rephrase remediation advice. It would sit after report
generation and never influence which findings are produced. It is out of scope
for v0.1.0.
