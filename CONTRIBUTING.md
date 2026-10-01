# Contributing to StackSentry

Thank you for helping to make Docker deployments safer. This guide covers the
development setup, how to add a rule and what we expect from pull requests.

## Local setup

Requirements:

- Go 1.26 or newer (CI tests the current stable and previous Go release)
- `make`
- [golangci-lint v2](https://golangci-lint.run/) for `make lint`
- Docker is **not** required; host-scan tests use an in-memory fake of the
  Docker API.

```sh
git clone https://github.com/6-SlX-6/stacksentry.git
cd stacksentry
make build          # ./bin/stacksentry
make run-example    # scan the bundled examples
```

## Running tests and checks

| Command | What it does |
|---|---|
| `make test` | Unit and integration tests. |
| `make test-race` | Tests with the race detector. |
| `make coverage` | Coverage profile (`coverage.out`) and per-package summary. |
| `make lint` | golangci-lint with the repository configuration. |
| `make fmt` | gofmt and goimports via golangci-lint. |
| `make vet` | `go vet`. |
| `make golden` | Regenerate golden reports in `testdata/expected` and `examples/reports`. |
| `make docs` | Regenerate the rule reference in `docs/rules.md` from rule metadata. |

Before opening a pull request, run `make fmt vet lint test`.

Golden files capture the exact table, JSON and Markdown output for fixtures. If
you change output on purpose, run `make golden`, review the diff carefully and
commit the updated files.

## Adding a rule

1. **Choose an ID.** Use the next free number in the matching prefix:
   `SST-SEC` (security and secrets), `SST-OPS` (operations, reliability,
   images), `SST-NET`, `SST-STO`, `SST-RES`, `SST-CFG` (configuration) or
   `SST-HOST`. IDs are stable forever: never reuse or renumber them.
2. **Implement it** in `internal/rules/compose` or `internal/rules/host` with
   `newRule(engine.Metadata{...}, check)`. Fill in every metadata field: title,
   category, default severity, description, rationale, remediation, detection
   and, where relevant, limitations and references.
3. **Return issues, not findings.** A rule reports targets and evidence; the
   engine adds metadata, IDs and timestamps. Override severity, confidence,
   description or remediation per issue only when the evidence justifies it.
4. **Register it** in the rule list of the package (`All()`).
5. **Test it** with a table-driven test in the package's `*_test.go`. Compose
   rule tests load real YAML through the loader (`runRuleCases`). The test
   suite fails if a registered rule has no table-driven test.
6. **Add fixtures** to `testdata/compose/` when a rule needs more than a
   snippet, and update golden files with `make golden`.
7. **Document it** with `make docs`, which regenerates the rule reference in
   `docs/rules.md` (a test fails if it is out of date). Update the "Planned
   rules" list if the rule was listed there.

## Rule design standards

- **Deterministic and local.** Rules use only the parsed configuration or the
  Docker API snapshot. No network access, no randomness, no dependency on the
  current time or environment.
- **Evidence-based.** Every finding must point to concrete evidence. Never
  report something that was not observed.
- **Conservative.** Prefer missing an edge case over flooding users with false
  positives. If a detection is heuristic, lower the confidence and say so.
- **Precise wording.** Say "may", "appears" or "looks like" when the tool
  cannot be certain (for example, a missing `user` does not prove the
  container runs as root).
- **Never print secrets.** Mask values with `composerules.Mask`; never include
  environment values, command lines or healthcheck tests verbatim if they
  could contain credentials.
- **Actionable remediation.** Explain the concrete change, ideally with a
  Compose snippet, and mention when the finding may be intentional.
- **Read-only.** Host rules must only use read-only Docker API calls and file
  reads. No shell commands, no modifications.
- **Stable output.** Sort anything derived from maps; evidence order must not
  depend on iteration order.

## Test requirements

- Table-driven tests for every rule, covering positive cases, negative cases
  and known false-positive traps.
- Error paths must be tested (invalid input must never panic).
- Changes to report output need updated golden files.
- Keep coverage of `internal/engine` and `internal/report` at 80% or higher.

## Pull request expectations

- One logical change per pull request, with a clear description of the
  problem and the approach. Link related issues.
- Tests and documentation updated in the same pull request.
- `make fmt vet lint test` passes locally; CI must be green.
- No new dependencies without discussion. Dependencies must be maintained,
  license-compatible with Apache-2.0 and must not perform network calls.
- Use only fake credentials in fixtures and examples.

## Commit messages

- Use the imperative mood and keep the subject line under ~72 characters:
  `Add SST-SEC-013 for pid: host`, `Fix false positive for /etc/localtime`.
- Optionally prefix with the area: `rules:`, `report:`, `cli:`, `docs:`, `ci:`.
- Explain *why* in the body when the change is not obvious.
- Reference issues with `Fixes #123` where applicable.

## Reporting security issues

Do not open public issues for vulnerabilities; follow [SECURITY.md](SECURITY.md).
