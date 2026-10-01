# Exit codes

`stacksentry scan compose` and `stacksentry scan host` use three exit codes:

| Code | Meaning |
|---|---|
| `0` | The scan completed and no finding is at or above the `--fail-on` threshold. Without `--fail-on`, a completed scan always exits with 0, whatever it found. |
| `1` | The scan completed and at least one finding is at or above the `--fail-on` severity. |
| `2` | The scan could not be completed: invalid flags or rule IDs, a missing, unreadable or invalid Compose file, an unsupported Compose structure, an unwritable `--output` path, or (for `scan host`) an unavailable or inaccessible Docker daemon. An explanation is printed to stderr. |

Other commands (`version`, `rules`, `completion`) exit with 0 on success and 2
on invalid usage.

## How `--fail-on` interacts with other options

- `--fail-on` accepts `info`, `low`, `medium`, `high`, `critical` (or `none`)
  and matches findings *at or above* that severity.
- `--severity` only controls which findings are **shown**. `--fail-on` is
  evaluated against **all** findings of the rules that ran, including findings
  hidden by `--severity`. This keeps the exit code independent of presentation
  choices; the report always states how many findings were hidden and the
  table and Markdown outputs print a `Result: FAIL …` line explaining the exit
  code.
- `--only` and `--exclude` decide which rules run. Findings of rules that did
  not run cannot trigger `--fail-on`.
- Findings suppressed with `x-stacksentry.ignore` are listed separately and
  never trigger `--fail-on`.
- Writing the report with `--output` does not change the exit code.

## CI/CD examples

### Shell

```sh
stacksentry scan compose ./compose.yaml --fail-on high
case $? in
  0) echo "No high or critical findings" ;;
  1) echo "Fix high/critical findings before deploying"; exit 1 ;;
  *) echo "StackSentry could not scan the stack"; exit 2 ;;
esac
```

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
      - name: Install StackSentry
        run: go install github.com/6-SlX-6/stacksentry/cmd/stacksentry@v0.1.0
      - name: Scan Compose stack
        run: stacksentry scan compose ./compose.yaml --fail-on high --format markdown --output stacksentry.md
      - name: Add report to job summary
        if: always()
        run: cat stacksentry.md >> "$GITHUB_STEP_SUMMARY"
```

Because `--output` is used, the job log only contains a one-line status; the
full Markdown report appears in the job summary. The job fails (exit code 1)
when a high or critical finding exists, and also (exit code 2) if the file
cannot be scanned.

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

### Allowing a non-blocking report

To publish a report without failing the pipeline, omit `--fail-on`. Errors
(exit code 2) still fail the step, which avoids silently skipping the check:

```sh
stacksentry scan compose compose.yaml --format markdown --output report.md
```
