# JSON report format

`--format json` produces a single JSON document. Its structure is versioned
with `schema_version` (currently `1.0.0`) and described formally by the JSON
Schema in [report.schema.json](report.schema.json); the test suite validates
generated reports against that schema.

Compatibility promise: within schema version `1.x`, fields are only added,
never removed or renamed, and the meaning of existing fields does not change.
Consumers should ignore unknown fields.

## Top-level fields

| Field | Type | Description |
|---|---|---|
| `schema_version` | string | Report schema version. |
| `scanner` | object | `name`, `version` and, when known, `commit` of the binary. |
| `scan` | object | `type` (`compose` or `host`), `started_at`, `finished_at` (ISO 8601, UTC, second precision), `rules_total`, `rules_evaluated` and the `options` that influenced the result: `min_severity`, `fail_on` (or `null`), `only`, `exclude`. |
| `target` | object | `type`, a display `name`, and either `compose` (`files`, `project_name`, `service_count`, `services`) or `host` (`endpoint`, `server_version`, `api_version`, `operating_system`, `os_type`, `architecture`, `containers_total`, `containers_running`, `images`). |
| `summary` | object | See below. |
| `findings` | array | Findings at or above `min_severity`, sorted by severity (descending), rule ID, target name and location. |
| `suppressed_findings` | array | Findings matched by `x-stacksentry.ignore`, each with a `suppression_reason`. |
| `skipped_rules` | array | Rules that were not evaluated, with `rule_id`, `title` and `reason`. |
| `limitations` | array of strings | Parts of the target that could not be analyzed. |
| `warnings` | array of strings | Parser warnings, ignored options and isolated rule failures. |

All arrays are always present (possibly empty).

## Summary

| Field | Description |
|---|---|
| `total` | Number of findings produced by the evaluated rules, including findings hidden by `--severity` and excluding suppressed findings. |
| `by_severity` | Counts for `critical`, `high`, `medium`, `low` and `info` (all findings). |
| `displayed` | Number of entries in `findings`. |
| `hidden_below_min_severity` | `total - displayed`. |
| `suppressed` | Number of entries in `suppressed_findings`. |
| `fail_on` | The `--fail-on` severity or `null`. |
| `at_or_above_fail_on` | Findings that meet the threshold (0 when no threshold is set). |
| `result` | `pass`, `fail` or `no_threshold`. `fail` corresponds to exit code 1. |

## Finding

| Field | Description |
|---|---|
| `id` | Stable 16-character fingerprint of rule, target and evidence. It does not change between scans of the same configuration and can be used for de-duplication. |
| `rule_id`, `rule_version` | Rule identifier (e.g. `SST-SEC-001`) and the version of its detection logic. |
| `title`, `category` | Rule title and category (`security`, `operations`, `reliability`, `maintainability`, `secrets`, `networking`, `storage`, `resource-management`, `supply-chain`). |
| `severity` | `critical`, `high`, `medium`, `low` or `info`. |
| `confidence` | `high`, `medium` or `low`. |
| `target_type`, `target_name` | What the finding is about: `service`, `project`, `container` or `host`, and its name. |
| `location` | Optional `file` and `line` of the service definition (Compose scans). |
| `description` | Finding-specific statement. |
| `evidence` | Array of evidence lines. Secret values are always masked as `********`. |
| `why_it_matters`, `remediation` | Rationale and recommended fix. |
| `documentation`, `references` | Link to the rule reference and further reading. |
| `timestamp`, `scanner_version` | Scan time and scanner version. |

## Example

An abbreviated report (see
[examples/reports/insecure-compose.json](../examples/reports/insecure-compose.json)
for a complete one):

```json
{
  "schema_version": "1.0.0",
  "scanner": {"name": "stacksentry", "version": "0.1.0"},
  "scan": {
    "type": "compose",
    "started_at": "2026-10-01T12:00:00Z",
    "finished_at": "2026-10-01T12:00:00Z",
    "rules_total": 27,
    "rules_evaluated": 27,
    "options": {"min_severity": "info", "fail_on": "high", "only": [], "exclude": []}
  },
  "target": {
    "type": "compose",
    "name": "compose.yaml",
    "compose": {"files": ["compose.yaml"], "project_name": "shop", "service_count": 3, "services": ["api", "db", "web"]}
  },
  "summary": {
    "total": 1,
    "by_severity": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
    "displayed": 1,
    "hidden_below_min_severity": 0,
    "suppressed": 0,
    "fail_on": "high",
    "at_or_above_fail_on": 1,
    "result": "fail"
  },
  "findings": [
    {
      "id": "3c4f0e8a9b1d2c7e",
      "rule_id": "SST-SEC-001",
      "rule_version": "1.0",
      "title": "Docker socket mount detected",
      "category": "security",
      "severity": "critical",
      "confidence": "high",
      "target_type": "service",
      "target_name": "api",
      "location": {"file": "compose.yaml", "line": 4},
      "description": "The Docker daemon socket is mounted into the container.",
      "evidence": ["/var/run/docker.sock:/var/run/docker.sock"],
      "why_it_matters": "Access to the Docker socket can effectively grant host-level control: …",
      "remediation": "Remove the mount unless this service explicitly requires Docker daemon access. …",
      "documentation": "https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-001",
      "references": ["https://docs.docker.com/engine/security/#docker-daemon-attack-surface"],
      "timestamp": "2026-10-01T12:00:00Z",
      "scanner_version": "0.1.0"
    }
  ],
  "suppressed_findings": [],
  "skipped_rules": [],
  "limitations": [],
  "warnings": []
}
```

## Processing with jq

```sh
# Rule IDs and targets of all high and critical findings
stacksentry scan compose compose.yaml --format json \
  | jq -r '.findings[] | select(.severity == "critical" or .severity == "high") | "\(.rule_id) \(.target_name)"'

# Fail a script when the report says so
stacksentry scan compose compose.yaml --format json --fail-on high --output report.json
jq -e '.summary.result != "fail"' report.json
```
