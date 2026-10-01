# Test data

- `compose/` contains Compose fixtures used by the loader, rule, report and CLI
  tests: valid, hardened, partial, invalid and edge-case files (ports, volumes,
  capabilities, healthchecks, secrets, variables, suppressions, `include`,
  obsolete `version`, and a directory with an override file).
- `expected/` contains golden outputs. Regenerate them with `make golden` and
  review the diff before committing.

All credentials in the fixtures are fake and exist only to test masking.
