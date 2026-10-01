# Security model

## Purpose and intended use

StackSentry is a defensive tool. It helps people who operate Docker Compose
stacks and Docker hosts find risky configuration *before* it causes harm. Use
it only on systems and files you own or are explicitly authorized to assess.
It performs no exploitation, network scanning or remote access.

## Threat model

StackSentry looks for configuration that makes the following outcomes more
likely:

- **Host takeover from a container:** Docker socket access, privileged mode,
  dangerous capabilities, sensitive host mounts, host networking, unencrypted
  Docker API listeners.
- **Unintended network exposure:** databases and admin interfaces published on
  all interfaces, often bypassing host firewalls because Docker manages its own
  iptables rules.
- **Credential leakage:** secrets written into Compose files and environment
  files that may end up in version control.
- **Operational failure:** missing restart policies and healthchecks, data
  stored without volumes, unbounded logs, missing resource limits.
- **Supply-chain drift:** mutable image tags and missing digests.

Out of scope for v0.1.0: vulnerability scanning of image contents (CVEs),
runtime behavior, kernel or Docker Engine vulnerabilities, network firewall
configuration and orchestration platforms other than Docker Compose and the
Docker Engine.

## Local-only operation

- No telemetry, analytics or update checks.
- No cloud service, account or API key.
- No network access during a Compose scan.
- A host scan talks only to the Docker daemon selected by `DOCKER_HOST`
  (by default the local socket). If you point `DOCKER_HOST` at a remote
  daemon, that connection is the only network traffic.
- No shell commands are executed. Host information is collected through the
  Docker Engine API and, on Linux, by reading `/etc/docker/daemon.json` and
  files under `/proc`.

## Data handling

- **Inputs read:** the Compose files you pass (plus files referenced by
  `extends`), and on host scans the Docker API responses and the files listed
  above. `env_file` contents, `.env` files and your shell environment are not
  read during Compose scans.
- **Secrets:** values of environment variables that look like credentials
  are never printed. They are replaced with a fixed-length mask
  (`********`) in all formats, and a final redaction pass removes such values
  from every report field in case they appear elsewhere. Tests assert that
  fixture secrets never appear in table, JSON or Markdown output.
- **Outputs:** reports go to stdout or to the file given with `--output`.
  Report files are written atomically with permissions `0600`, because they
  describe your infrastructure. Treat them as internal documents.
- **No persistence:** StackSentry keeps no cache, database or log files.

## Safety guarantees

- Read-only: StackSentry never modifies Compose files, containers, images,
  networks, volumes or daemon configuration. v0.1.0 contains no automatic
  remediation.
- Least privilege: host scans do not ask for elevated privileges. Information
  that cannot be read with the current permissions is listed as a scan
  limitation rather than causing a failure.
- Robust parsing: malformed input produces an error with exit code 2, never a
  panic. A failing rule is isolated and reported as a warning.

## Limitations

- Findings are heuristics based on configuration. They can be false positives
  (for example a monitoring agent that legitimately mounts `/proc`) or miss
  issues that are configured outside the scanned files (image `USER`,
  daemon-wide log rotation, values injected at deploy time).
- Static analysis does not know your deployment environment. Variables without
  defaults are evaluated as empty.
- The host scan sees the daemon at one point in time and only what the API and
  the readable files expose.

StackSentry findings support, but do not replace, a complete security review,
threat modeling for your environment, image vulnerability scanning and regular
patching.

## Reporting vulnerabilities in StackSentry

See [SECURITY.md](../SECURITY.md).
