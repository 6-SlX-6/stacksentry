# StackSentry Scan Report

## Scan Summary

| Property | Value |
|---|---|
| Scanner | StackSentry v0.1.0 |
| Scan type | Docker Compose (static analysis) |
| Scan time | 2026-10-01T12:00:00Z |
| Rules evaluated | 27 of 27 |
| Findings | 21 |
| Minimum severity shown | info |
| Fail-on threshold | not set |

## Target

| Property | Value |
|---|---|
| Compose files | `examples/n8n-postgres-compose.yaml` |
| Project | `n8n` |
| Services analyzed | 2 |
| Services | `n8n`, `postgres` |

## Finding Statistics

| Severity | Found | Shown in this report |
|---|---:|---:|
| Critical | 0 | 0 |
| High | 1 | 1 |
| Medium | 8 | 8 |
| Low | 12 | 12 |
| Info | 0 | 0 |
| **Total** | **21** | **21** |

## Findings by Severity

### High (1)

| # | Rule | Target | Finding |
|---:|---|---|---|
| 1 | SST-NET-001 | `postgres` | Publicly published database port |

### Medium (8)

| # | Rule | Target | Finding |
|---:|---|---|---|
| 2 | SST-CFG-001 | `n8n` | Required environment variable may be missing |
| 3 | SST-CFG-001 | `postgres` | Required environment variable may be missing |
| 4 | SST-OPS-001 | `n8n` | No healthcheck configured |
| 5 | SST-OPS-005 | `n8n` | Mutable image tag |
| 6 | SST-RES-003 | `n8n` | No log rotation configured |
| 7 | SST-RES-003 | `postgres` | No log rotation configured |
| 8 | SST-SEC-008 | `n8n` | No explicit non-root user |
| 9 | SST-SEC-008 | `postgres` | No explicit non-root user |

### Low (12)

| # | Rule | Target | Finding |
|---:|---|---|---|
| 10 | SST-OPS-004 | `n8n` | Container name explicitly hardcoded |
| 11 | SST-OPS-006 | `postgres` | Image digest not pinned |
| 12 | SST-OPS-007 | `n8n` | No stop grace period |
| 13 | SST-OPS-007 | `postgres` | No stop grace period |
| 14 | SST-RES-001 | `n8n` | No memory limit configured |
| 15 | SST-RES-001 | `postgres` | No memory limit configured |
| 16 | SST-RES-002 | `n8n` | No CPU limit configured |
| 17 | SST-RES-002 | `postgres` | No CPU limit configured |
| 18 | SST-SEC-005 | `n8n` | Linux capabilities not dropped |
| 19 | SST-SEC-005 | `postgres` | Linux capabilities not dropped |
| 20 | SST-SEC-009 | `n8n` | Read-only root filesystem not enabled |
| 21 | SST-SEC-009 | `postgres` | Read-only root filesystem not enabled |

## Detailed Findings

### 1. SST-NET-001: Publicly published database port

- **Rule ID:** SST-NET-001 (version 1.0)
- **Severity:** high
- **Category:** networking
- **Confidence:** high
- **Affected target:** service `postgres` (`examples/n8n-postgres-compose.yaml:30`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-net-001>

**Description:** A database port is published on all host interfaces.

**Evidence:**

```text
5432:5432/tcp (PostgreSQL port published on all host interfaces)
```

**Why it matters:** Published database ports are reachable from other machines and, on many Linux hosts, bypass host firewalls such as UFW or firewalld because Docker manages its own iptables rules. Databases reachable from the network are frequent targets of credential brute-forcing and ransom attacks.

**Recommended remediation:** Remove the ports entry if only other containers need the database; they can reach it over the Compose network by service name. If host access is required, bind to localhost, e.g. "127.0.0.1:5432:5432". Exposure may be intentional, but it should be reviewed.

### 2. SST-CFG-001: Required environment variable may be missing

- **Rule ID:** SST-CFG-001 (version 1.0)
- **Severity:** medium
- **Category:** operations
- **Confidence:** high
- **Affected target:** service `n8n` (`examples/n8n-postgres-compose.yaml:7`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-cfg-001>

**Description:** The Compose file uses variables without a default value, so the deployment depends on external configuration.

**Evidence:**

```text
${POSTGRES_PASSWORD} has no default (examples/n8n-postgres-compose.yaml:19, services.n8n.environment.DB_POSTGRESDB_PASSWORD)
${N8N_ENCRYPTION_KEY} has no default (examples/n8n-postgres-compose.yaml:20, services.n8n.environment.N8N_ENCRYPTION_KEY)
```

**Why it matters:** If such a variable is not set at deploy time, Docker Compose substitutes an empty string and only prints a warning. That can silently produce broken or insecure configuration such as empty passwords, wrong image tags or unexpected port bindings.

**Recommended remediation:** Document the variable and provide it in the deployment environment or .env file. Use ${VAR:-default} for a safe default, or ${VAR:?error message} to make Compose fail fast when it is missing.

### 3. SST-CFG-001: Required environment variable may be missing

- **Rule ID:** SST-CFG-001 (version 1.0)
- **Severity:** medium
- **Category:** operations
- **Confidence:** high
- **Affected target:** service `postgres` (`examples/n8n-postgres-compose.yaml:30`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-cfg-001>

**Description:** The Compose file uses variables without a default value, so the deployment depends on external configuration.

**Evidence:**

```text
${POSTGRES_PASSWORD} has no default (examples/n8n-postgres-compose.yaml:38, services.postgres.environment.POSTGRES_PASSWORD)
```

**Why it matters:** If such a variable is not set at deploy time, Docker Compose substitutes an empty string and only prints a warning. That can silently produce broken or insecure configuration such as empty passwords, wrong image tags or unexpected port bindings.

**Recommended remediation:** Document the variable and provide it in the deployment environment or .env file. Use ${VAR:-default} for a safe default, or ${VAR:?error message} to make Compose fail fast when it is missing.

### 4. SST-OPS-001: No healthcheck configured

- **Rule ID:** SST-OPS-001 (version 1.0)
- **Severity:** medium
- **Category:** reliability
- **Confidence:** high
- **Affected target:** service `n8n` (`examples/n8n-postgres-compose.yaml:7`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-001>

**Description:** No healthcheck is defined for the service in the Compose file.

**Evidence:**

```text
healthcheck is not defined
```

**Why it matters:** Without a healthcheck Docker only knows whether the process is running, not whether it works. depends\_on with condition: service\_healthy, automated recovery and monitoring cannot detect a hung or misconfigured service.

**Recommended remediation:** Add a healthcheck that exercises the service (for example an HTTP endpoint or a database ping) with sensible interval, timeout, retries and start\_period values.

### 5. SST-OPS-005: Mutable image tag

- **Rule ID:** SST-OPS-005 (version 1.0)
- **Severity:** medium
- **Category:** supply-chain
- **Confidence:** high
- **Affected target:** service `n8n` (`examples/n8n-postgres-compose.yaml:7`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-005>

**Description:** The image uses a mutable tag (latest or no tag at all).

**Evidence:**

```text
image: n8nio/n8n:latest
```

**Why it matters:** Mutable tags can point to a different image every time you pull. Deployments become non-reproducible, rollbacks unreliable, and unreviewed upstream changes can reach production silently.

**Recommended remediation:** Pin a specific version tag (for example postgres:16.4) and update it deliberately. For full reproducibility also pin the digest (image: name:tag@sha256:...).

### 6. SST-RES-003: No log rotation configured

- **Rule ID:** SST-RES-003 (version 1.0)
- **Severity:** medium
- **Category:** resource-management
- **Confidence:** high
- **Affected target:** service `n8n` (`examples/n8n-postgres-compose.yaml:7`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-res-003>

**Description:** Container logs are not configured to rotate.

**Evidence:**

```text
logging is not configured (the daemon's default log driver applies)
```

**Why it matters:** Docker's default json-file log driver keeps logs without limit unless max-size is set, so a chatty container can fill the disk.

**Recommended remediation:** Configure rotation, for example logging: {driver: json-file, options: {max-size: "10m", max-file: "3"}}, or set log-driver/log-opts once for all containers in the Docker daemon configuration.

### 7. SST-RES-003: No log rotation configured

- **Rule ID:** SST-RES-003 (version 1.0)
- **Severity:** medium
- **Category:** resource-management
- **Confidence:** high
- **Affected target:** service `postgres` (`examples/n8n-postgres-compose.yaml:30`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-res-003>

**Description:** Container logs are not configured to rotate.

**Evidence:**

```text
logging is not configured (the daemon's default log driver applies)
```

**Why it matters:** Docker's default json-file log driver keeps logs without limit unless max-size is set, so a chatty container can fill the disk.

**Recommended remediation:** Configure rotation, for example logging: {driver: json-file, options: {max-size: "10m", max-file: "3"}}, or set log-driver/log-opts once for all containers in the Docker daemon configuration.

### 8. SST-SEC-008: No explicit non-root user

- **Rule ID:** SST-SEC-008 (version 1.0)
- **Severity:** medium
- **Category:** security
- **Confidence:** high
- **Affected target:** service `n8n` (`examples/n8n-postgres-compose.yaml:7`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-008>

**Description:** No user is configured, so the container runs as the image's default user, which is root for many images.

**Evidence:**

```text
user is not set
```

**Why it matters:** Processes running as root inside a container have more power if they escape isolation or write to mounted volumes. Without a user setting the effective user depends on the image's USER instruction, which StackSentry cannot see without pulling the image.

**Recommended remediation:** Add a dedicated unprivileged user where supported by the image, e.g. user: "1000:1000" or a named user documented by the image (such as node). Make sure mounted volumes are writable by that UID.

### 9. SST-SEC-008: No explicit non-root user

- **Rule ID:** SST-SEC-008 (version 1.0)
- **Severity:** medium
- **Category:** security
- **Confidence:** high
- **Affected target:** service `postgres` (`examples/n8n-postgres-compose.yaml:30`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-008>

**Description:** No user is configured, so the container runs as the image's default user, which is root for many images.

**Evidence:**

```text
user is not set
```

**Why it matters:** Processes running as root inside a container have more power if they escape isolation or write to mounted volumes. Without a user setting the effective user depends on the image's USER instruction, which StackSentry cannot see without pulling the image.

**Recommended remediation:** Add a dedicated unprivileged user where supported by the image, e.g. user: "1000:1000" or a named user documented by the image (such as node). Make sure mounted volumes are writable by that UID.

### 10. SST-OPS-004: Container name explicitly hardcoded

- **Rule ID:** SST-OPS-004 (version 1.0)
- **Severity:** low
- **Category:** maintainability
- **Confidence:** high
- **Affected target:** service `n8n` (`examples/n8n-postgres-compose.yaml:7`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-004>

**Description:** The service sets a fixed container\_name.

**Evidence:**

```text
container_name: n8n
```

**Why it matters:** Fixed container names must be unique on the host. They prevent scaling the service, can clash with other projects or copies of the same stack, and bypass Compose's project-scoped naming.

**Recommended remediation:** Remove container\_name and let Compose generate project-scoped names. Other services can reach it by its service name, which works without container\_name.

### 11. SST-OPS-006: Image digest not pinned

- **Rule ID:** SST-OPS-006 (version 1.0)
- **Severity:** low
- **Category:** supply-chain
- **Confidence:** high
- **Affected target:** service `postgres` (`examples/n8n-postgres-compose.yaml:30`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-006>

**Description:** The image is pinned by version tag but not by digest.

**Evidence:**

```text
image: postgres:16.4 has no @sha256 digest
```

**Why it matters:** Tags can be re-pushed by the publisher, so the same tag may resolve to different content over time. Pinning the digest guarantees that every deployment runs exactly the reviewed image. This is a reproducibility recommendation, not a security vulnerability.

**Recommended remediation:** Append the digest: image: name:tag@sha256:\<digest\> (look it up with docker buildx imagetools inspect name:tag). Tools such as Renovate or Dependabot can keep digests up to date.

### 12. SST-OPS-007: No stop grace period

- **Rule ID:** SST-OPS-007 (version 1.0)
- **Severity:** low
- **Category:** reliability
- **Confidence:** high
- **Affected target:** service `n8n` (`examples/n8n-postgres-compose.yaml:7`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-007>

**Description:** No stop\_grace\_period is set, so Docker kills the container 10 seconds after asking it to stop.

**Evidence:**

```text
stop_grace_period is not set (Docker default: 10s)
```

**Why it matters:** Databases, queues and workflow engines may need more than 10 seconds to flush data, finish jobs or close connections. A forced kill can corrupt data or lose in-flight work.

**Recommended remediation:** Set stop\_grace\_period to match the service's shutdown behavior (for example stop\_grace\_period: 30s for databases and workflow tools) and make sure the process handles SIGTERM or the configured stop\_signal.

### 13. SST-OPS-007: No stop grace period

- **Rule ID:** SST-OPS-007 (version 1.0)
- **Severity:** low
- **Category:** reliability
- **Confidence:** high
- **Affected target:** service `postgres` (`examples/n8n-postgres-compose.yaml:30`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-007>

**Description:** No stop\_grace\_period is set, so Docker kills the container 10 seconds after asking it to stop.

**Evidence:**

```text
stop_grace_period is not set (Docker default: 10s)
```

**Why it matters:** Databases, queues and workflow engines may need more than 10 seconds to flush data, finish jobs or close connections. A forced kill can corrupt data or lose in-flight work.

**Recommended remediation:** Set stop\_grace\_period to match the service's shutdown behavior (for example stop\_grace\_period: 30s for databases and workflow tools) and make sure the process handles SIGTERM or the configured stop\_signal.

### 14. SST-RES-001: No memory limit configured

- **Rule ID:** SST-RES-001 (version 1.0)
- **Severity:** low
- **Category:** resource-management
- **Confidence:** high
- **Affected target:** service `n8n` (`examples/n8n-postgres-compose.yaml:7`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-res-001>

**Description:** No memory limit is configured for the service.

**Evidence:**

```text
deploy.resources.limits.memory and mem_limit are not set
```

**Why it matters:** A memory leak or load spike in one container can consume all host memory and trigger the kernel OOM killer for unrelated processes, including other services on the host.

**Recommended remediation:** Set deploy.resources.limits.memory (for example 512M) based on observed usage, or mem\_limit for older Compose versions.

### 15. SST-RES-001: No memory limit configured

- **Rule ID:** SST-RES-001 (version 1.0)
- **Severity:** low
- **Category:** resource-management
- **Confidence:** high
- **Affected target:** service `postgres` (`examples/n8n-postgres-compose.yaml:30`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-res-001>

**Description:** No memory limit is configured for the service.

**Evidence:**

```text
deploy.resources.limits.memory and mem_limit are not set
```

**Why it matters:** A memory leak or load spike in one container can consume all host memory and trigger the kernel OOM killer for unrelated processes, including other services on the host.

**Recommended remediation:** Set deploy.resources.limits.memory (for example 512M) based on observed usage, or mem\_limit for older Compose versions.

### 16. SST-RES-002: No CPU limit configured

- **Rule ID:** SST-RES-002 (version 1.0)
- **Severity:** low
- **Category:** resource-management
- **Confidence:** high
- **Affected target:** service `n8n` (`examples/n8n-postgres-compose.yaml:7`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-res-002>

**Description:** No CPU limit is configured for the service.

**Evidence:**

```text
deploy.resources.limits.cpus and cpus are not set
```

**Why it matters:** Without a CPU limit a busy or runaway container can starve other services on the same host.

**Recommended remediation:** Set deploy.resources.limits.cpus (for example "1.0") or cpus for older Compose versions.

### 17. SST-RES-002: No CPU limit configured

- **Rule ID:** SST-RES-002 (version 1.0)
- **Severity:** low
- **Category:** resource-management
- **Confidence:** high
- **Affected target:** service `postgres` (`examples/n8n-postgres-compose.yaml:30`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-res-002>

**Description:** No CPU limit is configured for the service.

**Evidence:**

```text
deploy.resources.limits.cpus and cpus are not set
```

**Why it matters:** Without a CPU limit a busy or runaway container can starve other services on the same host.

**Recommended remediation:** Set deploy.resources.limits.cpus (for example "1.0") or cpus for older Compose versions.

### 18. SST-SEC-005: Linux capabilities not dropped

- **Rule ID:** SST-SEC-005 (version 1.0)
- **Severity:** low
- **Category:** security
- **Confidence:** high
- **Affected target:** service `n8n` (`examples/n8n-postgres-compose.yaml:7`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-005>

**Description:** The service keeps Docker's default Linux capabilities (cap\_drop does not contain ALL).

**Evidence:**

```text
cap_drop is not set
```

**Why it matters:** Docker grants containers a default capability set (for example CHOWN, SETUID, NET\_RAW). Most applications need few or none of them. This is a hardening recommendation, not a defect: some images need specific capabilities to start.

**Recommended remediation:** Add cap\_drop: \[ALL\] and add back only what the service needs with cap\_add (for example NET\_BIND\_SERVICE to bind ports below 1024). Test the service after the change.

### 19. SST-SEC-005: Linux capabilities not dropped

- **Rule ID:** SST-SEC-005 (version 1.0)
- **Severity:** low
- **Category:** security
- **Confidence:** high
- **Affected target:** service `postgres` (`examples/n8n-postgres-compose.yaml:30`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-005>

**Description:** The service keeps Docker's default Linux capabilities (cap\_drop does not contain ALL).

**Evidence:**

```text
cap_drop is not set
```

**Why it matters:** Docker grants containers a default capability set (for example CHOWN, SETUID, NET\_RAW). Most applications need few or none of them. This is a hardening recommendation, not a defect: some images need specific capabilities to start.

**Recommended remediation:** Add cap\_drop: \[ALL\] and add back only what the service needs with cap\_add (for example NET\_BIND\_SERVICE to bind ports below 1024). Test the service after the change.

### 20. SST-SEC-009: Read-only root filesystem not enabled

- **Rule ID:** SST-SEC-009 (version 1.0)
- **Severity:** low
- **Category:** security
- **Confidence:** high
- **Affected target:** service `n8n` (`examples/n8n-postgres-compose.yaml:7`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-009>

**Description:** The container's root filesystem is writable (read\_only: true is not set).

**Evidence:**

```text
read_only is not set
```

**Why it matters:** A read-only root filesystem prevents an attacker from modifying binaries or dropping tools inside the container and makes unexpected writes visible.

**Recommended remediation:** Set read\_only: true and provide writable locations explicitly with tmpfs (for example /tmp or /run) or volumes for application data. Many applications need some writable directories; test before enforcing.

### 21. SST-SEC-009: Read-only root filesystem not enabled

- **Rule ID:** SST-SEC-009 (version 1.0)
- **Severity:** low
- **Category:** security
- **Confidence:** high
- **Affected target:** service `postgres` (`examples/n8n-postgres-compose.yaml:30`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-009>

**Description:** The container's root filesystem is writable (read\_only: true is not set).

**Evidence:**

```text
read_only is not set
```

**Why it matters:** A read-only root filesystem prevents an attacker from modifying binaries or dropping tools inside the container and makes unexpected writes visible.

**Recommended remediation:** Set read\_only: true and provide writable locations explicitly with tmpfs (for example /tmp or /run) or volumes for application data. Many applications need some writable directories; test before enforcing.

## Scan Limitations

- Static analysis sees only the Compose files. Image contents (USER, HEALTHCHECK), daemon-wide settings such as daemon.json log rotation, and values injected at deploy time are not visible to this scan.

## Remediation Priorities

1. **Fix soon (high)**
   - SST-NET-001 Publicly published database port: `postgres`
2. **Plan a fix (medium)**
   - SST-CFG-001 Required environment variable may be missing: `n8n`, `postgres`
   - SST-OPS-001 No healthcheck configured: `n8n`
   - SST-OPS-005 Mutable image tag: `n8n`
   - SST-RES-003 No log rotation configured: `n8n`, `postgres`
   - SST-SEC-008 No explicit non-root user: `n8n`, `postgres`
3. **Hardening backlog (low and info)**
   - SST-OPS-004 Container name explicitly hardcoded: `n8n`
   - SST-OPS-006 Image digest not pinned: `postgres`
   - SST-OPS-007 No stop grace period: `n8n`, `postgres`
   - SST-RES-001 No memory limit configured: `n8n`, `postgres`
   - SST-RES-002 No CPU limit configured: `n8n`, `postgres`
   - SST-SEC-005 Linux capabilities not dropped: `n8n`, `postgres`
   - SST-SEC-009 Read-only root filesystem not enabled: `n8n`, `postgres`

## Generated By

Generated by StackSentry v0.1.0 on 2026-10-01T12:00:00Z. StackSentry performs local, deterministic, rule-based analysis; no data left the machine that ran the scan. Findings support, but do not replace, a complete security review.
