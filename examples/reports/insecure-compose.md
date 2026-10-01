# StackSentry Scan Report

## Scan Summary

| Property | Value |
|---|---|
| Scanner | StackSentry v0.1.0 |
| Scan type | Docker Compose (static analysis) |
| Scan time | 2026-10-01T12:00:00Z |
| Rules evaluated | 27 of 27 |
| Findings | 35 |
| Minimum severity shown | info |
| Fail-on threshold | not set |

## Target

| Property | Value |
|---|---|
| Compose files | `examples/insecure-compose.yaml` |
| Project | `insecure-demo` |
| Services analyzed | 3 |
| Services | `db`, `manager`, `metrics` |

## Finding Statistics

| Severity | Found | Shown in this report |
|---|---:|---:|
| Critical | 2 | 2 |
| High | 5 | 5 |
| Medium | 13 | 13 |
| Low | 13 | 13 |
| Info | 2 | 2 |
| **Total** | **35** | **35** |

## Findings by Severity

### Critical (2)

| # | Rule | Target | Finding |
|---:|---|---|---|
| 1 | SST-SEC-001 | `manager` | Docker socket mount detected |
| 2 | SST-SEC-002 | `manager` | Privileged container detected |

### High (5)

| # | Rule | Target | Finding |
|---:|---|---|---|
| 3 | SST-NET-001 | `db` | Publicly published database port |
| 4 | SST-OPS-003 | `db` | No restart policy configured |
| 5 | SST-OPS-003 | `manager` | No restart policy configured |
| 6 | SST-SEC-003 | `metrics` | Host network mode detected |
| 7 | SST-SEC-011 | `db` | Likely secret in environment variable |

### Medium (13)

| # | Rule | Target | Finding |
|---:|---|---|---|
| 8 | SST-OPS-001 | `db` | No healthcheck configured |
| 9 | SST-OPS-001 | `manager` | No healthcheck configured |
| 10 | SST-OPS-001 | `metrics` | No healthcheck configured |
| 11 | SST-OPS-005 | `db` | Mutable image tag |
| 12 | SST-OPS-005 | `manager` | Mutable image tag |
| 13 | SST-RES-003 | `db` | No log rotation configured |
| 14 | SST-RES-003 | `manager` | No log rotation configured |
| 15 | SST-RES-003 | `metrics` | No log rotation configured |
| 16 | SST-SEC-006 | `db` | Writable host bind mount |
| 17 | SST-SEC-006 | `manager` | Writable host bind mount |
| 18 | SST-SEC-008 | `db` | No explicit non-root user |
| 19 | SST-SEC-008 | `manager` | No explicit non-root user |
| 20 | SST-SEC-008 | `metrics` | No explicit non-root user |

### Low (13)

| # | Rule | Target | Finding |
|---:|---|---|---|
| 21 | SST-OPS-006 | `metrics` | Image digest not pinned |
| 22 | SST-OPS-007 | `db` | No stop grace period |
| 23 | SST-RES-001 | `db` | No memory limit configured |
| 24 | SST-RES-001 | `manager` | No memory limit configured |
| 25 | SST-RES-001 | `metrics` | No memory limit configured |
| 26 | SST-RES-002 | `db` | No CPU limit configured |
| 27 | SST-RES-002 | `manager` | No CPU limit configured |
| 28 | SST-RES-002 | `metrics` | No CPU limit configured |
| 29 | SST-SEC-005 | `db` | Linux capabilities not dropped |
| 30 | SST-SEC-005 | `metrics` | Linux capabilities not dropped |
| 31 | SST-SEC-009 | `db` | Read-only root filesystem not enabled |
| 32 | SST-SEC-009 | `manager` | Read-only root filesystem not enabled |
| 33 | SST-SEC-009 | `metrics` | Read-only root filesystem not enabled |

### Info (2)

| # | Rule | Target | Finding |
|---:|---|---|---|
| 34 | SST-OPS-007 | `manager` | No stop grace period |
| 35 | SST-OPS-007 | `metrics` | No stop grace period |

## Detailed Findings

### 1. SST-SEC-001: Docker socket mount detected

- **Rule ID:** SST-SEC-001 (version 1.0)
- **Severity:** critical
- **Category:** security
- **Confidence:** high
- **Affected target:** service `manager` (`examples/insecure-compose.yaml:7`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-001>

**Description:** The Docker daemon socket is mounted into the container.

**Evidence:**

```text
/var/run/docker.sock:/var/run/docker.sock
```

**Why it matters:** Access to the Docker socket can effectively grant host-level control: anyone who can talk to it can start privileged containers and mount the host filesystem. Mounting it read-only (:ro) does not restrict API calls.

**Recommended remediation:** Remove the mount unless this service explicitly requires Docker daemon access. If it does (for example a reverse proxy reading container labels), put a filtering socket proxy in front of the socket that only allows the required read-only API endpoints.

### 2. SST-SEC-002: Privileged container detected

- **Rule ID:** SST-SEC-002 (version 1.0)
- **Severity:** critical
- **Category:** security
- **Confidence:** high
- **Affected target:** service `manager` (`examples/insecure-compose.yaml:7`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-002>

**Description:** The service runs in privileged mode.

**Evidence:**

```text
privileged: true
```

**Why it matters:** privileged: true grants all Linux capabilities and access to all host devices and disables most isolation (seccomp, AppArmor/SELinux confinement). A compromise of the process is close to a compromise of the host.

**Recommended remediation:** Remove privileged: true. Grant only the specific capabilities (cap\_add) or devices (devices) the workload needs, and document why they are required.

### 3. SST-NET-001: Publicly published database port

- **Rule ID:** SST-NET-001 (version 1.0)
- **Severity:** high
- **Category:** networking
- **Confidence:** high
- **Affected target:** service `db` (`examples/insecure-compose.yaml:23`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-net-001>

**Description:** A database port is published on all host interfaces.

**Evidence:**

```text
5432:5432/tcp (PostgreSQL port published on all host interfaces)
```

**Why it matters:** Published database ports are reachable from other machines and, on many Linux hosts, bypass host firewalls such as UFW or firewalld because Docker manages its own iptables rules. Databases reachable from the network are frequent targets of credential brute-forcing and ransom attacks.

**Recommended remediation:** Remove the ports entry if only other containers need the database; they can reach it over the Compose network by service name. If host access is required, bind to localhost, e.g. "127.0.0.1:5432:5432". Exposure may be intentional, but it should be reviewed.

### 4. SST-OPS-003: No restart policy configured

- **Rule ID:** SST-OPS-003 (version 1.0)
- **Severity:** high
- **Category:** reliability
- **Confidence:** high
- **Affected target:** service `db` (`examples/insecure-compose.yaml:23`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-003>

**Description:** No restart policy is configured, so the container stays down after a crash or host reboot.

**Evidence:**

```text
restart is missing
```

**Why it matters:** Docker's default restart policy is "no". A long-running service that crashes, or whose host reboots, stays down until someone intervenes.

**Recommended remediation:** Add: restart: unless-stopped (or always / on-failure, depending on the desired behavior).

### 5. SST-OPS-003: No restart policy configured

- **Rule ID:** SST-OPS-003 (version 1.0)
- **Severity:** high
- **Category:** reliability
- **Confidence:** high
- **Affected target:** service `manager` (`examples/insecure-compose.yaml:7`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-003>

**Description:** No restart policy is configured, so the container stays down after a crash or host reboot.

**Evidence:**

```text
restart is missing
```

**Why it matters:** Docker's default restart policy is "no". A long-running service that crashes, or whose host reboots, stays down until someone intervenes.

**Recommended remediation:** Add: restart: unless-stopped (or always / on-failure, depending on the desired behavior).

### 6. SST-SEC-003: Host network mode detected

- **Rule ID:** SST-SEC-003 (version 1.0)
- **Severity:** high
- **Category:** security
- **Confidence:** high
- **Affected target:** service `metrics` (`examples/insecure-compose.yaml:18`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-003>

**Description:** The service shares the host's network stack (network\_mode: host).

**Evidence:**

```text
network_mode: host
```

**Why it matters:** Host networking removes normal Docker network isolation: every port the process opens is reachable on all host interfaces, port publishing rules no longer apply, and the container can reach services bound to the host's localhost.

**Recommended remediation:** Use a bridge network and publish only the required ports, preferably bound to 127.0.0.1 or a specific interface. Keep host networking only for workloads that need it (for example some discovery or VPN tools) and document the exception.

### 7. SST-SEC-011: Likely secret in environment variable

- **Rule ID:** SST-SEC-011 (version 1.0)
- **Severity:** high
- **Category:** secrets
- **Confidence:** high
- **Affected target:** service `db` (`examples/insecure-compose.yaml:23`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-011>

**Description:** An environment variable that looks like a credential has an inline value in the Compose file.

**Evidence:**

```text
POSTGRES_PASSWORD=********
```

**Why it matters:** Inline secrets end up in version control, backups, CI logs and docker inspect output, and are visible to everyone who can read the Compose file.

**Recommended remediation:** Move the value out of the Compose file: use Docker secrets (with \*\_FILE variables where the image supports them), an external secret manager, or interpolation such as ${DB\_PASSWORD} with the value injected at deploy time from an environment file that is not committed. Rotate the secret if the file was ever shared.

### 8. SST-OPS-001: No healthcheck configured

- **Rule ID:** SST-OPS-001 (version 1.0)
- **Severity:** medium
- **Category:** reliability
- **Confidence:** high
- **Affected target:** service `db` (`examples/insecure-compose.yaml:23`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-001>

**Description:** No healthcheck is defined for the service in the Compose file.

**Evidence:**

```text
healthcheck is not defined
```

**Why it matters:** Without a healthcheck Docker only knows whether the process is running, not whether it works. depends\_on with condition: service\_healthy, automated recovery and monitoring cannot detect a hung or misconfigured service.

**Recommended remediation:** Add a healthcheck that exercises the service (for example an HTTP endpoint or a database ping) with sensible interval, timeout, retries and start\_period values.

### 9. SST-OPS-001: No healthcheck configured

- **Rule ID:** SST-OPS-001 (version 1.0)
- **Severity:** medium
- **Category:** reliability
- **Confidence:** high
- **Affected target:** service `manager` (`examples/insecure-compose.yaml:7`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-001>

**Description:** No healthcheck is defined for the service in the Compose file.

**Evidence:**

```text
healthcheck is not defined
```

**Why it matters:** Without a healthcheck Docker only knows whether the process is running, not whether it works. depends\_on with condition: service\_healthy, automated recovery and monitoring cannot detect a hung or misconfigured service.

**Recommended remediation:** Add a healthcheck that exercises the service (for example an HTTP endpoint or a database ping) with sensible interval, timeout, retries and start\_period values.

### 10. SST-OPS-001: No healthcheck configured

- **Rule ID:** SST-OPS-001 (version 1.0)
- **Severity:** medium
- **Category:** reliability
- **Confidence:** high
- **Affected target:** service `metrics` (`examples/insecure-compose.yaml:18`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-001>

**Description:** No healthcheck is defined for the service in the Compose file.

**Evidence:**

```text
healthcheck is not defined
```

**Why it matters:** Without a healthcheck Docker only knows whether the process is running, not whether it works. depends\_on with condition: service\_healthy, automated recovery and monitoring cannot detect a hung or misconfigured service.

**Recommended remediation:** Add a healthcheck that exercises the service (for example an HTTP endpoint or a database ping) with sensible interval, timeout, retries and start\_period values.

### 11. SST-OPS-005: Mutable image tag

- **Rule ID:** SST-OPS-005 (version 1.0)
- **Severity:** medium
- **Category:** supply-chain
- **Confidence:** high
- **Affected target:** service `db` (`examples/insecure-compose.yaml:23`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-005>

**Description:** The image uses a mutable tag (latest or no tag at all).

**Evidence:**

```text
image: postgres:latest
```

**Why it matters:** Mutable tags can point to a different image every time you pull. Deployments become non-reproducible, rollbacks unreliable, and unreviewed upstream changes can reach production silently.

**Recommended remediation:** Pin a specific version tag (for example postgres:16.4) and update it deliberately. For full reproducibility also pin the digest (image: name:tag@sha256:...).

### 12. SST-OPS-005: Mutable image tag

- **Rule ID:** SST-OPS-005 (version 1.0)
- **Severity:** medium
- **Category:** supply-chain
- **Confidence:** high
- **Affected target:** service `manager` (`examples/insecure-compose.yaml:7`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-005>

**Description:** The image uses a mutable tag (latest or no tag at all).

**Evidence:**

```text
image: example/stack-manager:latest
```

**Why it matters:** Mutable tags can point to a different image every time you pull. Deployments become non-reproducible, rollbacks unreliable, and unreviewed upstream changes can reach production silently.

**Recommended remediation:** Pin a specific version tag (for example postgres:16.4) and update it deliberately. For full reproducibility also pin the digest (image: name:tag@sha256:...).

### 13. SST-RES-003: No log rotation configured

- **Rule ID:** SST-RES-003 (version 1.0)
- **Severity:** medium
- **Category:** resource-management
- **Confidence:** high
- **Affected target:** service `db` (`examples/insecure-compose.yaml:23`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-res-003>

**Description:** Container logs are not configured to rotate.

**Evidence:**

```text
logging is not configured (the daemon's default log driver applies)
```

**Why it matters:** Docker's default json-file log driver keeps logs without limit unless max-size is set, so a chatty container can fill the disk.

**Recommended remediation:** Configure rotation, for example logging: {driver: json-file, options: {max-size: "10m", max-file: "3"}}, or set log-driver/log-opts once for all containers in the Docker daemon configuration.

### 14. SST-RES-003: No log rotation configured

- **Rule ID:** SST-RES-003 (version 1.0)
- **Severity:** medium
- **Category:** resource-management
- **Confidence:** high
- **Affected target:** service `manager` (`examples/insecure-compose.yaml:7`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-res-003>

**Description:** Container logs are not configured to rotate.

**Evidence:**

```text
logging is not configured (the daemon's default log driver applies)
```

**Why it matters:** Docker's default json-file log driver keeps logs without limit unless max-size is set, so a chatty container can fill the disk.

**Recommended remediation:** Configure rotation, for example logging: {driver: json-file, options: {max-size: "10m", max-file: "3"}}, or set log-driver/log-opts once for all containers in the Docker daemon configuration.

### 15. SST-RES-003: No log rotation configured

- **Rule ID:** SST-RES-003 (version 1.0)
- **Severity:** medium
- **Category:** resource-management
- **Confidence:** high
- **Affected target:** service `metrics` (`examples/insecure-compose.yaml:18`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-res-003>

**Description:** Container logs are not configured to rotate.

**Evidence:**

```text
logging is not configured (the daemon's default log driver applies)
```

**Why it matters:** Docker's default json-file log driver keeps logs without limit unless max-size is set, so a chatty container can fill the disk.

**Recommended remediation:** Configure rotation, for example logging: {driver: json-file, options: {max-size: "10m", max-file: "3"}}, or set log-driver/log-opts once for all containers in the Docker daemon configuration.

### 16. SST-SEC-006: Writable host bind mount

- **Rule ID:** SST-SEC-006 (version 1.0)
- **Severity:** medium
- **Category:** security
- **Confidence:** high
- **Affected target:** service `db` (`examples/insecure-compose.yaml:23`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-006>

**Description:** A host path is bind-mounted without read-only protection.

**Evidence:**

```text
./pgdata:/var/lib/postgresql/data (read-write)
```

**Why it matters:** A writable bind mount lets the container modify files on the host. If the container is compromised, an attacker can tamper with host files, configuration or data shared with other services.

**Recommended remediation:** Append :ro (short syntax) or set read\_only: true (long syntax) for mounts the container only reads, such as configuration files. For data the service must write, prefer a named volume or make sure the host directory is dedicated to this service.

### 17. SST-SEC-006: Writable host bind mount

- **Rule ID:** SST-SEC-006 (version 1.0)
- **Severity:** medium
- **Category:** security
- **Confidence:** high
- **Affected target:** service `manager` (`examples/insecure-compose.yaml:7`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-006>

**Description:** A host path is bind-mounted without read-only protection.

**Evidence:**

```text
./manager-data:/data (read-write)
```

**Why it matters:** A writable bind mount lets the container modify files on the host. If the container is compromised, an attacker can tamper with host files, configuration or data shared with other services.

**Recommended remediation:** Append :ro (short syntax) or set read\_only: true (long syntax) for mounts the container only reads, such as configuration files. For data the service must write, prefer a named volume or make sure the host directory is dedicated to this service.

### 18. SST-SEC-008: No explicit non-root user

- **Rule ID:** SST-SEC-008 (version 1.0)
- **Severity:** medium
- **Category:** security
- **Confidence:** high
- **Affected target:** service `db` (`examples/insecure-compose.yaml:23`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-008>

**Description:** No user is configured, so the container runs as the image's default user, which is root for many images.

**Evidence:**

```text
user is not set
```

**Why it matters:** Processes running as root inside a container have more power if they escape isolation or write to mounted volumes. Without a user setting the effective user depends on the image's USER instruction, which StackSentry cannot see without pulling the image.

**Recommended remediation:** Add a dedicated unprivileged user where supported by the image, e.g. user: "1000:1000" or a named user documented by the image (such as node). Make sure mounted volumes are writable by that UID.

### 19. SST-SEC-008: No explicit non-root user

- **Rule ID:** SST-SEC-008 (version 1.0)
- **Severity:** medium
- **Category:** security
- **Confidence:** high
- **Affected target:** service `manager` (`examples/insecure-compose.yaml:7`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-008>

**Description:** No user is configured, so the container runs as the image's default user, which is root for many images.

**Evidence:**

```text
user is not set
```

**Why it matters:** Processes running as root inside a container have more power if they escape isolation or write to mounted volumes. Without a user setting the effective user depends on the image's USER instruction, which StackSentry cannot see without pulling the image.

**Recommended remediation:** Add a dedicated unprivileged user where supported by the image, e.g. user: "1000:1000" or a named user documented by the image (such as node). Make sure mounted volumes are writable by that UID.

### 20. SST-SEC-008: No explicit non-root user

- **Rule ID:** SST-SEC-008 (version 1.0)
- **Severity:** medium
- **Category:** security
- **Confidence:** high
- **Affected target:** service `metrics` (`examples/insecure-compose.yaml:18`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-008>

**Description:** No user is configured, so the container runs as the image's default user, which is root for many images.

**Evidence:**

```text
user is not set
```

**Why it matters:** Processes running as root inside a container have more power if they escape isolation or write to mounted volumes. Without a user setting the effective user depends on the image's USER instruction, which StackSentry cannot see without pulling the image.

**Recommended remediation:** Add a dedicated unprivileged user where supported by the image, e.g. user: "1000:1000" or a named user documented by the image (such as node). Make sure mounted volumes are writable by that UID.

### 21. SST-OPS-006: Image digest not pinned

- **Rule ID:** SST-OPS-006 (version 1.0)
- **Severity:** low
- **Category:** supply-chain
- **Confidence:** high
- **Affected target:** service `metrics` (`examples/insecure-compose.yaml:18`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-006>

**Description:** The image is pinned by version tag but not by digest.

**Evidence:**

```text
image: prom/node-exporter:v1.8.2 has no @sha256 digest
```

**Why it matters:** Tags can be re-pushed by the publisher, so the same tag may resolve to different content over time. Pinning the digest guarantees that every deployment runs exactly the reviewed image. This is a reproducibility recommendation, not a security vulnerability.

**Recommended remediation:** Append the digest: image: name:tag@sha256:\<digest\> (look it up with docker buildx imagetools inspect name:tag). Tools such as Renovate or Dependabot can keep digests up to date.

### 22. SST-OPS-007: No stop grace period

- **Rule ID:** SST-OPS-007 (version 1.0)
- **Severity:** low
- **Category:** reliability
- **Confidence:** high
- **Affected target:** service `db` (`examples/insecure-compose.yaml:23`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-007>

**Description:** No stop\_grace\_period is set, so Docker kills the container 10 seconds after asking it to stop.

**Evidence:**

```text
stop_grace_period is not set (Docker default: 10s)
```

**Why it matters:** Databases, queues and workflow engines may need more than 10 seconds to flush data, finish jobs or close connections. A forced kill can corrupt data or lose in-flight work.

**Recommended remediation:** Set stop\_grace\_period to match the service's shutdown behavior (for example stop\_grace\_period: 30s for databases and workflow tools) and make sure the process handles SIGTERM or the configured stop\_signal.

### 23. SST-RES-001: No memory limit configured

- **Rule ID:** SST-RES-001 (version 1.0)
- **Severity:** low
- **Category:** resource-management
- **Confidence:** high
- **Affected target:** service `db` (`examples/insecure-compose.yaml:23`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-res-001>

**Description:** No memory limit is configured for the service.

**Evidence:**

```text
deploy.resources.limits.memory and mem_limit are not set
```

**Why it matters:** A memory leak or load spike in one container can consume all host memory and trigger the kernel OOM killer for unrelated processes, including other services on the host.

**Recommended remediation:** Set deploy.resources.limits.memory (for example 512M) based on observed usage, or mem\_limit for older Compose versions.

### 24. SST-RES-001: No memory limit configured

- **Rule ID:** SST-RES-001 (version 1.0)
- **Severity:** low
- **Category:** resource-management
- **Confidence:** high
- **Affected target:** service `manager` (`examples/insecure-compose.yaml:7`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-res-001>

**Description:** No memory limit is configured for the service.

**Evidence:**

```text
deploy.resources.limits.memory and mem_limit are not set
```

**Why it matters:** A memory leak or load spike in one container can consume all host memory and trigger the kernel OOM killer for unrelated processes, including other services on the host.

**Recommended remediation:** Set deploy.resources.limits.memory (for example 512M) based on observed usage, or mem\_limit for older Compose versions.

### 25. SST-RES-001: No memory limit configured

- **Rule ID:** SST-RES-001 (version 1.0)
- **Severity:** low
- **Category:** resource-management
- **Confidence:** high
- **Affected target:** service `metrics` (`examples/insecure-compose.yaml:18`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-res-001>

**Description:** No memory limit is configured for the service.

**Evidence:**

```text
deploy.resources.limits.memory and mem_limit are not set
```

**Why it matters:** A memory leak or load spike in one container can consume all host memory and trigger the kernel OOM killer for unrelated processes, including other services on the host.

**Recommended remediation:** Set deploy.resources.limits.memory (for example 512M) based on observed usage, or mem\_limit for older Compose versions.

### 26. SST-RES-002: No CPU limit configured

- **Rule ID:** SST-RES-002 (version 1.0)
- **Severity:** low
- **Category:** resource-management
- **Confidence:** high
- **Affected target:** service `db` (`examples/insecure-compose.yaml:23`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-res-002>

**Description:** No CPU limit is configured for the service.

**Evidence:**

```text
deploy.resources.limits.cpus and cpus are not set
```

**Why it matters:** Without a CPU limit a busy or runaway container can starve other services on the same host.

**Recommended remediation:** Set deploy.resources.limits.cpus (for example "1.0") or cpus for older Compose versions.

### 27. SST-RES-002: No CPU limit configured

- **Rule ID:** SST-RES-002 (version 1.0)
- **Severity:** low
- **Category:** resource-management
- **Confidence:** high
- **Affected target:** service `manager` (`examples/insecure-compose.yaml:7`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-res-002>

**Description:** No CPU limit is configured for the service.

**Evidence:**

```text
deploy.resources.limits.cpus and cpus are not set
```

**Why it matters:** Without a CPU limit a busy or runaway container can starve other services on the same host.

**Recommended remediation:** Set deploy.resources.limits.cpus (for example "1.0") or cpus for older Compose versions.

### 28. SST-RES-002: No CPU limit configured

- **Rule ID:** SST-RES-002 (version 1.0)
- **Severity:** low
- **Category:** resource-management
- **Confidence:** high
- **Affected target:** service `metrics` (`examples/insecure-compose.yaml:18`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-res-002>

**Description:** No CPU limit is configured for the service.

**Evidence:**

```text
deploy.resources.limits.cpus and cpus are not set
```

**Why it matters:** Without a CPU limit a busy or runaway container can starve other services on the same host.

**Recommended remediation:** Set deploy.resources.limits.cpus (for example "1.0") or cpus for older Compose versions.

### 29. SST-SEC-005: Linux capabilities not dropped

- **Rule ID:** SST-SEC-005 (version 1.0)
- **Severity:** low
- **Category:** security
- **Confidence:** high
- **Affected target:** service `db` (`examples/insecure-compose.yaml:23`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-005>

**Description:** The service keeps Docker's default Linux capabilities (cap\_drop does not contain ALL).

**Evidence:**

```text
cap_drop is not set
```

**Why it matters:** Docker grants containers a default capability set (for example CHOWN, SETUID, NET\_RAW). Most applications need few or none of them. This is a hardening recommendation, not a defect: some images need specific capabilities to start.

**Recommended remediation:** Add cap\_drop: \[ALL\] and add back only what the service needs with cap\_add (for example NET\_BIND\_SERVICE to bind ports below 1024). Test the service after the change.

### 30. SST-SEC-005: Linux capabilities not dropped

- **Rule ID:** SST-SEC-005 (version 1.0)
- **Severity:** low
- **Category:** security
- **Confidence:** high
- **Affected target:** service `metrics` (`examples/insecure-compose.yaml:18`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-005>

**Description:** The service keeps Docker's default Linux capabilities (cap\_drop does not contain ALL).

**Evidence:**

```text
cap_drop is not set
```

**Why it matters:** Docker grants containers a default capability set (for example CHOWN, SETUID, NET\_RAW). Most applications need few or none of them. This is a hardening recommendation, not a defect: some images need specific capabilities to start.

**Recommended remediation:** Add cap\_drop: \[ALL\] and add back only what the service needs with cap\_add (for example NET\_BIND\_SERVICE to bind ports below 1024). Test the service after the change.

### 31. SST-SEC-009: Read-only root filesystem not enabled

- **Rule ID:** SST-SEC-009 (version 1.0)
- **Severity:** low
- **Category:** security
- **Confidence:** high
- **Affected target:** service `db` (`examples/insecure-compose.yaml:23`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-009>

**Description:** The container's root filesystem is writable (read\_only: true is not set).

**Evidence:**

```text
read_only is not set
```

**Why it matters:** A read-only root filesystem prevents an attacker from modifying binaries or dropping tools inside the container and makes unexpected writes visible.

**Recommended remediation:** Set read\_only: true and provide writable locations explicitly with tmpfs (for example /tmp or /run) or volumes for application data. Many applications need some writable directories; test before enforcing.

### 32. SST-SEC-009: Read-only root filesystem not enabled

- **Rule ID:** SST-SEC-009 (version 1.0)
- **Severity:** low
- **Category:** security
- **Confidence:** high
- **Affected target:** service `manager` (`examples/insecure-compose.yaml:7`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-009>

**Description:** The container's root filesystem is writable (read\_only: true is not set).

**Evidence:**

```text
read_only is not set
```

**Why it matters:** A read-only root filesystem prevents an attacker from modifying binaries or dropping tools inside the container and makes unexpected writes visible.

**Recommended remediation:** Set read\_only: true and provide writable locations explicitly with tmpfs (for example /tmp or /run) or volumes for application data. Many applications need some writable directories; test before enforcing.

### 33. SST-SEC-009: Read-only root filesystem not enabled

- **Rule ID:** SST-SEC-009 (version 1.0)
- **Severity:** low
- **Category:** security
- **Confidence:** high
- **Affected target:** service `metrics` (`examples/insecure-compose.yaml:18`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-009>

**Description:** The container's root filesystem is writable (read\_only: true is not set).

**Evidence:**

```text
read_only is not set
```

**Why it matters:** A read-only root filesystem prevents an attacker from modifying binaries or dropping tools inside the container and makes unexpected writes visible.

**Recommended remediation:** Set read\_only: true and provide writable locations explicitly with tmpfs (for example /tmp or /run) or volumes for application data. Many applications need some writable directories; test before enforcing.

### 34. SST-OPS-007: No stop grace period

- **Rule ID:** SST-OPS-007 (version 1.0)
- **Severity:** info
- **Category:** reliability
- **Confidence:** high
- **Affected target:** service `manager` (`examples/insecure-compose.yaml:7`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-007>

**Description:** No stop\_grace\_period is set, so Docker kills the container 10 seconds after asking it to stop.

**Evidence:**

```text
stop_grace_period is not set (Docker default: 10s)
```

**Why it matters:** Databases, queues and workflow engines may need more than 10 seconds to flush data, finish jobs or close connections. A forced kill can corrupt data or lose in-flight work.

**Recommended remediation:** Set stop\_grace\_period to match the service's shutdown behavior (for example stop\_grace\_period: 30s for databases and workflow tools) and make sure the process handles SIGTERM or the configured stop\_signal.

### 35. SST-OPS-007: No stop grace period

- **Rule ID:** SST-OPS-007 (version 1.0)
- **Severity:** info
- **Category:** reliability
- **Confidence:** high
- **Affected target:** service `metrics` (`examples/insecure-compose.yaml:18`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-007>

**Description:** No stop\_grace\_period is set, so Docker kills the container 10 seconds after asking it to stop.

**Evidence:**

```text
stop_grace_period is not set (Docker default: 10s)
```

**Why it matters:** Databases, queues and workflow engines may need more than 10 seconds to flush data, finish jobs or close connections. A forced kill can corrupt data or lose in-flight work.

**Recommended remediation:** Set stop\_grace\_period to match the service's shutdown behavior (for example stop\_grace\_period: 30s for databases and workflow tools) and make sure the process handles SIGTERM or the configured stop\_signal.

## Scan Limitations

- Static analysis sees only the Compose files. Image contents (USER, HEALTHCHECK), daemon-wide settings such as daemon.json log rotation, and values injected at deploy time are not visible to this scan.

## Remediation Priorities

1. **Fix before deploying (critical)**
   - SST-SEC-001 Docker socket mount detected: `manager`
   - SST-SEC-002 Privileged container detected: `manager`
2. **Fix soon (high)**
   - SST-NET-001 Publicly published database port: `db`
   - SST-OPS-003 No restart policy configured: `db`, `manager`
   - SST-SEC-003 Host network mode detected: `metrics`
   - SST-SEC-011 Likely secret in environment variable: `db`
3. **Plan a fix (medium)**
   - SST-OPS-001 No healthcheck configured: `db`, `manager`, `metrics`
   - SST-OPS-005 Mutable image tag: `db`, `manager`
   - SST-RES-003 No log rotation configured: `db`, `manager`, `metrics`
   - SST-SEC-006 Writable host bind mount: `db`, `manager`
   - SST-SEC-008 No explicit non-root user: `db`, `manager`, `metrics`
4. **Hardening backlog (low and info)**
   - SST-OPS-006 Image digest not pinned: `metrics`
   - SST-OPS-007 No stop grace period: `db`, `manager`, `metrics`
   - SST-RES-001 No memory limit configured: `db`, `manager`, `metrics`
   - SST-RES-002 No CPU limit configured: `db`, `manager`, `metrics`
   - SST-SEC-005 Linux capabilities not dropped: `db`, `metrics`
   - SST-SEC-009 Read-only root filesystem not enabled: `db`, `manager`, `metrics`

## Generated By

Generated by StackSentry v0.1.0 on 2026-10-01T12:00:00Z. StackSentry performs local, deterministic, rule-based analysis; no data left the machine that ran the scan. Findings support, but do not replace, a complete security review.
