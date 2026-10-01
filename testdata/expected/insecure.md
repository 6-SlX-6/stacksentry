# StackSentry Scan Report

## Scan Summary

| Property | Value |
|---|---|
| Scanner | StackSentry v0.1.0 |
| Scan type | Docker Compose (static analysis) |
| Scan time | 2026-10-01T12:00:00Z |
| Rules evaluated | 27 of 27 |
| Findings | 42 |
| Minimum severity shown | info |
| Fail-on threshold | not set |

## Target

| Property | Value |
|---|---|
| Compose files | `testdata/compose/insecure.yaml` |
| Project | `compose` |
| Services analyzed | 3 |
| Services | `app`, `db`, `portainer` |

## Finding Statistics

| Severity | Found | Shown in this report |
|---|---:|---:|
| Critical | 3 | 3 |
| High | 10 | 10 |
| Medium | 13 | 13 |
| Low | 14 | 14 |
| Info | 2 | 2 |
| **Total** | **42** | **42** |

## Findings by Severity

### Critical (3)

| # | Rule | Target | Finding |
|---:|---|---|---|
| 1 | SST-SEC-001 | `app` | Docker socket mount detected |
| 2 | SST-SEC-002 | `app` | Privileged container detected |
| 3 | SST-SEC-010 | `portainer` | Insecure Docker API exposure |

### High (10)

| # | Rule | Target | Finding |
|---:|---|---|---|
| 4 | SST-NET-001 | `db` | Publicly published database port |
| 5 | SST-OPS-003 | `app` | No restart policy configured |
| 6 | SST-OPS-003 | `db` | No restart policy configured |
| 7 | SST-OPS-003 | `portainer` | No restart policy configured |
| 8 | SST-SEC-003 | `app` | Host network mode detected |
| 9 | SST-SEC-004 | `app` | Dangerous Linux capabilities added |
| 10 | SST-SEC-007 | `app` | Sensitive host path mounted |
| 11 | SST-SEC-011 | `app` | Likely secret in environment variable |
| 12 | SST-SEC-011 | `db` | Likely secret in environment variable |
| 13 | SST-STO-001 | `db` | Database service without persistent volume |

### Medium (13)

| # | Rule | Target | Finding |
|---:|---|---|---|
| 14 | SST-NET-003 | `portainer` | Admin interface likely published broadly |
| 15 | SST-OPS-001 | `app` | No healthcheck configured |
| 16 | SST-OPS-001 | `db` | No healthcheck configured |
| 17 | SST-OPS-001 | `portainer` | No healthcheck configured |
| 18 | SST-OPS-005 | `app` | Mutable image tag |
| 19 | SST-OPS-005 | `db` | Mutable image tag |
| 20 | SST-RES-003 | `app` | No log rotation configured |
| 21 | SST-RES-003 | `db` | No log rotation configured |
| 22 | SST-RES-003 | `portainer` | No log rotation configured |
| 23 | SST-SEC-006 | `app` | Writable host bind mount |
| 24 | SST-SEC-008 | `app` | No explicit non-root user |
| 25 | SST-SEC-008 | `db` | No explicit non-root user |
| 26 | SST-SEC-008 | `portainer` | No explicit non-root user |

### Low (14)

| # | Rule | Target | Finding |
|---:|---|---|---|
| 27 | SST-OPS-004 | `app` | Container name explicitly hardcoded |
| 28 | SST-OPS-006 | `portainer` | Image digest not pinned |
| 29 | SST-OPS-007 | `db` | No stop grace period |
| 30 | SST-RES-001 | `app` | No memory limit configured |
| 31 | SST-RES-001 | `db` | No memory limit configured |
| 32 | SST-RES-001 | `portainer` | No memory limit configured |
| 33 | SST-RES-002 | `app` | No CPU limit configured |
| 34 | SST-RES-002 | `db` | No CPU limit configured |
| 35 | SST-RES-002 | `portainer` | No CPU limit configured |
| 36 | SST-SEC-005 | `db` | Linux capabilities not dropped |
| 37 | SST-SEC-005 | `portainer` | Linux capabilities not dropped |
| 38 | SST-SEC-009 | `app` | Read-only root filesystem not enabled |
| 39 | SST-SEC-009 | `db` | Read-only root filesystem not enabled |
| 40 | SST-SEC-009 | `portainer` | Read-only root filesystem not enabled |

### Info (2)

| # | Rule | Target | Finding |
|---:|---|---|---|
| 41 | SST-OPS-007 | `app` | No stop grace period |
| 42 | SST-OPS-007 | `portainer` | No stop grace period |

## Detailed Findings

### 1. SST-SEC-001: Docker socket mount detected

- **Rule ID:** SST-SEC-001 (version 1.0)
- **Severity:** critical
- **Category:** security
- **Confidence:** high
- **Affected target:** service `app` (`testdata/compose/insecure.yaml:3`)
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
- **Affected target:** service `app` (`testdata/compose/insecure.yaml:3`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-002>

**Description:** The service runs in privileged mode.

**Evidence:**

```text
privileged: true
```

**Why it matters:** privileged: true grants all Linux capabilities and access to all host devices and disables most isolation (seccomp, AppArmor/SELinux confinement). A compromise of the process is close to a compromise of the host.

**Recommended remediation:** Remove privileged: true. Grant only the specific capabilities (cap\_add) or devices (devices) the workload needs, and document why they are required.

### 3. SST-SEC-010: Insecure Docker API exposure

- **Rule ID:** SST-SEC-010 (version 1.0)
- **Severity:** critical
- **Category:** security
- **Confidence:** medium
- **Affected target:** service `portainer` (`testdata/compose/insecure.yaml:24`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-010>

**Description:** The service appears to expose or use the Docker Engine API over unencrypted TCP.

**Evidence:**

```text
port 2375:2375/tcp publishes the unencrypted Docker API port 2375 (all host interfaces)
```

**Why it matters:** The Docker Engine API on TCP port 2375 has neither authentication nor encryption. Anyone who can reach it controls the Docker host, which is equivalent to root access.

**Recommended remediation:** Do not publish port 2375. If remote API access is required, use TLS with client certificate verification (port 2376, --tlsverify) or SSH (DOCKER\_HOST=ssh://user@host). Keep socket proxies on an internal network and never publish their port.

### 4. SST-NET-001: Publicly published database port

- **Rule ID:** SST-NET-001 (version 1.0)
- **Severity:** high
- **Category:** networking
- **Confidence:** high
- **Affected target:** service `db` (`testdata/compose/insecure.yaml:17`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-net-001>

**Description:** A database port is published on all host interfaces.

**Evidence:**

```text
5432:5432/tcp (PostgreSQL port published on all host interfaces)
```

**Why it matters:** Published database ports are reachable from other machines and, on many Linux hosts, bypass host firewalls such as UFW or firewalld because Docker manages its own iptables rules. Databases reachable from the network are frequent targets of credential brute-forcing and ransom attacks.

**Recommended remediation:** Remove the ports entry if only other containers need the database; they can reach it over the Compose network by service name. If host access is required, bind to localhost, e.g. "127.0.0.1:5432:5432". Exposure may be intentional, but it should be reviewed.

### 5. SST-OPS-003: No restart policy configured

- **Rule ID:** SST-OPS-003 (version 1.0)
- **Severity:** high
- **Category:** reliability
- **Confidence:** high
- **Affected target:** service `app` (`testdata/compose/insecure.yaml:3`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-003>

**Description:** No restart policy is configured, so the container stays down after a crash or host reboot.

**Evidence:**

```text
restart is missing
```

**Why it matters:** Docker's default restart policy is "no". A long-running service that crashes, or whose host reboots, stays down until someone intervenes.

**Recommended remediation:** Add: restart: unless-stopped (or always / on-failure, depending on the desired behavior).

### 6. SST-OPS-003: No restart policy configured

- **Rule ID:** SST-OPS-003 (version 1.0)
- **Severity:** high
- **Category:** reliability
- **Confidence:** high
- **Affected target:** service `db` (`testdata/compose/insecure.yaml:17`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-003>

**Description:** No restart policy is configured, so the container stays down after a crash or host reboot.

**Evidence:**

```text
restart is missing
```

**Why it matters:** Docker's default restart policy is "no". A long-running service that crashes, or whose host reboots, stays down until someone intervenes.

**Recommended remediation:** Add: restart: unless-stopped (or always / on-failure, depending on the desired behavior).

### 7. SST-OPS-003: No restart policy configured

- **Rule ID:** SST-OPS-003 (version 1.0)
- **Severity:** high
- **Category:** reliability
- **Confidence:** high
- **Affected target:** service `portainer` (`testdata/compose/insecure.yaml:24`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-003>

**Description:** No restart policy is configured, so the container stays down after a crash or host reboot.

**Evidence:**

```text
restart is missing
```

**Why it matters:** Docker's default restart policy is "no". A long-running service that crashes, or whose host reboots, stays down until someone intervenes.

**Recommended remediation:** Add: restart: unless-stopped (or always / on-failure, depending on the desired behavior).

### 8. SST-SEC-003: Host network mode detected

- **Rule ID:** SST-SEC-003 (version 1.0)
- **Severity:** high
- **Category:** security
- **Confidence:** high
- **Affected target:** service `app` (`testdata/compose/insecure.yaml:3`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-003>

**Description:** The service shares the host's network stack (network\_mode: host).

**Evidence:**

```text
network_mode: host
```

**Why it matters:** Host networking removes normal Docker network isolation: every port the process opens is reachable on all host interfaces, port publishing rules no longer apply, and the container can reach services bound to the host's localhost.

**Recommended remediation:** Use a bridge network and publish only the required ports, preferably bound to 127.0.0.1 or a specific interface. Keep host networking only for workloads that need it (for example some discovery or VPN tools) and document the exception.

### 9. SST-SEC-004: Dangerous Linux capabilities added

- **Rule ID:** SST-SEC-004 (version 1.0)
- **Severity:** high
- **Category:** security
- **Confidence:** high
- **Affected target:** service `app` (`testdata/compose/insecure.yaml:3`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-004>

**Description:** The service adds Linux capabilities that significantly weaken container isolation.

**Evidence:**

```text
cap_add: SYS_ADMIN (broad administrative privileges such as mounting filesystems; enables many escape techniques)
```

**Why it matters:** These capabilities grant kernel-level privileges that are commonly abused for container escapes, for example mounting filesystems, loading kernel modules or tracing other processes.

**Recommended remediation:** Remove the listed capabilities from cap\_add unless they are strictly required. If one is needed, document why and combine it with cap\_drop: \[ALL\], a non-root user and security\_opt: \[no-new-privileges:true\].

### 10. SST-SEC-007: Sensitive host path mounted

- **Rule ID:** SST-SEC-007 (version 1.0)
- **Severity:** high
- **Category:** security
- **Confidence:** high
- **Affected target:** service `app` (`testdata/compose/insecure.yaml:3`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-007>

**Description:** A sensitive host location is bind-mounted into the container.

**Evidence:**

```text
/:/host (read-write): the entire host filesystem
```

**Why it matters:** System locations such as /, /etc, /proc, /sys, /dev, /root or /var/lib/docker expose host credentials, kernel interfaces, devices or other containers' data. Write access usually allows a full host compromise; even read access can leak secrets.

**Recommended remediation:** Mount only the specific file or subdirectory the service needs, read-only where possible. Monitoring agents that legitimately need /proc or /sys should mount them read-only and be reviewed as privileged components.

### 11. SST-SEC-011: Likely secret in environment variable

- **Rule ID:** SST-SEC-011 (version 1.0)
- **Severity:** high
- **Category:** secrets
- **Confidence:** high
- **Affected target:** service `app` (`testdata/compose/insecure.yaml:3`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-011>

**Description:** An environment variable that looks like a credential has an inline value in the Compose file.

**Evidence:**

```text
API_TOKEN=********
DB_PASSWORD=********
```

**Why it matters:** Inline secrets end up in version control, backups, CI logs and docker inspect output, and are visible to everyone who can read the Compose file.

**Recommended remediation:** Move the value out of the Compose file: use Docker secrets (with \*\_FILE variables where the image supports them), an external secret manager, or interpolation such as ${DB\_PASSWORD} with the value injected at deploy time from an environment file that is not committed. Rotate the secret if the file was ever shared.

### 12. SST-SEC-011: Likely secret in environment variable

- **Rule ID:** SST-SEC-011 (version 1.0)
- **Severity:** high
- **Category:** secrets
- **Confidence:** high
- **Affected target:** service `db` (`testdata/compose/insecure.yaml:17`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-011>

**Description:** An environment variable that looks like a credential has an inline value in the Compose file.

**Evidence:**

```text
POSTGRES_PASSWORD=********
```

**Why it matters:** Inline secrets end up in version control, backups, CI logs and docker inspect output, and are visible to everyone who can read the Compose file.

**Recommended remediation:** Move the value out of the Compose file: use Docker secrets (with \*\_FILE variables where the image supports them), an external secret manager, or interpolation such as ${DB\_PASSWORD} with the value injected at deploy time from an environment file that is not committed. Rotate the secret if the file was ever shared.

### 13. SST-STO-001: Database service without persistent volume

- **Rule ID:** SST-STO-001 (version 1.0)
- **Severity:** high
- **Category:** storage
- **Confidence:** high
- **Affected target:** service `db` (`testdata/compose/insecure.yaml:17`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sto-001>

**Description:** The database service has no volume mounted at its data directory.

**Evidence:**

```text
no volume is mounted at /var/lib/postgresql/data (PostgreSQL data directory)
```

**Why it matters:** Without a volume the data lives in the container's writable layer and is lost when the container is recreated, for example by docker compose down, an image upgrade or a configuration change.

**Recommended remediation:** Mount a named volume at the data directory, e.g. "db-data:/var/lib/postgresql/data", declare it under the top-level volumes key and back it up regularly.

### 14. SST-NET-003: Admin interface likely published broadly

- **Rule ID:** SST-NET-003 (version 1.0)
- **Severity:** medium
- **Category:** networking
- **Confidence:** high
- **Affected target:** service `portainer` (`testdata/compose/insecure.yaml:24`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-net-003>

**Description:** An administration interface appears to be published on all host interfaces.

**Evidence:**

```text
portainer/portainer-ce:2.21.4 publishes 9443:9443/tcp on all host interfaces (Portainer)
portainer/portainer-ce:2.21.4 publishes 2375:2375/tcp on all host interfaces (Portainer)
```

**Why it matters:** Admin dashboards provide powerful control over infrastructure or data. Publishing them broadly increases exposure to credential guessing and to vulnerabilities in the tool itself.

**Recommended remediation:** Review the exposure. Bind the port to 127.0.0.1 and use an SSH tunnel or VPN, or put the interface behind a reverse proxy with strong authentication and TLS.

### 15. SST-OPS-001: No healthcheck configured

- **Rule ID:** SST-OPS-001 (version 1.0)
- **Severity:** medium
- **Category:** reliability
- **Confidence:** high
- **Affected target:** service `app` (`testdata/compose/insecure.yaml:3`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-001>

**Description:** No healthcheck is defined for the service in the Compose file.

**Evidence:**

```text
healthcheck is not defined
```

**Why it matters:** Without a healthcheck Docker only knows whether the process is running, not whether it works. depends\_on with condition: service\_healthy, automated recovery and monitoring cannot detect a hung or misconfigured service.

**Recommended remediation:** Add a healthcheck that exercises the service (for example an HTTP endpoint or a database ping) with sensible interval, timeout, retries and start\_period values.

### 16. SST-OPS-001: No healthcheck configured

- **Rule ID:** SST-OPS-001 (version 1.0)
- **Severity:** medium
- **Category:** reliability
- **Confidence:** high
- **Affected target:** service `db` (`testdata/compose/insecure.yaml:17`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-001>

**Description:** No healthcheck is defined for the service in the Compose file.

**Evidence:**

```text
healthcheck is not defined
```

**Why it matters:** Without a healthcheck Docker only knows whether the process is running, not whether it works. depends\_on with condition: service\_healthy, automated recovery and monitoring cannot detect a hung or misconfigured service.

**Recommended remediation:** Add a healthcheck that exercises the service (for example an HTTP endpoint or a database ping) with sensible interval, timeout, retries and start\_period values.

### 17. SST-OPS-001: No healthcheck configured

- **Rule ID:** SST-OPS-001 (version 1.0)
- **Severity:** medium
- **Category:** reliability
- **Confidence:** high
- **Affected target:** service `portainer` (`testdata/compose/insecure.yaml:24`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-001>

**Description:** No healthcheck is defined for the service in the Compose file.

**Evidence:**

```text
healthcheck is not defined
```

**Why it matters:** Without a healthcheck Docker only knows whether the process is running, not whether it works. depends\_on with condition: service\_healthy, automated recovery and monitoring cannot detect a hung or misconfigured service.

**Recommended remediation:** Add a healthcheck that exercises the service (for example an HTTP endpoint or a database ping) with sensible interval, timeout, retries and start\_period values.

### 18. SST-OPS-005: Mutable image tag

- **Rule ID:** SST-OPS-005 (version 1.0)
- **Severity:** medium
- **Category:** supply-chain
- **Confidence:** high
- **Affected target:** service `app` (`testdata/compose/insecure.yaml:3`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-005>

**Description:** The image uses a mutable tag (latest or no tag at all).

**Evidence:**

```text
image: example/app:latest
```

**Why it matters:** Mutable tags can point to a different image every time you pull. Deployments become non-reproducible, rollbacks unreliable, and unreviewed upstream changes can reach production silently.

**Recommended remediation:** Pin a specific version tag (for example postgres:16.4) and update it deliberately. For full reproducibility also pin the digest (image: name:tag@sha256:...).

### 19. SST-OPS-005: Mutable image tag

- **Rule ID:** SST-OPS-005 (version 1.0)
- **Severity:** medium
- **Category:** supply-chain
- **Confidence:** high
- **Affected target:** service `db` (`testdata/compose/insecure.yaml:17`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-005>

**Description:** The image uses a mutable tag (latest or no tag at all).

**Evidence:**

```text
image: postgres (no tag, resolves to latest)
```

**Why it matters:** Mutable tags can point to a different image every time you pull. Deployments become non-reproducible, rollbacks unreliable, and unreviewed upstream changes can reach production silently.

**Recommended remediation:** Pin a specific version tag (for example postgres:16.4) and update it deliberately. For full reproducibility also pin the digest (image: name:tag@sha256:...).

### 20. SST-RES-003: No log rotation configured

- **Rule ID:** SST-RES-003 (version 1.0)
- **Severity:** medium
- **Category:** resource-management
- **Confidence:** high
- **Affected target:** service `app` (`testdata/compose/insecure.yaml:3`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-res-003>

**Description:** Container logs are not configured to rotate.

**Evidence:**

```text
logging is not configured (the daemon's default log driver applies)
```

**Why it matters:** Docker's default json-file log driver keeps logs without limit unless max-size is set, so a chatty container can fill the disk.

**Recommended remediation:** Configure rotation, for example logging: {driver: json-file, options: {max-size: "10m", max-file: "3"}}, or set log-driver/log-opts once for all containers in the Docker daemon configuration.

### 21. SST-RES-003: No log rotation configured

- **Rule ID:** SST-RES-003 (version 1.0)
- **Severity:** medium
- **Category:** resource-management
- **Confidence:** high
- **Affected target:** service `db` (`testdata/compose/insecure.yaml:17`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-res-003>

**Description:** Container logs are not configured to rotate.

**Evidence:**

```text
logging is not configured (the daemon's default log driver applies)
```

**Why it matters:** Docker's default json-file log driver keeps logs without limit unless max-size is set, so a chatty container can fill the disk.

**Recommended remediation:** Configure rotation, for example logging: {driver: json-file, options: {max-size: "10m", max-file: "3"}}, or set log-driver/log-opts once for all containers in the Docker daemon configuration.

### 22. SST-RES-003: No log rotation configured

- **Rule ID:** SST-RES-003 (version 1.0)
- **Severity:** medium
- **Category:** resource-management
- **Confidence:** high
- **Affected target:** service `portainer` (`testdata/compose/insecure.yaml:24`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-res-003>

**Description:** Container logs are not configured to rotate.

**Evidence:**

```text
logging is not configured (the daemon's default log driver applies)
```

**Why it matters:** Docker's default json-file log driver keeps logs without limit unless max-size is set, so a chatty container can fill the disk.

**Recommended remediation:** Configure rotation, for example logging: {driver: json-file, options: {max-size: "10m", max-file: "3"}}, or set log-driver/log-opts once for all containers in the Docker daemon configuration.

### 23. SST-SEC-006: Writable host bind mount

- **Rule ID:** SST-SEC-006 (version 1.0)
- **Severity:** medium
- **Category:** security
- **Confidence:** high
- **Affected target:** service `app` (`testdata/compose/insecure.yaml:3`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-006>

**Description:** A host path is bind-mounted without read-only protection.

**Evidence:**

```text
/:/host (read-write)
./data:/data (read-write)
```

**Why it matters:** A writable bind mount lets the container modify files on the host. If the container is compromised, an attacker can tamper with host files, configuration or data shared with other services.

**Recommended remediation:** Append :ro (short syntax) or set read\_only: true (long syntax) for mounts the container only reads, such as configuration files. For data the service must write, prefer a named volume or make sure the host directory is dedicated to this service.

### 24. SST-SEC-008: No explicit non-root user

- **Rule ID:** SST-SEC-008 (version 1.0)
- **Severity:** medium
- **Category:** security
- **Confidence:** high
- **Affected target:** service `app` (`testdata/compose/insecure.yaml:3`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-008>

**Description:** No user is configured, so the container runs as the image's default user, which is root for many images.

**Evidence:**

```text
user is not set
```

**Why it matters:** Processes running as root inside a container have more power if they escape isolation or write to mounted volumes. Without a user setting the effective user depends on the image's USER instruction, which StackSentry cannot see without pulling the image.

**Recommended remediation:** Add a dedicated unprivileged user where supported by the image, e.g. user: "1000:1000" or a named user documented by the image (such as node). Make sure mounted volumes are writable by that UID.

### 25. SST-SEC-008: No explicit non-root user

- **Rule ID:** SST-SEC-008 (version 1.0)
- **Severity:** medium
- **Category:** security
- **Confidence:** high
- **Affected target:** service `db` (`testdata/compose/insecure.yaml:17`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-008>

**Description:** No user is configured, so the container runs as the image's default user, which is root for many images.

**Evidence:**

```text
user is not set
```

**Why it matters:** Processes running as root inside a container have more power if they escape isolation or write to mounted volumes. Without a user setting the effective user depends on the image's USER instruction, which StackSentry cannot see without pulling the image.

**Recommended remediation:** Add a dedicated unprivileged user where supported by the image, e.g. user: "1000:1000" or a named user documented by the image (such as node). Make sure mounted volumes are writable by that UID.

### 26. SST-SEC-008: No explicit non-root user

- **Rule ID:** SST-SEC-008 (version 1.0)
- **Severity:** medium
- **Category:** security
- **Confidence:** high
- **Affected target:** service `portainer` (`testdata/compose/insecure.yaml:24`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-008>

**Description:** No user is configured, so the container runs as the image's default user, which is root for many images.

**Evidence:**

```text
user is not set
```

**Why it matters:** Processes running as root inside a container have more power if they escape isolation or write to mounted volumes. Without a user setting the effective user depends on the image's USER instruction, which StackSentry cannot see without pulling the image.

**Recommended remediation:** Add a dedicated unprivileged user where supported by the image, e.g. user: "1000:1000" or a named user documented by the image (such as node). Make sure mounted volumes are writable by that UID.

### 27. SST-OPS-004: Container name explicitly hardcoded

- **Rule ID:** SST-OPS-004 (version 1.0)
- **Severity:** low
- **Category:** maintainability
- **Confidence:** high
- **Affected target:** service `app` (`testdata/compose/insecure.yaml:3`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-004>

**Description:** The service sets a fixed container\_name.

**Evidence:**

```text
container_name: app
```

**Why it matters:** Fixed container names must be unique on the host. They prevent scaling the service, can clash with other projects or copies of the same stack, and bypass Compose's project-scoped naming.

**Recommended remediation:** Remove container\_name and let Compose generate project-scoped names. Other services can reach it by its service name, which works without container\_name.

### 28. SST-OPS-006: Image digest not pinned

- **Rule ID:** SST-OPS-006 (version 1.0)
- **Severity:** low
- **Category:** supply-chain
- **Confidence:** high
- **Affected target:** service `portainer` (`testdata/compose/insecure.yaml:24`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-006>

**Description:** The image is pinned by version tag but not by digest.

**Evidence:**

```text
image: portainer/portainer-ce:2.21.4 has no @sha256 digest
```

**Why it matters:** Tags can be re-pushed by the publisher, so the same tag may resolve to different content over time. Pinning the digest guarantees that every deployment runs exactly the reviewed image. This is a reproducibility recommendation, not a security vulnerability.

**Recommended remediation:** Append the digest: image: name:tag@sha256:\<digest\> (look it up with docker buildx imagetools inspect name:tag). Tools such as Renovate or Dependabot can keep digests up to date.

### 29. SST-OPS-007: No stop grace period

- **Rule ID:** SST-OPS-007 (version 1.0)
- **Severity:** low
- **Category:** reliability
- **Confidence:** high
- **Affected target:** service `db` (`testdata/compose/insecure.yaml:17`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-007>

**Description:** No stop\_grace\_period is set, so Docker kills the container 10 seconds after asking it to stop.

**Evidence:**

```text
stop_grace_period is not set (Docker default: 10s)
```

**Why it matters:** Databases, queues and workflow engines may need more than 10 seconds to flush data, finish jobs or close connections. A forced kill can corrupt data or lose in-flight work.

**Recommended remediation:** Set stop\_grace\_period to match the service's shutdown behavior (for example stop\_grace\_period: 30s for databases and workflow tools) and make sure the process handles SIGTERM or the configured stop\_signal.

### 30. SST-RES-001: No memory limit configured

- **Rule ID:** SST-RES-001 (version 1.0)
- **Severity:** low
- **Category:** resource-management
- **Confidence:** high
- **Affected target:** service `app` (`testdata/compose/insecure.yaml:3`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-res-001>

**Description:** No memory limit is configured for the service.

**Evidence:**

```text
deploy.resources.limits.memory and mem_limit are not set
```

**Why it matters:** A memory leak or load spike in one container can consume all host memory and trigger the kernel OOM killer for unrelated processes, including other services on the host.

**Recommended remediation:** Set deploy.resources.limits.memory (for example 512M) based on observed usage, or mem\_limit for older Compose versions.

### 31. SST-RES-001: No memory limit configured

- **Rule ID:** SST-RES-001 (version 1.0)
- **Severity:** low
- **Category:** resource-management
- **Confidence:** high
- **Affected target:** service `db` (`testdata/compose/insecure.yaml:17`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-res-001>

**Description:** No memory limit is configured for the service.

**Evidence:**

```text
deploy.resources.limits.memory and mem_limit are not set
```

**Why it matters:** A memory leak or load spike in one container can consume all host memory and trigger the kernel OOM killer for unrelated processes, including other services on the host.

**Recommended remediation:** Set deploy.resources.limits.memory (for example 512M) based on observed usage, or mem\_limit for older Compose versions.

### 32. SST-RES-001: No memory limit configured

- **Rule ID:** SST-RES-001 (version 1.0)
- **Severity:** low
- **Category:** resource-management
- **Confidence:** high
- **Affected target:** service `portainer` (`testdata/compose/insecure.yaml:24`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-res-001>

**Description:** No memory limit is configured for the service.

**Evidence:**

```text
deploy.resources.limits.memory and mem_limit are not set
```

**Why it matters:** A memory leak or load spike in one container can consume all host memory and trigger the kernel OOM killer for unrelated processes, including other services on the host.

**Recommended remediation:** Set deploy.resources.limits.memory (for example 512M) based on observed usage, or mem\_limit for older Compose versions.

### 33. SST-RES-002: No CPU limit configured

- **Rule ID:** SST-RES-002 (version 1.0)
- **Severity:** low
- **Category:** resource-management
- **Confidence:** high
- **Affected target:** service `app` (`testdata/compose/insecure.yaml:3`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-res-002>

**Description:** No CPU limit is configured for the service.

**Evidence:**

```text
deploy.resources.limits.cpus and cpus are not set
```

**Why it matters:** Without a CPU limit a busy or runaway container can starve other services on the same host.

**Recommended remediation:** Set deploy.resources.limits.cpus (for example "1.0") or cpus for older Compose versions.

### 34. SST-RES-002: No CPU limit configured

- **Rule ID:** SST-RES-002 (version 1.0)
- **Severity:** low
- **Category:** resource-management
- **Confidence:** high
- **Affected target:** service `db` (`testdata/compose/insecure.yaml:17`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-res-002>

**Description:** No CPU limit is configured for the service.

**Evidence:**

```text
deploy.resources.limits.cpus and cpus are not set
```

**Why it matters:** Without a CPU limit a busy or runaway container can starve other services on the same host.

**Recommended remediation:** Set deploy.resources.limits.cpus (for example "1.0") or cpus for older Compose versions.

### 35. SST-RES-002: No CPU limit configured

- **Rule ID:** SST-RES-002 (version 1.0)
- **Severity:** low
- **Category:** resource-management
- **Confidence:** high
- **Affected target:** service `portainer` (`testdata/compose/insecure.yaml:24`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-res-002>

**Description:** No CPU limit is configured for the service.

**Evidence:**

```text
deploy.resources.limits.cpus and cpus are not set
```

**Why it matters:** Without a CPU limit a busy or runaway container can starve other services on the same host.

**Recommended remediation:** Set deploy.resources.limits.cpus (for example "1.0") or cpus for older Compose versions.

### 36. SST-SEC-005: Linux capabilities not dropped

- **Rule ID:** SST-SEC-005 (version 1.0)
- **Severity:** low
- **Category:** security
- **Confidence:** high
- **Affected target:** service `db` (`testdata/compose/insecure.yaml:17`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-005>

**Description:** The service keeps Docker's default Linux capabilities (cap\_drop does not contain ALL).

**Evidence:**

```text
cap_drop is not set
```

**Why it matters:** Docker grants containers a default capability set (for example CHOWN, SETUID, NET\_RAW). Most applications need few or none of them. This is a hardening recommendation, not a defect: some images need specific capabilities to start.

**Recommended remediation:** Add cap\_drop: \[ALL\] and add back only what the service needs with cap\_add (for example NET\_BIND\_SERVICE to bind ports below 1024). Test the service after the change.

### 37. SST-SEC-005: Linux capabilities not dropped

- **Rule ID:** SST-SEC-005 (version 1.0)
- **Severity:** low
- **Category:** security
- **Confidence:** high
- **Affected target:** service `portainer` (`testdata/compose/insecure.yaml:24`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-005>

**Description:** The service keeps Docker's default Linux capabilities (cap\_drop does not contain ALL).

**Evidence:**

```text
cap_drop is not set
```

**Why it matters:** Docker grants containers a default capability set (for example CHOWN, SETUID, NET\_RAW). Most applications need few or none of them. This is a hardening recommendation, not a defect: some images need specific capabilities to start.

**Recommended remediation:** Add cap\_drop: \[ALL\] and add back only what the service needs with cap\_add (for example NET\_BIND\_SERVICE to bind ports below 1024). Test the service after the change.

### 38. SST-SEC-009: Read-only root filesystem not enabled

- **Rule ID:** SST-SEC-009 (version 1.0)
- **Severity:** low
- **Category:** security
- **Confidence:** high
- **Affected target:** service `app` (`testdata/compose/insecure.yaml:3`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-009>

**Description:** The container's root filesystem is writable (read\_only: true is not set).

**Evidence:**

```text
read_only is not set
```

**Why it matters:** A read-only root filesystem prevents an attacker from modifying binaries or dropping tools inside the container and makes unexpected writes visible.

**Recommended remediation:** Set read\_only: true and provide writable locations explicitly with tmpfs (for example /tmp or /run) or volumes for application data. Many applications need some writable directories; test before enforcing.

### 39. SST-SEC-009: Read-only root filesystem not enabled

- **Rule ID:** SST-SEC-009 (version 1.0)
- **Severity:** low
- **Category:** security
- **Confidence:** high
- **Affected target:** service `db` (`testdata/compose/insecure.yaml:17`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-009>

**Description:** The container's root filesystem is writable (read\_only: true is not set).

**Evidence:**

```text
read_only is not set
```

**Why it matters:** A read-only root filesystem prevents an attacker from modifying binaries or dropping tools inside the container and makes unexpected writes visible.

**Recommended remediation:** Set read\_only: true and provide writable locations explicitly with tmpfs (for example /tmp or /run) or volumes for application data. Many applications need some writable directories; test before enforcing.

### 40. SST-SEC-009: Read-only root filesystem not enabled

- **Rule ID:** SST-SEC-009 (version 1.0)
- **Severity:** low
- **Category:** security
- **Confidence:** high
- **Affected target:** service `portainer` (`testdata/compose/insecure.yaml:24`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-sec-009>

**Description:** The container's root filesystem is writable (read\_only: true is not set).

**Evidence:**

```text
read_only is not set
```

**Why it matters:** A read-only root filesystem prevents an attacker from modifying binaries or dropping tools inside the container and makes unexpected writes visible.

**Recommended remediation:** Set read\_only: true and provide writable locations explicitly with tmpfs (for example /tmp or /run) or volumes for application data. Many applications need some writable directories; test before enforcing.

### 41. SST-OPS-007: No stop grace period

- **Rule ID:** SST-OPS-007 (version 1.0)
- **Severity:** info
- **Category:** reliability
- **Confidence:** high
- **Affected target:** service `app` (`testdata/compose/insecure.yaml:3`)
- **Documentation:** <https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md#sst-ops-007>

**Description:** No stop\_grace\_period is set, so Docker kills the container 10 seconds after asking it to stop.

**Evidence:**

```text
stop_grace_period is not set (Docker default: 10s)
```

**Why it matters:** Databases, queues and workflow engines may need more than 10 seconds to flush data, finish jobs or close connections. A forced kill can corrupt data or lose in-flight work.

**Recommended remediation:** Set stop\_grace\_period to match the service's shutdown behavior (for example stop\_grace\_period: 30s for databases and workflow tools) and make sure the process handles SIGTERM or the configured stop\_signal.

### 42. SST-OPS-007: No stop grace period

- **Rule ID:** SST-OPS-007 (version 1.0)
- **Severity:** info
- **Category:** reliability
- **Confidence:** high
- **Affected target:** service `portainer` (`testdata/compose/insecure.yaml:24`)
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
   - SST-SEC-001 Docker socket mount detected: `app`
   - SST-SEC-002 Privileged container detected: `app`
   - SST-SEC-010 Insecure Docker API exposure: `portainer`
2. **Fix soon (high)**
   - SST-NET-001 Publicly published database port: `db`
   - SST-OPS-003 No restart policy configured: `app`, `db`, `portainer`
   - SST-SEC-003 Host network mode detected: `app`
   - SST-SEC-004 Dangerous Linux capabilities added: `app`
   - SST-SEC-007 Sensitive host path mounted: `app`
   - SST-SEC-011 Likely secret in environment variable: `app`, `db`
   - SST-STO-001 Database service without persistent volume: `db`
3. **Plan a fix (medium)**
   - SST-NET-003 Admin interface likely published broadly: `portainer`
   - SST-OPS-001 No healthcheck configured: `app`, `db`, `portainer`
   - SST-OPS-005 Mutable image tag: `app`, `db`
   - SST-RES-003 No log rotation configured: `app`, `db`, `portainer`
   - SST-SEC-006 Writable host bind mount: `app`
   - SST-SEC-008 No explicit non-root user: `app`, `db`, `portainer`
4. **Hardening backlog (low and info)**
   - SST-OPS-004 Container name explicitly hardcoded: `app`
   - SST-OPS-006 Image digest not pinned: `portainer`
   - SST-OPS-007 No stop grace period: `db`, `app`, `portainer`
   - SST-RES-001 No memory limit configured: `app`, `db`, `portainer`
   - SST-RES-002 No CPU limit configured: `app`, `db`, `portainer`
   - SST-SEC-005 Linux capabilities not dropped: `db`, `portainer`
   - SST-SEC-009 Read-only root filesystem not enabled: `app`, `db`, `portainer`

## Generated By

Generated by StackSentry v0.1.0 on 2026-10-01T12:00:00Z. StackSentry performs local, deterministic, rule-based analysis; no data left the machine that ran the scan. Findings support, but do not replace, a complete security review.
