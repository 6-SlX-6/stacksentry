# Rule reference

StackSentry v0.1.0 ships 37 deterministic rules: 27 for static Docker Compose
analysis (`stacksentry scan compose`) and 10 for local Docker host inspection
(`stacksentry scan host`). Every rule has a stable ID in the form
`SST-<CATEGORY>-<NUMBER>`, a default severity, a category, documented detection
logic, a rationale, remediation guidance and unit tests.

The same information is available offline:

```sh
stacksentry rules list
stacksentry rules show SST-SEC-001
stacksentry rules list --format json
```

## Conventions

**Severity** describes how urgently a finding should be addressed:

| Severity | Meaning |
|---|---|
| critical | Likely to allow host compromise or full loss of isolation. Fix before deploying. |
| high | Significant security or reliability risk. Fix soon. |
| medium | Weakens security or operability; plan a fix. |
| low | Hardening recommendation or advisory. |
| info | Context that needs no action by default. |

Some rules adjust the severity of individual findings based on evidence, for
example a database port published on `127.0.0.1` is *low* while the same port
published on all interfaces is *high*. The rule's default severity is listed
below; the detection text explains adjustments.

**Confidence** is `high` unless stated otherwise. Heuristic detections, such as
recognising a Docker API only by its port number, are reported with `medium`
confidence and say so in the output.

**Evidence** never contains secret values. Environment values that look like
credentials are replaced with `********` in every output format, and all report
text passes through a final redaction step as a safety net.

**Static analysis limits.** A Compose scan sees only the Compose files. It does
not pull images, so it cannot see an image's `USER` or `HEALTHCHECK`
instructions, and it does not read daemon-wide settings such as log rotation in
`/etc/docker/daemon.json`. Variables are interpolated deterministically: the
shell environment and `.env` files are not read, defaults written in the file
are applied, and variables without a default are treated as empty (and reported
by SST-CFG-001). Files referenced with `include:` are not analyzed in v0.1.0.

## Documented exceptions

If a finding is intentional, either skip the rule for the whole scan with
`--exclude SST-XXX-000`, or document the exception next to the service:

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

Suppressed findings are listed in every report with their reason, are not
counted in the finding totals and never trigger `--fail-on`. Entries without a
`reason` are accepted but reported as "no reason given". Unknown rule IDs in
`x-stacksentry.ignore` produce a warning.

<!-- BEGIN GENERATED RULES: run `make docs` to update -->

## Compose rules (`stacksentry scan compose`)

| Rule ID | Severity | Category | Title |
|---|---|---|---|
| [SST-CFG-001](#sst-cfg-001) | medium | operations | Required environment variable may be missing |
| [SST-NET-001](#sst-net-001) | high | networking | Publicly published database port |
| [SST-NET-002](#sst-net-002) | low | networking | No explicit network segmentation |
| [SST-NET-003](#sst-net-003) | medium | networking | Admin interface likely published broadly |
| [SST-OPS-001](#sst-ops-001) | medium | reliability | No healthcheck configured |
| [SST-OPS-002](#sst-ops-002) | medium | reliability | Healthcheck disabled |
| [SST-OPS-003](#sst-ops-003) | high | reliability | No restart policy configured |
| [SST-OPS-004](#sst-ops-004) | low | maintainability | Container name explicitly hardcoded |
| [SST-OPS-005](#sst-ops-005) | medium | supply-chain | Mutable image tag |
| [SST-OPS-006](#sst-ops-006) | low | supply-chain | Image digest not pinned |
| [SST-OPS-007](#sst-ops-007) | low | reliability | No stop grace period |
| [SST-RES-001](#sst-res-001) | low | resource-management | No memory limit configured |
| [SST-RES-002](#sst-res-002) | low | resource-management | No CPU limit configured |
| [SST-RES-003](#sst-res-003) | medium | resource-management | No log rotation configured |
| [SST-SEC-001](#sst-sec-001) | critical | security | Docker socket mount detected |
| [SST-SEC-002](#sst-sec-002) | critical | security | Privileged container detected |
| [SST-SEC-003](#sst-sec-003) | high | security | Host network mode detected |
| [SST-SEC-004](#sst-sec-004) | high | security | Dangerous Linux capabilities added |
| [SST-SEC-005](#sst-sec-005) | low | security | Linux capabilities not dropped |
| [SST-SEC-006](#sst-sec-006) | medium | security | Writable host bind mount |
| [SST-SEC-007](#sst-sec-007) | high | security | Sensitive host path mounted |
| [SST-SEC-008](#sst-sec-008) | medium | security | No explicit non-root user |
| [SST-SEC-009](#sst-sec-009) | low | security | Read-only root filesystem not enabled |
| [SST-SEC-010](#sst-sec-010) | critical | security | Insecure Docker API exposure |
| [SST-SEC-011](#sst-sec-011) | high | secrets | Likely secret in environment variable |
| [SST-SEC-012](#sst-sec-012) | medium | secrets | Environment file potentially tracked |
| [SST-STO-001](#sst-sto-001) | high | storage | Database service without persistent volume |

### SST-CFG-001

**Required environment variable may be missing**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| medium | operations | compose | 1.0 |

The Compose file uses variables without a default value, so the deployment depends on external configuration.

- **Detection:** Interpolation expressions ${VAR} and $VAR in the raw YAML. Expressions with a default (${VAR:-default}, ${VAR-default}), required markers (${VAR:?msg}, ${VAR?msg}), alternatives (${VAR:+alt}, ${VAR+alt}) and escaped dollars ($$) are not reported. HOME, PWD, USER, LOGNAME, PATH, SHELL and COMPOSE\_PROJECT\_NAME are always available and are ignored.
- **Why it matters:** If such a variable is not set at deploy time, Docker Compose substitutes an empty string and only prints a warning. That can silently produce broken or insecure configuration such as empty passwords, wrong image tags or unexpected port bindings.
- **Remediation:** Document the variable and provide it in the deployment environment or .env file. Use ${VAR:-default} for a safe default, or ${VAR:?error message} to make Compose fail fast when it is missing.
- **Limitations and false positives:** StackSentry does not read your shell environment or .env file, so it cannot tell whether a variable is actually set where you deploy. Only the files passed to the scan are inspected.
- **References:** https://docs.docker.com/reference/compose-file/interpolation/

### SST-NET-001

**Publicly published database port**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| high | networking | compose | 1.0 |

A database port is published on all host interfaces.

- **Detection:** Published ports whose container port is a common data service port (PostgreSQL 5432, MySQL/MariaDB 3306, MongoDB 27017, Redis 6379, Elasticsearch 9200, RabbitMQ 5672, Memcached 11211, MS SQL 1433) or any published port of a known database image. Severity depends on the host binding: all interfaces (including a random host port) is high, a specific interface is medium and 127.0.0.1/::1 is low.
- **Why it matters:** Published database ports are reachable from other machines and, on many Linux hosts, bypass host firewalls such as UFW or firewalld because Docker manages its own iptables rules. Databases reachable from the network are frequent targets of credential brute-forcing and ransom attacks.
- **Remediation:** Remove the ports entry if only other containers need the database; they can reach it over the Compose network by service name. If host access is required, bind to localhost, e.g. "127.0.0.1:5432:5432". Exposure may be intentional, but it should be reviewed.
- **Limitations and false positives:** Ports published through variables without defaults are evaluated as unbound, which Docker treats as all interfaces.
- **References:** https://docs.docker.com/reference/compose-file/services/#ports, https://docs.docker.com/engine/network/packet-filtering-firewalls/

### SST-NET-002

**No explicit network segmentation**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| low | networking | compose | 1.0 |

All services share the default network even though the stack has distinct tiers.

- **Detection:** Projects with at least 3 services in which no service declares a network other than the default one, at least one service runs a known database image and at least one other service publishes ports.
- **Why it matters:** On a single shared network every container can reach every other container. Separating public-facing services from databases limits lateral movement if a public service is compromised.
- **Remediation:** Define separate networks (for example frontend and backend), attach databases only to the backend network and consider internal: true for networks that need no outbound access.
- **Limitations and false positives:** Advisory. Small stacks are not reported to avoid noise.
- **References:** https://docs.docker.com/reference/compose-file/networks/, https://docs.docker.com/compose/how-tos/networking/

### SST-NET-003

**Admin interface likely published broadly**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| medium | networking | compose | 1.0 |

An administration interface appears to be published on all host interfaces.

- **Detection:** Ports published on all interfaces by images of Portainer, pgAdmin, Adminer, Mongo Express, Grafana, Redis Commander and phpMyAdmin, and Traefik's API/dashboard port 8080.
- **Why it matters:** Admin dashboards provide powerful control over infrastructure or data. Publishing them broadly increases exposure to credential guessing and to vulnerabilities in the tool itself.
- **Remediation:** Review the exposure. Bind the port to 127.0.0.1 and use an SSH tunnel or VPN, or put the interface behind a reverse proxy with strong authentication and TLS.
- **Limitations and false positives:** Detection is based on the image name; custom or renamed images are not recognized. The tool may already be protected by its own authentication.
- **References:** https://docs.docker.com/reference/compose-file/services/#ports

### SST-OPS-001

**No healthcheck configured**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| medium | reliability | compose | 1.0 |

No healthcheck is defined for the service in the Compose file.

- **Detection:** Services without a healthcheck section. One-shot jobs are skipped when another service waits for them with depends\_on condition: service\_completed\_successfully.
- **Why it matters:** Without a healthcheck Docker only knows whether the process is running, not whether it works. depends\_on with condition: service\_healthy, automated recovery and monitoring cannot detect a hung or misconfigured service.
- **Remediation:** Add a healthcheck that exercises the service (for example an HTTP endpoint or a database ping) with sensible interval, timeout, retries and start\_period values.
- **Limitations and false positives:** The image may define its own HEALTHCHECK instruction, which StackSentry cannot see without pulling the image. Other one-shot jobs cannot be detected reliably and are reported.
- **References:** https://docs.docker.com/reference/compose-file/services/#healthcheck

### SST-OPS-002

**Healthcheck disabled**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| medium | reliability | compose | 1.0 |

The service's healthcheck is explicitly disabled.

- **Detection:** healthcheck.disable: true or healthcheck.test: \["NONE"\].
- **Why it matters:** disable: true (or test: \["NONE"\]) also turns off any HEALTHCHECK defined by the image, so failures inside the container go unnoticed.
- **Remediation:** Remove the override or replace it with a working healthcheck. If disabling is intentional (for example because the image's check is broken), document the reason.
- **References:** https://docs.docker.com/reference/compose-file/services/#healthcheck

### SST-OPS-003

**No restart policy configured**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| high | reliability | compose | 1.0 |

No restart policy is configured, so the container stays down after a crash or host reboot.

- **Detection:** Neither restart nor deploy.restart\_policy is set (high). An explicit restart: "no" is reported as low, or medium when the service is clearly long-running (it publishes ports, has a healthcheck or runs a known database image). unless-stopped, always and on-failure are accepted. One-shot jobs that other services wait for with condition: service\_completed\_successfully are skipped.
- **Why it matters:** Docker's default restart policy is "no". A long-running service that crashes, or whose host reboots, stays down until someone intervenes.
- **Remediation:** Add: restart: unless-stopped (or always / on-failure, depending on the desired behavior).
- **Limitations and false positives:** Short-lived tasks that are not declared as dependencies cannot be told apart from services.
- **References:** https://docs.docker.com/reference/compose-file/services/#restart

### SST-OPS-004

**Container name explicitly hardcoded**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| low | maintainability | compose | 1.0 |

The service sets a fixed container\_name.

- **Detection:** container\_name is set.
- **Why it matters:** Fixed container names must be unique on the host. They prevent scaling the service, can clash with other projects or copies of the same stack, and bypass Compose's project-scoped naming.
- **Remediation:** Remove container\_name and let Compose generate project-scoped names. Other services can reach it by its service name, which works without container\_name.
- **References:** https://docs.docker.com/reference/compose-file/services/#container_name

### SST-OPS-005

**Mutable image tag**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| medium | supply-chain | compose | 1.0 |

The image uses a mutable tag (latest or no tag at all).

- **Detection:** Images without a tag or with the tag latest (medium). Tags that contain no version number at all, such as stable, main, edge or alpine, are reported as low-severity moving channel tags. Version tags such as 1.2.3 or 16-alpine and digest-pinned images are not reported. Services that build their image are skipped.
- **Why it matters:** Mutable tags can point to a different image every time you pull. Deployments become non-reproducible, rollbacks unreliable, and unreviewed upstream changes can reach production silently.
- **Remediation:** Pin a specific version tag (for example postgres:16.4) and update it deliberately. For full reproducibility also pin the digest (image: name:tag@sha256:...).
- **Limitations and false positives:** Partial version tags such as 16 also move between patch releases but are not reported here; SST-OPS-006 recommends digest pinning for them.
- **References:** https://docs.docker.com/reference/compose-file/services/#image

### SST-OPS-006

**Image digest not pinned**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| low | supply-chain | compose | 1.0 |

The image is pinned by version tag but not by digest.

- **Detection:** Images with a version tag and no @sha256 digest. Untagged, latest and channel tags are covered by SST-OPS-005 instead. Services that build their image are skipped.
- **Why it matters:** Tags can be re-pushed by the publisher, so the same tag may resolve to different content over time. Pinning the digest guarantees that every deployment runs exactly the reviewed image. This is a reproducibility recommendation, not a security vulnerability.
- **Remediation:** Append the digest: image: name:tag@sha256:\<digest\> (look it up with docker buildx imagetools inspect name:tag). Tools such as Renovate or Dependabot can keep digests up to date.
- **References:** https://docs.docker.com/reference/cli/docker/image/pull/#pull-an-image-by-digest-immutable-identifier

### SST-OPS-007

**No stop grace period**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| low | reliability | compose | 1.0 |

No stop\_grace\_period is set, so Docker kills the container 10 seconds after asking it to stop.

- **Detection:** stop\_grace\_period is not set. Reported as low for databases, brokers, workflow tools and services with named volumes, and as info for other services. One-shot jobs are skipped.
- **Why it matters:** Databases, queues and workflow engines may need more than 10 seconds to flush data, finish jobs or close connections. A forced kill can corrupt data or lose in-flight work.
- **Remediation:** Set stop\_grace\_period to match the service's shutdown behavior (for example stop\_grace\_period: 30s for databases and workflow tools) and make sure the process handles SIGTERM or the configured stop\_signal.
- **Limitations and false positives:** This is a reliability suggestion; many stateless services stop well within 10 seconds.
- **References:** https://docs.docker.com/reference/compose-file/services/#stop_grace_period

### SST-RES-001

**No memory limit configured**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| low | resource-management | compose | 1.0 |

No memory limit is configured for the service.

- **Detection:** Neither deploy.resources.limits.memory nor mem\_limit is set.
- **Why it matters:** A memory leak or load spike in one container can consume all host memory and trigger the kernel OOM killer for unrelated processes, including other services on the host.
- **Remediation:** Set deploy.resources.limits.memory (for example 512M) based on observed usage, or mem\_limit for older Compose versions.
- **Limitations and false positives:** Advisory. Docker Compose applies deploy.resources limits to standalone containers, while Swarm interprets the deploy section differently; choose limits that suit how you deploy.
- **References:** https://docs.docker.com/reference/compose-file/deploy/#resources

### SST-RES-002

**No CPU limit configured**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| low | resource-management | compose | 1.0 |

No CPU limit is configured for the service.

- **Detection:** None of deploy.resources.limits.cpus, cpus or cpu\_quota is set.
- **Why it matters:** Without a CPU limit a busy or runaway container can starve other services on the same host.
- **Remediation:** Set deploy.resources.limits.cpus (for example "1.0") or cpus for older Compose versions.
- **Limitations and false positives:** Advisory, with the same Compose/Swarm caveat as SST-RES-001.
- **References:** https://docs.docker.com/reference/compose-file/deploy/#resources

### SST-RES-003

**No log rotation configured**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| medium | resource-management | compose | 1.0 |

Container logs are not configured to rotate.

- **Detection:** No logging section (the daemon default driver applies) or the json-file driver without a max-size option. The local driver, which rotates by default, and drivers that ship logs elsewhere are accepted.
- **Why it matters:** Docker's default json-file log driver keeps logs without limit unless max-size is set, so a chatty container can fill the disk.
- **Remediation:** Configure rotation, for example logging: {driver: json-file, options: {max-size: "10m", max-file: "3"}}, or set log-driver/log-opts once for all containers in the Docker daemon configuration.
- **Limitations and false positives:** The Docker daemon may already set log rotation globally in daemon.json; StackSentry cannot see that during a static scan, so treat this finding as advisory.
- **References:** https://docs.docker.com/engine/logging/drivers/json-file/

### SST-SEC-001

**Docker socket mount detected**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| critical | security | compose | 1.0 |

The Docker daemon socket is mounted into the container.

- **Detection:** Bind mounts and named pipes whose source or target ends in docker.sock (e.g. /var/run/docker.sock, /run/docker.sock, a rootless $XDG\_RUNTIME\_DIR/docker.sock) or refers to the Windows pipe \\\\.\\pipe\\docker\_engine, and services with use\_api\_socket: true.
- **Why it matters:** Access to the Docker socket can effectively grant host-level control: anyone who can talk to it can start privileged containers and mount the host filesystem. Mounting it read-only (:ro) does not restrict API calls.
- **Remediation:** Remove the mount unless this service explicitly requires Docker daemon access. If it does (for example a reverse proxy reading container labels), put a filtering socket proxy in front of the socket that only allows the required read-only API endpoints.
- **Limitations and false positives:** Sockets renamed to something other than docker.sock are not detected. Mounting a parent directory such as /var/run is reported by SST-SEC-007 instead.
- **References:** https://docs.docker.com/engine/security/#docker-daemon-attack-surface, https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

### SST-SEC-002

**Privileged container detected**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| critical | security | compose | 1.0 |

The service runs in privileged mode.

- **Detection:** privileged: true on a service.
- **Why it matters:** privileged: true grants all Linux capabilities and access to all host devices and disables most isolation (seccomp, AppArmor/SELinux confinement). A compromise of the process is close to a compromise of the host.
- **Remediation:** Remove privileged: true. Grant only the specific capabilities (cap\_add) or devices (devices) the workload needs, and document why they are required.
- **References:** https://docs.docker.com/reference/compose-file/services/#privileged, https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

### SST-SEC-003

**Host network mode detected**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| high | security | compose | 1.0 |

The service shares the host's network stack (network\_mode: host).

- **Detection:** network\_mode: host on a service.
- **Why it matters:** Host networking removes normal Docker network isolation: every port the process opens is reachable on all host interfaces, port publishing rules no longer apply, and the container can reach services bound to the host's localhost.
- **Remediation:** Use a bridge network and publish only the required ports, preferably bound to 127.0.0.1 or a specific interface. Keep host networking only for workloads that need it (for example some discovery or VPN tools) and document the exception.
- **References:** https://docs.docker.com/reference/compose-file/services/#network_mode

### SST-SEC-004

**Dangerous Linux capabilities added**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| high | security | compose | 1.0 |

The service adds Linux capabilities that significantly weaken container isolation.

- **Detection:** cap\_add contains one of: ALL, SYS\_ADMIN, SYS\_PTRACE, NET\_ADMIN, SYS\_MODULE, DAC\_READ\_SEARCH, SYS\_RAWIO, SYS\_BOOT, SYS\_TIME, MKNOD, BPF. The CAP\_ prefix and letter case are ignored.
- **Why it matters:** These capabilities grant kernel-level privileges that are commonly abused for container escapes, for example mounting filesystems, loading kernel modules or tracing other processes.
- **Remediation:** Remove the listed capabilities from cap\_add unless they are strictly required. If one is needed, document why and combine it with cap\_drop: \[ALL\], a non-root user and security\_opt: \[no-new-privileges:true\].
- **Limitations and false positives:** MKNOD is part of Docker's default capability set; it is reported only when added explicitly.
- **References:** https://man7.org/linux/man-pages/man7/capabilities.7.html, https://docs.docker.com/reference/compose-file/services/#cap_add

### SST-SEC-005

**Linux capabilities not dropped**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| low | security | compose | 1.0 |

The service keeps Docker's default Linux capabilities (cap\_drop does not contain ALL).

- **Detection:** cap\_drop does not contain ALL. Privileged services are skipped because SST-SEC-002 already covers them.
- **Why it matters:** Docker grants containers a default capability set (for example CHOWN, SETUID, NET\_RAW). Most applications need few or none of them. This is a hardening recommendation, not a defect: some images need specific capabilities to start.
- **Remediation:** Add cap\_drop: \[ALL\] and add back only what the service needs with cap\_add (for example NET\_BIND\_SERVICE to bind ports below 1024). Test the service after the change.
- **Limitations and false positives:** Compatibility may require some capabilities; treat this as advisory.
- **References:** https://man7.org/linux/man-pages/man7/capabilities.7.html, https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

### SST-SEC-006

**Writable host bind mount**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| medium | security | compose | 1.0 |

A host path is bind-mounted without read-only protection.

- **Detection:** Volumes of type bind without read-only protection.
- **Why it matters:** A writable bind mount lets the container modify files on the host. If the container is compromised, an attacker can tamper with host files, configuration or data shared with other services.
- **Remediation:** Append :ro (short syntax) or set read\_only: true (long syntax) for mounts the container only reads, such as configuration files. For data the service must write, prefer a named volume or make sure the host directory is dedicated to this service.
- **Limitations and false positives:** Named volumes, anonymous volumes and tmpfs mounts are not reported. Docker socket mounts are reported by SST-SEC-001 instead. Some services legitimately need to write to their bind mounts.
- **References:** https://docs.docker.com/reference/compose-file/services/#volumes

### SST-SEC-007

**Sensitive host path mounted**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| high | security | compose | 1.0 |

A sensitive host location is bind-mounted into the container.

- **Detection:** Bind mount sources equal to / or /home, inside /etc, /proc, /sys, /dev, /root, /boot, /var/lib/docker, /run or /var/run, whole user home directories (/home/\<user\>, ~) and credential directories inside them (.ssh, .gnupg, .aws, .kube, .docker, .azure, .config/gcloud).
- **Why it matters:** System locations such as /, /etc, /proc, /sys, /dev, /root or /var/lib/docker expose host credentials, kernel interfaces, devices or other containers' data. Write access usually allows a full host compromise; even read access can leak secrets.
- **Remediation:** Mount only the specific file or subdirectory the service needs, read-only where possible. Monitoring agents that legitimately need /proc or /sys should mount them read-only and be reviewed as privileged components.
- **Limitations and false positives:** Read-only mounts of /etc/localtime, /etc/timezone, /etc/machine-id and CA certificate directories and mounts of /dev/null, /dev/zero, /dev/random and /dev/urandom are not reported. Docker socket paths are reported by SST-SEC-001. Paths built from variables without defaults are evaluated with those variables empty.
- **References:** https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

### SST-SEC-008

**No explicit non-root user**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| medium | security | compose | 1.0 |

No user is configured, so the container runs as the image's default user, which is root for many images.

- **Detection:** user is not set, or is set to root, 0 or 0:\<gid\>.
- **Why it matters:** Processes running as root inside a container have more power if they escape isolation or write to mounted volumes. Without a user setting the effective user depends on the image's USER instruction, which StackSentry cannot see without pulling the image.
- **Remediation:** Add a dedicated unprivileged user where supported by the image, e.g. user: "1000:1000" or a named user documented by the image (such as node). Make sure mounted volumes are writable by that UID.
- **Limitations and false positives:** The absence of user does not prove that the container runs as root; the image may already define a non-root USER.
- **References:** https://docs.docker.com/reference/compose-file/services/#user, https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

### SST-SEC-009

**Read-only root filesystem not enabled**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| low | security | compose | 1.0 |

The container's root filesystem is writable (read\_only: true is not set).

- **Detection:** read\_only is not set to true.
- **Why it matters:** A read-only root filesystem prevents an attacker from modifying binaries or dropping tools inside the container and makes unexpected writes visible.
- **Remediation:** Set read\_only: true and provide writable locations explicitly with tmpfs (for example /tmp or /run) or volumes for application data. Many applications need some writable directories; test before enforcing.
- **Limitations and false positives:** Advisory hardening recommendation; some images cannot run with a read-only root filesystem.
- **References:** https://docs.docker.com/reference/compose-file/services/#read_only, https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

### SST-SEC-010

**Insecure Docker API exposure**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| critical | security | compose | 1.0 |

The service appears to expose or use the Docker Engine API over unencrypted TCP.

- **Detection:** Published ports 2375 (critical when reachable from the network, high on localhost); dockerd started with -H/--host tcp://… without --tlsverify (high); docker:dind with DOCKER\_TLS\_CERTDIR set to an empty value (high); DOCKER\_HOST=tcp://… without DOCKER\_CERT\_PATH (medium, or low when it points to another service of the same project). Confidence is high when the image or service name identifies a Docker daemon or socket proxy and medium when only the port number or a client setting indicates it.
- **Why it matters:** The Docker Engine API on TCP port 2375 has neither authentication nor encryption. Anyone who can reach it controls the Docker host, which is equivalent to root access.
- **Remediation:** Do not publish port 2375. If remote API access is required, use TLS with client certificate verification (port 2376, --tlsverify) or SSH (DOCKER\_HOST=ssh://user@host). Keep socket proxies on an internal network and never publish their port.
- **Limitations and false positives:** Detection is heuristic. A service may use port 2375 for something else, and DOCKER\_HOST may point to a properly restricted proxy.
- **References:** https://docs.docker.com/engine/security/protect-access/, https://docs.docker.com/engine/security/#docker-daemon-attack-surface

### SST-SEC-011

**Likely secret in environment variable**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| high | secrets | compose | 1.0 |

An environment variable that looks like a credential has an inline value in the Compose file.

- **Detection:** Inline environment values (after applying defaults written in the file) whose variable name contains PASSWORD, PASSWD, PASS, PASSPHRASE, PWD, SECRET, TOKEN, APIKEY, CREDENTIAL(S) or a pair such as API\_KEY, PRIVATE\_KEY, ACCESS\_KEY, SECRET\_KEY, ENCRYPTION\_KEY, SIGNING\_KEY, AUTH\_KEY, MASTER\_KEY or CLIENT\_SECRET, and any value that is a URL with an embedded password. Names ending in \_FILE, \_PATH, \_USER, \_NAME, \_URL and similar settings, empty values, booleans, short numbers, /run/secrets paths and obvious placeholders such as \<password\>, xxxx or your-token-here are ignored. Values are never printed; they are replaced with \*\*\*\*\*\*\*\*.
- **Why it matters:** Inline secrets end up in version control, backups, CI logs and docker inspect output, and are visible to everyone who can read the Compose file.
- **Remediation:** Move the value out of the Compose file: use Docker secrets (with \*\_FILE variables where the image supports them), an external secret manager, or interpolation such as ${DB\_PASSWORD} with the value injected at deploy time from an environment file that is not committed. Rotate the secret if the file was ever shared.
- **Limitations and false positives:** Name-based detection can miss secrets stored under unusual names and can flag non-secret settings. Values of variables interpolated without a default (${VAR}) are not known and therefore not reported.
- **References:** https://docs.docker.com/compose/how-tos/use-secrets/, https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html

### SST-SEC-012

**Environment file potentially tracked**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| medium | secrets | compose | 1.0 |

The service loads variables from an env\_file, which often contains credentials.

- **Detection:** Any env\_file entry on a service.
- **Why it matters:** Environment files frequently hold passwords and API keys. If they are committed to a repository or copied into backups or images, the secrets leak. StackSentry does not inspect your Git repository, so this is a reminder, not proof that the file is tracked.
- **Remediation:** Make sure the file is listed in .gitignore (and .dockerignore), restrict its permissions (for example chmod 600) and commit only a template such as .env.example without real values.
- **Limitations and false positives:** The file content and its Git status are not inspected.
- **References:** https://docs.docker.com/compose/how-tos/environment-variables/set-environment-variables/#use-the-env_file-attribute

### SST-STO-001

**Database service without persistent volume**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| high | storage | compose | 1.0 |

The database service has no volume mounted at its data directory.

- **Detection:** Known PostgreSQL, MySQL, MariaDB, MongoDB and Redis/Valkey images (official, Bitnami and common variants) without a volume or bind mount at, above or below their data directory. PGDATA is honored for PostgreSQL. Redis is reported as medium because it is often used as a disposable cache, and is skipped when persistence is disabled with --save "".
- **Why it matters:** Without a volume the data lives in the container's writable layer and is lost when the container is recreated, for example by docker compose down, an image upgrade or a configuration change.
- **Remediation:** Mount a named volume at the data directory, e.g. "pgdata:/var/lib/postgresql/data", declare it under the top-level volumes key and back it up regularly.
- **Limitations and false positives:** Conservative: unknown or custom database images, volumes\_from and tmpfs data directories are not reported.
- **References:** https://docs.docker.com/engine/storage/volumes/

## Host rules (`stacksentry scan host`)

| Rule ID | Severity | Category | Title |
|---|---|---|---|
| [SST-HOST-001](#sst-host-001) | info | operations | Docker daemon reachable |
| [SST-HOST-002](#sst-host-002) | high | security | Docker daemon TCP listener |
| [SST-HOST-003](#sst-host-003) | critical | security | Privileged container running |
| [SST-HOST-004](#sst-host-004) | critical | security | Container mounts Docker socket |
| [SST-HOST-005](#sst-host-005) | high | security | Container uses host network |
| [SST-HOST-006](#sst-host-006) | high | reliability | Container without restart policy |
| [SST-HOST-007](#sst-host-007) | info | maintainability | Stopped containers present |
| [SST-HOST-008](#sst-host-008) | low | resource-management | Dangling images |
| [SST-HOST-009](#sst-host-009) | medium | resource-management | Docker disk usage pressure |
| [SST-HOST-010](#sst-host-010) | medium | supply-chain | Running container uses mutable image reference |

### SST-HOST-001

**Docker daemon reachable**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| info | operations | host | 1.0 |

The Docker daemon is reachable and its version information was collected.

- **Detection:** Always reported when the daemon answers. If the daemon cannot be reached the scan stops with exit code 2 and an explanation instead.
- **Why it matters:** Knowing the exact Docker Engine and API version helps to correlate other findings with release notes and security advisories for that version.
- **Remediation:** No action required. Keep Docker Engine updated to a supported release.
- **References:** https://docs.docker.com/engine/release-notes/

### SST-HOST-002

**Docker daemon TCP listener**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| high | security | host | 1.0 |

The Docker daemon appears to accept API connections over TCP without TLS client verification.

- **Detection:** Docker API warnings about unencrypted API access, a DOCKER\_HOST of tcp:// without TLS, and on Linux with a local daemon: hosts in /etc/docker/daemon.json, -H/--host flags of the running dockerd process and sockets listening on port 2375 in /proc/net/tcp and /proc/net/tcp6 (medium confidence because the owning process is not identified). Listeners reachable from the network are critical; localhost-only listeners are high.
- **Why it matters:** The Docker API grants full control over the host. Without TLS client certificate verification, anyone who can reach the TCP port can run privileged containers, which is equivalent to root access.
- **Remediation:** Remove tcp:// entries from the daemon's -H flags and daemon.json "hosts", or enable TLS with --tlsverify and client certificates (port 2376). For remote administration prefer SSH (DOCKER\_HOST=ssh://user@host) or a VPN.
- **Limitations and false positives:** Sources that cannot be read (for example because of permissions, Docker Desktop or a remote daemon) are listed as scan limitations. No elevated privileges are requested.
- **References:** https://docs.docker.com/engine/security/protect-access/, https://docs.docker.com/engine/security/#docker-daemon-attack-surface

### SST-HOST-003

**Privileged container running**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| critical | security | host | 1.0 |

A running container was started in privileged mode.

- **Detection:** Running containers whose HostConfig.Privileged is true.
- **Why it matters:** Privileged containers have all capabilities and access to host devices; a compromise is close to a compromise of the host.
- **Remediation:** Recreate the container without --privileged / privileged: true and grant only the specific capabilities or devices it needs.
- **References:** https://docs.docker.com/reference/cli/docker/container/run/#privileged

### SST-HOST-004

**Container mounts Docker socket**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| critical | security | host | 1.0 |

A running container has the Docker daemon socket mounted.

- **Detection:** Mounts of running containers whose source or destination ends in docker.sock or docker.proxy.sock.
- **Why it matters:** Access to the Docker socket can effectively grant host-level control, even when it is mounted read-only.
- **Remediation:** Remove the socket mount unless the container must control Docker. If it must, use a filtering socket proxy that only allows the required read-only API endpoints.
- **References:** https://docs.docker.com/engine/security/#docker-daemon-attack-surface

### SST-HOST-005

**Container uses host network**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| high | security | host | 1.0 |

A running container shares the host's network namespace.

- **Detection:** Running containers whose network mode is host.
- **Why it matters:** Host networking removes Docker network isolation; every port the process opens is reachable on all host interfaces.
- **Remediation:** Recreate the container on a bridge network and publish only the required ports, preferably bound to 127.0.0.1 or a specific interface.
- **References:** https://docs.docker.com/engine/network/drivers/host/

### SST-HOST-006

**Container without restart policy**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| high | reliability | host | 1.0 |

A running container has no restart policy and will stay down after a crash or host reboot.

- **Detection:** Running containers whose restart policy is empty or "no". Containers started with --rm (auto-remove) are skipped because they are one-off tasks.
- **Why it matters:** Docker's default restart policy is "no". Long-running services without a restart policy need manual intervention after failures or reboots.
- **Remediation:** Recreate the container with a restart policy such as unless-stopped (docker update --restart unless-stopped \<container\> also works without recreating it).
- **References:** https://docs.docker.com/engine/containers/start-containers-automatically/

### SST-HOST-007

**Stopped containers present**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| info | maintainability | host | 1.0 |

The host has stopped containers.

- **Detection:** Containers in the exited, created or dead state. Up to 10 names are listed.
- **Why it matters:** Stopped containers keep their writable layer and configuration on disk and can make it harder to see which workloads are actually in use.
- **Remediation:** Review the stopped containers and remove those that are no longer needed (docker container prune removes all stopped containers; review the list first).
- **References:** https://docs.docker.com/engine/manage-resources/pruning/

### SST-HOST-008

**Dangling images**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| low | resource-management | host | 1.0 |

The host stores dangling images that are not referenced by any tag.

- **Detection:** Images returned by the API with the filter dangling=true.
- **Why it matters:** Dangling images are typically left behind by rebuilds and pulls. They consume disk space and are not used by new containers.
- **Remediation:** Remove them with docker image prune after confirming they are not needed.
- **References:** https://docs.docker.com/engine/manage-resources/pruning/

### SST-HOST-009

**Docker disk usage pressure**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| medium | resource-management | host | 1.0 |

A large amount of Docker disk space is reclaimable.

- **Detection:** Docker's disk usage data (docker system df) shows at least 20.0 GiB reclaimable, or at least 50% of Docker's total usage reclaimable with at least 5.0 GiB reclaimable.
- **Why it matters:** Unused images, stopped containers, unused volumes and build cache accumulate over time. When the filesystem holding Docker's data fills up, containers fail to start, write or log.
- **Remediation:** Review docker system df -v and remove unused data with docker image prune, docker builder prune and, carefully, docker volume prune. Consider scheduled cleanup and monitoring of the Docker data filesystem.
- **Limitations and false positives:** The Docker API does not report free space of the filesystem, so the check is based on reclaimable Docker data rather than actual disk fullness.
- **References:** https://docs.docker.com/engine/manage-resources/pruning/

### SST-HOST-010

**Running container uses mutable image reference**

| Default severity | Category | Scope | Version |
|---|---|---|---|
| medium | supply-chain | host | 1.0 |

A running container was created from a mutable image reference (latest or no tag).

- **Detection:** The image reference a running container was created from has no tag or the latest tag (medium), or a tag without any version number such as stable (low). Digest and image ID references are not reported.
- **Why it matters:** Recreating the container may silently pull a different image, which makes deployments non-reproducible and rollbacks unreliable.
- **Remediation:** Recreate the container from a pinned version tag, ideally with a digest (name:tag@sha256:...).
- **References:** https://docs.docker.com/reference/cli/docker/image/pull/#pull-an-image-by-digest-immutable-identifier

<!-- END GENERATED RULES -->

## Planned rules

The following checks were considered for v0.1.0 but are not implemented yet,
either because they need data StackSentry does not collect (such as image
contents) or because a reliable, low-noise detection needs more design:

- `pid: host`, `ipc: host` and `userns_mode: host` namespace sharing.
- `security_opt` disabling seccomp, AppArmor or SELinux (`seccomp:unconfined`),
  and missing `no-new-privileges`.
- Host devices passed with `devices:`.
- Secrets in `build.args`, labels (for example Traefik basic-auth hashes) and
  command-line arguments.
- Repository-aware checks, such as verifying that `env_file` files are ignored
  by Git.
- Analysis of files referenced with `include:`.
- Host checks for daemon settings such as `live-restore`, user namespace
  remapping and default log rotation.
