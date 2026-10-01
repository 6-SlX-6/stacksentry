// Package hostrules implements the Docker host rules evaluated against a
// snapshot collected from the local Docker daemon.
package hostrules

import (
	"fmt"
	"strings"

	"github.com/6-SlX-6/stacksentry/internal/docker"
	"github.com/6-SlX-6/stacksentry/internal/engine"
	"github.com/6-SlX-6/stacksentry/internal/findings"
	"github.com/6-SlX-6/stacksentry/internal/imageref"
)

// Rule is a Docker host rule.
type Rule = engine.Rule[*docker.Snapshot]

// Disk usage thresholds for SST-HOST-009.
const (
	// DiskReclaimableAbsolute reports when at least this much space could
	// be reclaimed by docker system prune.
	DiskReclaimableAbsolute int64 = 20 << 30
	// DiskReclaimableRatio reports when this share of Docker's disk usage is
	// reclaimable and the reclaimable amount is at least DiskRatioMinimum.
	DiskReclaimableRatio = 0.5
	// DiskRatioMinimum avoids reporting small hosts with little data.
	DiskRatioMinimum int64 = 5 << 30
	// stoppedNamesShown limits the names listed by SST-HOST-007.
	stoppedNamesShown = 10
)

const (
	refAttackSurface = "https://docs.docker.com/engine/security/#docker-daemon-attack-surface"
	refProtectAPI    = "https://docs.docker.com/engine/security/protect-access/"
	refRunPrivileged = "https://docs.docker.com/reference/cli/docker/container/run/#privileged"
	refRestart       = "https://docs.docker.com/engine/containers/start-containers-automatically/"
	refPrune         = "https://docs.docker.com/engine/manage-resources/pruning/"
	refHostNetwork   = "https://docs.docker.com/engine/network/drivers/host/"
	refDigest        = "https://docs.docker.com/reference/cli/docker/image/pull/#pull-an-image-by-digest-immutable-identifier"
)

func newRule(meta engine.Metadata, fn func(*docker.Snapshot) []engine.Issue) Rule {
	meta.Scope = engine.ScopeHost
	if meta.Version == "" {
		meta.Version = "1.0"
	}
	return engine.FuncRule[*docker.Snapshot]{Meta: meta, Fn: fn}
}

// Registry returns a validated registry of all host rules.
func Registry() *engine.Registry[*docker.Snapshot] {
	return engine.MustRegistry(engine.ScopeHost, All()...)
}

// All returns every built-in host rule.
func All() []Rule {
	return []Rule{
		newRule(engine.Metadata{
			ID:          "SST-HOST-001",
			Title:       "Docker daemon reachable",
			Category:    findings.CategoryOperations,
			Severity:    findings.SeverityInfo,
			Description: "The Docker daemon is reachable and its version information was collected.",
			Rationale: "Knowing the exact Docker Engine and API version helps to correlate other findings with release " +
				"notes and security advisories for that version.",
			Remediation: "No action required. Keep Docker Engine updated to a supported release.",
			Detection: "Always reported when the daemon answers. If the daemon cannot be reached the scan stops with " +
				"exit code 2 and an explanation instead.",
			References: []string{"https://docs.docker.com/engine/release-notes/"},
		}, func(s *docker.Snapshot) []engine.Issue {
			evidence := []string{"endpoint: " + s.Endpoint}
			if s.Daemon.Version != "" {
				evidence = append(evidence, fmt.Sprintf("Docker Engine %s (API %s, %s/%s)", s.Daemon.Version, s.Daemon.APIVersion, s.Daemon.OSType, s.Daemon.Architecture))
			}
			if s.Daemon.OperatingSystem != "" {
				evidence = append(evidence, "host OS: "+s.Daemon.OperatingSystem)
			}
			if s.Daemon.KernelVersion != "" {
				evidence = append(evidence, "kernel: "+s.Daemon.KernelVersion)
			}
			if s.Daemon.Rootless {
				evidence = append(evidence, "rootless mode: enabled")
			}
			return []engine.Issue{hostIssue(s, evidence...)}
		}),

		newRule(engine.Metadata{
			ID:          "SST-HOST-002",
			Title:       "Docker daemon TCP listener",
			Category:    findings.CategorySecurity,
			Severity:    findings.SeverityHigh,
			Description: "The Docker daemon appears to accept API connections over TCP without TLS client verification.",
			Rationale: "The Docker API grants full control over the host. Without TLS client certificate verification, " +
				"anyone who can reach the TCP port can run privileged containers, which is equivalent to root access.",
			Remediation: "Remove tcp:// entries from the daemon's -H flags and daemon.json \"hosts\", or enable TLS with " +
				"--tlsverify and client certificates (port 2376). For remote administration prefer SSH " +
				"(DOCKER_HOST=ssh://user@host) or a VPN.",
			Detection: "Docker API warnings about unencrypted API access, a DOCKER_HOST of tcp:// without TLS, and on " +
				"Linux with a local daemon: hosts in /etc/docker/daemon.json, -H/--host flags of the running dockerd " +
				"process and sockets listening on port 2375 in /proc/net/tcp and /proc/net/tcp6 (medium confidence because " +
				"the owning process is not identified). Listeners reachable from the network are critical; localhost-only " +
				"listeners are high.",
			Limitations: "Sources that cannot be read (for example because of permissions, Docker Desktop or a remote " +
				"daemon) are listed as scan limitations. No elevated privileges are requested.",
			References: []string{refProtectAPI, refAttackSurface},
		}, checkListeners),

		newRule(engine.Metadata{
			ID:          "SST-HOST-003",
			Title:       "Privileged container running",
			Category:    findings.CategorySecurity,
			Severity:    findings.SeverityCritical,
			Description: "A running container was started in privileged mode.",
			Rationale: "Privileged containers have all capabilities and access to host devices; a compromise is close to " +
				"a compromise of the host.",
			Remediation: "Recreate the container without --privileged / privileged: true and grant only the specific " +
				"capabilities or devices it needs.",
			Detection:  "Running containers whose HostConfig.Privileged is true.",
			References: []string{refRunPrivileged},
		}, perRunning(func(c docker.Container) []string {
			if !c.Privileged {
				return nil
			}
			return []string{"privileged: true"}
		})),

		newRule(engine.Metadata{
			ID:          "SST-HOST-004",
			Title:       "Container mounts Docker socket",
			Category:    findings.CategorySecurity,
			Severity:    findings.SeverityCritical,
			Description: "A running container has the Docker daemon socket mounted.",
			Rationale: "Access to the Docker socket can effectively grant host-level control, even when it is mounted " +
				"read-only.",
			Remediation: "Remove the socket mount unless the container must control Docker. If it must, use a filtering " +
				"socket proxy that only allows the required read-only API endpoints.",
			Detection:  "Mounts of running containers whose source or destination ends in docker.sock or docker.proxy.sock.",
			References: []string{refAttackSurface},
		}, perRunning(func(c docker.Container) []string {
			var evidence []string
			for _, m := range c.Mounts {
				if isSocket(m.Source) || isSocket(m.Destination) {
					access := "read-write"
					if !m.RW {
						access = "read-only"
					}
					evidence = append(evidence, fmt.Sprintf("%s -> %s (%s)", m.Source, m.Destination, access))
				}
			}
			return evidence
		})),

		newRule(engine.Metadata{
			ID:          "SST-HOST-005",
			Title:       "Container uses host network",
			Category:    findings.CategorySecurity,
			Severity:    findings.SeverityHigh,
			Description: "A running container shares the host's network namespace.",
			Rationale: "Host networking removes Docker network isolation; every port the process opens is reachable on " +
				"all host interfaces.",
			Remediation: "Recreate the container on a bridge network and publish only the required ports, preferably " +
				"bound to 127.0.0.1 or a specific interface.",
			Detection:  "Running containers whose network mode is host.",
			References: []string{refHostNetwork},
		}, perRunning(func(c docker.Container) []string {
			if c.NetworkMode != "host" {
				return nil
			}
			return []string{"network mode: host"}
		})),

		newRule(engine.Metadata{
			ID:          "SST-HOST-006",
			Title:       "Container without restart policy",
			Category:    findings.CategoryReliability,
			Severity:    findings.SeverityHigh,
			Description: "A running container has no restart policy and will stay down after a crash or host reboot.",
			Rationale: "Docker's default restart policy is \"no\". Long-running services without a restart policy need " +
				"manual intervention after failures or reboots.",
			Remediation: "Recreate the container with a restart policy such as unless-stopped (docker update " +
				"--restart unless-stopped <container> also works without recreating it).",
			Detection: "Running containers whose restart policy is empty or \"no\". Containers started with --rm " +
				"(auto-remove) are skipped because they are one-off tasks.",
			References: []string{refRestart},
		}, perRunning(func(c docker.Container) []string {
			if !c.Inspected || c.AutoRemove || (c.RestartPolicy != "" && c.RestartPolicy != "no") {
				return nil
			}
			policy := c.RestartPolicy
			if policy == "" {
				policy = "not set"
			}
			return []string{"restart policy: " + policy}
		})),

		newRule(engine.Metadata{
			ID:          "SST-HOST-007",
			Title:       "Stopped containers present",
			Category:    findings.CategoryMaintainability,
			Severity:    findings.SeverityInfo,
			Description: "The host has stopped containers.",
			Rationale: "Stopped containers keep their writable layer and configuration on disk and can make it harder " +
				"to see which workloads are actually in use.",
			Remediation: "Review the stopped containers and remove those that are no longer needed (docker container " +
				"prune removes all stopped containers; review the list first).",
			Detection:  fmt.Sprintf("Containers in the exited, created or dead state. Up to %d names are listed.", stoppedNamesShown),
			References: []string{refPrune},
		}, checkStopped),

		newRule(engine.Metadata{
			ID:          "SST-HOST-008",
			Title:       "Dangling images",
			Category:    findings.CategoryResourceManagement,
			Severity:    findings.SeverityLow,
			Description: "The host stores dangling images that are not referenced by any tag.",
			Rationale: "Dangling images are typically left behind by rebuilds and pulls. They consume disk space and " +
				"are not used by new containers.",
			Remediation: "Remove them with docker image prune after confirming they are not needed.",
			Detection:   "Images returned by the API with the filter dangling=true.",
			References:  []string{refPrune},
		}, func(s *docker.Snapshot) []engine.Issue {
			if len(s.DanglingImages) == 0 {
				return nil
			}
			var size int64
			for _, img := range s.DanglingImages {
				size += img.Size
			}
			return []engine.Issue{hostIssue(s, fmt.Sprintf("%d dangling image(s) using %s", len(s.DanglingImages), humanBytes(size)))}
		}),

		newRule(engine.Metadata{
			ID:          "SST-HOST-009",
			Title:       "Docker disk usage pressure",
			Category:    findings.CategoryResourceManagement,
			Severity:    findings.SeverityMedium,
			Description: "A large amount of Docker disk space is reclaimable.",
			Rationale: "Unused images, stopped containers, unused volumes and build cache accumulate over time. When the " +
				"filesystem holding Docker's data fills up, containers fail to start, write or log.",
			Remediation: "Review docker system df -v and remove unused data with docker image prune, docker builder prune " +
				"and, carefully, docker volume prune. Consider scheduled cleanup and monitoring of the Docker data filesystem.",
			Detection: fmt.Sprintf("Docker's disk usage data (docker system df) shows at least %s reclaimable, or at least "+
				"%.0f%% of Docker's total usage reclaimable with at least %s reclaimable.",
				humanBytes(DiskReclaimableAbsolute), DiskReclaimableRatio*100, humanBytes(DiskRatioMinimum)),
			Limitations: "The Docker API does not report free space of the filesystem, so the check is based on " +
				"reclaimable Docker data rather than actual disk fullness.",
			References: []string{refPrune},
		}, checkDiskUsage),

		newRule(engine.Metadata{
			ID:          "SST-HOST-010",
			Title:       "Running container uses mutable image reference",
			Category:    findings.CategorySupplyChain,
			Severity:    findings.SeverityMedium,
			Description: "A running container was created from a mutable image reference (latest or no tag).",
			Rationale: "Recreating the container may silently pull a different image, which makes deployments " +
				"non-reproducible and rollbacks unreliable.",
			Remediation: "Recreate the container from a pinned version tag, ideally with a digest (name:tag@sha256:...).",
			Detection: "The image reference a running container was created from has no tag or the latest tag " +
				"(medium), or a tag without any version number such as stable (low). Digest and image ID references are " +
				"not reported.",
			References: []string{refDigest},
		}, func(s *docker.Snapshot) []engine.Issue {
			var out []engine.Issue
			for _, c := range s.Containers {
				if !c.Running || c.Image == "" {
					continue
				}
				ref := imageref.Parse(c.Image)
				switch ref.Kind() {
				case imageref.KindUntagged, imageref.KindLatest:
					out = append(out, containerIssue(c, "image: "+c.Image))
				case imageref.KindChannel:
					issue := containerIssue(c, "image: "+c.Image)
					issue.Severity = findings.SeverityLow
					issue.Description = "A running container uses the moving channel tag \"" + ref.Tag + "\"."
					out = append(out, issue)
				}
			}
			return out
		}),
	}
}

func hostIssue(s *docker.Snapshot, evidence ...string) engine.Issue {
	name := s.Daemon.Name
	if name == "" {
		name = s.Endpoint
	}
	return engine.Issue{TargetType: findings.TargetHost, TargetName: name, Evidence: evidence}
}

func containerIssue(c docker.Container, evidence ...string) engine.Issue {
	return engine.Issue{TargetType: findings.TargetContainer, TargetName: c.Name,
		Evidence: append([]string{"container ID: " + c.ID}, evidence...)}
}

// perRunning reports one issue per running container for which check
// returns evidence.
func perRunning(check func(docker.Container) []string) func(*docker.Snapshot) []engine.Issue {
	return func(s *docker.Snapshot) []engine.Issue {
		var out []engine.Issue
		for _, c := range s.Containers {
			if !c.Running {
				continue
			}
			if evidence := check(c); len(evidence) > 0 {
				out = append(out, containerIssue(c, evidence...))
			}
		}
		return out
	}
}

func isSocket(p string) bool {
	lower := strings.ToLower(p)
	return strings.HasSuffix(lower, "docker.sock") || strings.HasSuffix(lower, "docker.proxy.sock")
}

func checkListeners(s *docker.Snapshot) []engine.Issue {
	if len(s.Listeners) == 0 {
		return nil
	}
	issue := hostIssue(s)
	issue.Severity = findings.SeverityHigh
	issue.Confidence = findings.ConfidenceMedium
	for _, l := range s.Listeners {
		exposure := "reachable from the network"
		if docker.ListenerExposure(l.Address) {
			exposure = "localhost only"
		} else {
			issue.Severity = findings.SeverityCritical
		}
		if l.Confidence.Rank() > issue.Confidence.Rank() {
			issue.Confidence = l.Confidence
		}
		issue.Evidence = append(issue.Evidence, fmt.Sprintf("%s: %s, %s (%s)", l.Source, l.Address, l.Detail, exposure))
	}
	return []engine.Issue{issue}
}

func checkStopped(s *docker.Snapshot) []engine.Issue {
	var names []string
	for _, c := range s.Containers {
		switch c.State {
		case "exited", "created", "dead":
			names = append(names, c.Name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	shown := names
	suffix := ""
	if len(names) > stoppedNamesShown {
		shown = names[:stoppedNamesShown]
		suffix = fmt.Sprintf(" (and %d more)", len(names)-stoppedNamesShown)
	}
	return []engine.Issue{hostIssue(s, fmt.Sprintf("%d stopped container(s): %s%s", len(names), strings.Join(shown, ", "), suffix))}
}

func checkDiskUsage(s *docker.Snapshot) []engine.Issue {
	du := s.DiskUsage
	if du == nil {
		return nil
	}
	total, reclaimable := du.Total(), du.Reclaimable()
	ratio := 0.0
	if total > 0 {
		ratio = float64(reclaimable) / float64(total)
	}
	if reclaimable < DiskReclaimableAbsolute && (ratio < DiskReclaimableRatio || reclaimable < DiskRatioMinimum) {
		return nil
	}
	issue := hostIssue(s, fmt.Sprintf("total Docker disk usage: %s, reclaimable: %s (%.0f%%)", humanBytes(total), humanBytes(reclaimable), ratio*100))
	if s.Daemon.RootDir != "" {
		issue.Evidence = append(issue.Evidence, "Docker root directory: "+s.Daemon.RootDir)
	}
	for _, item := range []struct {
		name string
		u    docker.UsageItem
	}{{"images", du.Images}, {"containers", du.Containers}, {"volumes", du.Volumes}, {"build cache", du.BuildCache}} {
		issue.Evidence = append(issue.Evidence, fmt.Sprintf("%s: %d using %s (%s reclaimable)",
			item.name, item.u.Count, humanBytes(item.u.Size), humanBytes(item.u.Reclaimable)))
	}
	return []engine.Issue{issue}
}

// humanBytes formats a byte count with binary units.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
