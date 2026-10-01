package composerules

import (
	"strings"

	"github.com/6-SlX-6/stacksentry/internal/compose"
	"github.com/6-SlX-6/stacksentry/internal/engine"
	"github.com/6-SlX-6/stacksentry/internal/findings"
	"github.com/6-SlX-6/stacksentry/internal/imageref"
)

const (
	refHealthcheck = "https://docs.docker.com/reference/compose-file/services/#healthcheck"
	refRestart     = "https://docs.docker.com/reference/compose-file/services/#restart"
	refImage       = "https://docs.docker.com/reference/compose-file/services/#image"
	refImageDigest = "https://docs.docker.com/reference/cli/docker/image/pull/#pull-an-image-by-digest-immutable-identifier"
	refStopGrace   = "https://docs.docker.com/reference/compose-file/services/#stop_grace_period"
)

func operationsRules() []Rule {
	return []Rule{
		newRule(engine.Metadata{
			ID:          "SST-OPS-001",
			Title:       "No healthcheck configured",
			Category:    findings.CategoryReliability,
			Severity:    findings.SeverityMedium,
			Description: "No healthcheck is defined for the service in the Compose file.",
			Rationale: "Without a healthcheck Docker only knows whether the process is running, not whether it works. " +
				"depends_on with condition: service_healthy, automated recovery and monitoring cannot detect a hung or " +
				"misconfigured service.",
			Remediation: "Add a healthcheck that exercises the service (for example an HTTP endpoint or a database ping) " +
				"with sensible interval, timeout, retries and start_period values.",
			Detection: "Services without a healthcheck section. One-shot jobs are skipped when another service waits for " +
				"them with depends_on condition: service_completed_successfully.",
			Limitations: "The image may define its own HEALTHCHECK instruction, which StackSentry cannot see without pulling " +
				"the image. Other one-shot jobs cannot be detected reliably and are reported.",
			References: []string{refHealthcheck},
		}, func(p *compose.Project) []engine.Issue {
			jobs := oneShotServices(p)
			return perService(func(s *compose.Service) []engine.Issue {
				if s.Healthcheck != nil || jobs[s.Name] {
					return nil
				}
				return one(serviceIssue(s, "healthcheck is not defined"))
			})(p)
		}),

		newRule(engine.Metadata{
			ID:          "SST-OPS-002",
			Title:       "Healthcheck disabled",
			Category:    findings.CategoryReliability,
			Severity:    findings.SeverityMedium,
			Description: "The service's healthcheck is explicitly disabled.",
			Rationale: "disable: true (or test: [\"NONE\"]) also turns off any HEALTHCHECK defined by the image, so failures " +
				"inside the container go unnoticed.",
			Remediation: "Remove the override or replace it with a working healthcheck. If disabling is intentional (for " +
				"example because the image's check is broken), document the reason.",
			Detection:  "healthcheck.disable: true or healthcheck.test: [\"NONE\"].",
			References: []string{refHealthcheck},
		}, perService(func(s *compose.Service) []engine.Issue {
			if s.Healthcheck == nil || !s.Healthcheck.Disabled {
				return nil
			}
			return one(serviceIssue(s, "healthcheck is disabled (disable: true or test: [\"NONE\"])"))
		})),

		newRule(engine.Metadata{
			ID:          "SST-OPS-003",
			Title:       "No restart policy configured",
			Category:    findings.CategoryReliability,
			Severity:    findings.SeverityHigh,
			Description: "No restart policy is configured, so the container stays down after a crash or host reboot.",
			Rationale: "Docker's default restart policy is \"no\". A long-running service that crashes, or whose host " +
				"reboots, stays down until someone intervenes.",
			Remediation: "Add: restart: unless-stopped (or always / on-failure, depending on the desired behavior).",
			Detection: "Neither restart nor deploy.restart_policy is set (high). An explicit restart: \"no\" is reported " +
				"as low, or medium when the service is clearly long-running (it publishes ports, has a healthcheck or runs a " +
				"known database image). unless-stopped, always and on-failure are accepted. One-shot jobs that other services " +
				"wait for with condition: service_completed_successfully are skipped.",
			Limitations: "Short-lived tasks that are not declared as dependencies cannot be told apart from services.",
			References:  []string{refRestart},
		}, checkRestartPolicy),

		newRule(engine.Metadata{
			ID:          "SST-OPS-004",
			Title:       "Container name explicitly hardcoded",
			Category:    findings.CategoryMaintainability,
			Severity:    findings.SeverityLow,
			Description: "The service sets a fixed container_name.",
			Rationale: "Fixed container names must be unique on the host. They prevent scaling the service, can clash with " +
				"other projects or copies of the same stack, and bypass Compose's project-scoped naming.",
			Remediation: "Remove container_name and let Compose generate project-scoped names. Other services can reach it " +
				"by its service name, which works without container_name.",
			Detection:  "container_name is set.",
			References: []string{refComposeServices + "#container_name"},
		}, perService(func(s *compose.Service) []engine.Issue {
			if s.ContainerName == "" {
				return nil
			}
			return one(serviceIssue(s, "container_name: "+s.ContainerName))
		})),

		newRule(engine.Metadata{
			ID:          "SST-OPS-005",
			Title:       "Mutable image tag",
			Category:    findings.CategorySupplyChain,
			Severity:    findings.SeverityMedium,
			Description: "The image uses a mutable tag (latest or no tag at all).",
			Rationale: "Mutable tags can point to a different image every time you pull. Deployments become " +
				"non-reproducible, rollbacks unreliable, and unreviewed upstream changes can reach production silently.",
			Remediation: "Pin a specific version tag (for example postgres:16.4) and update it deliberately. For full " +
				"reproducibility also pin the digest (image: name:tag@sha256:...).",
			Detection: "Images without a tag or with the tag latest (medium). Tags that contain no version number at all, " +
				"such as stable, main, edge or alpine, are reported as low-severity moving channel tags. Version tags such as " +
				"1.2.3 or 16-alpine and digest-pinned images are not reported. Services that build their image are skipped.",
			Limitations: "Partial version tags such as 16 also move between patch releases but are not reported here; " +
				"SST-OPS-006 recommends digest pinning for them.",
			References: []string{refImage},
		}, perService(func(s *compose.Service) []engine.Issue {
			if s.HasBuild || s.Image == "" {
				return nil
			}
			ref := imageref.Parse(s.Image)
			switch ref.Kind() {
			case imageref.KindUntagged:
				return one(serviceIssue(s, "image: "+s.Image+" (no tag, resolves to latest)"))
			case imageref.KindLatest:
				return one(serviceIssue(s, "image: "+s.Image))
			case imageref.KindChannel:
				issue := serviceIssue(s, "image: "+s.Image)
				issue.Severity = findings.SeverityLow
				issue.Description = "The image tag \"" + ref.Tag + "\" looks like a moving channel tag rather than a fixed version."
				return one(issue)
			default:
				return nil
			}
		})),

		newRule(engine.Metadata{
			ID:          "SST-OPS-006",
			Title:       "Image digest not pinned",
			Category:    findings.CategorySupplyChain,
			Severity:    findings.SeverityLow,
			Description: "The image is pinned by version tag but not by digest.",
			Rationale: "Tags can be re-pushed by the publisher, so the same tag may resolve to different content over time. " +
				"Pinning the digest guarantees that every deployment runs exactly the reviewed image. This is a " +
				"reproducibility recommendation, not a security vulnerability.",
			Remediation: "Append the digest: image: name:tag@sha256:<digest> (look it up with docker buildx imagetools " +
				"inspect name:tag). Tools such as Renovate or Dependabot can keep digests up to date.",
			Detection: "Images with a version tag and no @sha256 digest. Untagged, latest and channel tags are covered by " +
				"SST-OPS-005 instead. Services that build their image are skipped.",
			References: []string{refImageDigest},
		}, perService(func(s *compose.Service) []engine.Issue {
			if s.HasBuild || s.Image == "" || imageref.Parse(s.Image).Kind() != imageref.KindVersion {
				return nil
			}
			return one(serviceIssue(s, "image: "+s.Image+" has no @sha256 digest"))
		})),

		newRule(engine.Metadata{
			ID:          "SST-OPS-007",
			Title:       "No stop grace period",
			Category:    findings.CategoryReliability,
			Severity:    findings.SeverityLow,
			Description: "No stop_grace_period is set, so Docker kills the container 10 seconds after asking it to stop.",
			Rationale: "Databases, queues and workflow engines may need more than 10 seconds to flush data, finish jobs or " +
				"close connections. A forced kill can corrupt data or lose in-flight work.",
			Remediation: "Set stop_grace_period to match the service's shutdown behavior (for example stop_grace_period: 30s " +
				"for databases and workflow tools) and make sure the process handles SIGTERM or the configured stop_signal.",
			Detection: "stop_grace_period is not set. Reported as low for databases, brokers, workflow tools and services " +
				"with named volumes, and as info for other services. One-shot jobs are skipped.",
			Limitations: "This is a reliability suggestion; many stateless services stop well within 10 seconds.",
			References:  []string{refStopGrace},
		}, func(p *compose.Project) []engine.Issue {
			jobs := oneShotServices(p)
			return perService(func(s *compose.Service) []engine.Issue {
				if s.StopGracePeriod != nil || jobs[s.Name] {
					return nil
				}
				issue := serviceIssue(s, "stop_grace_period is not set (Docker default: 10s)")
				if !isStateful(s) {
					issue.Severity = findings.SeverityInfo
				}
				return one(issue)
			})(p)
		}),
	}
}

func checkRestartPolicy(p *compose.Project) []engine.Issue {
	jobs := oneShotServices(p)
	return perService(func(s *compose.Service) []engine.Issue {
		if jobs[s.Name] {
			return nil
		}
		restart := strings.ToLower(strings.TrimSpace(s.Restart))
		condition := strings.ToLower(s.DeployRestartCondition)
		switch {
		case restart == "always" || restart == "unless-stopped" || strings.HasPrefix(restart, "on-failure"):
			return nil
		case restart == "" && (condition == "any" || condition == "on-failure"):
			return nil
		case restart == "no" || (restart == "" && condition == "none"):
			evidence := "restart: \"no\""
			if restart == "" {
				evidence = "deploy.restart_policy.condition: none"
			}
			issue := serviceIssue(s, evidence)
			issue.Description = "Automatic restarts are explicitly disabled for this service."
			issue.Severity = findings.SeverityLow
			if isLongRunning(s) {
				issue.Severity = findings.SeverityMedium
				issue.Description += " It looks like a long-running service (published ports, healthcheck or database image)."
			}
			return one(issue)
		case restart == "":
			return one(serviceIssue(s, "restart is missing"))
		default:
			return nil
		}
	})(p)
}

func isLongRunning(s *compose.Service) bool {
	if len(s.Ports) > 0 || (s.Healthcheck != nil && !s.Healthcheck.Disabled) {
		return true
	}
	_, _, isDB := lookupDatabase(s.Image)
	return isDB
}
