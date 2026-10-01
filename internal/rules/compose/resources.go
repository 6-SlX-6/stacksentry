package composerules

import (
	"github.com/6-SlX-6/stacksentry/internal/compose"
	"github.com/6-SlX-6/stacksentry/internal/engine"
	"github.com/6-SlX-6/stacksentry/internal/findings"
)

const (
	refResources = "https://docs.docker.com/reference/compose-file/deploy/#resources"
	refLogging   = "https://docs.docker.com/engine/logging/drivers/json-file/"
)

// rotatingLogDrivers rotate by default or ship logs elsewhere, so they do
// not fill the local disk without bound.
var rotatingLogDrivers = map[string]bool{
	"local": true, "none": true, "syslog": true, "journald": true, "gelf": true, "fluentd": true,
	"awslogs": true, "splunk": true, "etwlogs": true, "gcplogs": true, "loki": true,
}

func resourceRules() []Rule {
	return []Rule{
		newRule(engine.Metadata{
			ID:          "SST-RES-001",
			Title:       "No memory limit configured",
			Category:    findings.CategoryResourceManagement,
			Severity:    findings.SeverityLow,
			Description: "No memory limit is configured for the service.",
			Rationale: "A memory leak or load spike in one container can consume all host memory and trigger the kernel OOM " +
				"killer for unrelated processes, including other services on the host.",
			Remediation: "Set deploy.resources.limits.memory (for example 512M) based on observed usage, or mem_limit for " +
				"older Compose versions.",
			Detection: "Neither deploy.resources.limits.memory nor mem_limit is set.",
			Limitations: "Advisory. Docker Compose applies deploy.resources limits to standalone containers, while Swarm " +
				"interprets the deploy section differently; choose limits that suit how you deploy.",
			References: []string{refResources},
		}, perService(func(s *compose.Service) []engine.Issue {
			if s.MemoryLimit > 0 {
				return nil
			}
			return one(serviceIssue(s, "deploy.resources.limits.memory and mem_limit are not set"))
		})),

		newRule(engine.Metadata{
			ID:          "SST-RES-002",
			Title:       "No CPU limit configured",
			Category:    findings.CategoryResourceManagement,
			Severity:    findings.SeverityLow,
			Description: "No CPU limit is configured for the service.",
			Rationale:   "Without a CPU limit a busy or runaway container can starve other services on the same host.",
			Remediation: "Set deploy.resources.limits.cpus (for example \"1.0\") or cpus for older Compose versions.",
			Detection:   "None of deploy.resources.limits.cpus, cpus or cpu_quota is set.",
			Limitations: "Advisory, with the same Compose/Swarm caveat as SST-RES-001.",
			References:  []string{refResources},
		}, perService(func(s *compose.Service) []engine.Issue {
			if s.CPULimit > 0 {
				return nil
			}
			return one(serviceIssue(s, "deploy.resources.limits.cpus and cpus are not set"))
		})),

		newRule(engine.Metadata{
			ID:          "SST-RES-003",
			Title:       "No log rotation configured",
			Category:    findings.CategoryResourceManagement,
			Severity:    findings.SeverityMedium,
			Description: "Container logs are not configured to rotate.",
			Rationale: "Docker's default json-file log driver keeps logs without limit unless max-size is set, so a chatty " +
				"container can fill the disk.",
			Remediation: "Configure rotation, for example logging: {driver: json-file, options: {max-size: \"10m\", " +
				"max-file: \"3\"}}, or set log-driver/log-opts once for all containers in the Docker daemon configuration.",
			Detection: "No logging section (the daemon default driver applies) or the json-file driver without a max-size " +
				"option. The local driver, which rotates by default, and drivers that ship logs elsewhere are accepted.",
			Limitations: "The Docker daemon may already set log rotation globally in daemon.json; StackSentry cannot see " +
				"that during a static scan, so treat this finding as advisory.",
			References: []string{refLogging},
		}, perService(func(s *compose.Service) []engine.Issue {
			driver := s.Logging.Driver
			switch {
			case rotatingLogDrivers[driver]:
				return nil
			case driver == "" && len(s.Logging.Options) == 0:
				return one(serviceIssue(s, "logging is not configured (the daemon's default log driver applies)"))
			case driver == "" || driver == "json-file":
				if s.Logging.Options["max-size"] != "" {
					return nil
				}
				return one(serviceIssue(s, "logging uses json-file without options.max-size"))
			default:
				// Third-party logging plugins manage their own storage.
				return nil
			}
		})),
	}
}
