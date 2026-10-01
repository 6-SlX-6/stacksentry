package composerules

import (
	"fmt"
	"strings"

	"github.com/6-SlX-6/stacksentry/internal/compose"
	"github.com/6-SlX-6/stacksentry/internal/engine"
	"github.com/6-SlX-6/stacksentry/internal/findings"
)

const (
	refPorts            = "https://docs.docker.com/reference/compose-file/services/#ports"
	refPortPublishing   = "https://docs.docker.com/engine/network/packet-filtering-firewalls/"
	refComposeNetworks  = "https://docs.docker.com/reference/compose-file/networks/"
	refComposeNetworkHT = "https://docs.docker.com/compose/how-tos/networking/"
)

// segmentationMinServices is the smallest stack for which SST-NET-002
// suggests network segmentation.
const segmentationMinServices = 3

func networkingRules() []Rule {
	return []Rule{
		newRule(engine.Metadata{
			ID:          "SST-NET-001",
			Title:       "Publicly published database port",
			Category:    findings.CategoryNetworking,
			Severity:    findings.SeverityHigh,
			Description: "A database port is published on all host interfaces.",
			Rationale: "Published database ports are reachable from other machines and, on many Linux hosts, bypass host " +
				"firewalls such as UFW or firewalld because Docker manages its own iptables rules. Databases reachable from " +
				"the network are frequent targets of credential brute-forcing and ransom attacks.",
			Remediation: "Remove the ports entry if only other containers need the database; they can reach it over the " +
				"Compose network by service name. If host access is required, bind to localhost, e.g. \"127.0.0.1:5432:5432\". " +
				"Exposure may be intentional, but it should be reviewed.",
			Detection: "Published ports whose container port is a common data service port (PostgreSQL 5432, MySQL/MariaDB " +
				"3306, MongoDB 27017, Redis 6379, Elasticsearch 9200, RabbitMQ 5672, Memcached 11211, MS SQL 1433) or any " +
				"published port of a known database image. Severity depends on the host binding: all interfaces (including " +
				"a random host port) is high, a specific interface is medium and 127.0.0.1/::1 is low.",
			Limitations: "Ports published through variables without defaults are evaluated as unbound, which Docker treats " +
				"as all interfaces.",
			References: []string{refPorts, refPortPublishing},
		}, perService(checkDatabasePorts)),

		newRule(engine.Metadata{
			ID:          "SST-NET-002",
			Title:       "No explicit network segmentation",
			Category:    findings.CategoryNetworking,
			Severity:    findings.SeverityLow,
			Description: "All services share the default network even though the stack has distinct tiers.",
			Rationale: "On a single shared network every container can reach every other container. Separating " +
				"public-facing services from databases limits lateral movement if a public service is compromised.",
			Remediation: "Define separate networks (for example frontend and backend), attach databases only to the backend " +
				"network and consider internal: true for networks that need no outbound access.",
			Detection: fmt.Sprintf("Projects with at least %d services in which no service declares a network other than the "+
				"default one, at least one service runs a known database image and at least one other service publishes "+
				"ports.", segmentationMinServices),
			Limitations: "Advisory. Small stacks are not reported to avoid noise.",
			References:  []string{refComposeNetworks, refComposeNetworkHT},
		}, checkSegmentation),

		newRule(engine.Metadata{
			ID:          "SST-NET-003",
			Title:       "Admin interface likely published broadly",
			Category:    findings.CategoryNetworking,
			Severity:    findings.SeverityMedium,
			Description: "An administration interface appears to be published on all host interfaces.",
			Rationale: "Admin dashboards provide powerful control over infrastructure or data. Publishing them broadly " +
				"increases exposure to credential guessing and to vulnerabilities in the tool itself.",
			Remediation: "Review the exposure. Bind the port to 127.0.0.1 and use an SSH tunnel or VPN, or put the interface " +
				"behind a reverse proxy with strong authentication and TLS.",
			Detection: "Ports published on all interfaces by images of Portainer, pgAdmin, Adminer, Mongo Express, Grafana, " +
				"Redis Commander and phpMyAdmin, and Traefik's API/dashboard port 8080.",
			Limitations: "Detection is based on the image name; custom or renamed images are not recognized. The tool may " +
				"already be protected by its own authentication.",
			References: []string{refPorts},
		}, perService(checkAdminExposure)),
	}
}

func checkDatabasePorts(s *compose.Service) []engine.Issue {
	if s.NetworkMode == "host" {
		return nil
	}
	db, _, isDB := lookupDatabase(s.Image)
	var out []engine.Issue
	for _, port := range s.Ports {
		label, known := databasePorts[port.Target]
		if isDB {
			label, known = db.Name, true
		}
		if !known {
			continue
		}
		exposure := port.Exposure()
		hostPort := ""
		if port.Published == "" {
			hostPort = ", random host port"
		}
		issue := serviceIssue(s, fmt.Sprintf("%s (%s port published on %s%s)", port.String(), label, exposure, hostPort))
		switch exposure {
		case compose.ExposureLoopback:
			issue.Severity = findings.SeverityLow
			issue.Description = "A database port is published on localhost only."
			issue.Remediation = "Exposure is limited to the host itself. Remove the mapping if host access is not needed; " +
				"other containers can reach the database over the Compose network."
		case compose.ExposureSpecificInterface:
			issue.Severity = findings.SeverityMedium
			issue.Description = "A database port is published on a specific host interface."
		}
		out = append(out, issue)
	}
	return out
}

func checkSegmentation(p *compose.Project) []engine.Issue {
	if len(p.Services) < segmentationMinServices {
		return nil
	}
	var data, exposed []string
	for i := range p.Services {
		s := &p.Services[i]
		if s.NetworkMode != "" {
			return nil
		}
		for _, n := range s.Networks {
			if n != "default" {
				return nil
			}
		}
		if _, _, isDB := lookupDatabase(s.Image); isDB {
			data = append(data, s.Name)
		} else if len(s.Ports) > 0 {
			exposed = append(exposed, s.Name)
		}
	}
	if len(data) == 0 || len(exposed) == 0 {
		return nil
	}
	issue := engine.Issue{
		TargetType: findings.TargetProject,
		TargetName: p.Name,
		Evidence: []string{
			fmt.Sprintf("all %d services use only the default network", len(p.Services)),
			"data services: " + strings.Join(data, ", "),
			"services with published ports: " + strings.Join(exposed, ", "),
		},
	}
	if len(p.Files) > 0 {
		issue.Location = &findings.Location{File: p.Files[0]}
	}
	return one(issue)
}

func checkAdminExposure(s *compose.Service) []engine.Issue {
	tool, ok := lookupAdminTool(s.Image)
	if !ok || s.NetworkMode == "host" {
		return nil
	}
	var evidence []string
	for _, port := range s.Ports {
		if port.Exposure() != compose.ExposureAllInterfaces {
			continue
		}
		if tool.DashboardPort != 0 && port.Target != tool.DashboardPort {
			continue
		}
		evidence = append(evidence, fmt.Sprintf("%s publishes %s on all host interfaces (%s)", s.Image, port.String(), tool.Name))
	}
	if len(evidence) == 0 {
		return nil
	}
	return one(serviceIssue(s, evidence...))
}
