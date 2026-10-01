package composerules

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/6-SlX-6/stacksentry/internal/compose"
	"github.com/6-SlX-6/stacksentry/internal/engine"
	"github.com/6-SlX-6/stacksentry/internal/findings"
)

const (
	refDockerAttackSurface = "https://docs.docker.com/engine/security/#docker-daemon-attack-surface"
	refOWASPDocker         = "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"
	refComposeServices     = "https://docs.docker.com/reference/compose-file/services/"
	refCapabilities        = "https://man7.org/linux/man-pages/man7/capabilities.7.html"
	refDockerAPIProtect    = "https://docs.docker.com/engine/security/protect-access/"
)

func securityRules() []Rule {
	return []Rule{
		newRule(engine.Metadata{
			ID:          "SST-SEC-001",
			Title:       "Docker socket mount detected",
			Category:    findings.CategorySecurity,
			Severity:    findings.SeverityCritical,
			Description: "The Docker daemon socket is mounted into the container.",
			Rationale: "Access to the Docker socket can effectively grant host-level control: anyone who can talk to it can start " +
				"privileged containers and mount the host filesystem. Mounting it read-only (:ro) does not restrict API calls.",
			Remediation: "Remove the mount unless this service explicitly requires Docker daemon access. If it does (for example a " +
				"reverse proxy reading container labels), put a filtering socket proxy in front of the socket that only allows " +
				"the required read-only API endpoints.",
			Detection: "Bind mounts and named pipes whose source or target ends in docker.sock (e.g. /var/run/docker.sock, " +
				"/run/docker.sock, a rootless $XDG_RUNTIME_DIR/docker.sock) or refers to the Windows pipe \\\\.\\pipe\\docker_engine, " +
				"and services with use_api_socket: true.",
			Limitations: "Sockets renamed to something other than docker.sock are not detected. Mounting a parent directory such " +
				"as /var/run is reported by SST-SEC-007 instead.",
			References: []string{refDockerAttackSurface, refOWASPDocker},
		}, perService(checkDockerSocket)),

		newRule(engine.Metadata{
			ID:          "SST-SEC-002",
			Title:       "Privileged container detected",
			Category:    findings.CategorySecurity,
			Severity:    findings.SeverityCritical,
			Description: "The service runs in privileged mode.",
			Rationale: "privileged: true grants all Linux capabilities and access to all host devices and disables most " +
				"isolation (seccomp, AppArmor/SELinux confinement). A compromise of the process is close to a compromise of the host.",
			Remediation: "Remove privileged: true. Grant only the specific capabilities (cap_add) or devices (devices) the " +
				"workload needs, and document why they are required.",
			Detection:  "privileged: true on a service.",
			References: []string{refComposeServices + "#privileged", refOWASPDocker},
		}, perService(func(s *compose.Service) []engine.Issue {
			if !s.Privileged {
				return nil
			}
			return one(serviceIssue(s, "privileged: true"))
		})),

		newRule(engine.Metadata{
			ID:          "SST-SEC-003",
			Title:       "Host network mode detected",
			Category:    findings.CategorySecurity,
			Severity:    findings.SeverityHigh,
			Description: "The service shares the host's network stack (network_mode: host).",
			Rationale: "Host networking removes normal Docker network isolation: every port the process opens is reachable on " +
				"all host interfaces, port publishing rules no longer apply, and the container can reach services bound to the " +
				"host's localhost.",
			Remediation: "Use a bridge network and publish only the required ports, preferably bound to 127.0.0.1 or a specific " +
				"interface. Keep host networking only for workloads that need it (for example some discovery or VPN tools) and " +
				"document the exception.",
			Detection:  "network_mode: host on a service.",
			References: []string{refComposeServices + "#network_mode"},
		}, perService(func(s *compose.Service) []engine.Issue {
			if s.NetworkMode != "host" {
				return nil
			}
			return one(serviceIssue(s, "network_mode: host"))
		})),

		newRule(engine.Metadata{
			ID:          "SST-SEC-004",
			Title:       "Dangerous Linux capabilities added",
			Category:    findings.CategorySecurity,
			Severity:    findings.SeverityHigh,
			Description: "The service adds Linux capabilities that significantly weaken container isolation.",
			Rationale: "These capabilities grant kernel-level privileges that are commonly abused for container escapes, " +
				"for example mounting filesystems, loading kernel modules or tracing other processes.",
			Remediation: "Remove the listed capabilities from cap_add unless they are strictly required. If one is needed, " +
				"document why and combine it with cap_drop: [ALL], a non-root user and security_opt: [no-new-privileges:true].",
			Detection: "cap_add contains one of: " + strings.Join(dangerousCapabilityNames(), ", ") +
				". The CAP_ prefix and letter case are ignored.",
			Limitations: "MKNOD is part of Docker's default capability set; it is reported only when added explicitly.",
			References:  []string{refCapabilities, refComposeServices + "#cap_add"},
		}, perService(checkDangerousCapabilities)),

		newRule(engine.Metadata{
			ID:          "SST-SEC-005",
			Title:       "Linux capabilities not dropped",
			Category:    findings.CategorySecurity,
			Severity:    findings.SeverityLow,
			Description: "The service keeps Docker's default Linux capabilities (cap_drop does not contain ALL).",
			Rationale: "Docker grants containers a default capability set (for example CHOWN, SETUID, NET_RAW). Most " +
				"applications need few or none of them. This is a hardening recommendation, not a defect: some images need " +
				"specific capabilities to start.",
			Remediation: "Add cap_drop: [ALL] and add back only what the service needs with cap_add (for example " +
				"NET_BIND_SERVICE to bind ports below 1024). Test the service after the change.",
			Detection:   "cap_drop does not contain ALL. Privileged services are skipped because SST-SEC-002 already covers them.",
			Limitations: "Compatibility may require some capabilities; treat this as advisory.",
			References:  []string{refCapabilities, refOWASPDocker},
		}, perService(func(s *compose.Service) []engine.Issue {
			if s.Privileged || containsFold(s.CapDrop, "ALL") {
				return nil
			}
			evidence := "cap_drop is not set"
			if len(s.CapDrop) > 0 {
				evidence = "cap_drop: [" + strings.Join(s.CapDrop, ", ") + "] does not include ALL"
			}
			return one(serviceIssue(s, evidence))
		})),

		newRule(engine.Metadata{
			ID:          "SST-SEC-006",
			Title:       "Writable host bind mount",
			Category:    findings.CategorySecurity,
			Severity:    findings.SeverityMedium,
			Description: "A host path is bind-mounted without read-only protection.",
			Rationale: "A writable bind mount lets the container modify files on the host. If the container is compromised, " +
				"an attacker can tamper with host files, configuration or data shared with other services.",
			Remediation: "Append :ro (short syntax) or set read_only: true (long syntax) for mounts the container only reads, " +
				"such as configuration files. For data the service must write, prefer a named volume or make sure the host " +
				"directory is dedicated to this service.",
			Detection: "Volumes of type bind without read-only protection.",
			Limitations: "Named volumes, anonymous volumes and tmpfs mounts are not reported. Docker socket mounts are " +
				"reported by SST-SEC-001 instead. Some services legitimately need to write to their bind mounts.",
			References: []string{refComposeServices + "#volumes"},
		}, perService(func(s *compose.Service) []engine.Issue {
			var evidence []string
			for _, m := range s.Mounts {
				if m.Type == compose.MountBind && !m.ReadOnly && !isDockerSocketPath(m.Source) && !isDockerSocketPath(m.Target) {
					evidence = append(evidence, m.String()+" (read-write)")
				}
			}
			if len(evidence) == 0 {
				return nil
			}
			return one(serviceIssue(s, evidence...))
		})),

		newRule(engine.Metadata{
			ID:          "SST-SEC-007",
			Title:       "Sensitive host path mounted",
			Category:    findings.CategorySecurity,
			Severity:    findings.SeverityHigh,
			Description: "A sensitive host location is bind-mounted into the container.",
			Rationale: "System locations such as /, /etc, /proc, /sys, /dev, /root or /var/lib/docker expose host credentials, " +
				"kernel interfaces, devices or other containers' data. Write access usually allows a full host compromise; " +
				"even read access can leak secrets.",
			Remediation: "Mount only the specific file or subdirectory the service needs, read-only where possible. Monitoring " +
				"agents that legitimately need /proc or /sys should mount them read-only and be reviewed as privileged components.",
			Detection: "Bind mount sources equal to / or /home, inside /etc, /proc, /sys, /dev, /root, /boot, " +
				"/var/lib/docker, /run or /var/run, whole user home directories (/home/<user>, ~) and credential " +
				"directories inside them (.ssh, .gnupg, .aws, .kube, .docker, .azure, .config/gcloud).",
			Limitations: "Read-only mounts of /etc/localtime, /etc/timezone, /etc/machine-id and CA certificate directories " +
				"and mounts of /dev/null, /dev/zero, /dev/random and /dev/urandom are not reported. Docker socket paths are " +
				"reported by SST-SEC-001. Paths built from variables without defaults are evaluated with those variables empty.",
			References: []string{refOWASPDocker},
		}, perService(checkSensitiveMounts)),

		newRule(engine.Metadata{
			ID:          "SST-SEC-008",
			Title:       "No explicit non-root user",
			Category:    findings.CategorySecurity,
			Severity:    findings.SeverityMedium,
			Description: "No user is configured, so the container runs as the image's default user, which is root for many images.",
			Rationale: "Processes running as root inside a container have more power if they escape isolation or write to " +
				"mounted volumes. Without a user setting the effective user depends on the image's USER instruction, which " +
				"StackSentry cannot see without pulling the image.",
			Remediation: "Add a dedicated unprivileged user where supported by the image, e.g. user: \"1000:1000\" or a named " +
				"user documented by the image (such as node). Make sure mounted volumes are writable by that UID.",
			Detection:   "user is not set, or is set to root, 0 or 0:<gid>.",
			Limitations: "The absence of user does not prove that the container runs as root; the image may already define a non-root USER.",
			References:  []string{refComposeServices + "#user", refOWASPDocker},
		}, perService(func(s *compose.Service) []engine.Issue {
			user := strings.TrimSpace(s.User)
			if user == "" {
				return one(serviceIssue(s, "user is not set"))
			}
			name, _, _ := strings.Cut(user, ":")
			if name == "root" || name == "0" {
				issue := serviceIssue(s, "user: "+user)
				issue.Description = "The service is explicitly configured to run as root."
				return one(issue)
			}
			return nil
		})),

		newRule(engine.Metadata{
			ID:          "SST-SEC-009",
			Title:       "Read-only root filesystem not enabled",
			Category:    findings.CategorySecurity,
			Severity:    findings.SeverityLow,
			Description: "The container's root filesystem is writable (read_only: true is not set).",
			Rationale: "A read-only root filesystem prevents an attacker from modifying binaries or dropping tools inside " +
				"the container and makes unexpected writes visible.",
			Remediation: "Set read_only: true and provide writable locations explicitly with tmpfs (for example /tmp or /run) " +
				"or volumes for application data. Many applications need some writable directories; test before enforcing.",
			Detection:   "read_only is not set to true.",
			Limitations: "Advisory hardening recommendation; some images cannot run with a read-only root filesystem.",
			References:  []string{refComposeServices + "#read_only", refOWASPDocker},
		}, perService(func(s *compose.Service) []engine.Issue {
			if s.ReadOnly {
				return nil
			}
			return one(serviceIssue(s, "read_only is not set"))
		})),

		newRule(engine.Metadata{
			ID:          "SST-SEC-010",
			Title:       "Insecure Docker API exposure",
			Category:    findings.CategorySecurity,
			Severity:    findings.SeverityCritical,
			Description: "The service appears to expose or use the Docker Engine API over unencrypted TCP.",
			Rationale: "The Docker Engine API on TCP port 2375 has neither authentication nor encryption. Anyone who can reach " +
				"it controls the Docker host, which is equivalent to root access.",
			Remediation: "Do not publish port 2375. If remote API access is required, use TLS with client certificate " +
				"verification (port 2376, --tlsverify) or SSH (DOCKER_HOST=ssh://user@host). Keep socket proxies on an " +
				"internal network and never publish their port.",
			Detection: "Published ports 2375 (critical when reachable from the network, high on localhost); dockerd started " +
				"with -H/--host tcp://… without --tlsverify (high); docker:dind with DOCKER_TLS_CERTDIR set to an empty value " +
				"(high); DOCKER_HOST=tcp://… without DOCKER_CERT_PATH (medium, or low when it points to another service of " +
				"the same project). Confidence is high when the image or service name identifies a Docker daemon or socket " +
				"proxy and medium when only the port number or a client setting indicates it.",
			Limitations: "Detection is heuristic. A service may use port 2375 for something else, and DOCKER_HOST may point to " +
				"a properly restricted proxy.",
			References: []string{refDockerAPIProtect, refDockerAttackSurface},
		}, checkDockerAPIExposure),
	}
}

func checkDockerSocket(s *compose.Service) []engine.Issue {
	var evidence []string
	if s.UseAPISocket {
		evidence = append(evidence, "use_api_socket: true (Compose mounts the Docker API socket)")
	}
	for _, m := range s.Mounts {
		if !m.IsHostPath() || (!isDockerSocketPath(m.Source) && !isDockerSocketPath(m.Target)) {
			continue
		}
		line := m.String()
		if m.ReadOnly {
			line += " (read-only does not restrict Docker API access)"
		}
		evidence = append(evidence, line)
	}
	if len(evidence) == 0 {
		return nil
	}
	return one(serviceIssue(s, evidence...))
}

// dangerousCapabilities explains why each capability is considered
// dangerous. Keep docs/rules.md in sync.
var dangerousCapabilities = map[string]string{
	"ALL":             "grants every capability",
	"SYS_ADMIN":       "broad administrative privileges such as mounting filesystems; enables many escape techniques",
	"SYS_PTRACE":      "trace and modify other processes",
	"NET_ADMIN":       "reconfigure network interfaces, routing and firewall rules",
	"SYS_MODULE":      "load and unload kernel modules",
	"DAC_READ_SEARCH": "bypass file read permission checks, including on host files via open_by_handle_at",
	"SYS_RAWIO":       "raw access to I/O ports and devices",
	"SYS_BOOT":        "reboot the host",
	"SYS_TIME":        "change the host system clock",
	"MKNOD":           "create device files",
	"BPF":             "load eBPF programs into the kernel",
}

func dangerousCapabilityNames() []string {
	return []string{"ALL", "SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "SYS_MODULE", "DAC_READ_SEARCH", "SYS_RAWIO", "SYS_BOOT", "SYS_TIME", "MKNOD", "BPF"}
}

func checkDangerousCapabilities(s *compose.Service) []engine.Issue {
	var evidence []string
	seen := map[string]bool{}
	for _, c := range s.CapAdd {
		reason, ok := dangerousCapabilities[c]
		if !ok || seen[c] {
			continue
		}
		seen[c] = true
		evidence = append(evidence, fmt.Sprintf("cap_add: %s (%s)", c, reason))
	}
	if len(evidence) == 0 {
		return nil
	}
	return one(serviceIssue(s, evidence...))
}

type sensitivePath struct {
	path    string
	subtree bool
	reason  string
}

var sensitivePaths = []sensitivePath{
	{"/", false, "the entire host filesystem"},
	{"/etc", true, "host configuration, including password hashes and service credentials"},
	{"/proc", true, "host kernel and process information"},
	{"/sys", true, "kernel parameters and device configuration"},
	{"/dev", true, "host devices, including raw disks"},
	{"/root", true, "the root user's home directory, often containing SSH keys and credentials"},
	{"/boot", true, "kernel images and boot configuration"},
	{"/home", false, "all user home directories"},
	{"/var/lib/docker", true, "Docker's data directory with all images, containers and volumes"},
	{"/run", true, "runtime sockets and state of host services such as systemd and D-Bus"},
	{"/var/run", true, "runtime sockets and state of host services such as systemd and D-Bus"},
}

// harmlessReadOnly are commonly mounted host files that are safe read-only.
var harmlessReadOnly = []string{"/etc/localtime", "/etc/timezone", "/etc/machine-id", "/etc/ssl/certs", "/etc/ca-certificates", "/etc/pki/ca-trust"}

var harmlessDevices = []string{"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"}

var credentialDirs = []string{".ssh", ".gnupg", ".aws", ".kube", ".docker", ".azure", ".config/gcloud"}

func sensitiveReason(source string, readOnly bool) (string, bool) {
	p := cleanHostPath(source)
	if p == "" || isDockerSocketPath(p) {
		return "", false
	}
	if containsFold(harmlessDevices, p) || (readOnly && withinAny(p, harmlessReadOnly)) {
		return "", false
	}
	if reason, ok := homeReason(p); ok {
		return reason, true
	}
	for _, sp := range sensitivePaths {
		if p == sp.path || (sp.subtree && strings.HasPrefix(p, sp.path+"/")) {
			return sp.reason, true
		}
	}
	return "", false
}

// homeReason flags whole home directories and credential directories in
// them, but not ordinary project directories below a home directory.
func homeReason(p string) (string, bool) {
	var rest string
	switch {
	case p == "~":
		return "the user's entire home directory", true
	case strings.HasPrefix(p, "~/"):
		rest = strings.TrimPrefix(p, "~/")
	case strings.HasPrefix(p, "/home/"):
		user, after, found := strings.Cut(strings.TrimPrefix(p, "/home/"), "/")
		if !found || after == "" {
			return fmt.Sprintf("the entire home directory of user %q", user), true
		}
		rest = after
	default:
		return "", false
	}
	for _, dir := range credentialDirs {
		if rest == dir || strings.HasPrefix(rest, dir+"/") {
			return "a credentials directory (" + dir + ")", true
		}
	}
	return "", false
}

func checkSensitiveMounts(s *compose.Service) []engine.Issue {
	var evidence []string
	for _, m := range s.Mounts {
		if m.Type != compose.MountBind {
			continue
		}
		reason, ok := sensitiveReason(m.Source, m.ReadOnly)
		if !ok {
			continue
		}
		access := "read-write"
		if m.ReadOnly {
			access = "read-only"
		}
		evidence = append(evidence, fmt.Sprintf("%s (%s): %s", m.String(), access, reason))
	}
	if len(evidence) == 0 {
		return nil
	}
	return one(serviceIssue(s, evidence...))
}

// apiIndicator is one sign of Docker API exposure found in a service.
type apiIndicator struct {
	severity   findings.Severity
	confidence findings.Confidence
	evidence   string
}

func checkDockerAPIExposure(p *compose.Project) []engine.Issue {
	services := map[string]bool{}
	for _, s := range p.Services {
		services[s.Name] = true
	}
	var out []engine.Issue
	for i := range p.Services {
		s := &p.Services[i]
		indicators := dockerAPIIndicators(s, services)
		if len(indicators) == 0 {
			continue
		}
		issue := serviceIssue(s)
		for _, ind := range indicators {
			issue.Evidence = append(issue.Evidence, ind.evidence)
			if ind.severity > issue.Severity ||
				(ind.severity == issue.Severity && ind.confidence.Rank() > issue.Confidence.Rank()) {
				issue.Severity, issue.Confidence = ind.severity, ind.confidence
			}
		}
		out = append(out, issue)
	}
	return out
}

func dockerAPIIndicators(s *compose.Service, services map[string]bool) []apiIndicator {
	var out []apiIndicator
	apiService := isDockerAPIService(s)
	nameConfidence := findings.ConfidenceMedium
	if apiService {
		nameConfidence = findings.ConfidenceHigh
	}
	if s.NetworkMode != "host" {
		for _, port := range s.Ports {
			if port.Target != 2375 && port.Published != "2375" {
				continue
			}
			sev := findings.SeverityCritical
			if port.Exposure() == compose.ExposureLoopback {
				sev = findings.SeverityHigh
			}
			out = append(out, apiIndicator{sev, nameConfidence, fmt.Sprintf(
				"port %s publishes the unencrypted Docker API port 2375 (%s)", port.String(), port.Exposure())})
		}
	}

	tokens := commandTokens(s)
	tls := false
	daemon := isDind(s)
	for _, t := range tokens {
		switch {
		case t == "--tlsverify" || t == "--tlsverify=true":
			tls = true
		case t == "dockerd" || strings.HasSuffix(t, "/dockerd"):
			daemon = true
		}
	}
	for i, t := range tokens {
		var host string
		switch {
		case (t == "-H" || t == "--host") && i+1 < len(tokens):
			host = tokens[i+1]
		case strings.HasPrefix(t, "--host="):
			host = strings.TrimPrefix(t, "--host=")
		case strings.HasPrefix(t, "-H="):
			host = strings.TrimPrefix(t, "-H=")
		}
		if !strings.HasPrefix(host, "tcp://") || tls {
			continue
		}
		if daemon {
			out = append(out, apiIndicator{findings.SeverityHigh, findings.ConfidenceHigh,
				"dockerd listens on " + sanitizeURL(host) + " without --tlsverify"})
		} else {
			out = append(out, apiIndicator{findings.SeverityMedium, findings.ConfidenceMedium,
				"command connects to a Docker API at " + sanitizeURL(host) + " without --tlsverify"})
		}
	}

	if certDir, ok := s.Env("DOCKER_TLS_CERTDIR"); ok && isDind(s) && certDir.HasValue && strings.TrimSpace(certDir.Value) == "" {
		out = append(out, apiIndicator{findings.SeverityHigh, findings.ConfidenceHigh,
			"DOCKER_TLS_CERTDIR is empty, so docker:dind serves the API on port 2375 without TLS"})
	}

	if host, ok := s.Env("DOCKER_HOST"); ok && strings.HasPrefix(host.Value, "tcp://") {
		certPath, hasCert := s.Env("DOCKER_CERT_PATH")
		if !hasCert || certPath.Value == "" {
			target := sanitizeURL(host.Value)
			if u, err := url.Parse(host.Value); err == nil && services[u.Hostname()] {
				out = append(out, apiIndicator{findings.SeverityLow, findings.ConfidenceMedium,
					"DOCKER_HOST=" + target + " uses unencrypted TCP to another service of this project (ensure it is a restricted proxy that is not published)"})
			} else {
				out = append(out, apiIndicator{findings.SeverityMedium, findings.ConfidenceMedium,
					"DOCKER_HOST=" + target + " uses unencrypted TCP without DOCKER_CERT_PATH"})
			}
		}
	}
	return out
}

// sanitizeURL removes user information from a URL before it is shown.
func sanitizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	u.User = nil
	return u.String()
}

func containsFold(list []string, needle string) bool {
	for _, v := range list {
		if strings.EqualFold(v, needle) {
			return true
		}
	}
	return false
}

func withinAny(p string, roots []string) bool {
	for _, r := range roots {
		if p == r || strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
}
