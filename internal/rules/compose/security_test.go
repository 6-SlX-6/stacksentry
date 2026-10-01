package composerules

import (
	"testing"

	"github.com/6-SlX-6/stacksentry/internal/findings"
)

const (
	crit = findings.SeverityCritical
	high = findings.SeverityHigh
	med  = findings.SeverityMedium
	low  = findings.SeverityLow
	info = findings.SeverityInfo
)

func TestSEC001DockerSocket(t *testing.T) {
	runRuleCases(t, "SST-SEC-001", []ruleCase{
		{"short syntax", svc("image: x:1\nvolumes:\n  - /var/run/docker.sock:/var/run/docker.sock"),
			[]want{{"app", crit, []string{"/var/run/docker.sock:/var/run/docker.sock"}}}},
		{"read-only still flagged", svc("image: x:1\nvolumes:\n  - /run/docker.sock:/var/run/docker.sock:ro"),
			[]want{{"app", crit, []string{"read-only does not restrict"}}}},
		{"rootless socket", svc("image: x:1\nvolumes:\n  - /run/user/1000/docker.sock:/var/run/docker.sock"),
			[]want{{"app", crit, []string{"/run/user/1000/docker.sock"}}}},
		{"long syntax", svc("image: x:1\nvolumes:\n  - type: bind\n    source: /var/run/docker.sock\n    target: /sock"),
			[]want{{"app", crit, nil}}},
		{"windows named pipe", svc("image: x:1\nvolumes:\n  - type: npipe\n    source: \\\\.\\pipe\\docker_engine\n    target: \\\\.\\pipe\\docker_engine"),
			[]want{{"app", crit, []string{"docker_engine"}}}},
		{"use_api_socket", svc("image: x:1\nuse_api_socket: true"),
			[]want{{"app", crit, []string{"use_api_socket: true"}}}},
		{"named volume called docker.sock is ignored", svc("image: x:1\nvolumes:\n  - data:/data\n") + "volumes:\n  data:\n", nil},
		{"no mounts", svc("image: x:1"), nil},
	})
}

func TestSEC002Privileged(t *testing.T) {
	runRuleCases(t, "SST-SEC-002", []ruleCase{
		{"privileged", svc("image: x:1\nprivileged: true"), []want{{"app", crit, []string{"privileged: true"}}}},
		{"explicitly false", svc("image: x:1\nprivileged: false"), nil},
		{"unset", svc("image: x:1"), nil},
	})
}

func TestSEC003HostNetwork(t *testing.T) {
	runRuleCases(t, "SST-SEC-003", []ruleCase{
		{"host", svc("image: x:1\nnetwork_mode: host"), []want{{"app", high, []string{"network_mode: host"}}}},
		{"bridge", svc("image: x:1\nnetwork_mode: bridge"), nil},
		{"none", svc("image: x:1\nnetwork_mode: none"), nil},
		{"default", svc("image: x:1"), nil},
	})
}

func TestSEC004DangerousCapabilities(t *testing.T) {
	runRuleCases(t, "SST-SEC-004", []ruleCase{
		{"sys_admin and net_admin", svc("image: x:1\ncap_add: [SYS_ADMIN, NET_ADMIN, CHOWN]"),
			[]want{{"app", high, []string{"cap_add: SYS_ADMIN", "cap_add: NET_ADMIN"}}}},
		{"cap prefix and lower case", svc("image: x:1\ncap_add: [cap_sys_module]"),
			[]want{{"app", high, []string{"SYS_MODULE"}}}},
		{"all", svc("image: x:1\ncap_add: [ALL]"), []want{{"app", high, []string{"cap_add: ALL"}}}},
		{"each listed capability", svc("image: x:1\ncap_add: [SYS_PTRACE, DAC_READ_SEARCH, SYS_RAWIO, SYS_BOOT, SYS_TIME, MKNOD, BPF]"),
			[]want{{"app", high, []string{"SYS_PTRACE", "DAC_READ_SEARCH", "SYS_RAWIO", "SYS_BOOT", "SYS_TIME", "MKNOD", "BPF"}}}},
		{"harmless capability", svc("image: x:1\ncap_add: [NET_BIND_SERVICE]"), nil},
		{"none", svc("image: x:1"), nil},
	})
}

func TestSEC005CapDrop(t *testing.T) {
	runRuleCases(t, "SST-SEC-005", []ruleCase{
		{"not set", svc("image: x:1"), []want{{"app", low, []string{"cap_drop is not set"}}}},
		{"partial", svc("image: x:1\ncap_drop: [NET_RAW]"), []want{{"app", low, []string{"[NET_RAW] does not include ALL"}}}},
		{"all", svc("image: x:1\ncap_drop: [ALL]"), nil},
		{"all lower case", svc("image: x:1\ncap_drop: [all]"), nil},
		{"privileged is skipped", svc("image: x:1\nprivileged: true"), nil},
	})
}

func TestSEC006WritableBindMount(t *testing.T) {
	runRuleCases(t, "SST-SEC-006", []ruleCase{
		{"relative bind", svc("image: x:1\nvolumes:\n  - ./data:/data"), []want{{"app", med, []string{"./data:/data (read-write)"}}}},
		{"two binds", svc("image: x:1\nvolumes:\n  - ./a:/a\n  - /srv/b:/b"), []want{{"app", med, []string{"./a:/a", "/srv/b:/b"}}}},
		{"read-only short", svc("image: x:1\nvolumes:\n  - ./conf:/etc/app:ro"), nil},
		{"read-only long", svc("image: x:1\nvolumes:\n  - type: bind\n    source: ./conf\n    target: /conf\n    read_only: true"), nil},
		{"named volume", svc("image: x:1\nvolumes:\n  - data:/data") + "volumes:\n  data:\n", nil},
		{"anonymous volume", svc("image: x:1\nvolumes:\n  - /data"), nil},
		{"tmpfs", svc("image: x:1\ntmpfs: [/tmp]"), nil},
		{"docker socket left to SEC-001", svc("image: x:1\nvolumes:\n  - /var/run/docker.sock:/var/run/docker.sock"), nil},
	})
}

func TestSEC007SensitiveHostPath(t *testing.T) {
	runRuleCases(t, "SST-SEC-007", []ruleCase{
		{"root filesystem", svc("image: x:1\nvolumes:\n  - /:/host:ro"), []want{{"app", high, []string{"/:/host:ro (read-only): the entire host filesystem"}}}},
		{"etc subtree", svc("image: x:1\nvolumes:\n  - /etc/letsencrypt:/certs"), []want{{"app", high, []string{"/etc/letsencrypt:/certs (read-write)"}}}},
		{"proc sys dev", svc("image: x:1\nvolumes:\n  - /proc:/host/proc:ro\n  - /sys:/host/sys:ro\n  - /dev/sda:/dev/sda"),
			[]want{{"app", high, []string{"/proc:/host/proc", "/sys:/host/sys", "/dev/sda"}}}},
		{"root home and docker data", svc("image: x:1\nvolumes:\n  - /root/.ssh:/keys:ro\n  - /var/lib/docker:/docker"),
			[]want{{"app", high, []string{"/root/.ssh", "/var/lib/docker"}}}},
		{"run and var run", svc("image: x:1\nvolumes:\n  - /run/dbus:/run/dbus\n  - /var/run:/var/run"),
			[]want{{"app", high, []string{"/run/dbus", "/var/run:/var/run"}}}},
		{"whole home directory", svc("image: x:1\nvolumes:\n  - /home/alice:/data"), []want{{"app", high, []string{"home directory of user \"alice\""}}}},
		{"all homes", svc("image: x:1\nvolumes:\n  - /home:/homes:ro"), []want{{"app", high, []string{"all user home directories"}}}},
		{"ssh dir under home", svc("image: x:1\nvolumes:\n  - /home/alice/.ssh:/root/.ssh:ro\n  - ~/.aws:/aws:ro"),
			[]want{{"app", high, []string{"credentials directory (.ssh)", "credentials directory (.aws)"}}}},
		{"tilde home", svc("image: x:1\nvolumes:\n  - ~:/home"), []want{{"app", high, []string{"entire home directory"}}}},
		{"project dir under home is fine", svc("image: x:1\nvolumes:\n  - /home/alice/stack/data:/data"), nil},
		{"localtime read-only is fine", svc("image: x:1\nvolumes:\n  - /etc/localtime:/etc/localtime:ro\n  - /etc/ssl/certs:/etc/ssl/certs:ro"), nil},
		{"localtime writable is flagged", svc("image: x:1\nvolumes:\n  - /etc/localtime:/etc/localtime"), []want{{"app", high, []string{"/etc/localtime"}}}},
		{"dev null is fine", svc("image: x:1\nvolumes:\n  - /dev/null:/app/.env"), nil},
		{"docker socket left to SEC-001", svc("image: x:1\nvolumes:\n  - /var/run/docker.sock:/var/run/docker.sock"), nil},
		{"similar prefix is fine", svc("image: x:1\nvolumes:\n  - /etcetera:/x\n  - /srv/data:/data\n  - /runner:/r"), nil},
		{"named volume is fine", svc("image: x:1\nvolumes:\n  - etc:/etc") + "volumes:\n  etc:\n", nil},
	})
}

func TestSEC008NonRootUser(t *testing.T) {
	runRuleCases(t, "SST-SEC-008", []ruleCase{
		{"unset", svc("image: x:1"), []want{{"app", med, []string{"user is not set"}}}},
		{"root", svc("image: x:1\nuser: root"), []want{{"app", med, []string{"user: root"}}}},
		{"uid zero with group", svc("image: x:1\nuser: \"0:1000\""), []want{{"app", med, []string{"user: 0:1000"}}}},
		{"non-root uid", svc("image: x:1\nuser: \"1000:1000\""), nil},
		{"named user", svc("image: x:1\nuser: node"), nil},
	})
}

func TestSEC009ReadOnlyRootFS(t *testing.T) {
	runRuleCases(t, "SST-SEC-009", []ruleCase{
		{"unset", svc("image: x:1"), []want{{"app", low, []string{"read_only is not set"}}}},
		{"false", svc("image: x:1\nread_only: false"), []want{{"app", low, nil}}},
		{"true", svc("image: x:1\nread_only: true"), nil},
	})
}

func TestSEC010DockerAPIExposure(t *testing.T) {
	runRuleCases(t, "SST-SEC-010", []ruleCase{
		{"dind publishes 2375", svc("image: docker:27-dind\nports:\n  - \"2375:2375\""),
			[]want{{"app", crit, []string{"publishes the unencrypted Docker API port 2375 (all host interfaces)"}}}},
		{"loopback port is high", svc("image: x:1\nports:\n  - \"127.0.0.1:2375:2375\""),
			[]want{{"app", high, []string{"localhost only"}}}},
		{"dockerd tcp listener", svc("image: docker:27-dind\ncommand: [\"dockerd\", \"-H\", \"tcp://0.0.0.0:2375\"]"),
			[]want{{"app", high, []string{"dockerd listens on tcp://0.0.0.0:2375 without --tlsverify"}}}},
		{"dind args go to dockerd", svc("image: docker:dind\ncommand: --host=tcp://0.0.0.0:2375"),
			[]want{{"app", high, []string{"dockerd listens on tcp://0.0.0.0:2375"}}}},
		{"tlsverify is fine", svc("image: docker:27-dind\ncommand: [\"dockerd\", \"-H\", \"tcp://0.0.0.0:2376\", \"--tlsverify\"]"), nil},
		{"client flag", svc("image: alpine:3\ncommand: docker -H tcp://remote:2375 ps"),
			[]want{{"app", med, []string{"connects to a Docker API at tcp://remote:2375"}}}},
		{"credentials in command url are removed", svc("image: alpine:3\ncommand: docker -H tcp://admin:pw@remote:2375 ps"),
			[]want{{"app", med, []string{"at tcp://remote:2375 without"}}}},
		{"dind with tls disabled", svc("image: docker:27-dind\nenvironment:\n  DOCKER_TLS_CERTDIR: \"\""),
			[]want{{"app", high, []string{"DOCKER_TLS_CERTDIR is empty"}}}},
		{"tls certdir ignored for other images", svc("image: alpine:3\nenvironment:\n  DOCKER_TLS_CERTDIR: \"\""), nil},
		{"docker host to remote", svc("image: portainer/agent:2\nenvironment:\n  DOCKER_HOST: tcp://admin:pw@10.0.0.5:2375"),
			[]want{{"app", med, []string{"DOCKER_HOST=tcp://10.0.0.5:2375 uses unencrypted TCP"}}}},
		{"docker host with cert path is fine", svc("image: x:1\nenvironment:\n  DOCKER_HOST: tcp://10.0.0.5:2376\n  DOCKER_CERT_PATH: /certs"), nil},
		{"socket proxy pattern is low", "services:\n  proxy:\n    image: tecnativa/docker-socket-proxy:0.3\n  traefik:\n    image: traefik:v3.1\n    environment:\n      DOCKER_HOST: tcp://proxy:2375\n",
			[]want{{"traefik", low, []string{"another service of this project"}}}},
		{"combined indicators take the highest severity", svc("image: docker:27-dind\nenvironment:\n  DOCKER_TLS_CERTDIR: \"\"\nports:\n  - \"2375:2375\""),
			[]want{{"app", crit, []string{"DOCKER_TLS_CERTDIR", "port 2375:2375"}}}},
		{"host network ports ignored", svc("image: x:1\nnetwork_mode: host\nports:\n  - \"2375:2375\""), nil},
		{"unrelated service", svc("image: nginx:1.27\nports:\n  - \"8080:80\""), nil},
	})
}
