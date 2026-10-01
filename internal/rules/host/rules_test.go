package hostrules

import (
	"strings"
	"testing"
	"time"

	"github.com/6-SlX-6/stacksentry/internal/docker"
	"github.com/6-SlX-6/stacksentry/internal/engine"
	"github.com/6-SlX-6/stacksentry/internal/findings"
)

type want struct {
	target   string
	severity findings.Severity
	evidence []string
}

func run(t *testing.T, ruleID string, s *docker.Snapshot) []findings.Finding {
	t.Helper()
	rule, ok := Registry().Lookup(ruleID)
	if !ok {
		t.Fatalf("rule %s missing", ruleID)
	}
	res := engine.Run([]Rule{rule}, s, engine.RunConfig{ScannerVersion: "test", Now: time.Unix(0, 0)})
	if len(res.Errors) > 0 {
		t.Fatal(res.Errors)
	}
	return res.Findings
}

func check(t *testing.T, ruleID string, cases []struct {
	name string
	snap *docker.Snapshot
	want []want
}) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := run(t, ruleID, tc.snap)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d findings, want %d: %+v", len(got), len(tc.want), got)
			}
			for i, w := range tc.want {
				f := got[i]
				if f.TargetName != w.target || f.Severity != w.severity {
					t.Errorf("finding %d = %s/%s, want %s/%s", i, f.TargetName, f.Severity, w.target, w.severity)
				}
				joined := strings.Join(f.Evidence, "\n")
				for _, ev := range w.evidence {
					if !strings.Contains(joined, ev) {
						t.Errorf("evidence %q does not contain %q", joined, ev)
					}
				}
			}
		})
	}
}

func snap(containers ...docker.Container) *docker.Snapshot {
	return &docker.Snapshot{
		Endpoint: "unix:///var/run/docker.sock",
		Daemon: docker.Daemon{Name: "host1", Version: "27.3.1", APIVersion: "1.47", OSType: "linux",
			Architecture: "amd64", OperatingSystem: "Debian GNU/Linux 12", KernelVersion: "6.1.0-25-amd64", RootDir: "/var/lib/docker"},
		Containers: containers,
	}
}

func running(name string, mutate func(*docker.Container)) docker.Container {
	c := docker.Container{ID: "0123456789ab", Name: name, Image: "nginx:1.27.2", State: "running", Running: true,
		Inspected: true, NetworkMode: "bridge", RestartPolicy: "unless-stopped"}
	if mutate != nil {
		mutate(&c)
	}
	return c
}

type cases = []struct {
	name string
	snap *docker.Snapshot
	want []want
}

func TestRegistry(t *testing.T) {
	var ids []string
	for _, m := range Registry().Metadata() {
		ids = append(ids, m.ID)
	}
	if strings.Join(ids, ",") != "SST-HOST-001,SST-HOST-002,SST-HOST-003,SST-HOST-004,SST-HOST-005,SST-HOST-006,SST-HOST-007,SST-HOST-008,SST-HOST-009,SST-HOST-010" {
		t.Fatalf("host rules: %v", ids)
	}
}

func TestHOST001DaemonReachable(t *testing.T) {
	rootless := snap()
	rootless.Daemon.Rootless = true
	noName := &docker.Snapshot{Endpoint: "unix:///run/user/1000/docker.sock"}
	check(t, "SST-HOST-001", cases{
		{"version info", snap(), []want{{"host1", findings.SeverityInfo, []string{"Docker Engine 27.3.1 (API 1.47, linux/amd64)", "host OS: Debian", "kernel: 6.1.0-25-amd64"}}}},
		{"rootless", rootless, []want{{"host1", findings.SeverityInfo, []string{"rootless mode: enabled"}}}},
		{"minimal data falls back to endpoint", noName, []want{{"unix:///run/user/1000/docker.sock", findings.SeverityInfo, []string{"endpoint: unix:///run/user/1000/docker.sock"}}}},
	})
}

func TestHOST002Listeners(t *testing.T) {
	withListeners := func(obs ...docker.ListenerObservation) *docker.Snapshot {
		s := snap()
		s.Listeners = obs
		return s
	}
	public := docker.ListenerObservation{Source: "/etc/docker/daemon.json (hosts)", Address: "tcp://0.0.0.0:2375", Detail: "TCP listener without TLS", Confidence: findings.ConfidenceHigh}
	local := docker.ListenerObservation{Source: "/proc/net/tcp", Address: "tcp://127.0.0.1:2375", Detail: "listens", Confidence: findings.ConfidenceMedium}
	check(t, "SST-HOST-002", cases{
		{"none", snap(), nil},
		{"public listener is critical", withListeners(public), []want{{"host1", findings.SeverityCritical, []string{"tcp://0.0.0.0:2375", "reachable from the network"}}}},
		{"loopback listener is high", withListeners(local), []want{{"host1", findings.SeverityHigh, []string{"localhost only"}}}},
		{"combined", withListeners(local, public), []want{{"host1", findings.SeverityCritical, []string{"127.0.0.1", "0.0.0.0"}}}},
	})
	got := run(t, "SST-HOST-002", withListeners(local))
	if got[0].Confidence != findings.ConfidenceMedium {
		t.Fatalf("socket-table-only observation should be medium confidence, got %s", got[0].Confidence)
	}
	got = run(t, "SST-HOST-002", withListeners(local, public))
	if got[0].Confidence != findings.ConfidenceHigh {
		t.Fatalf("confidence should be high, got %s", got[0].Confidence)
	}
}

func TestHOST003Privileged(t *testing.T) {
	check(t, "SST-HOST-003", cases{
		{"privileged running", snap(running("vpn", func(c *docker.Container) { c.Privileged = true })), []want{{"vpn", findings.SeverityCritical, []string{"privileged: true", "container ID: 0123456789ab"}}}},
		{"privileged stopped is ignored", snap(docker.Container{Name: "old", Privileged: true, State: "exited"}), nil},
		{"unprivileged", snap(running("web", nil)), nil},
	})
}

func TestHOST004DockerSocket(t *testing.T) {
	check(t, "SST-HOST-004", cases{
		{"socket ro", snap(running("traefik", func(c *docker.Container) {
			c.Mounts = []docker.Mount{{Type: "bind", Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock"}}
		})), []want{{"traefik", findings.SeverityCritical, []string{"/var/run/docker.sock -> /var/run/docker.sock (read-only)"}}}},
		{"docker desktop proxy socket", snap(running("agent", func(c *docker.Container) {
			c.Mounts = []docker.Mount{{Type: "bind", Source: "/run/host-services/docker.proxy.sock", Destination: "/sock", RW: true}}
		})), []want{{"agent", findings.SeverityCritical, []string{"(read-write)"}}}},
		{"other mounts", snap(running("web", func(c *docker.Container) {
			c.Mounts = []docker.Mount{{Type: "volume", Source: "/var/lib/docker/volumes/x/_data", Destination: "/data", RW: true}}
		})), nil},
	})
}

func TestHOST005HostNetwork(t *testing.T) {
	check(t, "SST-HOST-005", cases{
		{"host", snap(running("ha", func(c *docker.Container) { c.NetworkMode = "host" })), []want{{"ha", findings.SeverityHigh, []string{"network mode: host"}}}},
		{"bridge", snap(running("web", nil)), nil},
	})
}

func TestHOST006RestartPolicy(t *testing.T) {
	check(t, "SST-HOST-006", cases{
		{"no policy", snap(running("api", func(c *docker.Container) { c.RestartPolicy = "no" })), []want{{"api", findings.SeverityHigh, []string{"restart policy: no"}}}},
		{"empty policy", snap(running("api", func(c *docker.Container) { c.RestartPolicy = "" })), []want{{"api", findings.SeverityHigh, []string{"restart policy: not set"}}}},
		{"auto remove", snap(running("job", func(c *docker.Container) { c.RestartPolicy = "no"; c.AutoRemove = true })), nil},
		{"not inspected", snap(running("x", func(c *docker.Container) { c.RestartPolicy = ""; c.Inspected = false })), nil},
		{"always", snap(running("web", func(c *docker.Container) { c.RestartPolicy = "always" })), nil},
	})
}

func TestHOST007Stopped(t *testing.T) {
	var many []docker.Container
	for i := 0; i < 12; i++ {
		many = append(many, docker.Container{Name: string(rune('a' + i)), State: "exited"})
	}
	check(t, "SST-HOST-007", cases{
		{"some stopped", snap(running("web", nil), docker.Container{Name: "old", State: "exited"}, docker.Container{Name: "new", State: "created"}, docker.Container{Name: "paused", State: "paused"}),
			[]want{{"host1", findings.SeverityInfo, []string{"2 stopped container(s): old, new"}}}},
		{"truncated list", snap(many...), []want{{"host1", findings.SeverityInfo, []string{"12 stopped container(s)", "(and 2 more)"}}}},
		{"none", snap(running("web", nil)), nil},
	})
}

func TestHOST008Dangling(t *testing.T) {
	s := snap()
	s.DanglingImages = []docker.Image{{ID: "a", Size: 1536}, {ID: "b", Size: 1 << 30}}
	check(t, "SST-HOST-008", cases{
		{"dangling", s, []want{{"host1", findings.SeverityLow, []string{"2 dangling image(s) using 1.0 GiB"}}}},
		{"none", snap(), nil},
	})
}

func TestHOST009DiskUsage(t *testing.T) {
	gib := int64(1 << 30)
	usage := func(total, reclaimable int64) *docker.Snapshot {
		s := snap()
		s.DiskUsage = &docker.DiskUsage{Images: docker.UsageItem{Count: 12, Size: total, Reclaimable: reclaimable}}
		return s
	}
	check(t, "SST-HOST-009", cases{
		{"absolute threshold", usage(100*gib, 25*gib), []want{{"host1", findings.SeverityMedium, []string{"reclaimable: 25.0 GiB (25%)", "Docker root directory: /var/lib/docker", "images: 12 using 100.0 GiB (25.0 GiB reclaimable)"}}}},
		{"ratio threshold", usage(10*gib, 6*gib), []want{{"host1", findings.SeverityMedium, []string{"(60%)"}}}},
		{"high ratio but small", usage(2*gib, 2*gib), nil},
		{"low ratio and below absolute", usage(100*gib, 10*gib), nil},
		{"no data", snap(), nil},
		{"empty usage", usage(0, 0), nil},
	})
}

func TestHOST010MutableImages(t *testing.T) {
	check(t, "SST-HOST-010", cases{
		{"latest", snap(running("web", func(c *docker.Container) { c.Image = "nginx:latest" })), []want{{"web", findings.SeverityMedium, []string{"image: nginx:latest"}}}},
		{"untagged", snap(running("web", func(c *docker.Container) { c.Image = "nginx" })), []want{{"web", findings.SeverityMedium, nil}}},
		{"channel", snap(running("web", func(c *docker.Container) { c.Image = "nginx:mainline" })), []want{{"web", findings.SeverityLow, nil}}},
		{"version", snap(running("web", nil)), nil},
		{"image id", snap(running("web", func(c *docker.Container) { c.Image = "sha256:abcdef" })), nil},
		{"stopped ignored", snap(docker.Container{Name: "old", Image: "nginx", State: "exited"}), nil},
	})
}

func TestHumanBytes(t *testing.T) {
	tests := map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 1536: "1.5 KiB", 5 << 20: "5.0 MiB", 3 << 40: "3.0 TiB"}
	for in, want := range tests {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}
