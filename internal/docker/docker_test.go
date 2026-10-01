package docker

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"syscall"
	"testing"
	"testing/fstest"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/api/types/system"
	"github.com/moby/moby/client"

	"github.com/6-SlX-6/stacksentry/internal/docker/dockertest"
)

func healthyFake() *dockertest.Fake {
	return &dockertest.Fake{
		Version: client.ServerVersionResult{Version: "27.3.1", APIVersion: "1.47", Os: "linux", Arch: "amd64"},
		SystemInfo: system.Info{
			Name: "build-host", OperatingSystem: "Ubuntu 24.04.1 LTS", KernelVersion: "6.8.0", Images: 7,
			DockerRootDir: "/var/lib/docker", SecurityOptions: []string{"name=seccomp,profile=builtin", "name=rootless"},
		},
		Containers: []container.Summary{
			{ID: "aaaaaaaaaaaaaaaaaaaa", Names: []string{"/web"}, Image: "nginx", State: container.StateRunning},
			{ID: "bbbbbbbbbbbbbbbbbbbb", Names: []string{"/old"}, Image: "busybox:1.36", State: container.StateExited,
				Mounts: []container.MountPoint{{Type: "bind", Source: "/srv", Destination: "/srv", RW: true}}},
		},
		Inspect: map[string]container.InspectResponse{
			"aaaaaaaaaaaaaaaaaaaa": {
				Config: &container.Config{Image: "nginx:latest"},
				HostConfig: &container.HostConfig{
					Privileged: true, NetworkMode: "host", AutoRemove: true,
					RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyDisabled},
				},
				Mounts: []container.MountPoint{{Type: "bind", Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock", RW: false}},
			},
		},
		Images: []image.Summary{{ID: "sha256:ffffffffffffffffffff", Size: 100}, {ID: "sha256:eeeeeeeeeeeeeeee", Size: 50}},
		Usage: client.DiskUsageResult{
			Images:     client.ImagesDiskUsage{TotalCount: 7, TotalSize: 1000, Reclaimable: 400},
			Containers: client.ContainersDiskUsage{TotalCount: 2, TotalSize: 10, Reclaimable: 5},
			Volumes:    client.VolumesDiskUsage{TotalCount: 1, TotalSize: 100},
			BuildCache: client.BuildCacheDiskUsage{TotalCount: 3, TotalSize: 300, Reclaimable: 300},
		},
	}
}

func TestInspectCollectsSnapshot(t *testing.T) {
	api := healthyFake()
	in := &Inspector{Conn: &Connection{API: api, Endpoint: "unix:///var/run/docker.sock"}, GOOS: "linux", HostFS: fstest.MapFS{
		"proc/net/tcp": {Data: []byte(procTCPHeader)},
		"proc/1/comm":  {Data: []byte("systemd\n")},
	}}
	s := in.Inspect(context.Background())
	if s.Daemon.Version != "27.3.1" || s.Daemon.APIVersion != "1.47" || s.Daemon.OperatingSystem != "Ubuntu 24.04.1 LTS" || !s.Daemon.Rootless {
		t.Fatalf("daemon: %+v", s.Daemon)
	}
	if s.ImagesTotal != 7 || len(s.DanglingImages) != 2 || s.DanglingImages[0].ID != "eeeeeeeeeeee" {
		t.Fatalf("images: %+v", s.DanglingImages)
	}
	if !api.ImageFilters["dangling"]["true"] {
		t.Fatalf("dangling filter not applied: %v", api.ImageFilters)
	}
	if len(s.Containers) != 2 || s.Containers[0].Name != "old" || s.Containers[1].Name != "web" {
		t.Fatalf("containers not sorted: %+v", s.Containers)
	}
	web := s.Containers[1]
	if !web.Running || !web.Inspected || !web.Privileged || web.NetworkMode != "host" || web.RestartPolicy != "no" ||
		!web.AutoRemove || web.Image != "nginx:latest" || web.ID != "aaaaaaaaaaaa" || len(web.Mounts) != 1 || web.Mounts[0].RW {
		t.Fatalf("web: %+v", web)
	}
	if old := s.Containers[0]; old.Running || old.Inspected || len(old.Mounts) != 1 {
		t.Fatalf("stopped containers must not be inspected: %+v", old)
	}
	if s.DiskUsage == nil || s.DiskUsage.Total() != 1410 || s.DiskUsage.Reclaimable() != 705 {
		t.Fatalf("disk usage: %+v", s.DiskUsage)
	}
	if len(s.Listeners) != 0 {
		t.Fatalf("unexpected listeners: %+v", s.Listeners)
	}
	joined := strings.Join(s.Limitations, "\n")
	if !strings.Contains(joined, "No dockerd process is visible") || strings.Contains(joined, "daemon.json") {
		t.Fatalf("limitations: %v", s.Limitations)
	}
}

func TestInspectRecordsLimitations(t *testing.T) {
	boom := errors.New("boom")
	api := healthyFake()
	api.VersionErr, api.InfoErr, api.ImageErr, api.DiskUsageErr, api.InspectErr = boom, boom, boom, boom, boom
	s := (&Inspector{Conn: &Connection{API: api, Endpoint: "unix:///var/run/docker.sock"}, GOOS: "darwin"}).Inspect(context.Background())
	joined := strings.Join(s.Limitations, "\n")
	for _, want := range []string{"version information", "docker info", "could not be inspected", "image list", "disk usage", "only inspected on Linux"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing limitation %q in:\n%s", want, joined)
		}
	}
	if s.DiskUsage != nil || len(s.DanglingImages) != 0 {
		t.Fatal("unavailable data must stay unset")
	}

	api = healthyFake()
	api.ListErr = boom
	s = (&Inspector{Conn: &Connection{API: api, Endpoint: "unix:///var/run/docker.sock"}, GOOS: "linux"}).Inspect(context.Background())
	if len(s.Containers) != 0 || !strings.Contains(strings.Join(s.Limitations, "\n"), "container list") {
		t.Fatalf("list error: %+v", s.Limitations)
	}
	if !strings.Contains(strings.Join(s.Limitations, "\n"), "Host filesystem inspection is disabled") {
		t.Fatalf("nil HostFS should be a limitation: %v", s.Limitations)
	}
}

func TestVerifyAndClassify(t *testing.T) {
	if err := Verify(context.Background(), &Connection{API: &dockertest.Fake{}, Endpoint: "unix:///x"}); err != nil {
		t.Fatalf("healthy ping failed: %v", err)
	}
	tests := []struct {
		name   string
		err    error
		reason string
	}{
		{"permission", fmt.Errorf("dial: %w", fs.ErrPermission), "permission denied"},
		{"permission text", errors.New("Got permission denied while trying to connect"), "permission denied"},
		{"refused", syscall.ECONNREFUSED, "not reachable"},
		{"missing socket", errors.New("dial unix /var/run/docker.sock: connect: no such file or directory"), "not reachable"},
		{"timeout", context.DeadlineExceeded, "did not respond in time"},
		{"other", errors.New("tls: bad certificate"), "tls: bad certificate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Verify(context.Background(), &Connection{API: &dockertest.Fake{PingErr: tt.err}, Endpoint: "unix:///var/run/docker.sock"})
			var ue *UnavailableError
			if !errors.As(err, &ue) || ue.Reason != tt.reason && !strings.Contains(ue.Reason, tt.reason) {
				t.Fatalf("got %v, want reason %q", err, tt.reason)
			}
			if !errors.Is(err, tt.err) {
				t.Fatal("cause not wrapped")
			}
			if !strings.Contains(err.Error(), "unix:///var/run/docker.sock") {
				t.Fatalf("endpoint missing from %q", err)
			}
		})
	}
	if msg := (&UnavailableError{Reason: "x"}).Error(); !strings.Contains(msg, "default endpoint") {
		t.Fatalf("message without endpoint: %q", msg)
	}
}

func TestConnectUnreachable(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:1")
	t.Setenv("DOCKER_CERT_PATH", "")
	_, err := Connect(context.Background())
	var ue *UnavailableError
	if !errors.As(err, &ue) || ue.Endpoint != "tcp://127.0.0.1:1" {
		t.Fatalf("expected UnavailableError for closed port, got %v", err)
	}
	t.Setenv("DOCKER_HOST", "not a url ::")
	if _, err := Connect(context.Background()); !errors.As(err, &ue) || !strings.Contains(err.Error(), "invalid Docker client configuration") {
		t.Fatalf("expected configuration error, got %v", err)
	}
}

const procTCPHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

func TestListenerProbeSources(t *testing.T) {
	fsys := fstest.MapFS{
		"etc/docker/daemon.json": {Data: []byte(`{"hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"], "tls": true}`)},
		"proc/1/comm":            {Data: []byte("systemd\n")},
		"proc/812/comm":          {Data: []byte("dockerd\n")},
		"proc/812/cmdline":       {Data: []byte("/usr/bin/dockerd\x00-H\x00fd://\x00-H=tcp://127.0.0.1:2375\x00")},
		"proc/self/comm":         {Data: []byte("dockerd\n")},
		"proc/net/tcp": {Data: []byte(procTCPHeader +
			"   0: 00000000:0947 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1\n" +
			"   1: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1\n" +
			"   2: 0100007F:0947 0100007F:9C40 01 00000000:00000000 00:00000000 00000000     0        0 3 1\n")},
		"proc/net/tcp6": {Data: []byte(procTCPHeader +
			"   0: 00000000000000000000000001000000:0947 00000000000000000000000000000000:0000 0A 0 0 0 0 0 4 1\n")},
	}
	p := listenerProbe{fsys: fsys, goos: "linux", endpoint: "unix:///var/run/docker.sock"}
	warnings := []string{"WARNING: bridge-nf-call-iptables is disabled",
		"[DEPRECATION NOTICE]: API is accessible on http://0.0.0.0:2375 without encryption.\n Access to the remote API is equivalent to root access"}
	obs, lim := p.run(warnings, nil)
	if len(lim) != 0 {
		t.Fatalf("unexpected limitations: %v", lim)
	}
	var got []string
	for _, o := range obs {
		got = append(got, o.Source+"|"+o.Address+"|"+string(o.Confidence))
	}
	want := []string{
		"Docker API (docker info warnings)|http://0.0.0.0:2375|high",
		"/etc/docker/daemon.json (hosts)|tcp://0.0.0.0:2375|high",
		"dockerd command line (pid 812)|tcp://127.0.0.1:2375|high",
		"/proc/net/tcp|tcp://0.0.0.0:2375|medium",
		"/proc/net/tcp6|tcp://[::1]:2375|medium",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("observations:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !strings.Contains(obs[1].Detail, "without client certificate verification") {
		t.Fatalf("tls without verify detail: %q", obs[1].Detail)
	}
}

func TestListenerProbeEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		probe    listenerProbe
		wantObs  int
		wantLim  string
		warnings []string
	}{
		{"remote tcp endpoint without tls", listenerProbe{endpoint: "tcp://10.0.0.5:2375", goos: "linux"}, 1, "not local", nil},
		{"remote tcp with tls", listenerProbe{endpoint: "tcp://10.0.0.5:2376", tls: true, goos: "linux"}, 0, "not local", nil},
		{"ssh endpoint", listenerProbe{endpoint: "ssh://admin@host", goos: "linux"}, 0, "not local", nil},
		{"windows", listenerProbe{endpoint: "npipe:////./pipe/docker_engine", goos: "windows"}, 0, "only inspected on Linux", nil},
		{"tlsverify in daemon.json", listenerProbe{endpoint: "unix:///var/run/docker.sock", goos: "linux", fsys: fstest.MapFS{
			"etc/docker/daemon.json": {Data: []byte(`{"hosts": ["tcp://0.0.0.0:2376"], "tlsverify": true}`)},
			"proc/net/tcp":           {Data: []byte(procTCPHeader)},
			"proc/9/comm":            {Data: []byte("dockerd")},
			"proc/9/cmdline":         {Data: []byte("dockerd\x00--tlsverify\x00--host=tcp://0.0.0.0:2376")},
		}}, 0, "", nil},
		{"invalid daemon.json", listenerProbe{endpoint: "unix:///var/run/docker.sock", goos: "linux", fsys: fstest.MapFS{
			"etc/docker/daemon.json": {Data: []byte(`{nope`)},
			"proc/net/tcp":           {Data: []byte(procTCPHeader)},
		}}, 0, "not valid JSON", nil},
		{"no proc", listenerProbe{endpoint: "unix:///var/run/docker.sock", goos: "linux", fsys: fstest.MapFS{}}, 0, "/proc could not be read", nil},
		{"unreadable cmdline", listenerProbe{endpoint: "unix:///var/run/docker.sock", goos: "linux", fsys: fstest.MapFS{
			"proc/9/comm":  {Data: []byte("dockerd")},
			"proc/net/tcp": {Data: []byte(procTCPHeader)},
		}}, 0, "command line could not be read", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obs, lim := tt.probe.run(tt.warnings, nil)
			if len(obs) != tt.wantObs {
				t.Fatalf("observations = %+v, want %d", obs, tt.wantObs)
			}
			joined := strings.Join(lim, "\n")
			if (tt.wantLim == "") != (joined == "") || !strings.Contains(joined, tt.wantLim) {
				t.Fatalf("limitations = %q, want %q", joined, tt.wantLim)
			}
		})
	}
}

func TestParseDaemonArgs(t *testing.T) {
	hosts, verify, tls := parseDaemonArgs([]string{"dockerd", "-H", "unix:///s", "--host=tcp://0.0.0.0:2375", "-Htcp://1.2.3.4:2375", "--tls"})
	if strings.Join(hosts, ",") != "unix:///s,tcp://0.0.0.0:2375,tcp://1.2.3.4:2375" || verify || !tls {
		t.Fatalf("hosts=%v verify=%v tls=%v", hosts, verify, tls)
	}
}

func TestListenerExposure(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"tcp://127.0.0.1:2375", true}, {"http://localhost:2375", true}, {"tcp://[::1]:2375", true},
		{"tcp://0.0.0.0:2375", false}, {"http://0.0.0.0:2375/", false}, {"tcp://10.0.0.5:2375", false},
		{"tcp://:2375", false}, {"garbage", false},
	}
	for _, tt := range tests {
		if got := ListenerExposure(tt.addr); got != tt.want {
			t.Errorf("ListenerExposure(%q) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func TestDecodeProcIP(t *testing.T) {
	if ip := decodeProcIP("0100007F"); ip.String() != "127.0.0.1" {
		t.Fatalf("ipv4: %v", ip)
	}
	if ip := decodeProcIP("zz"); ip != nil {
		t.Fatal("invalid hex must fail")
	}
	if got := listeningOn([]byte("garbage line\n 0: 0100007F 00 0A\n 1: XYZ:0947 0 0A\n"), 2375); len(got) != 0 {
		t.Fatalf("malformed lines must be skipped: %v", got)
	}
	if r := reason(fs.ErrPermission); r != "permission denied" {
		t.Fatal(r)
	}
	if r := reason(errors.New("x")); r != "x" {
		t.Fatal(r)
	}
}
