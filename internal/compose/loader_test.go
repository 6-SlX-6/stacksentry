package compose

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const fixtures = "../../testdata/compose/"

func load(t *testing.T, paths ...string) (*Project, error) {
	t.Helper()
	return Load(context.Background(), paths)
}

func TestLoadErrors(t *testing.T) {
	tests := []struct {
		name     string
		paths    []string
		kind     ErrorKind
		contains string
	}{
		{"missing file", []string{fixtures + "does-not-exist.yaml"}, ErrNotFound, "not found"},
		{"missing second file", []string{fixtures + "valid-minimal.yaml", fixtures + "nope.yaml"}, ErrNotFound, "nope.yaml"},
		{"no paths", nil, ErrNotFound, "no Compose file given"},
		{"invalid yaml", []string{fixtures + "invalid-yaml.yaml"}, ErrInvalidYAML, "line 4"},
		{"services list", []string{fixtures + "services-list.yaml"}, ErrUnsupported, "\"services\" must be a mapping"},
		{"top-level list", []string{fixtures + "top-level-list.yaml"}, ErrUnsupported, "top-level element must be a mapping"},
		{"empty file", []string{fixtures + "empty.yaml"}, ErrNoServices, "the file is empty"},
		{"schema violation", []string{fixtures + "invalid-schema.yaml"}, ErrInvalidCompose, "restartt"},
		{"include only", []string{writeTemp(t, "include:\n  - other.yaml\n")}, ErrNoServices, "\"include\" are not analyzed"},
		{"directory without compose file", []string{t.TempDir()}, ErrNotFound, "no Compose file found"},
		{"directory among several paths", []string{fixtures + "valid-minimal.yaml", fixtures + "project-dir"}, ErrRead, "is a directory"},
		{"undefined network", []string{writeTemp(t, "services:\n  web:\n    image: x:1\n    networks: [missing]\n")}, ErrInvalidCompose, "missing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(t, tt.paths...)
			var le *LoadError
			if !errors.As(err, &le) {
				t.Fatalf("expected *LoadError, got %T: %v", err, err)
			}
			if le.Kind != tt.kind {
				t.Fatalf("kind = %s, want %s (%v)", le.Kind, tt.kind, err)
			}
			if !strings.Contains(err.Error(), tt.contains) {
				t.Fatalf("error %q does not contain %q", err, tt.contains)
			}
		})
	}
}

func TestLoadErrorMessages(t *testing.T) {
	tests := []struct {
		err  *LoadError
		want string
	}{
		{&LoadError{Kind: ErrNotFound, Path: "a.yml"}, `compose file "a.yml" not found`},
		{&LoadError{Kind: ErrNotFound, Path: "dir", Detail: "no Compose file found"}, `"dir": no Compose file found`},
		{&LoadError{Kind: ErrPermission, Path: "a.yml"}, `cannot read compose file "a.yml": permission denied`},
		{&LoadError{Kind: ErrInvalidYAML, Path: "a.yml", Detail: "bad"}, `invalid YAML in "a.yml": bad`},
		{&LoadError{Kind: ErrUnsupported, Path: "a.yml", Detail: "bad"}, `unsupported Compose structure in "a.yml": bad`},
		{&LoadError{Kind: ErrInvalidCompose, Path: "a.yml", Detail: "bad"}, `invalid Compose configuration in "a.yml": bad`},
		{&LoadError{Kind: ErrNoServices, Path: "a.yml"}, `"a.yml" defines no services`},
		{&LoadError{Kind: ErrRead, Path: "a.yml", Detail: "boom"}, `cannot read compose file "a.yml": boom`},
	}
	for _, tt := range tests {
		if got := tt.err.Error(); got != tt.want {
			t.Errorf("Error() = %q, want %q", got, tt.want)
		}
	}
	inner := errors.New("inner")
	if !errors.Is(&LoadError{Kind: ErrRead, Err: inner}, inner) {
		t.Fatal("Unwrap does not expose the cause")
	}
}

func TestLoadPermissionDenied(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission bits are not enforced for this user/platform")
	}
	file := writeTemp(t, "services:\n  web:\n    image: x:1\n")
	if err := os.Chmod(file, 0o000); err != nil {
		t.Fatal(err)
	}
	_, err := load(t, file)
	var le *LoadError
	if !errors.As(err, &le) || le.Kind != ErrPermission {
		t.Fatalf("expected permission error, got %v", err)
	}
}

func TestLoadValidProject(t *testing.T) {
	p, err := load(t, fixtures+"multi-service.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "shop" {
		t.Fatalf("project name = %q", p.Name)
	}
	if got := strings.Join(p.ServiceNames(), ","); got != "api,cache,db,debug,frontend,worker" {
		t.Fatalf("services = %s (profile-gated services must be included)", got)
	}
	db, ok := p.Service("db")
	if !ok || db.Line != 17 || db.File != fixtures+"multi-service.yaml" {
		t.Fatalf("db location = %s:%d", db.File, db.Line)
	}
	if _, ok := p.Service("nope"); ok {
		t.Fatal("unexpected service")
	}
	if len(p.Files) != 1 || p.WorkingDir == "" {
		t.Fatalf("files=%v workdir=%q", p.Files, p.WorkingDir)
	}
}

func TestDirectoryDiscoveryMergesOverride(t *testing.T) {
	p, err := load(t, fixtures+"project-dir")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Files) != 2 || filepath.Base(p.Files[0]) != "compose.yaml" || filepath.Base(p.Files[1]) != "compose.override.yaml" {
		t.Fatalf("files = %v", p.Files)
	}
	web, _ := p.Service("web")
	if len(web.Ports) != 1 || web.Ports[0].Target != 80 || web.Restart != "unless-stopped" {
		t.Fatalf("override not merged: %+v", web)
	}
}

func TestExplicitMultipleFiles(t *testing.T) {
	p, err := load(t, fixtures+"project-dir/compose.yaml", fixtures+"project-dir/compose.override.yaml")
	if err != nil {
		t.Fatal(err)
	}
	web, _ := p.Service("web")
	if len(web.Environment) != 1 || web.Environment[0].Name != "DEBUG" {
		t.Fatalf("environment not merged: %+v", web.Environment)
	}
}

func TestInterpolationIsDeterministic(t *testing.T) {
	t.Setenv("DB_HOST", "leaked-from-shell")
	t.Setenv("APP_VERSION", "9.9.9")
	p, err := load(t, fixtures+"missing-variables.yaml")
	if err != nil {
		t.Fatal(err)
	}
	app, _ := p.Service("app")
	if app.Image != "ghcr.io/example/app:" {
		t.Fatalf("image = %q; the shell environment must not be used", app.Image)
	}
	for _, e := range app.Environment {
		if strings.Contains(e.Value, "leaked") {
			t.Fatalf("shell environment leaked into %s", e.Name)
		}
		if e.Name == "LOG_LEVEL" && e.Value != "info" {
			t.Fatalf("default not applied: %q", e.Value)
		}
		if e.Name == "REQUIRED_TOKEN" && e.Value != "" {
			t.Fatalf("required variable should resolve empty, got %q", e.Value)
		}
	}
	var metrics *Port
	for i := range app.Ports {
		if app.Ports[i].Target == 9090 {
			metrics = &app.Ports[i]
		}
	}
	if metrics == nil || metrics.HostIP != "127.0.0.1" {
		t.Fatalf("default host IP not applied: %+v", app.Ports)
	}

	var names []string
	for _, v := range p.Variables {
		names = append(names, v.Name+"@"+v.Path)
	}
	want := []string{
		"APP_VERSION@services.app.image",
		"HTTP_PORT@services.app.ports.0",
		"DB_HOST@services.app.environment.DATABASE_HOST",
		"HEALTH_USER@services.app.healthcheck.test.1",
		"NETWORK_NAME@networks.default.name",
	}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("variables = %v\nwant %v", names, want)
	}
	if p.Variables[0].Line != 4 || p.Variables[0].Service != "app" || p.Variables[4].Service != "" {
		t.Fatalf("variable metadata wrong: %+v", p.Variables)
	}
}

func TestWarningsAndLimitations(t *testing.T) {
	p, err := load(t, fixtures+"obsolete-version.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "\"version\" attribute is obsolete") {
		t.Fatalf("warnings = %v", p.Warnings)
	}
	// Loading twice must produce the same warnings (compose-go only warns once).
	again, _ := load(t, fixtures+"obsolete-version.yaml")
	if len(again.Warnings) != 1 {
		t.Fatalf("warnings not deterministic: %v", again.Warnings)
	}

	inc, err := load(t, fixtures+"include.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(inc.Limitations) != 1 || !strings.Contains(inc.Limitations[0], "include") {
		t.Fatalf("limitations = %v", inc.Limitations)
	}
}

func TestSuppressionsParsing(t *testing.T) {
	p, err := load(t, fixtures+"suppressions.yaml")
	if err != nil {
		t.Fatal(err)
	}
	traefik, _ := p.Service("traefik")
	if !strings.HasPrefix(traefik.Ignore["SST-SEC-001"], "Traefik reads") {
		t.Fatalf("reason not parsed: %v", traefik.Ignore)
	}
	if !strings.Contains(traefik.Ignore["SST-OPS-004"], "no reason given") {
		t.Fatalf("plain rule ID not parsed: %v", traefik.Ignore)
	}
	if _, ok := traefik.Ignore["SST-NOPE-999"]; !ok {
		t.Fatal("unknown IDs are kept so that the caller can warn about them")
	}
}

func TestParseIgnoreMalformed(t *testing.T) {
	tests := []struct {
		name     string
		ext      any
		wantLen  int
		wantWarn string
	}{
		{"nil", nil, 0, ""},
		{"not a mapping", "SST-SEC-001", 0, "expected a mapping"},
		{"no ignore key", map[string]any{"other": 1}, 0, ""},
		{"ignore not a list", map[string]any{"ignore": "SST-SEC-001"}, 0, "must be a list"},
		{"entry without id", map[string]any{"ignore": []any{map[string]any{"reason": "x"}, "sst-sec-002"}}, 1, "without a rule ID"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, warnings := parseIgnore("svc", tt.ext)
			if len(got) != tt.wantLen {
				t.Fatalf("got %v", got)
			}
			joined := strings.Join(warnings, "\n")
			if (tt.wantWarn == "") != (joined == "") || !strings.Contains(joined, tt.wantWarn) {
				t.Fatalf("warnings = %q, want %q", joined, tt.wantWarn)
			}
		})
	}
}

func TestNormalizedServiceDetails(t *testing.T) {
	p, err := load(t, writeTemp(t, `services:
  app:
    image: x:1
    build: .
    network_mode: host
    cap_add: [cap_net_admin]
    tmpfs: ["/run:size=10m"]
    cpu_quota: 50000
    cpu_period: 100000
    mem_limit: 256m
    logging:
      driver: json-file
      options:
        max-size: 5m
    stop_grace_period: 45s
    ports:
      - target: 80
        mode: host
    environment:
      - PASSTHROUGH
`))
	if err != nil {
		t.Fatal(err)
	}
	app := p.Services[0]
	if !app.HasBuild || app.NetworkMode != "host" || app.CapAdd[0] != "NET_ADMIN" {
		t.Fatalf("basic fields: %+v", app)
	}
	if len(app.Mounts) != 1 || app.Mounts[0].Type != MountTmpfs || app.Mounts[0].Target != "/run" {
		t.Fatalf("tmpfs: %+v", app.Mounts)
	}
	if app.CPULimit != 0.5 || app.MemoryLimit != 256<<20 {
		t.Fatalf("limits: cpu=%v mem=%v", app.CPULimit, app.MemoryLimit)
	}
	if app.Logging.Driver != "json-file" || app.Logging.Options["max-size"] != "5m" {
		t.Fatalf("logging: %+v", app.Logging)
	}
	if app.StopGracePeriod == nil || app.StopGracePeriod.Seconds() != 45 {
		t.Fatalf("stop grace: %v", app.StopGracePeriod)
	}
	if len(app.Ports) != 0 {
		t.Fatalf("unpublished host-mode port should be skipped: %+v", app.Ports)
	}
	if e, ok := app.Env("PASSTHROUGH"); !ok || e.HasValue {
		t.Fatalf("pass-through env: %+v", e)
	}
	if _, ok := app.Env("MISSING"); ok {
		t.Fatal("unexpected env")
	}
}

func TestMountAndPortRendering(t *testing.T) {
	mounts := []struct {
		m    Mount
		want string
	}{
		{Mount{Type: MountBind, Source: "./a", Target: "/a"}, "./a:/a"},
		{Mount{Type: MountBind, Source: "/etc", Target: "/e", ReadOnly: true}, "/etc:/e:ro"},
		{Mount{Type: MountVolume, Target: "/anon"}, "/anon"},
	}
	for _, tt := range mounts {
		if got := tt.m.String(); got != tt.want {
			t.Errorf("Mount.String() = %q, want %q", got, tt.want)
		}
	}
	ports := []struct {
		p        Port
		want     string
		exposure Exposure
	}{
		{Port{Published: "5432", Target: 5432, Protocol: "tcp"}, "5432:5432/tcp", ExposureAllInterfaces},
		{Port{Target: 6379}, "6379", ExposureAllInterfaces},
		{Port{HostIP: "0.0.0.0", Published: "80", Target: 80}, "0.0.0.0:80:80", ExposureAllInterfaces},
		{Port{HostIP: "::", Published: "80", Target: 80}, "[::]:80:80", ExposureAllInterfaces},
		{Port{HostIP: "127.0.0.1", Published: "80", Target: 80}, "127.0.0.1:80:80", ExposureLoopback},
		{Port{HostIP: "127.0.0.53", Target: 53}, "127.0.0.53::53", ExposureLoopback},
		{Port{HostIP: "::1", Published: "80", Target: 80}, "[::1]:80:80", ExposureLoopback},
		{Port{HostIP: "localhost", Published: "80", Target: 80}, "localhost:80:80", ExposureLoopback},
		{Port{HostIP: "10.1.2.3", Published: "80", Target: 80, Protocol: "udp"}, "10.1.2.3:80:80/udp", ExposureSpecificInterface},
	}
	for _, tt := range ports {
		if got := tt.p.String(); got != tt.want {
			t.Errorf("Port.String() = %q, want %q", got, tt.want)
		}
		if got := tt.p.Exposure(); got != tt.exposure {
			t.Errorf("%s exposure = %v, want %v", tt.want, got, tt.exposure)
		}
	}
	for _, e := range []Exposure{ExposureAllInterfaces, ExposureLoopback, ExposureSpecificInterface} {
		if e.String() == "" {
			t.Errorf("empty description for exposure %d", e)
		}
	}
}

func TestFindUndefaultedVariables(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"plain", ""},
		{"${A}", "A"},
		{"$A and $B_2", "A,B_2"},
		{"pre${A}post", "A"},
		{"$$A $${B}", ""},
		{"${A:-x} ${B-y} ${C:?e} ${D?e} ${E:+z} ${F+z}", ""},
		{"${A:-${B}}", "B"},
		{"${A:-${B:-c}}", ""},
		{"${A:+$B}", "B"},
		{"${HOME}/x $PWD ${COMPOSE_PROJECT_NAME}", ""},
		{"$1 $ ${", ""},
		{"${A", ""},
		{"${}", ""},
		{"${9A}", ""},
		{"trailing $", ""},
	}
	for _, tt := range tests {
		var got []string
		for _, v := range findUndefaultedVariables(tt.in) {
			got = append(got, v.Name)
		}
		if strings.Join(got, ",") != tt.want {
			t.Errorf("findUndefaultedVariables(%q) = %v, want %s", tt.in, got, tt.want)
		}
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "compose.yaml")
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}
