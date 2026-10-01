package app

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/api/types/system"
	"github.com/moby/moby/client"

	"github.com/6-SlX-6/stacksentry/internal/compose"
	"github.com/6-SlX-6/stacksentry/internal/docker"
	"github.com/6-SlX-6/stacksentry/internal/docker/dockertest"
	"github.com/6-SlX-6/stacksentry/internal/engine"
	"github.com/6-SlX-6/stacksentry/internal/findings"
	"github.com/6-SlX-6/stacksentry/internal/report"
	"github.com/6-SlX-6/stacksentry/internal/version"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata/expected and examples/reports")

var fixedTime = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func testApp(api docker.API) *App {
	return &App{
		Version: version.Info{Version: "0.1.0"},
		Now:     func() time.Time { return fixedTime },
		ConnectDocker: func(context.Context) (*docker.Connection, error) {
			if api == nil {
				return nil, &docker.UnavailableError{Endpoint: "unix:///var/run/docker.sock", Reason: "the daemon is not reachable"}
			}
			return &docker.Connection{API: api, Endpoint: "unix:///var/run/docker.sock"}, nil
		},
		GOOS: "linux",
		HostFS: fstest.MapFS{
			"proc/net/tcp": {Data: []byte("  sl  local_address rem_address   st\n   0: 00000000:0947 00000000:0000 0A 0 0 0 0 0 1 1\n")},
		},
	}
}

// repoRoot switches to the repository root so that paths in reports are
// stable and readable.
func repoRoot(t *testing.T) {
	t.Helper()
	t.Chdir(filepath.Join("..", ".."))
}

func render(t *testing.T, r *report.Report, format report.Format) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := report.Render(&buf, r, report.RenderOptions{Format: format}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func golden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/app -update to create golden files)", err)
	}
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(got, want) {
		t.Fatalf("output differs from %s (run go test ./internal/app -update after reviewing the change)\n--- got ---\n%s", path, got)
	}
}

func TestGoldenComposeReports(t *testing.T) {
	repoRoot(t)
	tests := []struct {
		input   string
		output  string
		formats []report.Format
		opts    ScanOptions
	}{
		{"testdata/compose/insecure.yaml", "testdata/expected/insecure", []report.Format{report.FormatTable, report.FormatJSON, report.FormatMarkdown}, ScanOptions{}},
		{"testdata/compose/secure.yaml", "testdata/expected/secure", []report.Format{report.FormatTable}, ScanOptions{}},
		{"testdata/compose/partial.yaml", "testdata/expected/partial-filtered", []report.Format{report.FormatTable},
			ScanOptions{MinSeverity: findings.SeverityMedium, FailOn: sev(findings.SeverityMedium), Exclude: []string{"SST-RES-003"}}},
		{"examples/insecure-compose.yaml", "examples/reports/insecure-compose", []report.Format{report.FormatTable, report.FormatJSON, report.FormatMarkdown}, ScanOptions{}},
		{"examples/n8n-postgres-compose.yaml", "examples/reports/n8n-postgres", []report.Format{report.FormatTable, report.FormatMarkdown}, ScanOptions{}},
		{"examples/reasonably-secure-compose.yaml", "examples/reports/reasonably-secure", []report.Format{report.FormatTable}, ScanOptions{}},
	}
	ext := map[report.Format]string{report.FormatTable: ".txt", report.FormatJSON: ".json", report.FormatMarkdown: ".md"}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			r, err := testApp(nil).ScanCompose(context.Background(), []string{tt.input}, tt.opts)
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range tt.formats {
				golden(t, tt.output+ext[f], render(t, r, f))
			}
		})
	}
}

func TestOutputIsDeterministic(t *testing.T) {
	repoRoot(t)
	var first []byte
	for i := 0; i < 5; i++ {
		r, err := testApp(nil).ScanCompose(context.Background(), []string{"testdata/compose/multi-service.yaml"}, ScanOptions{})
		if err != nil {
			t.Fatal(err)
		}
		out := render(t, r, report.FormatJSON)
		if first == nil {
			first = out
		} else if !bytes.Equal(first, out) {
			t.Fatal("repeated scans of the same input produced different output")
		}
	}
}

// secretValues are the fake credentials embedded in the fixtures.
var secretValues = []string{
	"correct-horse-battery-staple", "sk_live_FAKE0123456789abcdef", "url-embedded-pw-77", "default-session-secret-xyz",
	"Sup3rS3cretValue!", "tok_live_51Hx9yZq", "postgres-root-pw-42", "Winter2024!",
}

func TestSecretsNeverAppearInAnyFormat(t *testing.T) {
	repoRoot(t)
	for _, input := range []string{"testdata/compose/secrets.yaml", "testdata/compose/insecure.yaml", "examples/insecure-compose.yaml"} {
		r, err := testApp(nil).ScanCompose(context.Background(), []string{input}, ScanOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if r.Summary.BySeverity.High == 0 {
			t.Fatalf("%s: expected secret findings", input)
		}
		for _, f := range []report.Format{report.FormatTable, report.FormatJSON, report.FormatMarkdown} {
			out := string(render(t, r, f))
			for _, secret := range secretValues {
				if strings.Contains(out, secret) {
					t.Fatalf("%s (%s) leaks %q", input, f, secret)
				}
			}
			if !strings.Contains(out, "********") {
				t.Fatalf("%s (%s) should contain masked values", input, f)
			}
		}
	}
}

func TestSecretsFixtureFindings(t *testing.T) {
	repoRoot(t)
	r, err := testApp(nil).ScanCompose(context.Background(), []string{"testdata/compose/secrets.yaml"}, ScanOptions{Only: []string{"SST-SEC-011"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("findings: %+v", r.Findings)
	}
	got := strings.Join(r.Findings[0].Evidence, "\n")
	want := "DATABASE_URL=******** (URL with embedded credentials)\nDB_PASSWORD=********\nSESSION_SECRET=********\nSTRIPE_API_KEY=********"
	if got != want {
		t.Fatalf("evidence:\n%s\nwant:\n%s", got, want)
	}
}

func TestScanComposeFiltersAndSuppressions(t *testing.T) {
	repoRoot(t)
	a := testApp(nil)
	r, err := a.ScanCompose(context.Background(), []string{"testdata/compose/suppressions.yaml"}, ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Summary.Suppressed != 2 || len(r.Suppressed) != 2 {
		t.Fatalf("suppressed = %+v", r.Suppressed)
	}
	for _, f := range r.Findings {
		if f.RuleID == "SST-SEC-001" || f.RuleID == "SST-OPS-004" {
			t.Fatalf("suppressed finding reported: %+v", f)
		}
	}
	if !strings.Contains(strings.Join(r.Warnings, "\n"), "SST-NOPE-999, which is not a Compose rule") {
		t.Fatalf("unknown suppression not warned about: %v", r.Warnings)
	}

	r, err = a.ScanCompose(context.Background(), []string{"testdata/compose/insecure.yaml"},
		ScanOptions{Only: []string{"SST-SEC-001", "SST-SEC-002"}, Exclude: []string{"SST-SEC-002"}})
	if err != nil {
		t.Fatal(err)
	}
	if r.Scan.RulesEvaluated != 1 || len(r.SkippedRules) != 26 || r.Summary.Total != 1 || r.Findings[0].RuleID != "SST-SEC-001" {
		t.Fatalf("only/exclude: evaluated=%d skipped=%d findings=%+v", r.Scan.RulesEvaluated, len(r.SkippedRules), r.Findings)
	}
}

func TestScanComposeErrors(t *testing.T) {
	repoRoot(t)
	a := testApp(nil)
	_, err := a.ScanCompose(context.Background(), []string{"testdata/compose/invalid-yaml.yaml"}, ScanOptions{})
	var le *compose.LoadError
	if !errors.As(err, &le) || le.Kind != compose.ErrInvalidYAML {
		t.Fatalf("expected invalid YAML error, got %v", err)
	}
	_, err = a.ScanCompose(context.Background(), []string{"testdata/compose/insecure.yaml"}, ScanOptions{Only: []string{"SST-SEC-0O1"}})
	var se *SelectionError
	if !errors.As(err, &se) || !strings.Contains(err.Error(), "did you mean SST-SEC-001") {
		t.Fatalf("expected selection error with suggestion, got %v", err)
	}
}

func TestValidateSelection(t *testing.T) {
	tests := []struct {
		name     string
		scope    engine.Scope
		opts     ScanOptions
		wantErr  string
		wantWarn string
	}{
		{"empty", engine.ScopeCompose, ScanOptions{}, "", ""},
		{"valid only", engine.ScopeCompose, ScanOptions{Only: []string{"SST-SEC-001"}}, "", ""},
		{"unknown", engine.ScopeCompose, ScanOptions{Exclude: []string{"SST-FOO-001"}}, "unknown rule ID SST-FOO-001", ""},
		{"unknown deduplicated", engine.ScopeHost, ScanOptions{Only: []string{"SST-X-1"}, Exclude: []string{"SST-X-1"}}, "unknown rule ID SST-X-1;", ""},
		{"only from other scope", engine.ScopeCompose, ScanOptions{Only: []string{"SST-HOST-003"}}, "none of the rules given with --only apply to compose scans", ""},
		{"mixed only", engine.ScopeHost, ScanOptions{Only: []string{"SST-HOST-003", "SST-SEC-001"}}, "", "--only SST-SEC-001 ignored: it is a compose rule"},
		{"exclude from other scope", engine.ScopeHost, ScanOptions{Exclude: []string{"SST-SEC-001"}}, "", "--exclude SST-SEC-001 ignored"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings, err := validateSelection(tt.scope, tt.opts)
			if (tt.wantErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
			joined := strings.Join(warnings, "\n")
			if (tt.wantWarn == "") != (joined == "") || !strings.Contains(joined, tt.wantWarn) {
				t.Fatalf("warnings = %q, want %q", joined, tt.wantWarn)
			}
		})
	}
	if levenshtein("kitten", "sitting") != 3 || levenshtein("", "abc") != 3 {
		t.Fatal("levenshtein is wrong")
	}
}

func TestRulesCatalog(t *testing.T) {
	all := Rules()
	if len(all) != 37 {
		t.Fatalf("expected 37 rules, got %d", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].ID >= all[i].ID {
			t.Fatalf("rules not sorted: %s >= %s", all[i-1].ID, all[i].ID)
		}
	}
	if m, ok := Rule(" sst-host-002 "); !ok || m.Scope != engine.ScopeHost {
		t.Fatalf("Rule lookup failed: %+v", m)
	}
	if _, ok := Rule("SST-NOPE-001"); ok {
		t.Fatal("unexpected rule")
	}
}

func hostFake() *dockertest.Fake {
	return &dockertest.Fake{
		Version:    client.ServerVersionResult{Version: "27.3.1", APIVersion: "1.47", Os: "linux", Arch: "amd64"},
		SystemInfo: system.Info{Name: "docker-01", OperatingSystem: "Ubuntu 24.04.1 LTS", Images: 4},
		Containers: []container.Summary{
			{ID: "1111111111111111", Names: []string{"/traefik"}, Image: "traefik:v3.1.6", State: container.StateRunning},
			{ID: "2222222222222222", Names: []string{"/watchtower"}, Image: "containrrr/watchtower", State: container.StateRunning},
			{ID: "3333333333333333", Names: []string{"/old-backup"}, Image: "alpine:3.20", State: container.StateExited},
		},
		Inspect: map[string]container.InspectResponse{
			"1111111111111111": {Config: &container.Config{Image: "traefik:v3.1.6"}, HostConfig: &container.HostConfig{
				RestartPolicy: container.RestartPolicy{Name: container.RestartPolicyUnlessStopped}},
				Mounts: []container.MountPoint{{Type: "bind", Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock"}}},
			"2222222222222222": {Config: &container.Config{Image: "containrrr/watchtower"}, HostConfig: &container.HostConfig{
				Privileged: true, NetworkMode: "host"},
				Mounts: []container.MountPoint{{Type: "bind", Source: "/var/run/docker.sock", Destination: "/var/run/docker.sock", RW: true}}},
		},
		Images: []image.Summary{{ID: "sha256:abc", Size: 300 << 20}},
		Usage: client.DiskUsageResult{
			Images:     client.ImagesDiskUsage{TotalCount: 4, TotalSize: 30 << 30, Reclaimable: 24 << 30},
			BuildCache: client.BuildCacheDiskUsage{TotalSize: 2 << 30, Reclaimable: 2 << 30},
		},
	}
}

func TestGoldenHostReport(t *testing.T) {
	api := hostFake()
	r, err := testApp(api).ScanHost(context.Background(), ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !api.Closed {
		t.Fatal("Docker client was not closed")
	}
	if r.Target.Host.ContainersTotal != 3 || r.Target.Host.ContainersRunning != 2 || r.Target.Host.ServerVersion != "27.3.1" {
		t.Fatalf("host target: %+v", r.Target.Host)
	}
	repoRoot(t)
	golden(t, "testdata/expected/host.txt", render(t, r, report.FormatTable))
	golden(t, "testdata/expected/host.json", render(t, r, report.FormatJSON))
}

func TestScanHostUnavailable(t *testing.T) {
	_, err := testApp(nil).ScanHost(context.Background(), ScanOptions{})
	var ue *docker.UnavailableError
	if !errors.As(err, &ue) {
		t.Fatalf("expected UnavailableError, got %v", err)
	}
	_, err = testApp(hostFake()).ScanHost(context.Background(), ScanOptions{Only: []string{"SST-SEC-001"}})
	var se *SelectionError
	if !errors.As(err, &se) {
		t.Fatalf("expected selection error before connecting, got %v", err)
	}
}

func TestNewDefaults(t *testing.T) {
	a := New()
	if a.Version.Version == "" || a.Now == nil || a.ConnectDocker == nil || a.GOOS == "" {
		t.Fatalf("incomplete defaults: %+v", a)
	}
}

func sev(s findings.Severity) *findings.Severity { return &s }
