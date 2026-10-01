package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"

	"github.com/6-SlX-6/stacksentry/internal/app"
	"github.com/6-SlX-6/stacksentry/internal/docker"
	"github.com/6-SlX-6/stacksentry/internal/docker/dockertest"
	"github.com/6-SlX-6/stacksentry/internal/version"
)

const (
	insecure = "../../testdata/compose/insecure.yaml"
	secure   = "../../testdata/compose/secure.yaml"
)

type result struct {
	code   int
	stdout string
	stderr string
}

func testApp(api docker.API) *app.App {
	return &app.App{
		Version: version.Info{Version: "0.1.0", GoVersion: "go1.26.0", Platform: "linux/amd64"},
		Now:     func() time.Time { return time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC) },
		ConnectDocker: func(ctx context.Context) (*docker.Connection, error) {
			if api == nil {
				return docker.Connect(ctx)
			}
			return &docker.Connection{API: api, Endpoint: "unix:///var/run/docker.sock"}, nil
		},
		GOOS: "darwin",
	}
}

func run(t *testing.T, a *app.App, terminal bool, args ...string) result {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Execute(context.Background(), args, a, Streams{
		Out: &out, Err: &errOut, IsTerminal: func(io.Writer) bool { return terminal },
	})
	return result{code: code, stdout: out.String(), stderr: errOut.String()}
}

func TestExitCodes(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{"no args shows help", nil, ExitOK, "Usage:", ""},
		{"version", []string{"version"}, ExitOK, "stacksentry v0.1.0 (go1.26.0, linux/amd64)", ""},
		{"version flag", []string{"--version"}, ExitOK, "stacksentry v0.1.0", ""},
		{"scan help", []string{"scan"}, ExitOK, "compose", ""},
		{"findings without fail-on", []string{"scan", "compose", insecure}, ExitOK, "CRITICAL  SST-SEC-001", ""},
		{"fail-on high", []string{"scan", "compose", insecure, "--fail-on", "high"}, ExitFindings, "Result: FAIL", ""},
		{"fail-on none", []string{"scan", "compose", insecure, "--fail-on", "none"}, ExitOK, "", ""},
		{"fail-on passes", []string{"scan", "compose", secure, "--fail-on", "low"}, ExitOK, "Result: PASS", ""},
		{"fail-on counts hidden findings", []string{"scan", "compose", insecure, "--severity", "critical", "--fail-on", "medium"}, ExitFindings, "below \"critical\" not shown", ""},
		{"only narrows fail-on", []string{"scan", "compose", insecure, "--only", "SST-OPS-004", "--fail-on", "medium"}, ExitOK, "LOW  SST-OPS-004", ""},
		{"missing file", []string{"scan", "compose", "nope.yaml"}, ExitError, "", `compose file "nope.yaml" not found`},
		{"invalid yaml", []string{"scan", "compose", "../../testdata/compose/invalid-yaml.yaml"}, ExitError, "", "invalid YAML"},
		{"unsupported structure", []string{"scan", "compose", "../../testdata/compose/services-list.yaml"}, ExitError, "", "unsupported Compose structure"},
		{"no path", []string{"scan", "compose"}, ExitError, "", "requires at least 1 arg"},
		{"invalid format", []string{"scan", "compose", insecure, "--format", "xml"}, ExitError, "", "invalid format"},
		{"invalid severity", []string{"scan", "compose", insecure, "--severity", "urgent"}, ExitError, "", "--severity: invalid severity"},
		{"invalid fail-on", []string{"scan", "compose", insecure, "--fail-on", "urgent"}, ExitError, "", "--fail-on: invalid severity"},
		{"empty output name", []string{"scan", "compose", insecure, "--output", " "}, ExitError, "", "--output: file name is empty"},
		{"unknown rule", []string{"scan", "compose", insecure, "--exclude", "SST-SEC-0001"}, ExitError, "", "unknown rule ID SST-SEC-0001"},
		{"unknown flag", []string{"scan", "compose", insecure, "--bogus"}, ExitError, "", "unknown flag: --bogus"},
		{"unknown command", []string{"bogus"}, ExitError, "", "unknown command"},
		{"host scan unavailable", []string{"scan", "host"}, ExitError, "", "cannot use the Docker daemon at tcp://127.0.0.1:1"},
		{"host only from compose scope", []string{"scan", "host", "--only", "SST-SEC-001"}, ExitError, "", "none of the rules given with --only apply to host scans"},
	}
	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:1")
	t.Setenv("DOCKER_CERT_PATH", "")
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := run(t, testApp(nil), false, tt.args...)
			if r.code != tt.code {
				t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", r.code, tt.code, r.stdout, r.stderr)
			}
			if !strings.Contains(r.stdout, tt.stdout) {
				t.Errorf("stdout does not contain %q:\n%s", tt.stdout, r.stdout)
			}
			if !strings.Contains(r.stderr, tt.stderr) {
				t.Errorf("stderr does not contain %q:\n%s", tt.stderr, r.stderr)
			}
			if tt.code == ExitError && !strings.HasPrefix(r.stderr, "Error: ") {
				t.Errorf("errors must be reported on stderr with an Error: prefix, got %q", r.stderr)
			}
		})
	}
}

func TestUsageHint(t *testing.T) {
	r := run(t, testApp(nil), false, "scan", "compose", insecure, "--format", "xml")
	if !strings.Contains(r.stderr, "Run 'stacksentry scan compose --help' for usage.") {
		t.Fatalf("missing usage hint: %q", r.stderr)
	}
	r = run(t, testApp(nil), false, "scan", "compose", "nope.yaml")
	if strings.Contains(r.stderr, "--help") {
		t.Fatalf("non-usage errors should not print a usage hint: %q", r.stderr)
	}
}

func TestSpecExamples(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		args []string
		code int
	}{
		{[]string{"scan", "compose", insecure}, ExitOK},
		{[]string{"scan", "compose", secure, "--format", "markdown", "--output", filepath.Join(dir, "report.md")}, ExitOK},
		{[]string{"scan", "compose", insecure, "--fail-on", "high"}, ExitFindings},
		{[]string{"scan", "compose", insecure, "--exclude", "SST-SEC-001,SST-OPS-003"}, ExitOK},
		{[]string{"rules", "list"}, ExitOK},
		{[]string{"rules", "show", "SST-SEC-001"}, ExitOK},
		{[]string{"scan", "host", "--format", "json", "--output", filepath.Join(dir, "stacksentry-host-report.json")}, ExitOK},
		{[]string{"completion", "bash"}, ExitOK},
		{[]string{"completion", "zsh"}, ExitOK},
		{[]string{"completion", "fish"}, ExitOK},
		{[]string{"completion", "powershell"}, ExitOK},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			r := run(t, testApp(&dockertest.Fake{}), false, tt.args...)
			if r.code != tt.code {
				t.Fatalf("exit code = %d, want %d: %s", r.code, tt.code, r.stderr)
			}
		})
	}
	data, err := os.ReadFile(filepath.Join(dir, "stacksentry-host-report.json"))
	if err != nil || !json.Valid(data) {
		t.Fatalf("host JSON report invalid: %v", err)
	}
}

func TestExcludeRemovesFindings(t *testing.T) {
	r := run(t, testApp(nil), false, "scan", "compose", insecure, "--exclude", "SST-SEC-001", "--exclude", "sst-ops-003")
	if strings.Contains(r.stdout, "  SST-SEC-001  ") || strings.Contains(r.stdout, "  SST-OPS-003  ") {
		t.Fatalf("excluded rules still reported:\n%s", r.stdout)
	}
	if !strings.Contains(r.stdout, "2 rules not evaluated (--only/--exclude): SST-OPS-003, SST-SEC-001.") {
		t.Fatalf("skipped rules not listed:\n%s", r.stdout)
	}
}

func TestOutputFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	r := run(t, testApp(nil), true, "scan", "compose", insecure, "--format", "json", "--output", path, "--fail-on", "critical")
	if r.code != ExitFindings || r.stdout != "" {
		t.Fatalf("code=%d stdout=%q", r.code, r.stdout)
	}
	if !strings.Contains(r.stderr, "Report written to "+path+" (42 findings, result: FAIL)") {
		t.Fatalf("stderr = %q", r.stderr)
	}
	data, _ := os.ReadFile(path)
	if !json.Valid(data) || strings.Contains(string(data), "\x1b[") {
		t.Fatal("output file must contain plain, valid JSON")
	}

	quiet := run(t, testApp(nil), false, "scan", "compose", insecure, "-o", filepath.Join(dir, "r.txt"), "-q")
	if quiet.code != ExitOK || quiet.stderr != "" || quiet.stdout != "" {
		t.Fatalf("quiet output should print nothing: %+v", quiet)
	}
	bad := run(t, testApp(nil), false, "scan", "compose", insecure, "-o", filepath.Join(dir, "missing", "r.txt"))
	if bad.code != ExitError || !strings.Contains(bad.stderr, "cannot write report") {
		t.Fatalf("unwritable output: %+v", bad)
	}
}

func TestColor(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	colored := run(t, testApp(nil), true, "scan", "compose", insecure)
	if !strings.Contains(colored.stdout, "\x1b[") {
		t.Fatal("expected ANSI colors on a terminal")
	}
	for _, args := range [][]string{
		{"scan", "compose", insecure, "--no-color"},
		{"scan", "compose", insecure, "--format", "markdown"},
		{"scan", "compose", insecure, "--format", "json"},
	} {
		if r := run(t, testApp(nil), true, args...); strings.Contains(r.stdout, "\x1b[") {
			t.Fatalf("%v must not produce ANSI codes", args)
		}
	}
	if r := run(t, testApp(nil), false, "scan", "compose", insecure); strings.Contains(r.stdout, "\x1b[") {
		t.Fatal("no colors expected when stdout is not a terminal")
	}
	t.Setenv("NO_COLOR", "1")
	if r := run(t, testApp(nil), true, "scan", "compose", insecure); strings.Contains(r.stdout, "\x1b[") {
		t.Fatal("NO_COLOR must disable colors")
	}
}

func TestJSONOnStdout(t *testing.T) {
	r := run(t, testApp(nil), false, "scan", "compose", insecure, "--format", "json", "--severity", "high")
	var decoded struct {
		Findings []struct {
			Severity string `json:"severity"`
		} `json:"findings"`
		Summary struct {
			Hidden int `json:"hidden_below_min_severity"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if decoded.Summary.Hidden == 0 {
		t.Fatal("expected hidden findings")
	}
	for _, f := range decoded.Findings {
		if f.Severity != "high" && f.Severity != "critical" {
			t.Fatalf("--severity high leaked a %s finding", f.Severity)
		}
	}
}

func TestHostScanWithFake(t *testing.T) {
	fake := &dockertest.Fake{
		Version: client.ServerVersionResult{Version: "27.3.1", APIVersion: "1.47"},
		Containers: []container.Summary{
			{ID: "abc", Names: []string{"/vpn"}, Image: "vpn:1.0", State: container.StateRunning},
		},
		Inspect: map[string]container.InspectResponse{
			"abc": {HostConfig: &container.HostConfig{Privileged: true, RestartPolicy: container.RestartPolicy{Name: "always"}}},
		},
	}
	r := run(t, testApp(fake), false, "scan", "host", "--fail-on", "critical")
	if r.code != ExitFindings || !strings.Contains(r.stdout, "CRITICAL  SST-HOST-003  vpn") {
		t.Fatalf("code=%d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stdout, "only inspected on Linux") {
		t.Fatalf("limitations missing:\n%s", r.stdout)
	}
	r = run(t, testApp(fake), false, "scan", "host", "--exclude", "SST-HOST-003", "--fail-on", "critical")
	if r.code != ExitOK {
		t.Fatalf("excluded rule should not fail: %d\n%s", r.code, r.stdout)
	}
}

func TestRulesCommands(t *testing.T) {
	tests := []struct {
		name string
		args []string
		code int
		want []string
	}{
		{"list", []string{"rules", "list"}, ExitOK, []string{"ID", "SST-SEC-001", "SST-HOST-010", "37 rules."}},
		{"list compose", []string{"rules", "list", "--scope", "compose"}, ExitOK, []string{"27 rules."}},
		{"list host", []string{"rules", "list", "--scope", "HOST"}, ExitOK, []string{"10 rules."}},
		{"list markdown", []string{"rules", "list", "-f", "markdown"}, ExitOK, []string{"| [SST-SEC-001](#sst-sec-001) | critical | security | compose | Docker socket mount detected |"}},
		{"show", []string{"rules", "show", "sst-net-001"}, ExitOK, []string{"SST-NET-001: Publicly published database port", "Default severity: high", "Detection:", "Limitations and false positives:", "References:"}},
		{"show markdown", []string{"rules", "show", "SST-HOST-002", "--format", "markdown"}, ExitOK, []string{"### SST-HOST-002", "- **Detection:**"}},
		{"show unknown", []string{"rules", "show", "SST-XXX-001"}, ExitError, nil},
		{"show without id", []string{"rules", "show"}, ExitError, nil},
		{"list bad scope", []string{"rules", "list", "--scope", "cloud"}, ExitError, nil},
		{"list bad format", []string{"rules", "list", "--format", "xml"}, ExitError, nil},
		{"show bad format", []string{"rules", "show", "SST-SEC-001", "--format", "xml"}, ExitError, nil},
		{"rules help", []string{"rules"}, ExitOK, []string{"list", "show"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := run(t, testApp(nil), false, tt.args...)
			if r.code != tt.code {
				t.Fatalf("exit code %d, want %d: %s", r.code, tt.code, r.stderr)
			}
			for _, w := range tt.want {
				if !strings.Contains(r.stdout, w) {
					t.Errorf("output missing %q:\n%s", w, r.stdout)
				}
			}
		})
	}

	r := run(t, testApp(nil), false, "rules", "list", "--format", "json")
	var list []ruleJSON
	if err := json.Unmarshal([]byte(r.stdout), &list); err != nil || len(list) != 37 {
		t.Fatalf("rules JSON: %v (%d rules)", err, len(list))
	}
	r = run(t, testApp(nil), false, "rules", "show", "SST-SEC-011", "--format", "json")
	var one ruleJSON
	if err := json.Unmarshal([]byte(r.stdout), &one); err != nil || one.ID != "SST-SEC-011" || one.Category != "secrets" || len(one.References) == 0 {
		t.Fatalf("rule JSON: %v %+v", err, one)
	}
}

func TestVersionJSON(t *testing.T) {
	r := run(t, testApp(nil), false, "version", "--json")
	var v version.Info
	if err := json.Unmarshal([]byte(r.stdout), &v); err != nil || v.Version != "0.1.0" {
		t.Fatalf("version JSON: %v %q", err, r.stdout)
	}
}

func TestDefaultStreams(t *testing.T) {
	s := DefaultStreams()
	if s.Out != os.Stdout || s.Err != os.Stderr || s.IsTerminal == nil {
		t.Fatal("unexpected default streams")
	}
	if isTerminalFile(&bytes.Buffer{}) {
		t.Fatal("a buffer is not a terminal")
	}
	f, err := os.CreateTemp(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if s.IsTerminal(f) {
		t.Fatal("a regular file is not a terminal")
	}
	if code := Execute(context.Background(), []string{"version"}, testApp(nil), Streams{Out: io.Discard, Err: io.Discard}); code != ExitOK {
		t.Fatal("Execute without IsTerminal should work")
	}
}

func TestWrapText(t *testing.T) {
	got := wrapText("one two three four", "  ", 12)
	if strings.Join(got, "|") != "  one two|  three four" {
		t.Fatalf("wrapText = %q", got)
	}
	if len(wrapText("", "  ", 10)) != 0 {
		t.Fatal("empty input should produce no lines")
	}
}
