package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/6-SlX-6/stacksentry/internal/engine"
	"github.com/6-SlX-6/stacksentry/internal/findings"
)

var fixedTime = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func finding(id string, sev findings.Severity, target string, evidence ...string) findings.Finding {
	return findings.Finding{
		ID: findings.Fingerprint(id, findings.TargetService, target, evidence), RuleID: id, RuleVersion: "1.0",
		Title: "Title of " + id, Category: findings.CategorySecurity, Severity: sev, Confidence: findings.ConfidenceHigh,
		TargetType: findings.TargetService, TargetName: target, Location: &findings.Location{File: "compose.yaml", Line: 3},
		Description: "Description of " + id + ".", Evidence: evidence, WhyItMatters: "Because it matters.",
		Remediation: "Do the right thing.", Documentation: engine.DocsBaseURL + "#" + strings.ToLower(id),
		References: []string{"https://docs.docker.com/"}, Timestamp: fixedTime, ScannerVersion: "0.1.0",
	}
}

func sev(s findings.Severity) *findings.Severity { return &s }

func sampleInput() Input {
	return Input{
		Scanner:    Scanner{Name: "stacksentry", Version: "0.1.0"},
		ScanType:   ScanCompose,
		StartedAt:  fixedTime,
		FinishedAt: fixedTime.Add(1500 * time.Millisecond),
		RulesTotal: 27,
		Result: engine.Result{
			Findings: []findings.Finding{
				finding("SST-SEC-009", findings.SeverityLow, "web", "read_only is not set"),
				finding("SST-SEC-001", findings.SeverityCritical, "proxy", "/var/run/docker.sock:/var/run/docker.sock"),
				finding("SST-OPS-001", findings.SeverityMedium, "web", "healthcheck is not defined"),
				finding("SST-OPS-007", findings.SeverityInfo, "web", "stop_grace_period is not set"),
				finding("SST-NET-001", findings.SeverityHigh, "db", "5432:5432/tcp", "second | line with `ticks`"),
			},
			Suppressed: []engine.SuppressedFinding{{Finding: finding("SST-OPS-004", findings.SeverityLow, "proxy", "container_name: proxy"), SuppressionReason: "fixed name required by monitoring"}},
			Evaluated:  []string{"SST-SEC-001", "SST-SEC-009", "SST-OPS-001", "SST-OPS-004", "SST-OPS-007", "SST-NET-001"},
			Errors:     []engine.RuleError{{RuleID: "SST-RES-001", Message: "internal error: boom"}},
		},
		SkippedRules: []engine.SkippedRule{{RuleID: "SST-SEC-002", Title: "Privileged container detected", Reason: engine.ReasonExcluded}},
		Target: Target{Type: ScanCompose, Name: "compose.yaml", Compose: &ComposeTarget{
			Files: []string{"compose.yaml"}, ProjectName: "demo", ServiceCount: 3, Services: []string{"db", "proxy", "web"}}},
		Limitations: []string{"compose.yaml uses \"include\"; included files are not analyzed in this version."},
		Warnings:    []string{"compose.yaml: the top-level \"version\" attribute is obsolete."},
		MinSeverity: findings.SeverityInfo,
		Exclude:     []string{"SST-SEC-002"},
	}
}

func TestParseFormat(t *testing.T) {
	tests := []struct {
		in   string
		want Format
	}{{"table", FormatTable}, {"JSON", FormatJSON}, {" markdown ", FormatMarkdown}, {"md", FormatMarkdown}}
	for _, tt := range tests {
		got, err := ParseFormat(tt.in)
		if err != nil || got != tt.want {
			t.Errorf("ParseFormat(%q) = %q, %v", tt.in, got, err)
		}
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Fatal("expected error for xml")
	}
}

func TestBuildSummaryAndFiltering(t *testing.T) {
	tests := []struct {
		name        string
		min         findings.Severity
		failOn      *findings.Severity
		displayed   int
		hidden      int
		atOrAbove   int
		result      string
		firstRuleID string
	}{
		{"defaults", findings.SeverityUnknown, nil, 5, 0, 0, ResultNoThreshold, "SST-SEC-001"},
		{"fail on high", findings.SeverityInfo, sev(findings.SeverityHigh), 5, 0, 2, ResultFail, "SST-SEC-001"},
		{"fail on critical passes when filtered", findings.SeverityCritical, sev(findings.SeverityCritical), 1, 4, 1, ResultFail, "SST-SEC-001"},
		{"hidden findings still count for fail-on", findings.SeverityCritical, sev(findings.SeverityMedium), 1, 4, 3, ResultFail, "SST-SEC-001"},
		{"critical threshold with medium display", findings.SeverityMedium, sev(findings.SeverityCritical), 3, 2, 1, ResultFail, "SST-SEC-001"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := sampleInput()
			in.MinSeverity, in.FailOn = tt.min, tt.failOn
			r := Build(in)
			if r.Summary.Total != 5 || r.Summary.Displayed != tt.displayed || r.Summary.HiddenBelowMinSeverity != tt.hidden ||
				r.Summary.AtOrAboveFailOn != tt.atOrAbove || r.Summary.Result != tt.result || r.Summary.Suppressed != 1 {
				t.Fatalf("summary = %+v", r.Summary)
			}
			if len(r.Findings) != tt.displayed || r.Findings[0].RuleID != tt.firstRuleID {
				t.Fatalf("findings = %+v", r.Findings)
			}
			if r.Failed() != (tt.result == ResultFail) {
				t.Fatal("Failed() mismatch")
			}
		})
	}
	in := sampleInput()
	in.Result.Findings = in.Result.Findings[:1] // only the low finding
	in.FailOn = sev(findings.SeverityHigh)
	if r := Build(in); r.Summary.Result != ResultPass || r.Failed() {
		t.Fatalf("expected pass, got %+v", r.Summary)
	}
}

func TestBuildMetadata(t *testing.T) {
	r := Build(sampleInput())
	if r.SchemaVersion != SchemaVersion || r.Scan.RulesEvaluated != 6 || r.Scan.RulesTotal != 27 {
		t.Fatalf("scan metadata: %+v", r.Scan)
	}
	if r.Scan.FinishedAt.Sub(r.Scan.StartedAt) != time.Second {
		t.Fatalf("timestamps should be truncated to seconds: %v %v", r.Scan.StartedAt, r.Scan.FinishedAt)
	}
	if len(r.Warnings) != 2 || !strings.Contains(r.Warnings[1], "SST-RES-001 failed") {
		t.Fatalf("rule errors should become warnings: %v", r.Warnings)
	}
	order := []string{}
	for _, f := range r.Findings {
		order = append(order, f.RuleID)
	}
	if strings.Join(order, ",") != "SST-SEC-001,SST-NET-001,SST-OPS-001,SST-SEC-009,SST-OPS-007" {
		t.Fatalf("findings not sorted by severity then rule: %v", order)
	}
	empty := Build(Input{})
	if empty.Findings == nil || empty.Suppressed == nil || empty.SkippedRules == nil || empty.Limitations == nil || empty.Warnings == nil ||
		empty.Scan.Options.Only == nil || empty.Scan.Options.Exclude == nil {
		t.Fatal("slices must be non-nil so that JSON contains [] rather than null")
	}
}

func TestRedact(t *testing.T) {
	in := sampleInput()
	in.Result.Findings[0].Evidence = []string{"PASSWORD=hunter2-secret", "url postgres://u:hunter2-secret@db"}
	in.Result.Findings[0].Description = "mentions hunter2-secret"
	in.Result.Suppressed[0].SuppressionReason = "hunter2-secret"
	in.Warnings = []string{"warning hunter2-secret"}
	in.Limitations = []string{"limitation hunter2-secret"}
	original := in.Result.Findings[0].Evidence[0]
	r := Build(in)
	Redact(r, []string{"hunter2-secret", ""}, "****")
	Redact(r, nil, "****")
	var buf bytes.Buffer
	if err := RenderJSON(&buf, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "hunter2") {
		t.Fatalf("secret survived redaction:\n%s", buf.String())
	}
	if in.Result.Findings[0].Evidence[0] != original {
		t.Fatal("Redact must not modify the caller's evidence slices")
	}
}

func TestRenderTableNoColor(t *testing.T) {
	in := sampleInput()
	in.FailOn = sev(findings.SeverityHigh)
	var buf bytes.Buffer
	if err := RenderTable(&buf, Build(in), TableOptions{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "\x1b[") {
		t.Fatal("no ANSI escape codes expected without color")
	}
	for _, want := range []string{
		"StackSentry v0.1.0",
		"Target: compose.yaml (project \"demo\")",
		"Scan time: 2026-10-01T12:00:00Z",
		"Rules evaluated: 6 of 27",
		"Services analyzed: 3",
		"Findings: 1 critical, 1 high, 1 medium, 1 low, 1 info",
		"CRITICAL  SST-SEC-001  proxy  (compose.yaml:3)",
		"  Evidence: 5432:5432/tcp\n            second | line with `ticks`",
		"  Why this matters: Because it matters.",
		"  Fix: Do the right thing.",
		"Notes:",
		"1 finding suppressed by documented x-stacksentry exceptions.",
		"1 rule not evaluated (--only/--exclude): SST-SEC-002.",
		"Limitation: compose.yaml uses",
		"Warning: rule SST-RES-001 failed",
		"Result: FAIL: 2 findings at or above \"high\" (--fail-on high)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("table output missing %q\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if len(line) > DefaultWidth+20 {
			t.Errorf("line too long (%d): %s", len(line), line)
		}
	}
}

func TestRenderTableColorAndQuiet(t *testing.T) {
	var color bytes.Buffer
	if err := RenderTable(&color, Build(sampleInput()), TableOptions{Color: true}); err != nil {
		t.Fatal(err)
	}
	for sev, code := range severityColors {
		if !strings.Contains(color.String(), code+sev.Label()+ansiReset) {
			t.Errorf("missing color for %s", sev)
		}
	}

	var quiet bytes.Buffer
	if err := RenderTable(&quiet, Build(sampleInput()), TableOptions{Quiet: true}); err != nil {
		t.Fatal(err)
	}
	q := quiet.String()
	if strings.Contains(q, "StackSentry v") || strings.Contains(q, "Notes:") || !strings.HasPrefix(q, "CRITICAL  SST-SEC-001") {
		t.Fatalf("quiet output should only contain findings:\n%s", q)
	}

	var none bytes.Buffer
	if err := RenderTable(&none, Build(Input{Scanner: Scanner{Version: "0.1.0"}, Target: Target{Name: "x"}}), TableOptions{Quiet: true}); err != nil || none.Len() != 0 {
		t.Fatalf("quiet output without findings should be empty, got %q", none.String())
	}
}

func TestRenderTableEmptyStates(t *testing.T) {
	var buf bytes.Buffer
	in := sampleInput()
	in.Result.Findings = nil
	in.FailOn = sev(findings.SeverityLow)
	_ = RenderTable(&buf, Build(in), TableOptions{})
	if !strings.Contains(buf.String(), "No findings.") || !strings.Contains(buf.String(), "Result: PASS") {
		t.Fatalf("empty report:\n%s", buf.String())
	}
	buf.Reset()
	in = sampleInput()
	in.MinSeverity = findings.SeverityCritical
	in.Result.Findings = in.Result.Findings[:1]
	_ = RenderTable(&buf, Build(in), TableOptions{})
	if !strings.Contains(buf.String(), "No findings at or above the selected severity.") ||
		!strings.Contains(buf.String(), "1 finding below \"critical\" not shown") {
		t.Fatalf("filtered report:\n%s", buf.String())
	}
}

func TestRenderTableHostTarget(t *testing.T) {
	in := sampleInput()
	in.ScanType = ScanHost
	in.Target = Target{Type: ScanHost, Name: "unix:///var/run/docker.sock", Host: &HostTarget{
		Endpoint: "unix:///var/run/docker.sock", ServerVersion: "27.3.1", APIVersion: "1.47", ContainersTotal: 5, ContainersRunning: 3}}
	var buf bytes.Buffer
	_ = RenderTable(&buf, Build(in), TableOptions{})
	for _, want := range []string{"Target: Docker daemon at unix:///var/run/docker.sock (Docker 27.3.1, API 1.47)", "Containers analyzed: 5 (3 running)"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
	buf.Reset()
	_ = RenderMarkdown(&buf, Build(in))
	for _, want := range []string{"| Docker endpoint | `unix:///var/run/docker.sock` |", "| Containers analyzed | 5 (3 running) |", "Docker host (local daemon inspection)"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}

func TestWrap(t *testing.T) {
	got := wrap("aaa bbb ccc dddddddddddddddddddd", "> ", "  ", 10)
	want := []string{"> aaa bbb", "  ccc", "  dddddddddddddddddddd"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("wrap = %q", got)
	}
	if got := wrap("", "Label: ", "", 10); len(got) != 1 || got[0] != "Label:" {
		t.Fatalf("empty wrap = %q", got)
	}
}

func TestRenderJSONMatchesSchema(t *testing.T) {
	for _, mutate := range []func(*Input){
		func(*Input) {},
		func(in *Input) { in.FailOn = sev(findings.SeverityHigh) },
		func(in *Input) {
			in.ScanType = ScanHost
			in.Target = Target{Type: ScanHost, Name: "unix:///var/run/docker.sock", Host: &HostTarget{Endpoint: "unix:///var/run/docker.sock"}}
		},
		func(in *Input) { in.Result = engine.Result{} },
	} {
		in := sampleInput()
		mutate(&in)
		var buf bytes.Buffer
		if err := RenderJSON(&buf, Build(in)); err != nil {
			t.Fatal(err)
		}
		validateAgainstSchema(t, buf.Bytes())
		if strings.Contains(buf.String(), "\x1b[") {
			t.Fatal("JSON must not contain color codes")
		}
		if !strings.HasSuffix(buf.String(), "}\n") {
			t.Fatal("JSON output should end with a newline")
		}
	}
}

func validateAgainstSchema(t *testing.T, data []byte) {
	t.Helper()
	schemaFile, err := os.Open(filepath.Join("..", "..", "docs", "report.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer schemaFile.Close()
	doc, err := jsonschema.UnmarshalJSON(schemaFile)
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("report.schema.json", doc); err != nil {
		t.Fatal(err)
	}
	schema, err := c.Compile("report.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if err := schema.Validate(inst); err != nil {
		t.Fatalf("report does not match schema: %v\n%s", err, data)
	}
}

func TestRenderJSONFields(t *testing.T) {
	var buf bytes.Buffer
	in := sampleInput()
	in.FailOn = sev(findings.SeverityHigh)
	if err := RenderJSON(&buf, Build(in)); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	summary := decoded["summary"].(map[string]any)
	if summary["result"] != "fail" || summary["fail_on"] != "high" {
		t.Fatalf("summary = %v", summary)
	}
	f := decoded["findings"].([]any)[0].(map[string]any)
	if f["severity"] != "critical" || f["timestamp"] != "2026-10-01T12:00:00Z" || f["target_type"] != "service" {
		t.Fatalf("finding = %v", f)
	}
}

func TestRenderMarkdownSections(t *testing.T) {
	in := sampleInput()
	in.FailOn = sev(findings.SeverityCritical)
	var buf bytes.Buffer
	if err := RenderMarkdown(&buf, Build(in)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	sections := []string{
		"# StackSentry Scan Report", "## Scan Summary", "## Target", "## Finding Statistics", "## Findings by Severity",
		"## Detailed Findings", "## Scan Limitations", "## Remediation Priorities", "## Generated By",
	}
	last := -1
	for _, s := range sections {
		idx := strings.Index(out, s+"\n")
		if idx < 0 || idx < last {
			t.Fatalf("section %q missing or out of order", s)
		}
		last = idx
	}
	for _, want := range []string{
		"| Result | **FAIL** (1 at or above threshold) |",
		"| Compose files | `compose.yaml` |",
		"| Critical | 1 | 1 |",
		"| **Total** | **5** | **5** |",
		"### Critical (1)",
		"| 1 | SST-SEC-001 | `proxy` | Title of SST-SEC-001 |",
		"- **Rule ID:** SST-SEC-001 (version 1.0)",
		"- **Severity:** critical",
		"- **Category:** security",
		"- **Affected target:** service `proxy` (`compose.yaml:3`)",
		"**Description:**", "**Evidence:**", "**Why it matters:**", "**Recommended remediation:**",
		"```text\n5432:5432/tcp\nsecond | line with `ticks`\n```",
		"1 finding was suppressed",
		"- Suppressed SST-OPS-004 for `proxy`: fixed name required by monitoring",
		"1. **Fix before deploying (critical)**\n   - SST-SEC-001 Title of SST-SEC-001: `proxy`",
		"4. **Hardening backlog (low and info)**\n   - SST-SEC-009 Title of SST-SEC-009: `web`\n   - SST-OPS-007",
		"Generated by StackSentry v0.1.0 on 2026-10-01T12:00:00Z",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Fatal("markdown must not contain color codes")
	}
	buf.Reset()
	in.Result = engine.Result{}
	_ = RenderMarkdown(&buf, Build(in))
	if strings.Count(buf.String(), "No findings to report.") != 2 || !strings.Contains(buf.String(), "Nothing to remediate") {
		t.Fatalf("empty markdown report:\n%s", buf.String())
	}
}

func TestMarkdownEscaping(t *testing.T) {
	if got := text("a_b *c* [d] <e> `f` | #g"); got != `a\_b \*c\* \[d\] \<e\> `+"\\`f\\`"+` \| \#g` {
		t.Fatalf("text() = %s", got)
	}
	tests := map[string]string{"": "—", "plain": "`plain`", "a`b": "``a`b``", "`x": "`` `x ``", "a|b": "`a\\|b`"}
	for in, want := range tests {
		if got := code(in); got != want {
			t.Errorf("code(%q) = %q, want %q", in, got, want)
		}
	}
	if got := codeBlock([]string{"```", "x"}); !strings.HasPrefix(got, "````text\n") || !strings.HasSuffix(got, "\n````\n") {
		t.Fatalf("codeBlock fence not extended: %q", got)
	}
	if codeList(nil) != "—" {
		t.Fatal("empty code list")
	}
}

func TestRenderDispatch(t *testing.T) {
	r := Build(sampleInput())
	for _, f := range []Format{FormatTable, FormatJSON, FormatMarkdown, ""} {
		var buf bytes.Buffer
		if err := Render(&buf, r, RenderOptions{Format: f}); err != nil || buf.Len() == 0 {
			t.Fatalf("Render(%q) = %v", f, err)
		}
	}
	if err := Render(&bytes.Buffer{}, r, RenderOptions{Format: "xml"}); err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

func TestWriteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.md")
	if err := os.WriteFile(path, []byte("old content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, Build(sampleInput()), RenderOptions{Format: FormatMarkdown}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.HasPrefix(string(data), "# StackSentry Scan Report") {
		t.Fatalf("unexpected file content: %v %q", err, data)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("report mode = %v, want 0600", info.Mode().Perm())
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
	err = WriteFile(filepath.Join(dir, "missing", "report.json"), Build(sampleInput()), RenderOptions{Format: FormatJSON})
	if err == nil || !regexp.MustCompile(`cannot write report to ".*report\.json"`).MatchString(err.Error()) {
		t.Fatalf("expected write error, got %v", err)
	}
	if err := WriteFile(path, Build(sampleInput()), RenderOptions{Format: "xml"}); err == nil {
		t.Fatal("expected render error")
	}
}
