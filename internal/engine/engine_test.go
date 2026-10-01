package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/6-SlX-6/stacksentry/internal/findings"
)

type target struct{ names []string }

func meta(id string, sev findings.Severity) Metadata {
	return Metadata{
		ID: id, Version: "1.0", Title: "Title " + id, Category: findings.CategorySecurity,
		Severity: sev, Scope: ScopeCompose, Description: "desc", Rationale: "why",
		Remediation: "fix", Detection: "how", References: []string{"https://example.com"},
	}
}

func perName(id string, sev findings.Severity) Rule[target] {
	return FuncRule[target]{Meta: meta(id, sev), Fn: func(t target) []Issue {
		var out []Issue
		for _, n := range t.names {
			out = append(out, Issue{TargetType: findings.TargetService, TargetName: n, Evidence: []string{"evidence " + n}})
		}
		return out
	}}
}

func TestMetadataValidate(t *testing.T) {
	good := meta("SST-SEC-001", findings.SeverityHigh)
	if err := good.Validate(); err != nil {
		t.Fatalf("valid metadata rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*Metadata)
		want   string
	}{
		{"bad id", func(m *Metadata) { m.ID = "SEC-1" }, "does not match"},
		{"lower id", func(m *Metadata) { m.ID = "sst-sec-001" }, "does not match"},
		{"no version", func(m *Metadata) { m.Version = "" }, "version"},
		{"bad category", func(m *Metadata) { m.Category = "nope" }, "category"},
		{"no severity", func(m *Metadata) { m.Severity = findings.SeverityUnknown }, "severity"},
		{"bad scope", func(m *Metadata) { m.Scope = "cloud" }, "scope"},
		{"no title", func(m *Metadata) { m.Title = " " }, "title"},
		{"no detection", func(m *Metadata) { m.Detection = "" }, "detection"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := good
			tt.mutate(&m)
			err := m.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tt.want)
			}
		})
	}
	if got := good.DocumentationURL(); !strings.HasSuffix(got, "rules.md#sst-sec-001") {
		t.Fatalf("DocumentationURL() = %s", got)
	}
}

func TestNewRegistry(t *testing.T) {
	reg, err := NewRegistry(ScopeCompose, perName("SST-SEC-002", findings.SeverityLow), perName("SST-SEC-001", findings.SeverityHigh))
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, m := range reg.Metadata() {
		ids = append(ids, m.ID)
	}
	if strings.Join(ids, ",") != "SST-SEC-001,SST-SEC-002" {
		t.Fatalf("rules not sorted: %v", ids)
	}
	if _, ok := reg.Lookup("SST-SEC-002"); !ok || !reg.Has("SST-SEC-001") || reg.Has("SST-SEC-003") {
		t.Fatal("lookup mismatch")
	}
	if len(reg.Rules()) != 2 {
		t.Fatal("Rules() length")
	}

	tests := []struct {
		name  string
		rules []Rule[target]
		want  string
	}{
		{"duplicate", []Rule[target]{perName("SST-SEC-001", findings.SeverityLow), perName("SST-SEC-001", findings.SeverityLow)}, "duplicate"},
		{"invalid", []Rule[target]{perName("BAD", findings.SeverityLow)}, "does not match"},
		{"scope", []Rule[target]{FuncRule[target]{Meta: func() Metadata { m := meta("SST-HOST-001", findings.SeverityInfo); m.Scope = ScopeHost; return m }()}}, "scope"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewRegistry(ScopeCompose, tt.rules...)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("NewRegistry() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestMustRegistryPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	MustRegistry(ScopeCompose, perName("BAD", findings.SeverityLow))
}

func TestParseRuleIDs(t *testing.T) {
	got := ParseRuleIDs([]string{"sst-sec-001, SST-OPS-003", "SST-SEC-001", "", " ,sst-net-001"})
	want := "SST-SEC-001,SST-OPS-003,SST-NET-001"
	if strings.Join(got, ",") != want {
		t.Fatalf("ParseRuleIDs = %v, want %s", got, want)
	}
}

func TestSelect(t *testing.T) {
	reg := MustRegistry(ScopeCompose,
		perName("SST-SEC-001", findings.SeverityCritical),
		perName("SST-SEC-002", findings.SeverityHigh),
		perName("SST-OPS-003", findings.SeverityHigh),
	)
	tests := []struct {
		name        string
		sel         Selection
		wantEnabled string
		wantSkipped string
	}{
		{"all", Selection{}, "SST-OPS-003,SST-SEC-001,SST-SEC-002", ""},
		{"exclude", Selection{Exclude: []string{"SST-SEC-001", "SST-OPS-003"}}, "SST-SEC-002", "SST-OPS-003=" + ReasonExcluded + ";SST-SEC-001=" + ReasonExcluded},
		{"only", Selection{Only: []string{"SST-SEC-002"}}, "SST-SEC-002", "SST-OPS-003=" + ReasonNotInOnly + ";SST-SEC-001=" + ReasonNotInOnly},
		{"only and exclude", Selection{Only: []string{"SST-SEC-001", "SST-SEC-002"}, Exclude: []string{"SST-SEC-002"}}, "SST-SEC-001", "SST-OPS-003=" + ReasonNotInOnly + ";SST-SEC-002=" + ReasonExcluded},
		{"only unknown to registry is ignored", Selection{Only: []string{"SST-HOST-001"}}, "SST-OPS-003,SST-SEC-001,SST-SEC-002", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enabled, skipped := Select(reg, tt.sel)
			var e, s []string
			for _, r := range enabled {
				e = append(e, r.Metadata().ID)
			}
			for _, sk := range skipped {
				s = append(s, sk.RuleID+"="+sk.Reason)
				if sk.Title == "" {
					t.Error("skipped rule without title")
				}
			}
			if strings.Join(e, ",") != tt.wantEnabled {
				t.Errorf("enabled = %v, want %s", e, tt.wantEnabled)
			}
			if strings.Join(s, ";") != tt.wantSkipped {
				t.Errorf("skipped = %v, want %s", s, tt.wantSkipped)
			}
		})
	}
}

func TestRunBuildsFindings(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 30, 45, 999, time.FixedZone("CEST", 2*3600))
	override := FuncRule[target]{Meta: meta("SST-NET-001", findings.SeverityHigh), Fn: func(target) []Issue {
		return []Issue{
			{TargetType: findings.TargetService, TargetName: "db", Severity: findings.SeverityLow, Confidence: findings.ConfidenceMedium,
				Description: "specific", Remediation: "specific fix", Evidence: []string{"127.0.0.1:5432:5432"},
				Location: &findings.Location{File: "compose.yml", Line: 7}},
			// exact duplicate is dropped
			{TargetType: findings.TargetService, TargetName: "db", Evidence: []string{"127.0.0.1:5432:5432"}},
			// empty location is dropped
			{TargetType: findings.TargetService, TargetName: "cache", Location: &findings.Location{}},
		}
	}}
	res := Run([]Rule[target]{perName("SST-SEC-001", findings.SeverityCritical), override}, target{names: []string{"web", "app"}}, RunConfig{ScannerVersion: "9.9.9", Now: now})
	if len(res.Errors) != 0 {
		t.Fatalf("unexpected errors %v", res.Errors)
	}
	if strings.Join(res.Evaluated, ",") != "SST-SEC-001,SST-NET-001" {
		t.Fatalf("evaluated = %v", res.Evaluated)
	}
	if len(res.Findings) != 4 {
		t.Fatalf("expected 4 findings, got %d: %+v", len(res.Findings), res.Findings)
	}
	first := res.Findings[0]
	if first.RuleID != "SST-SEC-001" || first.TargetName != "app" || first.Severity != findings.SeverityCritical {
		t.Fatalf("unexpected first finding %+v", first)
	}
	if first.Confidence != findings.ConfidenceHigh || first.Description != "desc" || first.Remediation != "fix" || first.WhyItMatters != "why" {
		t.Fatalf("defaults not applied: %+v", first)
	}
	if first.Timestamp.Format(time.RFC3339Nano) != "2026-10-01T10:30:45Z" {
		t.Fatalf("timestamp not normalized to UTC seconds: %s", first.Timestamp.Format(time.RFC3339Nano))
	}
	if first.ScannerVersion != "9.9.9" || first.RuleVersion != "1.0" || first.Documentation == "" || len(first.References) != 1 {
		t.Fatalf("metadata not stamped: %+v", first)
	}
	var db, cache *findings.Finding
	for i := range res.Findings {
		switch res.Findings[i].TargetName {
		case "db":
			db = &res.Findings[i]
		case "cache":
			cache = &res.Findings[i]
		}
	}
	if db == nil || db.Severity != findings.SeverityLow || db.Confidence != findings.ConfidenceMedium || db.Description != "specific" || db.Remediation != "specific fix" || db.Location.String() != "compose.yml:7" {
		t.Fatalf("overrides not applied: %+v", db)
	}
	if cache == nil || cache.Location != nil || cache.Evidence == nil {
		t.Fatalf("empty location should be dropped and evidence non-nil: %+v", cache)
	}
}

func TestRunRecoversFromPanics(t *testing.T) {
	boom := FuncRule[target]{Meta: meta("SST-SEC-009", findings.SeverityLow), Fn: func(target) []Issue { panic("kaboom") }}
	res := Run([]Rule[target]{boom, perName("SST-SEC-001", findings.SeverityCritical)}, target{names: []string{"web"}}, RunConfig{})
	if len(res.Errors) != 1 || res.Errors[0].RuleID != "SST-SEC-009" || !strings.Contains(res.Errors[0].Error(), "kaboom") {
		t.Fatalf("panic not captured: %+v", res.Errors)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("other rules must still run, got %d findings", len(res.Findings))
	}
}

func TestRunSuppression(t *testing.T) {
	cfg := RunConfig{Suppress: func(f findings.Finding) (string, bool) {
		if f.TargetName == "web" {
			return "documented exception", true
		}
		return "", false
	}}
	res := Run([]Rule[target]{perName("SST-SEC-002", findings.SeverityHigh), perName("SST-SEC-001", findings.SeverityCritical)}, target{names: []string{"web", "app"}}, cfg)
	if len(res.Findings) != 2 || len(res.Suppressed) != 2 {
		t.Fatalf("findings=%d suppressed=%d", len(res.Findings), len(res.Suppressed))
	}
	if res.Suppressed[0].RuleID != "SST-SEC-001" || res.Suppressed[0].SuppressionReason != "documented exception" {
		t.Fatalf("suppressed not sorted or reason lost: %+v", res.Suppressed[0])
	}
}
