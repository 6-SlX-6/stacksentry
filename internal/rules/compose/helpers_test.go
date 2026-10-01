package composerules

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/6-SlX-6/stacksentry/internal/compose"
	"github.com/6-SlX-6/stacksentry/internal/engine"
	"github.com/6-SlX-6/stacksentry/internal/findings"
)

// want describes one expected finding. Evidence entries are substrings that
// must all appear in the finding's evidence.
type want struct {
	target   string
	severity findings.Severity
	evidence []string
}

type ruleCase struct {
	name string
	yaml string
	want []want
}

var (
	testedMu    sync.Mutex
	testedRules = map[string]bool{}
)

func TestMain(m *testing.M) {
	code := m.Run()
	if code == 0 && flag.Lookup("test.run").Value.String() == "" {
		var missing []string
		for _, meta := range Registry().Metadata() {
			if !testedRules[meta.ID] {
				missing = append(missing, meta.ID)
			}
		}
		if len(missing) > 0 {
			fmt.Fprintf(os.Stderr, "rules without table-driven tests: %s\n", strings.Join(missing, ", "))
			code = 1
		}
	}
	os.Exit(code)
}

func loadYAML(t *testing.T, content string) *compose.Project {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "compose.yaml")
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := compose.Load(context.Background(), []string{file})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return p
}

func runRule(t *testing.T, ruleID string, p *compose.Project) []findings.Finding {
	t.Helper()
	rule, ok := Registry().Lookup(ruleID)
	if !ok {
		t.Fatalf("rule %s not registered", ruleID)
	}
	res := engine.Run([]Rule{rule}, p, engine.RunConfig{ScannerVersion: "test", Now: time.Unix(0, 0)})
	if len(res.Errors) > 0 {
		t.Fatalf("rule errors: %v", res.Errors)
	}
	return res.Findings
}

func runRuleCases(t *testing.T, ruleID string, cases []ruleCase) {
	t.Helper()
	testedMu.Lock()
	testedRules[ruleID] = true
	testedMu.Unlock()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := runRule(t, ruleID, loadYAML(t, tc.yaml))
			if len(got) != len(tc.want) {
				t.Fatalf("got %d findings, want %d:\n%s", len(got), len(tc.want), describe(got))
			}
			sort.SliceStable(got, func(i, j int) bool { return key(got[i]) < key(got[j]) })
			wants := append([]want(nil), tc.want...)
			sort.SliceStable(wants, func(i, j int) bool {
				return wants[i].target+wants[i].severity.String() < wants[j].target+wants[j].severity.String()
			})
			for i, w := range wants {
				f := got[i]
				if f.TargetName != w.target || f.Severity != w.severity {
					t.Errorf("finding %d = %s/%s, want %s/%s\n%s", i, f.TargetName, f.Severity, w.target, w.severity, describe(got))
					continue
				}
				joined := strings.Join(f.Evidence, "\n")
				for _, ev := range w.evidence {
					if !strings.Contains(joined, ev) {
						t.Errorf("finding %s evidence %q does not contain %q", f.TargetName, joined, ev)
					}
				}
				if f.RuleID != ruleID || f.Title == "" || f.Remediation == "" || f.WhyItMatters == "" {
					t.Errorf("finding not fully described: %+v", f)
				}
			}
		})
	}
}

func key(f findings.Finding) string { return f.TargetName + f.Severity.String() }

func describe(list []findings.Finding) string {
	var b strings.Builder
	for _, f := range list {
		fmt.Fprintf(&b, "  %s %s %s %q\n", f.RuleID, f.Severity, f.TargetName, f.Evidence)
	}
	return b.String()
}

// svc builds a compose file with a single service "app".
func svc(body string) string {
	return "services:\n  app:\n" + indent(body, "    ")
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		if l != "" {
			lines[i] = prefix + l
		}
	}
	return strings.Join(lines, "\n") + "\n"
}
