package composerules

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/6-SlX-6/stacksentry/internal/compose"
	"github.com/6-SlX-6/stacksentry/internal/engine"
	"github.com/6-SlX-6/stacksentry/internal/findings"
)

// fixtureFindings scans a file from testdata/compose with all rules and
// returns "target=severity" entries for one rule, sorted.
func fixtureFindings(t *testing.T, file, ruleID string) (map[string]findings.Finding, []string) {
	t.Helper()
	p, err := compose.Load(context.Background(), []string{"../../../testdata/compose/" + file})
	if err != nil {
		t.Fatal(err)
	}
	res := engine.Run(All(), p, engine.RunConfig{})
	byTarget := map[string]findings.Finding{}
	var keys []string
	for _, f := range res.Findings {
		if f.RuleID == ruleID {
			byTarget[f.TargetName] = f
			keys = append(keys, f.TargetName+"="+f.Severity.String())
		}
	}
	sort.Strings(keys)
	return byTarget, keys
}

func TestFixturePorts(t *testing.T) {
	_, got := fixtureFindings(t, "ports.yaml", "SST-NET-001")
	want := "ipv6=low,long-syntax=high,mongo=medium,mysql=low,postgres=high,redis=high"
	if strings.Join(got, ",") != want {
		t.Fatalf("SST-NET-001 = %v, want %s", got, want)
	}
}

func TestFixtureCapabilities(t *testing.T) {
	byTarget, got := fixtureFindings(t, "capabilities.yaml", "SST-SEC-004")
	if strings.Join(got, ",") != "dangerous=high,everything=high" {
		t.Fatalf("SST-SEC-004 = %v", got)
	}
	ev := strings.Join(byTarget["dangerous"].Evidence, "\n")
	for _, c := range []string{"NET_ADMIN", "SYS_PTRACE", "SYS_MODULE"} {
		if !strings.Contains(ev, "cap_add: "+c) {
			t.Errorf("evidence lacks %s: %s", c, ev)
		}
	}
	_, got = fixtureFindings(t, "capabilities.yaml", "SST-SEC-005")
	if strings.Join(got, ",") != "dangerous=low,everything=low,partial-drop=low" {
		t.Fatalf("SST-SEC-005 = %v", got)
	}
}

func TestFixtureHealthchecks(t *testing.T) {
	_, missing := fixtureFindings(t, "healthchecks.yaml", "SST-OPS-001")
	_, disabled := fixtureFindings(t, "healthchecks.yaml", "SST-OPS-002")
	if strings.Join(missing, ",") != "unchecked=medium" || strings.Join(disabled, ",") != "disabled=medium,none-test=medium" {
		t.Fatalf("OPS-001 = %v, OPS-002 = %v", missing, disabled)
	}
}

func TestFixtureVolumeEdgeCases(t *testing.T) {
	writable, _ := fixtureFindings(t, "volumes-edge.yaml", "SST-SEC-006")
	ev := strings.Join(writable["app"].Evidence, "\n")
	if ev != "./uploads:/srv/uploads (read-write)\n/home/deploy/stack/data:/data (read-write)" {
		t.Fatalf("SST-SEC-006 evidence:\n%s", ev)
	}
	sensitive, _ := fixtureFindings(t, "volumes-edge.yaml", "SST-SEC-007")
	ev = strings.Join(sensitive["app"].Evidence, "\n")
	if !strings.Contains(ev, "/etc/letsencrypt:/certs:ro (read-only)") || !strings.Contains(ev, "/home/deploy/.ssh:/root/.ssh:ro") ||
		strings.Contains(ev, "localtime") || strings.Contains(ev, "stack/data") || strings.Contains(ev, "docker.sock") {
		t.Fatalf("SST-SEC-007 evidence:\n%s", ev)
	}
	socket, _ := fixtureFindings(t, "volumes-edge.yaml", "SST-SEC-001")
	if ev := strings.Join(socket["app"].Evidence, "\n"); !strings.Contains(ev, "/run/docker.sock:/var/run/docker.sock:ro") {
		t.Fatalf("SST-SEC-001 evidence:\n%s", ev)
	}
}

func TestFixtureMultiServiceSegmentation(t *testing.T) {
	_, got := fixtureFindings(t, "multi-service.yaml", "SST-NET-002")
	if strings.Join(got, ",") != "shop=low" {
		t.Fatalf("SST-NET-002 = %v", got)
	}
}
