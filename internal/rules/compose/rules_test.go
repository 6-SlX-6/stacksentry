package composerules

import (
	"strings"
	"testing"

	"github.com/6-SlX-6/stacksentry/internal/engine"
	"github.com/6-SlX-6/stacksentry/internal/findings"
)

func TestRegistryContainsAllRequiredRules(t *testing.T) {
	want := []string{
		"SST-CFG-001",
		"SST-NET-001", "SST-NET-002", "SST-NET-003",
		"SST-OPS-001", "SST-OPS-002", "SST-OPS-003", "SST-OPS-004", "SST-OPS-005", "SST-OPS-006", "SST-OPS-007",
		"SST-RES-001", "SST-RES-002", "SST-RES-003",
		"SST-SEC-001", "SST-SEC-002", "SST-SEC-003", "SST-SEC-004", "SST-SEC-005", "SST-SEC-006",
		"SST-SEC-007", "SST-SEC-008", "SST-SEC-009", "SST-SEC-010", "SST-SEC-011", "SST-SEC-012",
		"SST-STO-001",
	}
	var got []string
	for _, m := range Registry().Metadata() {
		got = append(got, m.ID)
		if m.Scope != engine.ScopeCompose {
			t.Errorf("%s has scope %s", m.ID, m.Scope)
		}
		if len(m.References) == 0 {
			t.Errorf("%s has no references", m.ID)
		}
		for _, text := range []string{m.Title, m.Description, m.Rationale, m.Remediation} {
			if strings.HasSuffix(text, " ") || strings.Contains(text, "  ") {
				t.Errorf("%s has sloppy whitespace in %q", m.ID, text)
			}
		}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("registered rules:\n%v\nwant:\n%v", got, want)
	}
}

func TestDefaultSeverities(t *testing.T) {
	want := map[string]findings.Severity{
		"SST-SEC-001": crit, "SST-SEC-002": crit, "SST-SEC-003": high, "SST-SEC-004": high, "SST-SEC-005": low,
		"SST-SEC-006": med, "SST-SEC-007": high, "SST-SEC-008": med, "SST-SEC-009": low, "SST-SEC-010": crit,
		"SST-SEC-011": high, "SST-SEC-012": med, "SST-CFG-001": med,
		"SST-OPS-001": med, "SST-OPS-002": med, "SST-OPS-003": high, "SST-OPS-004": low, "SST-OPS-005": med,
		"SST-OPS-006": low, "SST-OPS-007": low,
		"SST-NET-001": high, "SST-NET-002": low, "SST-NET-003": med, "SST-STO-001": high,
		"SST-RES-001": low, "SST-RES-002": low, "SST-RES-003": med,
	}
	for _, m := range Registry().Metadata() {
		if want[m.ID] != m.Severity {
			t.Errorf("%s default severity = %s, want %s", m.ID, m.Severity, want[m.ID])
		}
	}
}

func TestSEC010Confidence(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want findings.Confidence
	}{
		{"port only", svc("image: x:1\nports: [\"2375:2375\"]"), findings.ConfidenceMedium},
		{"dind image", svc("image: docker:27-dind\nports: [\"2375:2375\"]"), findings.ConfidenceHigh},
		{"proxy service name", "services:\n  socket-proxy:\n    image: custom:1\n    ports: [\"2375:2375\"]\n", findings.ConfidenceHigh},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runRule(t, "SST-SEC-010", loadYAML(t, tt.yaml))
			if len(got) != 1 || got[0].Confidence != tt.want {
				t.Fatalf("got %+v, want confidence %s", got, tt.want)
			}
		})
	}
}

func TestHardenedServiceHasNoFindings(t *testing.T) {
	yaml := `services:
  db:
    image: postgres:16.4@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    user: "999:999"
    read_only: true
    restart: unless-stopped
    cap_drop: [ALL]
    stop_grace_period: 30s
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    secrets: [db_password]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $${POSTGRES_USER:-postgres}"]
    volumes:
      - pgdata:/var/lib/postgresql/data
    tmpfs: [/tmp, /run/postgresql]
    networks: [backend]
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: "1.0"
    logging:
      driver: json-file
      options:
        max-size: 10m
        max-file: "3"
networks:
  backend:
    internal: true
volumes:
  pgdata:
secrets:
  db_password:
    file: ./db_password.txt
`
	p := loadYAML(t, yaml)
	res := engine.Run(All(), p, engine.RunConfig{})
	if len(res.Findings) != 0 || len(res.Errors) != 0 {
		t.Fatalf("expected no findings, got:\n%s errors=%v", describe(res.Findings), res.Errors)
	}
}
