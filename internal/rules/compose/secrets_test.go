package composerules

import (
	"strings"
	"testing"

	"github.com/6-SlX-6/stacksentry/internal/findings"
)

func TestSEC011InlineSecrets(t *testing.T) {
	runRuleCases(t, "SST-SEC-011", []ruleCase{
		{"password map syntax", svc("image: x:1\nenvironment:\n  POSTGRES_PASSWORD: s3cr3t-value\n  POSTGRES_USER: app"),
			[]want{{"app", high, []string{"POSTGRES_PASSWORD=" + Mask}}}},
		{"list syntax and several names", svc("image: x:1\nenvironment:\n  - API_KEY=abcdef123456\n  - JWT_SECRET=zzz-top\n  - GITHUB_TOKEN=ghp_xxxxxxxxxxxxyyyy\n  - N8N_ENCRYPTION_KEY=0123456789abcdef\n  - AWS_SECRET_ACCESS_KEY=AKIAblah"),
			[]want{{"app", high, []string{"API_KEY=", "JWT_SECRET=", "GITHUB_TOKEN=", "N8N_ENCRYPTION_KEY=", "AWS_SECRET_ACCESS_KEY="}}}},
		{"default value in file counts", svc("image: x:1\nenvironment:\n  DB_PASSWORD: ${DB_PASSWORD:-changeme}"),
			[]want{{"app", high, []string{"DB_PASSWORD=" + Mask}}}},
		{"url with credentials", svc("image: x:1\nenvironment:\n  DATABASE_URL: postgres://app:hunter22@db:5432/app"),
			[]want{{"app", high, []string{"DATABASE_URL=" + Mask + " (URL with embedded credentials)"}}}},
		{"interpolated without default", svc("image: x:1\nenvironment:\n  DB_PASSWORD: ${DB_PASSWORD}\n  TOKEN: ${TOKEN:?required}"), nil},
		{"secret file references", svc("image: x:1\nenvironment:\n  POSTGRES_PASSWORD_FILE: /run/secrets/db_password\n  API_KEY: /run/secrets/api"), nil},
		{"placeholders and flags", svc("image: x:1\nenvironment:\n  ADMIN_PASSWORD: \"<change-me>\"\n  API_TOKEN: xxxxxxxx\n  SECRET: your-secret-here\n  PASSWORD_RESET: \"true\"\n  TOKEN_TTL: \"3600\"\n  PASSWORD: \"\""), nil},
		{"non-secret names", svc("image: x:1\nenvironment:\n  PWD: /app\n  TOKEN_URL: https://auth.example.com/token\n  DB_USER: app\n  PASSWORD_MIN_LENGTH: \"12\""), nil},
		{"url without password", svc("image: x:1\nenvironment:\n  REDIS_URL: redis://cache:6379/0\n  DB_URL: postgres://app@db/app"), nil},
		{"pass-through variable", svc("image: x:1\nenvironment:\n  - DB_PASSWORD"), nil},
	})
}

func TestSEC011NeverLeaksValues(t *testing.T) {
	p := loadYAML(t, svc("image: x:1\nenvironment:\n  POSTGRES_PASSWORD: very-secret-value-123\n  DATABASE_URL: postgres://u:another-secret@db/x"))
	got := runRule(t, "SST-SEC-011", p)
	for _, f := range got {
		text := strings.Join(append(f.Evidence, f.Description, f.Remediation, f.WhyItMatters, f.Title), "\n")
		if strings.Contains(text, "very-secret-value-123") || strings.Contains(text, "another-secret") {
			t.Fatalf("secret leaked: %s", text)
		}
	}
	values := SensitiveValues(p)
	if len(values) != 2 || values[0] != "postgres://u:another-secret@db/x" || values[1] != "very-secret-value-123" {
		t.Fatalf("SensitiveValues = %q", values)
	}
}

func TestSecretNameHeuristics(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"PASSWORD", true}, {"db_password", true}, {"MYSQL_ROOT_PASSWORD", true}, {"REDIS_PASS", true},
		{"SMTP_PASSWD", true}, {"GPG_PASSPHRASE", true}, {"CLIENT_SECRET", true}, {"OAUTH_CLIENT_SECRET", true},
		{"API_KEY", true}, {"APIKEY", true}, {"PRIVATE_KEY", true}, {"ACCESS_KEY", true}, {"SECRET_KEY_BASE", true},
		{"ENCRYPTION_KEY", true}, {"SIGNING_KEY", true}, {"AUTH_KEY", true}, {"MASTER_KEY", true},
		{"SLACK_TOKEN", true}, {"GOOGLE_CREDENTIALS", true}, {"DB-PWD", true},
		{"PWD", false}, {"PASSWORD_FILE", false}, {"API_KEY_PATH", false}, {"DB_USER", false},
		{"KEY", false}, {"PRIMARY_KEY", false}, {"MONKEY", false}, {"TOKEN_EXPIRY", false}, {"BYPASS", false},
		{"", false}, {"___", false},
	}
	for _, tt := range tests {
		if got := isSecretName(tt.name); got != tt.want {
			t.Errorf("isSecretName(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestSEC012EnvFile(t *testing.T) {
	runRuleCases(t, "SST-SEC-012", []ruleCase{
		{"single env file", svc("image: x:1\nenv_file: .env"), []want{{"app", med, []string{"env_file: .env"}}}},
		{"several env files", svc("image: x:1\nenv_file:\n  - .env\n  - path: ./secrets.env\n    required: false"),
			[]want{{"app", med, []string{"env_file: .env", "env_file: ./secrets.env"}}}},
		{"none", svc("image: x:1"), nil},
	})
}

func TestCFG001MissingVariables(t *testing.T) {
	runRuleCases(t, "SST-CFG-001", []ruleCase{
		{"braced and plain", svc("image: app:${TAG}\nenvironment:\n  URL: http://$API_HOST/v1"),
			[]want{{"app", med, []string{"${TAG} has no default", "$API_HOST has no default", "services.app.environment.URL"}}}},
		{"defaults are fine", svc("image: app:${TAG:-1.0}\nenvironment:\n  A: ${A-x}\n  B: ${B:?must be set}\n  C: ${C?}\n  D: ${D:+on}\n  E: $$NOT_INTERPOLATED"), nil},
		{"nested default", svc("image: app:${TAG:-${FALLBACK}}"), []want{{"app", med, []string{"${FALLBACK}"}}}},
		{"shell variables ignored", svc("image: x:1\nvolumes:\n  - ${HOME}/data:/data\n  - ${PWD}/conf:/conf:ro"), nil},
		{"project level", "name: proj\nservices:\n  app:\n    image: x:1\nnetworks:\n  edge:\n    name: ${EDGE_NETWORK}\n",
			[]want{{"proj", med, []string{"${EDGE_NETWORK}", "networks.edge.name"}}}},
		{"grouped per service", "services:\n  a:\n    image: a:${TAG_A}\n  b:\n    image: b:${TAG_B}\n    environment:\n      X: ${TAG_B}\n",
			[]want{{"a", med, []string{"${TAG_A}"}}, {"b", med, []string{"${TAG_B} has no default", "services.b.image", "services.b.environment.X"}}}},
	})
}

func TestCFG001ProjectFindingUsesProjectName(t *testing.T) {
	p := loadYAML(t, "name: demo\nservices:\n  app:\n    image: x:1\nvolumes:\n  data:\n    name: ${VOLUME_NAME}\n")
	got := runRule(t, "SST-CFG-001", p)
	if len(got) != 1 || got[0].TargetType != findings.TargetProject || got[0].TargetName != "demo" || got[0].Location == nil || got[0].Location.Line != 7 {
		t.Fatalf("unexpected project finding: %+v", got)
	}
}
