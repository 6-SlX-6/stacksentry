package composerules

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/6-SlX-6/stacksentry/internal/compose"
	"github.com/6-SlX-6/stacksentry/internal/engine"
	"github.com/6-SlX-6/stacksentry/internal/findings"
)

// Mask replaces secret values in all output. Its length is fixed so that it
// does not reveal the length of the original value.
const Mask = "********"

const (
	refSensitiveDataHowTo = "https://docs.docker.com/compose/how-tos/use-secrets/"
	refComposeEnvFile     = "https://docs.docker.com/compose/how-tos/environment-variables/set-environment-variables/#use-the-env_file-attribute"
	refComposeInterpolate = "https://docs.docker.com/reference/compose-file/interpolation/"
)

func secretRules() []Rule {
	return []Rule{
		newRule(engine.Metadata{
			ID:          "SST-SEC-011",
			Title:       "Likely secret in environment variable",
			Category:    findings.CategorySecrets,
			Severity:    findings.SeverityHigh,
			Description: "An environment variable that looks like a credential has an inline value in the Compose file.",
			Rationale: "Inline secrets end up in version control, backups, CI logs and docker inspect output, and are visible " +
				"to everyone who can read the Compose file.",
			Remediation: "Move the value out of the Compose file: use Docker secrets (with *_FILE variables where the image " +
				"supports them), an external secret manager, or interpolation such as ${DB_PASSWORD} with the value injected " +
				"at deploy time from an environment file that is not committed. Rotate the secret if the file was ever shared.",
			Detection: "Inline environment values (after applying defaults written in the file) whose variable name contains " +
				"PASSWORD, PASSWD, PASS, PASSPHRASE, PWD, SECRET, TOKEN, APIKEY, CREDENTIAL(S) or a pair such as API_KEY, PRIVATE_KEY, " +
				"ACCESS_KEY, SECRET_KEY, ENCRYPTION_KEY, SIGNING_KEY, AUTH_KEY, MASTER_KEY or CLIENT_SECRET, and any value " +
				"that is a URL with an embedded password. Names ending in _FILE, _PATH, _USER, _NAME, _URL and similar settings, " +
				"empty values, booleans, short numbers, /run/secrets paths and obvious placeholders such as <password>, xxxx " +
				"or your-token-here are ignored. Values are never printed; they are replaced with " + Mask + ".",
			Limitations: "Name-based detection can miss secrets stored under unusual names and can flag non-secret settings. " +
				"Values of variables interpolated without a default (${VAR}) are not known and therefore not reported.",
			References: []string{refSensitiveDataHowTo, refOWASPDocker},
		}, perService(checkInlineSecrets)),

		newRule(engine.Metadata{
			ID:          "SST-SEC-012",
			Title:       "Environment file potentially tracked",
			Category:    findings.CategorySecrets,
			Severity:    findings.SeverityMedium,
			Description: "The service loads variables from an env_file, which often contains credentials.",
			Rationale: "Environment files frequently hold passwords and API keys. If they are committed to a repository or " +
				"copied into backups or images, the secrets leak. StackSentry does not inspect your Git repository, so this " +
				"is a reminder, not proof that the file is tracked.",
			Remediation: "Make sure the file is listed in .gitignore (and .dockerignore), restrict its permissions (for example " +
				"chmod 600) and commit only a template such as .env.example without real values.",
			Detection:   "Any env_file entry on a service.",
			Limitations: "The file content and its Git status are not inspected.",
			References:  []string{refComposeEnvFile},
		}, perService(func(s *compose.Service) []engine.Issue {
			if len(s.EnvFiles) == 0 {
				return nil
			}
			var evidence []string
			for _, f := range s.EnvFiles {
				evidence = append(evidence, "env_file: "+f)
			}
			return one(serviceIssue(s, evidence...))
		})),

		newRule(engine.Metadata{
			ID:          "SST-CFG-001",
			Title:       "Required environment variable may be missing",
			Category:    findings.CategoryOperations,
			Severity:    findings.SeverityMedium,
			Description: "The Compose file uses variables without a default value, so the deployment depends on external configuration.",
			Rationale: "If such a variable is not set at deploy time, Docker Compose substitutes an empty string and only prints " +
				"a warning. That can silently produce broken or insecure configuration such as empty passwords, wrong image " +
				"tags or unexpected port bindings.",
			Remediation: "Document the variable and provide it in the deployment environment or .env file. Use " +
				"${VAR:-default} for a safe default, or ${VAR:?error message} to make Compose fail fast when it is missing.",
			Detection: "Interpolation expressions ${VAR} and $VAR in the raw YAML. Expressions with a default " +
				"(${VAR:-default}, ${VAR-default}), required markers (${VAR:?msg}, ${VAR?msg}), alternatives " +
				"(${VAR:+alt}, ${VAR+alt}) and escaped dollars ($$) are not reported. HOME, PWD, USER, LOGNAME, PATH, SHELL " +
				"and COMPOSE_PROJECT_NAME are always available and are ignored.",
			Limitations: "StackSentry does not read your shell environment or .env file, so it cannot tell whether a variable " +
				"is actually set where you deploy. Only the files passed to the scan are inspected.",
			References: []string{refComposeInterpolate},
		}, checkMissingVariables),
	}
}

var (
	secretTokens = map[string]bool{
		"PASSWORD": true, "PASSWD": true, "PASS": true, "PWD": true, "SECRET": true, "TOKEN": true,
		"PASSPHRASE": true, "APIKEY": true, "CREDENTIAL": true, "CREDENTIALS": true, "PRIVATEKEY": true, "SECRETKEY": true,
	}
	secretPairs = map[string][]string{
		"KEY":    {"API", "PRIVATE", "ACCESS", "SECRET", "ENCRYPTION", "SIGNING", "AUTH", "MASTER"},
		"SECRET": {"CLIENT"},
	}
	// nonSecretSuffixes mark settings about a secret rather than the secret.
	nonSecretSuffixes = map[string]bool{
		"FILE": true, "PATH": true, "DIR": true, "LOCATION": true, "HOST": true, "PORT": true, "USER": true,
		"USERNAME": true, "NAME": true, "TYPE": true, "LENGTH": true, "EXPIRY": true, "EXPIRATION": true,
		"EXPIRES": true, "TTL": true, "TIMEOUT": true, "ENABLED": true, "DISABLED": true, "REQUIRED": true,
		"POLICY": true, "MODE": true, "METHOD": true, "PROVIDER": true, "ALGORITHM": true, "ISSUER": true,
		"AUDIENCE": true, "HEADER": true, "COOKIE": true, "ROTATION": true, "RESET": true, "URL": true,
		"URI": true, "ENDPOINT": true, "SERVER": true,
	}
	urlCredentials = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://[^/@:\s]*:[^/@\s]+@`)
	placeholder    = regexp.MustCompile(`^(<[^>]*>|\{\{.*\}\}|[xX*#._-]+|(?i:your[-_ ].*))$`)
	shortNumber    = regexp.MustCompile(`^[0-9]{1,5}$`)
)

// isSecretName reports whether an environment variable name looks like it
// holds a credential.
func isSecretName(name string) bool {
	upper := strings.ToUpper(name)
	if upper == "PWD" {
		return false
	}
	tokens := strings.FieldsFunc(upper, func(c rune) bool {
		return (c < 'A' || c > 'Z') && (c < '0' || c > '9')
	})
	if len(tokens) == 0 || nonSecretSuffixes[tokens[len(tokens)-1]] {
		return false
	}
	for i, t := range tokens {
		if secretTokens[t] {
			return true
		}
		if i > 0 {
			for _, prefix := range secretPairs[t] {
				if tokens[i-1] == prefix {
					return true
				}
			}
		}
	}
	return false
}

// isSecretValue reports whether a value is a plausible real secret rather
// than an empty value, flag, number, file reference or placeholder.
func isSecretValue(value string) bool {
	v := strings.TrimSpace(value)
	if v == "" || shortNumber.MatchString(v) || placeholder.MatchString(v) {
		return false
	}
	switch strings.ToLower(v) {
	case "true", "false", "yes", "no", "on", "off", "null", "none":
		return false
	}
	if strings.HasPrefix(v, "/run/secrets/") || strings.HasPrefix(v, "/var/run/secrets/") || strings.Contains(v, "${") {
		return false
	}
	return true
}

func hasURLCredentials(value string) bool {
	return urlCredentials.MatchString(strings.TrimSpace(value))
}

func checkInlineSecrets(s *compose.Service) []engine.Issue {
	var evidence []string
	for _, e := range s.Environment {
		if !e.HasValue {
			continue
		}
		switch {
		case isSecretName(e.Name) && isSecretValue(e.Value):
			evidence = append(evidence, e.Name+"="+Mask)
		case hasURLCredentials(e.Value):
			evidence = append(evidence, e.Name+"="+Mask+" (URL with embedded credentials)")
		}
	}
	if len(evidence) == 0 {
		return nil
	}
	return one(serviceIssue(s, evidence...))
}

// SensitiveValues returns all environment values that output must never
// contain. It is broader than SST-SEC-011 on purpose: report renderers use
// it as a last line of defense to redact values that might have leaked into
// any finding text.
func SensitiveValues(p *compose.Project) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range p.Services {
		for _, e := range s.Environment {
			v := strings.TrimSpace(e.Value)
			if !e.HasValue || len(v) < 4 || seen[v] {
				continue
			}
			if (isSecretName(e.Name) && isSecretValue(v)) || hasURLCredentials(v) {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	// Longest first so that overlapping values are fully replaced.
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return out[i] < out[j]
	})
	return out
}

func checkMissingVariables(p *compose.Project) []engine.Issue {
	type group struct {
		issue engine.Issue
		seen  map[string]bool
	}
	groups := map[string]*group{}
	var order []string
	for _, ref := range p.Variables {
		key := ref.Service
		g, ok := groups[key]
		if !ok {
			g = &group{seen: map[string]bool{}}
			if svc, found := p.Service(ref.Service); found {
				g.issue = serviceIssue(svc)
			} else {
				g.issue = engine.Issue{TargetType: findings.TargetProject, TargetName: p.Name,
					Location: &findings.Location{File: ref.File, Line: ref.Line}}
			}
			groups[key] = g
			order = append(order, key)
		}
		line := fmt.Sprintf("%s has no default (%s:%d, %s)", ref.Expression, ref.File, ref.Line, ref.Path)
		if g.seen[line] {
			continue
		}
		g.seen[line] = true
		g.issue.Evidence = append(g.issue.Evidence, line)
	}
	sort.Strings(order)
	out := make([]engine.Issue, 0, len(order))
	for _, key := range order {
		out = append(out, groups[key].issue)
	}
	return out
}
