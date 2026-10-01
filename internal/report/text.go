package report

import (
	"fmt"
	"strings"

	"github.com/6-SlX-6/stacksentry/internal/findings"
)

// wrap breaks text into lines of at most width columns. The first line is
// prefixed with first, continuation lines with rest. Words longer than the
// available width are kept intact.
func wrap(text, first, rest string, width int) []string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return []string{strings.TrimRight(first, " ")}
	}
	var lines []string
	line := first + words[0]
	for _, w := range words[1:] {
		if len(line)+1+len(w) > width {
			lines = append(lines, line)
			line = rest + w
			continue
		}
		line += " " + w
	}
	return append(lines, line)
}

func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %s", n, pluralForm)
}

// countsLine renders "2 critical, 3 high, 5 medium, 4 low" and appends the
// info count only when non-zero.
func countsLine(c findings.Counts, colorize func(findings.Severity, string) string) string {
	parts := []string{}
	for _, sev := range findings.AllSeverities() {
		if sev == findings.SeverityInfo && c.Info == 0 {
			continue
		}
		parts = append(parts, colorize(sev, fmt.Sprintf("%d %s", c.Get(sev), sev)))
	}
	return strings.Join(parts, ", ")
}

func targetLine(r *Report) string {
	switch {
	case r.Target.Compose != nil:
		line := strings.Join(r.Target.Compose.Files, ", ")
		if r.Target.Compose.ProjectName != "" {
			line += fmt.Sprintf(" (project %q)", r.Target.Compose.ProjectName)
		}
		return line
	case r.Target.Host != nil:
		h := r.Target.Host
		line := "Docker daemon at " + h.Endpoint
		if h.ServerVersion != "" {
			line += fmt.Sprintf(" (Docker %s, API %s)", h.ServerVersion, h.APIVersion)
		}
		return line
	default:
		return r.Target.Name
	}
}

func scopeLine(r *Report) (string, string) {
	switch {
	case r.Target.Compose != nil:
		return "Services analyzed", fmt.Sprintf("%d", r.Target.Compose.ServiceCount)
	case r.Target.Host != nil:
		return "Containers analyzed", fmt.Sprintf("%d (%d running)", r.Target.Host.ContainersTotal, r.Target.Host.ContainersRunning)
	default:
		return "", ""
	}
}

func resultSentence(r *Report) string {
	if r.Summary.FailOn == nil {
		return ""
	}
	threshold := r.Summary.FailOn.String()
	if r.Failed() {
		return fmt.Sprintf("FAIL: %s at or above %q (--fail-on %s)",
			plural(r.Summary.AtOrAboveFailOn, "finding", "findings"), threshold, threshold)
	}
	return fmt.Sprintf("PASS: no findings at or above %q (--fail-on %s)", threshold, threshold)
}

// notes collects the explanatory notes shared by the table and Markdown
// renderers.
func notes(r *Report) []string {
	var out []string
	if n := r.Summary.HiddenBelowMinSeverity; n > 0 {
		out = append(out, fmt.Sprintf("%s below %q not shown (--severity %s); they still count for --fail-on.",
			plural(n, "finding", "findings"), r.Scan.Options.MinSeverity, r.Scan.Options.MinSeverity))
	}
	if n := len(r.Suppressed); n > 0 {
		out = append(out, fmt.Sprintf("%s suppressed by documented x-stacksentry exceptions.", plural(n, "finding", "findings")))
	}
	if n := len(r.SkippedRules); n > 0 {
		ids := make([]string, 0, n)
		for _, s := range r.SkippedRules {
			ids = append(ids, s.RuleID)
		}
		out = append(out, fmt.Sprintf("%s not evaluated (--only/--exclude): %s.", plural(n, "rule", "rules"), strings.Join(ids, ", ")))
	}
	for _, l := range r.Limitations {
		out = append(out, "Limitation: "+l)
	}
	for _, w := range r.Warnings {
		out = append(out, "Warning: "+w)
	}
	return out
}
