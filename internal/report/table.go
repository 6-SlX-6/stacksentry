package report

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/6-SlX-6/stacksentry/internal/findings"
)

// DefaultWidth is the line width the table renderer wraps text to.
const DefaultWidth = 100

// TableOptions controls terminal rendering.
type TableOptions struct {
	// Color enables ANSI colors. Callers enable it only for terminals.
	Color bool
	// Quiet prints only the findings, without header, notes or result.
	Quiet bool
	// Width is the wrapping width; DefaultWidth is used when zero.
	Width int
}

const ansiReset = "\x1b[0m"

var severityColors = map[findings.Severity]string{
	findings.SeverityCritical: "\x1b[1;91m",
	findings.SeverityHigh:     "\x1b[31m",
	findings.SeverityMedium:   "\x1b[33m",
	findings.SeverityLow:      "\x1b[34m",
	findings.SeverityInfo:     "\x1b[90m",
}

// RenderTable writes the human-readable terminal report.
func RenderTable(w io.Writer, r *Report, opts TableOptions) error {
	width := opts.Width
	if width <= 0 {
		width = DefaultWidth
	}
	colorize := func(sev findings.Severity, s string) string {
		if !opts.Color {
			return s
		}
		return severityColors[sev] + s + ansiReset
	}
	bw := bufio.NewWriter(w)

	if !opts.Quiet {
		fmt.Fprintf(bw, "StackSentry v%s\n", r.Scanner.Version)
		fmt.Fprintf(bw, "Target: %s\n", targetLine(r))
		fmt.Fprintf(bw, "Scan time: %s\n", r.Scan.StartedAt.Format("2006-01-02T15:04:05Z"))
		fmt.Fprintf(bw, "Rules evaluated: %d of %d\n", r.Scan.RulesEvaluated, r.Scan.RulesTotal)
		if label, value := scopeLine(r); label != "" {
			fmt.Fprintf(bw, "%s: %s\n", label, value)
		}
		fmt.Fprintf(bw, "Findings: %s\n", countsLine(r.Summary.BySeverity, colorize))
		if len(r.Findings) == 0 {
			if r.Summary.Total == 0 {
				fmt.Fprintln(bw, "\nNo findings.")
			} else {
				fmt.Fprintln(bw, "\nNo findings at or above the selected severity.")
			}
		}
	}

	for i, f := range r.Findings {
		if i > 0 || !opts.Quiet {
			fmt.Fprintln(bw)
		}
		writeFinding(bw, f, width, colorize)
	}

	if !opts.Quiet {
		if n := notes(r); len(n) > 0 {
			fmt.Fprintln(bw, "\nNotes:")
			for _, note := range n {
				for _, line := range wrap(note, "  - ", "    ", width) {
					fmt.Fprintln(bw, line)
				}
			}
		}
		if s := resultSentence(r); s != "" {
			sev := findings.SeverityInfo
			if r.Failed() {
				sev = findings.SeverityCritical
			}
			fmt.Fprintf(bw, "\nResult: %s\n", colorize(sev, s))
		}
	}
	return bw.Flush()
}

func writeFinding(w io.Writer, f findings.Finding, width int, colorize func(findings.Severity, string) string) {
	header := fmt.Sprintf("%s  %s  %s", colorize(f.Severity, f.Severity.Label()), f.RuleID, f.TargetName)
	if loc := f.Location.String(); loc != "" {
		header += "  (" + loc + ")"
	}
	fmt.Fprintln(w, header)
	for _, line := range wrap(f.Description, "  ", "  ", width) {
		fmt.Fprintln(w, line)
	}
	if len(f.Evidence) > 0 {
		for i, ev := range f.Evidence {
			prefix := "  Evidence: "
			if i > 0 {
				prefix = strings.Repeat(" ", len(prefix))
			}
			for _, line := range wrap(ev, prefix, strings.Repeat(" ", len(prefix)+2), width) {
				fmt.Fprintln(w, line)
			}
		}
	}
	if f.Confidence != "" && f.Confidence != findings.ConfidenceHigh {
		fmt.Fprintf(w, "  Confidence: %s\n", f.Confidence)
	}
	for _, line := range wrap(f.WhyItMatters, "  Why this matters: ", "    ", width) {
		fmt.Fprintln(w, line)
	}
	for _, line := range wrap(f.Remediation, "  Fix: ", "    ", width) {
		fmt.Fprintln(w, line)
	}
}
