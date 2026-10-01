// Package report builds the scan report model and renders it as a terminal
// table, JSON or Markdown.
package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/6-SlX-6/stacksentry/internal/engine"
	"github.com/6-SlX-6/stacksentry/internal/findings"
)

// SchemaVersion is the version of the JSON report schema. It follows
// semantic versioning: additive changes bump the minor version, breaking
// changes the major version.
const SchemaVersion = "1.0.0"

// Format is an output format.
type Format string

// Supported formats.
const (
	FormatTable    Format = "table"
	FormatJSON     Format = "json"
	FormatMarkdown Format = "markdown"
)

// ParseFormat validates a user supplied format name.
func ParseFormat(s string) (Format, error) {
	switch f := Format(strings.ToLower(strings.TrimSpace(s))); f {
	case FormatTable, FormatJSON, FormatMarkdown:
		return f, nil
	case "md":
		return FormatMarkdown, nil
	default:
		return "", fmt.Errorf("invalid format %q: must be one of table, json, markdown", s)
	}
}

// ScanType identifies the kind of scan.
type ScanType string

// Scan types.
const (
	ScanCompose ScanType = "compose"
	ScanHost    ScanType = "host"
)

// Result values of a scan with respect to --fail-on.
const (
	ResultPass        = "pass"
	ResultFail        = "fail"
	ResultNoThreshold = "no_threshold"
)

// Report is the complete, renderer-independent result of a scan.
type Report struct {
	SchemaVersion string                     `json:"schema_version"`
	Scanner       Scanner                    `json:"scanner"`
	Scan          Scan                       `json:"scan"`
	Target        Target                     `json:"target"`
	Summary       Summary                    `json:"summary"`
	Findings      []findings.Finding         `json:"findings"`
	Suppressed    []engine.SuppressedFinding `json:"suppressed_findings"`
	SkippedRules  []engine.SkippedRule       `json:"skipped_rules"`
	Limitations   []string                   `json:"limitations"`
	Warnings      []string                   `json:"warnings"`
}

// Scanner identifies the tool that produced the report.
type Scanner struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
}

// Scan holds scan metadata.
type Scan struct {
	Type           ScanType  `json:"type"`
	StartedAt      time.Time `json:"started_at"`
	FinishedAt     time.Time `json:"finished_at"`
	RulesTotal     int       `json:"rules_total"`
	RulesEvaluated int       `json:"rules_evaluated"`
	Options        Options   `json:"options"`
}

// Options records the user options that influenced the report.
type Options struct {
	MinSeverity findings.Severity  `json:"min_severity"`
	FailOn      *findings.Severity `json:"fail_on"`
	Only        []string           `json:"only"`
	Exclude     []string           `json:"exclude"`
}

// Target describes what was scanned.
type Target struct {
	Type    ScanType       `json:"type"`
	Name    string         `json:"name"`
	Compose *ComposeTarget `json:"compose,omitempty"`
	Host    *HostTarget    `json:"host,omitempty"`
}

// ComposeTarget holds metadata about a scanned Compose project.
type ComposeTarget struct {
	Files        []string `json:"files"`
	ProjectName  string   `json:"project_name"`
	ServiceCount int      `json:"service_count"`
	Services     []string `json:"services"`
}

// HostTarget holds metadata about a scanned Docker host.
type HostTarget struct {
	Endpoint          string `json:"endpoint"`
	ServerVersion     string `json:"server_version"`
	APIVersion        string `json:"api_version"`
	OperatingSystem   string `json:"operating_system"`
	OSType            string `json:"os_type"`
	Architecture      string `json:"architecture"`
	ContainersTotal   int    `json:"containers_total"`
	ContainersRunning int    `json:"containers_running"`
	Images            int    `json:"images"`
}

// Summary aggregates the findings of a scan.
type Summary struct {
	// Total counts all findings produced by the evaluated rules, including
	// findings hidden from the report by --severity.
	Total      int             `json:"total"`
	BySeverity findings.Counts `json:"by_severity"`
	Displayed  int             `json:"displayed"`
	// HiddenBelowMinSeverity counts findings omitted by --severity.
	HiddenBelowMinSeverity int `json:"hidden_below_min_severity"`
	// Suppressed counts findings matched by x-stacksentry exceptions; they
	// are not part of Total and never trigger --fail-on.
	Suppressed int `json:"suppressed"`
	// FailOn is the --fail-on threshold, if any.
	FailOn *findings.Severity `json:"fail_on"`
	// AtOrAboveFailOn counts findings that meet the threshold, including
	// findings hidden by --severity.
	AtOrAboveFailOn int    `json:"at_or_above_fail_on"`
	Result          string `json:"result"`
}

// Input collects everything needed to build a report.
type Input struct {
	Scanner      Scanner
	ScanType     ScanType
	StartedAt    time.Time
	FinishedAt   time.Time
	RulesTotal   int
	Result       engine.Result
	SkippedRules []engine.SkippedRule
	Target       Target
	Limitations  []string
	Warnings     []string
	MinSeverity  findings.Severity
	FailOn       *findings.Severity
	Only         []string
	Exclude      []string
}

// Build assembles a report. --severity only affects which findings are
// displayed; --fail-on is evaluated against all findings so that the exit
// code does not depend on presentation options.
func Build(in Input) *Report {
	minSeverity := in.MinSeverity
	if !minSeverity.Valid() {
		minSeverity = findings.SeverityInfo
	}
	all := append([]findings.Finding(nil), in.Result.Findings...)
	findings.Sort(all)
	displayed := findings.FilterMinSeverity(all, minSeverity)
	counts := findings.Count(all)

	warnings := append([]string(nil), in.Warnings...)
	for _, e := range in.Result.Errors {
		warnings = append(warnings, e.Error()+"; results of this rule are missing")
	}

	r := &Report{
		SchemaVersion: SchemaVersion,
		Scanner:       in.Scanner,
		Scan: Scan{
			Type:           in.ScanType,
			StartedAt:      in.StartedAt.UTC().Truncate(time.Second),
			FinishedAt:     in.FinishedAt.UTC().Truncate(time.Second),
			RulesTotal:     in.RulesTotal,
			RulesEvaluated: len(in.Result.Evaluated),
			Options: Options{
				MinSeverity: minSeverity,
				FailOn:      in.FailOn,
				Only:        nonNil(in.Only),
				Exclude:     nonNil(in.Exclude),
			},
		},
		Target: in.Target,
		Summary: Summary{
			Total:                  counts.Total(),
			BySeverity:             counts,
			Displayed:              len(displayed),
			HiddenBelowMinSeverity: counts.Total() - len(displayed),
			Suppressed:             len(in.Result.Suppressed),
			FailOn:                 in.FailOn,
			Result:                 ResultNoThreshold,
		},
		Findings:     displayed,
		Suppressed:   append([]engine.SuppressedFinding{}, in.Result.Suppressed...),
		SkippedRules: append([]engine.SkippedRule{}, in.SkippedRules...),
		Limitations:  nonNil(in.Limitations),
		Warnings:     nonNil(warnings),
	}
	if in.FailOn != nil {
		r.Summary.AtOrAboveFailOn = counts.AtLeast(*in.FailOn)
		r.Summary.Result = ResultPass
		if r.Summary.AtOrAboveFailOn > 0 {
			r.Summary.Result = ResultFail
		}
	}
	return r
}

// Failed reports whether the --fail-on threshold was met.
func (r *Report) Failed() bool {
	return r.Summary.Result == ResultFail
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return append([]string{}, s...)
}

// Redact replaces every occurrence of the given sensitive values in all
// report text derived from the scanned configuration with mask. It is a
// defense in depth: rules are written never to include secret values in the
// first place. Constant rule texts (title, why it matters) are left intact.
func Redact(r *Report, values []string, mask string) {
	if len(values) == 0 {
		return
	}
	pairs := make([]string, 0, 2*len(values))
	for _, v := range values {
		if v != "" {
			pairs = append(pairs, v, mask)
		}
	}
	rep := strings.NewReplacer(pairs...)
	redactFinding := func(f *findings.Finding) {
		f.TargetName = rep.Replace(f.TargetName)
		f.Description = rep.Replace(f.Description)
		f.Remediation = rep.Replace(f.Remediation)
		evidence := make([]string, len(f.Evidence))
		for i, e := range f.Evidence {
			evidence[i] = rep.Replace(e)
		}
		f.Evidence = evidence
	}
	for i := range r.Findings {
		redactFinding(&r.Findings[i])
	}
	for i := range r.Suppressed {
		redactFinding(&r.Suppressed[i].Finding)
		r.Suppressed[i].SuppressionReason = rep.Replace(r.Suppressed[i].SuppressionReason)
	}
	for i := range r.Warnings {
		r.Warnings[i] = rep.Replace(r.Warnings[i])
	}
	for i := range r.Limitations {
		r.Limitations[i] = rep.Replace(r.Limitations[i])
	}
}
