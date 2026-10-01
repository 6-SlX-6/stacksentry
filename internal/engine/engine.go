package engine

import (
	"fmt"
	"time"

	"github.com/6-SlX-6/stacksentry/internal/findings"
)

// RunConfig carries scan-wide values stamped onto every finding.
type RunConfig struct {
	ScannerVersion string
	Now            time.Time
	// Suppress optionally reports whether a finding was suppressed by the
	// scanned configuration itself, returning the documented reason.
	Suppress func(findings.Finding) (reason string, suppressed bool)
}

// SuppressedFinding is a finding that matched an explicit, documented
// exception in the scanned configuration.
type SuppressedFinding struct {
	findings.Finding
	SuppressionReason string `json:"suppression_reason"`
}

// RuleError records a rule that failed during evaluation.
type RuleError struct {
	RuleID  string
	Message string
}

// Error implements error.
func (e RuleError) Error() string {
	return fmt.Sprintf("rule %s failed: %s", e.RuleID, e.Message)
}

// Result is the outcome of evaluating a set of rules against one target.
type Result struct {
	Findings   []findings.Finding
	Suppressed []SuppressedFinding
	Evaluated  []string
	Errors     []RuleError
}

// Run evaluates every rule against target. A rule that panics is recorded
// in Result.Errors and does not abort the scan. Findings are de-duplicated
// by fingerprint and returned in deterministic order.
func Run[T any](rules []Rule[T], target T, cfg RunConfig) Result {
	var res Result
	seen := make(map[string]bool)
	ts := cfg.Now.UTC().Truncate(time.Second)
	for _, rule := range rules {
		meta := rule.Metadata()
		res.Evaluated = append(res.Evaluated, meta.ID)
		issues, err := safeCheck(rule, target)
		if err != nil {
			res.Errors = append(res.Errors, RuleError{RuleID: meta.ID, Message: err.Error()})
			continue
		}
		for _, issue := range issues {
			f := BuildFinding(meta, issue, cfg.ScannerVersion, ts)
			if seen[f.ID] {
				continue
			}
			seen[f.ID] = true
			if cfg.Suppress != nil {
				if reason, ok := cfg.Suppress(f); ok {
					res.Suppressed = append(res.Suppressed, SuppressedFinding{Finding: f, SuppressionReason: reason})
					continue
				}
			}
			res.Findings = append(res.Findings, f)
		}
	}
	findings.Sort(res.Findings)
	sortSuppressed(res.Suppressed)
	return res
}

func safeCheck[T any](rule Rule[T], target T) (issues []Issue, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("internal error: %v", r)
		}
	}()
	return rule.Check(target), nil
}

// BuildFinding combines rule metadata with a reported issue.
func BuildFinding(meta Metadata, issue Issue, scannerVersion string, ts time.Time) findings.Finding {
	sev := issue.Severity
	if !sev.Valid() {
		sev = meta.Severity
	}
	confidence := issue.Confidence
	if confidence == "" {
		confidence = findings.ConfidenceHigh
	}
	description := issue.Description
	if description == "" {
		description = meta.Description
	}
	remediation := issue.Remediation
	if remediation == "" {
		remediation = meta.Remediation
	}
	evidence := make([]string, len(issue.Evidence))
	copy(evidence, issue.Evidence)
	var refs []string
	if len(meta.References) > 0 {
		refs = append(refs, meta.References...)
	}
	var loc *findings.Location
	if issue.Location != nil && issue.Location.File != "" {
		l := *issue.Location
		loc = &l
	}
	return findings.Finding{
		ID:             findings.Fingerprint(meta.ID, issue.TargetType, issue.TargetName, evidence),
		RuleID:         meta.ID,
		RuleVersion:    meta.Version,
		Title:          meta.Title,
		Category:       meta.Category,
		Severity:       sev,
		Confidence:     confidence,
		TargetType:     issue.TargetType,
		TargetName:     issue.TargetName,
		Location:       loc,
		Description:    description,
		Evidence:       evidence,
		WhyItMatters:   meta.Rationale,
		Remediation:    remediation,
		Documentation:  meta.DocumentationURL(),
		References:     refs,
		Timestamp:      ts,
		ScannerVersion: scannerVersion,
	}
}

func sortSuppressed(list []SuppressedFinding) {
	plain := make([]findings.Finding, len(list))
	reasons := make(map[string]string, len(list))
	for i, s := range list {
		plain[i] = s.Finding
		reasons[s.ID] = s.SuppressionReason
	}
	findings.Sort(plain)
	for i, f := range plain {
		list[i] = SuppressedFinding{Finding: f, SuppressionReason: reasons[f.ID]}
	}
}
