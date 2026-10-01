package findings

import (
	"sort"
	"strings"
)

// Counts holds the number of findings per severity.
type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// Count tallies findings by severity.
func Count(list []Finding) Counts {
	var c Counts
	for _, f := range list {
		c.Add(f.Severity)
	}
	return c
}

// Add increments the counter for sev.
func (c *Counts) Add(sev Severity) {
	switch sev {
	case SeverityCritical:
		c.Critical++
	case SeverityHigh:
		c.High++
	case SeverityMedium:
		c.Medium++
	case SeverityLow:
		c.Low++
	case SeverityInfo:
		c.Info++
	}
}

// Get returns the counter for sev.
func (c Counts) Get(sev Severity) int {
	switch sev {
	case SeverityCritical:
		return c.Critical
	case SeverityHigh:
		return c.High
	case SeverityMedium:
		return c.Medium
	case SeverityLow:
		return c.Low
	case SeverityInfo:
		return c.Info
	default:
		return 0
	}
}

// Total returns the number of counted findings.
func (c Counts) Total() int {
	return c.Critical + c.High + c.Medium + c.Low + c.Info
}

// AtLeast returns the number of findings at or above threshold.
func (c Counts) AtLeast(threshold Severity) int {
	n := 0
	for _, sev := range AllSeverities() {
		if sev.AtLeast(threshold) {
			n += c.Get(sev)
		}
	}
	return n
}

// Sort orders findings deterministically: severity descending, then rule ID,
// target name, location, evidence and finally the fingerprint as a
// tie-breaker so that equal inputs always produce identical output.
func Sort(list []Finding) {
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.TargetName != b.TargetName {
			return a.TargetName < b.TargetName
		}
		if c := compareLocation(a.Location, b.Location); c != 0 {
			return c < 0
		}
		if ea, eb := strings.Join(a.Evidence, "\n"), strings.Join(b.Evidence, "\n"); ea != eb {
			return ea < eb
		}
		return a.ID < b.ID
	})
}

// FilterMinSeverity returns the findings at or above min, preserving order.
func FilterMinSeverity(list []Finding, min Severity) []Finding {
	out := make([]Finding, 0, len(list))
	for _, f := range list {
		if f.Severity.AtLeast(min) {
			out = append(out, f)
		}
	}
	return out
}

func compareLocation(a, b *Location) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	case a.File != b.File:
		return strings.Compare(a.File, b.File)
	default:
		return a.Line - b.Line
	}
}
