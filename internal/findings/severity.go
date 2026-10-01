// Package findings defines the finding model shared by rules, the scanning
// engine and report renderers.
package findings

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity ranks how urgently a finding should be addressed. The zero value
// is SeverityUnknown, which allows rules to leave the severity unset and
// inherit the rule's default.
type Severity int

// Severity levels in ascending order.
const (
	SeverityUnknown Severity = iota
	SeverityInfo
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = map[Severity]string{
	SeverityInfo:     "info",
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
}

// AllSeverities lists the valid severities from most to least severe.
func AllSeverities() []Severity {
	return []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}
}

// SeverityNames lists the valid severity names from least to most severe,
// which is the order users usually expect in help texts.
func SeverityNames() []string {
	return []string{"info", "low", "medium", "high", "critical"}
}

// ParseSeverity converts a case-insensitive severity name.
func ParseSeverity(s string) (Severity, error) {
	needle := strings.ToLower(strings.TrimSpace(s))
	for sev, name := range severityNames {
		if name == needle {
			return sev, nil
		}
	}
	return SeverityUnknown, fmt.Errorf("invalid severity %q: must be one of %s", s, strings.Join(SeverityNames(), ", "))
}

// String returns the lowercase severity name.
func (s Severity) String() string {
	if name, ok := severityNames[s]; ok {
		return name
	}
	return "unknown"
}

// Label returns the uppercase severity name used in terminal output.
func (s Severity) Label() string {
	return strings.ToUpper(s.String())
}

// Valid reports whether s is one of the defined severities.
func (s Severity) Valid() bool {
	_, ok := severityNames[s]
	return ok
}

// AtLeast reports whether s is at least as severe as threshold.
func (s Severity) AtLeast(threshold Severity) bool {
	return s >= threshold
}

// MarshalJSON encodes the severity as its lowercase name.
func (s Severity) MarshalJSON() ([]byte, error) {
	if !s.Valid() {
		return nil, fmt.Errorf("cannot marshal invalid severity %d", int(s))
	}
	return json.Marshal(s.String())
}

// UnmarshalJSON decodes a severity name.
func (s *Severity) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		return err
	}
	parsed, err := ParseSeverity(name)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// Confidence expresses how certain a rule is that a finding is accurate.
type Confidence string

// Confidence levels.
const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Rank orders confidence levels so the strongest can be selected.
func (c Confidence) Rank() int {
	switch c {
	case ConfidenceHigh:
		return 3
	case ConfidenceMedium:
		return 2
	case ConfidenceLow:
		return 1
	default:
		return 0
	}
}
