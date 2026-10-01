package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// Category groups rules by the kind of risk they address.
type Category string

// Rule categories.
const (
	CategorySecurity           Category = "security"
	CategoryOperations         Category = "operations"
	CategoryReliability        Category = "reliability"
	CategoryMaintainability    Category = "maintainability"
	CategorySecrets            Category = "secrets"
	CategoryNetworking         Category = "networking"
	CategoryStorage            Category = "storage"
	CategoryResourceManagement Category = "resource-management"
	CategorySupplyChain        Category = "supply-chain"
)

// Categories lists all valid categories.
func Categories() []Category {
	return []Category{
		CategorySecurity, CategoryOperations, CategoryReliability, CategoryMaintainability,
		CategorySecrets, CategoryNetworking, CategoryStorage, CategoryResourceManagement,
		CategorySupplyChain,
	}
}

// Valid reports whether c is a known category.
func (c Category) Valid() bool {
	for _, known := range Categories() {
		if c == known {
			return true
		}
	}
	return false
}

// TargetType identifies the kind of object a finding is about.
type TargetType string

// Target types.
const (
	TargetService   TargetType = "service"
	TargetProject   TargetType = "project"
	TargetContainer TargetType = "container"
	TargetHost      TargetType = "host"
)

// Location points to the place in a source file a finding relates to.
type Location struct {
	File string `json:"file"`
	Line int    `json:"line,omitempty"`
}

// String renders the location as file:line.
func (l *Location) String() string {
	if l == nil || l.File == "" {
		return ""
	}
	if l.Line > 0 {
		return l.File + ":" + strconv.Itoa(l.Line)
	}
	return l.File
}

// Finding is a single, fully described result of a rule evaluation.
type Finding struct {
	ID             string     `json:"id"`
	RuleID         string     `json:"rule_id"`
	RuleVersion    string     `json:"rule_version"`
	Title          string     `json:"title"`
	Category       Category   `json:"category"`
	Severity       Severity   `json:"severity"`
	Confidence     Confidence `json:"confidence"`
	TargetType     TargetType `json:"target_type"`
	TargetName     string     `json:"target_name"`
	Location       *Location  `json:"location,omitempty"`
	Description    string     `json:"description"`
	Evidence       []string   `json:"evidence"`
	WhyItMatters   string     `json:"why_it_matters"`
	Remediation    string     `json:"remediation"`
	Documentation  string     `json:"documentation,omitempty"`
	References     []string   `json:"references,omitempty"`
	Timestamp      time.Time  `json:"timestamp"`
	ScannerVersion string     `json:"scanner_version"`
}

// Fingerprint returns a stable identifier derived from the parts of a finding
// that describe *what* was found, independent of when it was found. It is
// suitable for de-duplication and future baseline support.
func Fingerprint(ruleID string, targetType TargetType, targetName string, evidence []string) string {
	h := sha256.New()
	for _, part := range []string{ruleID, string(targetType), targetName, strings.Join(evidence, "\n")} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
