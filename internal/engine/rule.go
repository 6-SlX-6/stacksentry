// Package engine contains the rule model, the rule registry and the scanning
// engine that turns rule issues into fully described findings.
package engine

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/6-SlX-6/stacksentry/internal/findings"
)

// DocsBaseURL is the location of the rule reference documentation.
const DocsBaseURL = "https://github.com/6-SlX-6/stacksentry/blob/main/docs/rules.md"

// Scope identifies which kind of scan a rule belongs to.
type Scope string

// Rule scopes.
const (
	ScopeCompose Scope = "compose"
	ScopeHost    Scope = "host"
)

var ruleIDPattern = regexp.MustCompile(`^SST-[A-Z]{3,4}-[0-9]{3}$`)

// Metadata describes a rule independently of its implementation. It is used
// to build findings and to render "stacksentry rules" output and docs.
type Metadata struct {
	ID          string
	Version     string
	Title       string
	Category    findings.Category
	Severity    findings.Severity
	Scope       Scope
	Description string
	Rationale   string
	Remediation string
	Detection   string
	Limitations string
	References  []string
}

// DocumentationURL returns the link to the rule's reference entry.
func (m Metadata) DocumentationURL() string {
	return DocsBaseURL + "#" + strings.ToLower(m.ID)
}

// Validate checks that the metadata is complete and well-formed.
func (m Metadata) Validate() error {
	var errs []error
	if !ruleIDPattern.MatchString(m.ID) {
		errs = append(errs, fmt.Errorf("rule ID %q does not match SST-<CATEGORY>-<NUMBER>", m.ID))
	}
	if m.Version == "" {
		errs = append(errs, errors.New("version is empty"))
	}
	if !m.Category.Valid() {
		errs = append(errs, fmt.Errorf("invalid category %q", m.Category))
	}
	if !m.Severity.Valid() {
		errs = append(errs, errors.New("default severity is not set"))
	}
	if m.Scope != ScopeCompose && m.Scope != ScopeHost {
		errs = append(errs, fmt.Errorf("invalid scope %q", m.Scope))
	}
	for name, value := range map[string]string{
		"title":       m.Title,
		"description": m.Description,
		"rationale":   m.Rationale,
		"remediation": m.Remediation,
		"detection":   m.Detection,
	} {
		if strings.TrimSpace(value) == "" {
			errs = append(errs, fmt.Errorf("%s is empty", name))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("rule %s: %w", m.ID, err)
	}
	return nil
}

// Issue is what a rule reports. Optional fields left at their zero value are
// filled from the rule's metadata when the engine builds the final finding.
type Issue struct {
	TargetType findings.TargetType
	TargetName string
	Location   *findings.Location
	Evidence   []string

	// Severity overrides the rule's default severity when set.
	Severity findings.Severity
	// Confidence defaults to high when empty.
	Confidence findings.Confidence
	// Description overrides the rule's generic description when set.
	Description string
	// Remediation overrides the rule's generic remediation when set.
	Remediation string
}

// Rule is a deterministic check against a scan target of type T.
type Rule[T any] interface {
	Metadata() Metadata
	Check(target T) []Issue
}

// FuncRule adapts a plain function into a Rule.
type FuncRule[T any] struct {
	Meta Metadata
	Fn   func(target T) []Issue
}

// Metadata implements Rule.
func (r FuncRule[T]) Metadata() Metadata { return r.Meta }

// Check implements Rule.
func (r FuncRule[T]) Check(target T) []Issue { return r.Fn(target) }
