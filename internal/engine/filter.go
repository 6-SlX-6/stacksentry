package engine

import (
	"strings"
)

// Selection restricts which rules run. Only, when non-empty, is an allow
// list; Exclude is applied afterwards and always wins.
type Selection struct {
	Only    []string
	Exclude []string
}

// SkippedRule records a rule that was not evaluated and why.
type SkippedRule struct {
	RuleID string `json:"rule_id"`
	Title  string `json:"title"`
	Reason string `json:"reason"`
}

// Skip reasons.
const (
	ReasonExcluded  = "excluded with --exclude"
	ReasonNotInOnly = "not selected with --only"
)

// ParseRuleIDs normalizes user supplied rule IDs. Each value may itself be a
// comma-separated list. IDs are trimmed, upper-cased and de-duplicated while
// preserving their first occurrence order.
func ParseRuleIDs(values []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			id := strings.ToUpper(strings.TrimSpace(part))
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// Select returns the rules to evaluate and the rules skipped by the
// selection. IDs that are not registered are ignored here; callers validate
// user input beforehand so that typos are reported as errors.
func Select[T any](reg *Registry[T], sel Selection) (enabled []Rule[T], skipped []SkippedRule) {
	only := toSet(sel.Only)
	exclude := toSet(sel.Exclude)
	restrict := false
	for id := range only {
		if reg.Has(id) {
			restrict = true
			break
		}
	}
	for _, r := range reg.Rules() {
		meta := r.Metadata()
		switch {
		case exclude[meta.ID]:
			skipped = append(skipped, SkippedRule{RuleID: meta.ID, Title: meta.Title, Reason: ReasonExcluded})
		case restrict && !only[meta.ID]:
			skipped = append(skipped, SkippedRule{RuleID: meta.ID, Title: meta.Title, Reason: ReasonNotInOnly})
		default:
			enabled = append(enabled, r)
		}
	}
	return enabled, skipped
}

func toSet(ids []string) map[string]bool {
	set := make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set
}
