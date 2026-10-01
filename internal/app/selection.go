package app

import (
	"fmt"
	"sort"
	"strings"

	"github.com/6-SlX-6/stacksentry/internal/engine"
)

// SelectionError reports invalid --only/--exclude values. It is a user
// input error and maps to exit code 2.
type SelectionError struct {
	Message string
}

// Error implements error.
func (e *SelectionError) Error() string { return e.Message }

// validateSelection checks rule IDs given with --only and --exclude. Unknown
// IDs are errors. IDs of the other scan mode are ignored with a warning, so
// that one exclusion list can be shared between compose and host scans,
// unless they leave --only without any applicable rule.
func validateSelection(scope engine.Scope, opts ScanOptions) ([]string, error) {
	scopes := map[string]engine.Scope{}
	var known []string
	for _, m := range Rules() {
		scopes[m.ID] = m.Scope
		known = append(known, m.ID)
	}
	var unknown []string
	for _, id := range append(append([]string{}, opts.Only...), opts.Exclude...) {
		if _, ok := scopes[id]; !ok && !contains(unknown, id) {
			unknown = append(unknown, id)
		}
	}
	if len(unknown) > 0 {
		msg := fmt.Sprintf("unknown rule ID %s", strings.Join(unknown, ", "))
		if s := suggest(unknown, known); len(s) > 0 {
			msg += fmt.Sprintf(" (did you mean %s?)", strings.Join(s, ", "))
		}
		msg += `; run "stacksentry rules list" to see all rules`
		return nil, &SelectionError{Message: msg}
	}

	var warnings []string
	applicable := 0
	for _, id := range opts.Only {
		if scopes[id] == scope {
			applicable++
			continue
		}
		warnings = append(warnings, fmt.Sprintf("--only %s ignored: it is a %s rule and does not apply to %s scans.", id, scopes[id], scope))
	}
	if len(opts.Only) > 0 && applicable == 0 {
		return nil, &SelectionError{Message: fmt.Sprintf("none of the rules given with --only apply to %s scans (%s)",
			scope, strings.Join(opts.Only, ", "))}
	}
	for _, id := range opts.Exclude {
		if scopes[id] != scope {
			warnings = append(warnings, fmt.Sprintf("--exclude %s ignored: it is a %s rule and does not apply to %s scans.", id, scopes[id], scope))
		}
	}
	return warnings, nil
}

// suggest returns, for each unknown ID, the known IDs with the smallest edit
// distance, provided that distance is at most two.
func suggest(unknown, known []string) []string {
	var out []string
	for _, u := range unknown {
		best, matches := 3, []string(nil)
		for _, k := range known {
			switch d := levenshtein(u, k); {
			case d < best:
				best, matches = d, []string{k}
			case d == best:
				matches = append(matches, k)
			}
		}
		for _, m := range matches {
			if !contains(out, m) {
				out = append(out, m)
			}
		}
	}
	sort.Strings(out)
	return out
}

func levenshtein(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
