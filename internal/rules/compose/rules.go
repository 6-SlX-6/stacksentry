// Package composerules implements the static Docker Compose rules.
package composerules

import (
	"github.com/6-SlX-6/stacksentry/internal/compose"
	"github.com/6-SlX-6/stacksentry/internal/engine"
)

// All returns every built-in Compose rule.
func All() []Rule {
	var rules []Rule
	rules = append(rules, securityRules()...)
	rules = append(rules, secretRules()...)
	rules = append(rules, operationsRules()...)
	rules = append(rules, networkingRules()...)
	rules = append(rules, storageRules()...)
	rules = append(rules, resourceRules()...)
	return rules
}

// Registry returns a validated registry of all Compose rules.
func Registry() *engine.Registry[*compose.Project] {
	return engine.MustRegistry(engine.ScopeCompose, All()...)
}
