package engine

import (
	"errors"
	"fmt"
	"sort"
)

// Registry holds the rules available for one scan scope.
type Registry[T any] struct {
	rules []Rule[T]
	index map[string]Rule[T]
}

// NewRegistry validates the rules' metadata and indexes them by ID.
func NewRegistry[T any](scope Scope, rules ...Rule[T]) (*Registry[T], error) {
	reg := &Registry[T]{index: make(map[string]Rule[T], len(rules))}
	var errs []error
	for _, r := range rules {
		meta := r.Metadata()
		if err := meta.Validate(); err != nil {
			errs = append(errs, err)
			continue
		}
		if meta.Scope != scope {
			errs = append(errs, fmt.Errorf("rule %s has scope %q, registry expects %q", meta.ID, meta.Scope, scope))
			continue
		}
		if _, dup := reg.index[meta.ID]; dup {
			errs = append(errs, fmt.Errorf("duplicate rule ID %s", meta.ID))
			continue
		}
		reg.index[meta.ID] = r
		reg.rules = append(reg.rules, r)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, fmt.Errorf("invalid rule registry: %w", err)
	}
	sort.Slice(reg.rules, func(i, j int) bool {
		return reg.rules[i].Metadata().ID < reg.rules[j].Metadata().ID
	})
	return reg, nil
}

// MustRegistry is like NewRegistry but panics on invalid built-in rules. It
// is intended for package-level initialization of compiled-in rule sets,
// whose validity is enforced by unit tests.
func MustRegistry[T any](scope Scope, rules ...Rule[T]) *Registry[T] {
	reg, err := NewRegistry(scope, rules...)
	if err != nil {
		panic(err)
	}
	return reg
}

// Rules returns all rules sorted by ID.
func (r *Registry[T]) Rules() []Rule[T] {
	out := make([]Rule[T], len(r.rules))
	copy(out, r.rules)
	return out
}

// Metadata returns the metadata of all rules sorted by ID.
func (r *Registry[T]) Metadata() []Metadata {
	out := make([]Metadata, 0, len(r.rules))
	for _, rule := range r.rules {
		out = append(out, rule.Metadata())
	}
	return out
}

// Lookup returns the rule with the given ID.
func (r *Registry[T]) Lookup(id string) (Rule[T], bool) {
	rule, ok := r.index[id]
	return rule, ok
}

// Has reports whether a rule with the given ID is registered.
func (r *Registry[T]) Has(id string) bool {
	_, ok := r.index[id]
	return ok
}
