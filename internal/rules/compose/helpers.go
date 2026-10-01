package composerules

import (
	"github.com/6-SlX-6/stacksentry/internal/compose"
	"github.com/6-SlX-6/stacksentry/internal/engine"
	"github.com/6-SlX-6/stacksentry/internal/findings"
)

// Rule is a Compose rule.
type Rule = engine.Rule[*compose.Project]

func newRule(meta engine.Metadata, fn func(*compose.Project) []engine.Issue) Rule {
	meta.Scope = engine.ScopeCompose
	if meta.Version == "" {
		meta.Version = "1.0"
	}
	return engine.FuncRule[*compose.Project]{Meta: meta, Fn: fn}
}

// perService adapts a per-service check into a project check.
func perService(fn func(*compose.Service) []engine.Issue) func(*compose.Project) []engine.Issue {
	return func(p *compose.Project) []engine.Issue {
		var out []engine.Issue
		for i := range p.Services {
			out = append(out, fn(&p.Services[i])...)
		}
		return out
	}
}

func serviceIssue(s *compose.Service, evidence ...string) engine.Issue {
	issue := engine.Issue{TargetType: findings.TargetService, TargetName: s.Name, Evidence: evidence}
	if s.File != "" {
		issue.Location = &findings.Location{File: s.File, Line: s.Line}
	}
	return issue
}

func one(issue engine.Issue) []engine.Issue { return []engine.Issue{issue} }
