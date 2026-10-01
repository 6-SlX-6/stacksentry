// Package app wires the Compose loader, the Docker inspector, the rule
// engine and the report builder into the two scan workflows.
package app

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/6-SlX-6/stacksentry/internal/compose"
	"github.com/6-SlX-6/stacksentry/internal/docker"
	"github.com/6-SlX-6/stacksentry/internal/engine"
	"github.com/6-SlX-6/stacksentry/internal/findings"
	"github.com/6-SlX-6/stacksentry/internal/report"
	composerules "github.com/6-SlX-6/stacksentry/internal/rules/compose"
	hostrules "github.com/6-SlX-6/stacksentry/internal/rules/host"
	"github.com/6-SlX-6/stacksentry/internal/version"
)

// HostScanTimeout bounds the total time spent talking to the Docker daemon.
const HostScanTimeout = 2 * time.Minute

// ScanOptions are the user options shared by both scan modes.
type ScanOptions struct {
	// MinSeverity hides less severe findings from the report.
	MinSeverity findings.Severity
	// FailOn is the exit code threshold; nil disables it.
	FailOn *findings.Severity
	// Only and Exclude contain normalized rule IDs.
	Only    []string
	Exclude []string
}

// App runs scans. The zero value is not usable; use New.
type App struct {
	Version version.Info
	Now     func() time.Time
	// ConnectDocker opens a verified connection to the Docker daemon.
	ConnectDocker func(context.Context) (*docker.Connection, error)
	// HostFS is the host root filesystem used by the host scan for
	// daemon.json and /proc. Nil disables those checks.
	HostFS fs.FS
	GOOS   string
}

// New returns an App configured for the current machine.
func New() *App {
	a := &App{
		Version:       version.Get(),
		Now:           time.Now,
		ConnectDocker: docker.Connect,
		GOOS:          runtime.GOOS,
	}
	if runtime.GOOS == "linux" {
		a.HostFS = os.DirFS("/")
	}
	return a
}

var (
	composeRegistry = sync.OnceValue(composerules.Registry)
	hostRegistry    = sync.OnceValue(hostrules.Registry)
)

// Rules returns the metadata of all built-in rules sorted by ID.
func Rules() []engine.Metadata {
	all := append(composeRegistry().Metadata(), hostRegistry().Metadata()...)
	sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
	return all
}

// Rule returns the metadata of one rule. The lookup is case-insensitive.
func Rule(id string) (engine.Metadata, bool) {
	id = strings.ToUpper(strings.TrimSpace(id))
	for _, m := range Rules() {
		if m.ID == id {
			return m, true
		}
	}
	return engine.Metadata{}, false
}

// ScanCompose statically analyzes Compose files.
func (a *App) ScanCompose(ctx context.Context, paths []string, opts ScanOptions) (*report.Report, error) {
	reg := composeRegistry()
	warnings, err := validateSelection(engine.ScopeCompose, opts)
	if err != nil {
		return nil, err
	}
	started := a.Now()
	project, err := compose.Load(ctx, paths)
	if err != nil {
		return nil, err
	}
	enabled, skipped := engine.Select(reg, engine.Selection{Only: opts.Only, Exclude: opts.Exclude})
	warnings = append(warnings, unknownSuppressions(project)...)
	res := engine.Run(enabled, project, engine.RunConfig{
		ScannerVersion: a.Version.Version,
		Now:            started,
		Suppress:       suppressor(project),
	})

	r := report.Build(report.Input{
		Scanner:      a.scanner(),
		ScanType:     report.ScanCompose,
		StartedAt:    started,
		FinishedAt:   a.Now(),
		RulesTotal:   len(reg.Rules()),
		Result:       res,
		SkippedRules: skipped,
		Target: report.Target{
			Type: report.ScanCompose,
			Name: strings.Join(project.Files, ", "),
			Compose: &report.ComposeTarget{
				Files:        project.Files,
				ProjectName:  project.Name,
				ServiceCount: len(project.Services),
				Services:     project.ServiceNames(),
			},
		},
		Limitations: project.Limitations,
		Warnings:    append(project.Warnings, warnings...),
		MinSeverity: opts.MinSeverity,
		FailOn:      opts.FailOn,
		Only:        opts.Only,
		Exclude:     opts.Exclude,
	})
	report.Redact(r, composerules.SensitiveValues(project), composerules.Mask)
	return r, nil
}

// ScanHost inspects the local Docker daemon. It returns a
// *docker.UnavailableError when the daemon cannot be used.
func (a *App) ScanHost(ctx context.Context, opts ScanOptions) (*report.Report, error) {
	reg := hostRegistry()
	warnings, err := validateSelection(engine.ScopeHost, opts)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, HostScanTimeout)
	defer cancel()

	started := a.Now()
	conn, err := a.ConnectDocker(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.API.Close()

	snapshot := (&docker.Inspector{Conn: conn, HostFS: a.HostFS, GOOS: a.GOOS}).Inspect(ctx)
	enabled, skipped := engine.Select(reg, engine.Selection{Only: opts.Only, Exclude: opts.Exclude})
	res := engine.Run(enabled, snapshot, engine.RunConfig{ScannerVersion: a.Version.Version, Now: started})

	running := 0
	for _, c := range snapshot.Containers {
		if c.Running {
			running++
		}
	}
	d := snapshot.Daemon
	return report.Build(report.Input{
		Scanner:      a.scanner(),
		ScanType:     report.ScanHost,
		StartedAt:    started,
		FinishedAt:   a.Now(),
		RulesTotal:   len(reg.Rules()),
		Result:       res,
		SkippedRules: skipped,
		Target: report.Target{
			Type: report.ScanHost,
			Name: snapshot.Endpoint,
			Host: &report.HostTarget{
				Endpoint: snapshot.Endpoint, ServerVersion: d.Version, APIVersion: d.APIVersion,
				OperatingSystem: d.OperatingSystem, OSType: d.OSType, Architecture: d.Architecture,
				ContainersTotal: len(snapshot.Containers), ContainersRunning: running, Images: snapshot.ImagesTotal,
			},
		},
		Limitations: snapshot.Limitations,
		Warnings:    warnings,
		MinSeverity: opts.MinSeverity,
		FailOn:      opts.FailOn,
		Only:        opts.Only,
		Exclude:     opts.Exclude,
	}), nil
}

func (a *App) scanner() report.Scanner {
	return report.Scanner{Name: "stacksentry", Version: a.Version.Version, Commit: a.Version.Commit}
}

// suppressor honors x-stacksentry.ignore entries of the affected service.
func suppressor(p *compose.Project) func(findings.Finding) (string, bool) {
	return func(f findings.Finding) (string, bool) {
		if f.TargetType != findings.TargetService {
			return "", false
		}
		svc, ok := p.Service(f.TargetName)
		if !ok {
			return "", false
		}
		reason, ok := svc.Ignore[f.RuleID]
		return reason, ok
	}
}

func unknownSuppressions(p *compose.Project) []string {
	var out []string
	for _, s := range p.Services {
		ids := make([]string, 0, len(s.Ignore))
		for id := range s.Ignore {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			if !composeRegistry().Has(id) {
				out = append(out, fmt.Sprintf("service %q: %s.ignore lists %s, which is not a Compose rule; the entry has no effect.", s.Name, compose.ExtensionKey, id))
			}
		}
	}
	return out
}
