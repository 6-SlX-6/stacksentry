package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/6-SlX-6/stacksentry/internal/app"
	"github.com/6-SlX-6/stacksentry/internal/engine"
	"github.com/6-SlX-6/stacksentry/internal/findings"
	"github.com/6-SlX-6/stacksentry/internal/report"
)

func newScanCommand(a *app.App, s Streams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a Docker Compose project or the local Docker host",
		Long: "Scan a Docker Compose project statically (scan compose) or inspect the local Docker daemon\n" +
			"(scan host). Both commands share the same output, filtering and exit code options.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newScanComposeCommand(a, s), newScanHostCommand(a, s))
	return cmd
}

// scanFlags holds the flags shared by both scan commands.
type scanFlags struct {
	format   string
	output   string
	severity string
	failOn   string
	noColor  bool
	quiet    bool
	exclude  []string
	only     []string
}

const scanFlagsHelp = `
Filtering and exit codes:
  --severity hides less severe findings from the report; it does not change
  which rules run. --fail-on is evaluated against all findings of the rules
  that ran, including findings hidden by --severity, so the exit code never
  depends on presentation. Findings suppressed with x-stacksentry never count.

  Exit codes: 0 = no finding at or above --fail-on (or --fail-on not set),
  1 = at least one finding at or above --fail-on, 2 = error (invalid input,
  unreadable or invalid file, Docker daemon unavailable).`

func (f *scanFlags) register(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringVarP(&f.format, "format", "f", "table", "output format: table, json or markdown")
	fl.StringVarP(&f.output, "output", "o", "", "write the report to this file instead of stdout")
	fl.StringVar(&f.severity, "severity", "info", "only show findings at or above this severity: info, low, medium, high or critical")
	fl.StringVar(&f.failOn, "fail-on", "", "exit with code 1 if a finding at or above this severity exists: info, low, medium, high or critical")
	fl.BoolVar(&f.noColor, "no-color", false, "disable colored output (also honors the NO_COLOR environment variable)")
	fl.BoolVarP(&f.quiet, "quiet", "q", false, "print only findings in table output and no status messages")
	fl.StringSliceVar(&f.exclude, "exclude", nil, "rule IDs to skip, comma-separated or repeated (e.g. SST-SEC-001,SST-OPS-003)")
	fl.StringSliceVar(&f.only, "only", nil, "run only these rule IDs, comma-separated or repeated")
	_ = cmd.RegisterFlagCompletionFunc("format", cobra.FixedCompletions([]string{"table", "json", "markdown"}, cobra.ShellCompDirectiveNoFileComp))
	severities := cobra.FixedCompletions(findings.SeverityNames(), cobra.ShellCompDirectiveNoFileComp)
	_ = cmd.RegisterFlagCompletionFunc("severity", severities)
	_ = cmd.RegisterFlagCompletionFunc("fail-on", severities)
	ruleIDs := func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		var ids []string
		for _, m := range app.Rules() {
			ids = append(ids, m.ID+"\t"+m.Title)
		}
		return ids, cobra.ShellCompDirectiveNoFileComp
	}
	_ = cmd.RegisterFlagCompletionFunc("exclude", ruleIDs)
	_ = cmd.RegisterFlagCompletionFunc("only", ruleIDs)
}

// parsedScanFlags are validated scan options.
type parsedScanFlags struct {
	opts   app.ScanOptions
	render report.RenderOptions
	output string
	quiet  bool
}

func (f *scanFlags) parse(s Streams) (parsedScanFlags, error) {
	format, err := report.ParseFormat(f.format)
	if err != nil {
		return parsedScanFlags{}, &usageError{err}
	}
	minSev, err := findings.ParseSeverity(f.severity)
	if err != nil {
		return parsedScanFlags{}, &usageError{fmt.Errorf("--severity: %w", err)}
	}
	var failOn *findings.Severity
	if v := strings.TrimSpace(f.failOn); v != "" && !strings.EqualFold(v, "none") {
		sev, err := findings.ParseSeverity(v)
		if err != nil {
			return parsedScanFlags{}, &usageError{fmt.Errorf("--fail-on: %w", err)}
		}
		failOn = &sev
	}
	if strings.TrimSpace(f.output) == "" && f.output != "" {
		return parsedScanFlags{}, &usageError{fmt.Errorf("--output: file name is empty")}
	}
	color := format == report.FormatTable && f.output == "" && !f.noColor &&
		os.Getenv("NO_COLOR") == "" && s.IsTerminal(s.Out)
	return parsedScanFlags{
		opts: app.ScanOptions{
			MinSeverity: minSev,
			FailOn:      failOn,
			Only:        engine.ParseRuleIDs(f.only),
			Exclude:     engine.ParseRuleIDs(f.exclude),
		},
		render: report.RenderOptions{Format: format, Table: report.TableOptions{Color: color, Quiet: f.quiet}},
		output: f.output,
		quiet:  f.quiet,
	}, nil
}

// emit renders or writes the report and converts the --fail-on result into
// the command's error.
func emit(s Streams, r *report.Report, p parsedScanFlags) error {
	if p.output != "" {
		if err := report.WriteFile(p.output, r, p.render); err != nil {
			return err
		}
		if !p.quiet {
			status := ""
			if r.Summary.FailOn != nil {
				status = ", result: " + strings.ToUpper(r.Summary.Result)
			}
			fmt.Fprintf(s.Err, "Report written to %s (%d findings%s)\n", p.output, r.Summary.Total, status)
		}
	} else if err := report.Render(s.Out, r, p.render); err != nil {
		return err
	}
	if r.Failed() {
		return errThresholdExceeded
	}
	return nil
}
