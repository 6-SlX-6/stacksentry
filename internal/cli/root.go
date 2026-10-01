// Package cli implements the stacksentry command-line interface.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/6-SlX-6/stacksentry/internal/app"
)

// Exit codes. See docs/exit-codes.md.
const (
	// ExitOK means the command succeeded and no finding met --fail-on.
	ExitOK = 0
	// ExitFindings means at least one finding met the --fail-on threshold.
	ExitFindings = 1
	// ExitError means invalid input, an unreadable file, an invalid
	// configuration or an unavailable Docker daemon.
	ExitError = 2
)

// errThresholdExceeded signals exit code 1 without printing an error; the
// report already explains which findings met the threshold.
var errThresholdExceeded = errors.New("findings at or above the --fail-on threshold")

// usageError marks errors caused by invalid command-line usage.
type usageError struct{ err error }

func (e *usageError) Error() string { return e.err.Error() }
func (e *usageError) Unwrap() error { return e.err }

// Streams are the standard streams of the process.
type Streams struct {
	Out io.Writer
	Err io.Writer
	// IsTerminal reports whether w is an interactive terminal.
	IsTerminal func(w io.Writer) bool
}

// Execute runs the CLI with the given arguments and returns the exit code.
func Execute(ctx context.Context, args []string, a *app.App, s Streams) int {
	if s.IsTerminal == nil {
		s.IsTerminal = func(io.Writer) bool { return false }
	}
	root := NewRootCommand(a, s)
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	switch {
	case err == nil:
		return ExitOK
	case errors.Is(err, errThresholdExceeded):
		return ExitFindings
	}
	fmt.Fprintf(s.Err, "Error: %s\n", err)
	var ue *usageError
	if errors.As(err, &ue) || isCobraUsageError(err) {
		fmt.Fprintf(s.Err, "Run '%s --help' for usage.\n", commandPath(root, args))
	}
	return ExitError
}

// NewRootCommand builds the command tree.
func NewRootCommand(a *app.App, s Streams) *cobra.Command {
	root := &cobra.Command{
		Use:   "stacksentry",
		Short: "Check Docker Compose stacks and Docker hosts before you deploy",
		Long: "StackSentry is a local-first preflight checker for Docker Compose stacks and Docker hosts.\n" +
			"It reports insecure, fragile, outdated or incomplete configuration with evidence and\n" +
			"remediation guidance. It runs entirely on your machine: no telemetry, no cloud services.",
		Example: "  stacksentry scan compose ./docker-compose.yml\n" +
			"  stacksentry scan compose ./compose.yaml --format markdown --output report.md\n" +
			"  stacksentry scan compose ./docker-compose.yml --fail-on high\n" +
			"  stacksentry scan host --format json --output stacksentry-host-report.json\n" +
			"  stacksentry rules list",
		Version:       a.Version.Version,
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	root.SetOut(s.Out)
	root.SetErr(s.Err)
	root.SetVersionTemplate(a.Version.String() + "\n")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return &usageError{err} })
	root.AddCommand(newVersionCommand(a), newScanCommand(a, s), newRulesCommand())
	return root
}

func isCobraUsageError(err error) bool {
	msg := err.Error()
	return strings.HasPrefix(msg, "unknown command") || strings.HasPrefix(msg, "accepts ") ||
		strings.HasPrefix(msg, "requires at least") || strings.HasPrefix(msg, "unknown flag") ||
		strings.HasPrefix(msg, "invalid argument")
}

// commandPath returns the deepest known command named in args for the
// usage hint, e.g. "stacksentry scan compose".
func commandPath(root *cobra.Command, args []string) string {
	cmd, _, err := root.Find(args)
	if err != nil || cmd == nil {
		return root.Name()
	}
	return cmd.CommandPath()
}

// isTerminalFile reports whether w is a terminal character device.
func isTerminalFile(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// DefaultStreams returns the process' standard streams.
func DefaultStreams() Streams {
	return Streams{Out: os.Stdout, Err: os.Stderr, IsTerminal: func(w io.Writer) bool {
		return isTerminalFile(w) && enableVirtualTerminal(w)
	}}
}
