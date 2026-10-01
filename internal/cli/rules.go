package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/6-SlX-6/stacksentry/internal/app"
	"github.com/6-SlX-6/stacksentry/internal/engine"
	"github.com/6-SlX-6/stacksentry/internal/report"
)

func newRulesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "List and explain the built-in rules",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return cmd.Help() },
	}
	cmd.AddCommand(newRulesListCommand(), newRulesShowCommand())
	return cmd
}

// ruleJSON is the stable JSON representation of rule metadata.
type ruleJSON struct {
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	Severity      string   `json:"severity"`
	Category      string   `json:"category"`
	Scope         string   `json:"scope"`
	Version       string   `json:"version"`
	Description   string   `json:"description"`
	WhyItMatters  string   `json:"why_it_matters"`
	Remediation   string   `json:"remediation"`
	Detection     string   `json:"detection"`
	Limitations   string   `json:"limitations,omitempty"`
	References    []string `json:"references"`
	Documentation string   `json:"documentation"`
}

func toJSON(m engine.Metadata) ruleJSON {
	refs := m.References
	if refs == nil {
		refs = []string{}
	}
	return ruleJSON{
		ID: m.ID, Title: m.Title, Severity: m.Severity.String(), Category: string(m.Category), Scope: string(m.Scope),
		Version: m.Version, Description: m.Description, WhyItMatters: m.Rationale, Remediation: m.Remediation,
		Detection: m.Detection, Limitations: m.Limitations, References: refs, Documentation: m.DocumentationURL(),
	}
}

func newRulesListCommand() *cobra.Command {
	var format, scope string
	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List all rules",
		Example: "  stacksentry rules list\n  stacksentry rules list --scope host\n  stacksentry rules list --format json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := report.ParseFormat(format)
			if err != nil {
				return &usageError{err}
			}
			var rules []engine.Metadata
			for _, m := range app.Rules() {
				if scope == "" || string(m.Scope) == strings.ToLower(scope) {
					rules = append(rules, m)
				}
			}
			if scope != "" && len(rules) == 0 {
				return &usageError{fmt.Errorf("invalid scope %q: must be compose or host", scope)}
			}
			out := cmd.OutOrStdout()
			switch f {
			case report.FormatJSON:
				list := make([]ruleJSON, 0, len(rules))
				for _, m := range rules {
					list = append(list, toJSON(m))
				}
				return writeJSON(out, list)
			case report.FormatMarkdown:
				fmt.Fprintln(out, "| Rule ID | Severity | Category | Scope | Title |")
				fmt.Fprintln(out, "|---|---|---|---|---|")
				for _, m := range rules {
					fmt.Fprintf(out, "| [%s](#%s) | %s | %s | %s | %s |\n", m.ID, strings.ToLower(m.ID), m.Severity, m.Category, m.Scope, report.EscapeMarkdown(m.Title))
				}
				return nil
			default:
				tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
				fmt.Fprintln(tw, "ID\tSEVERITY\tCATEGORY\tSCOPE\tTITLE")
				for _, m := range rules {
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", m.ID, m.Severity, m.Category, m.Scope, m.Title)
				}
				if err := tw.Flush(); err != nil {
					return err
				}
				_, err := fmt.Fprintf(out, "\n%d rules. Run \"stacksentry rules show <rule-id>\" for details.\n", len(rules))
				return err
			}
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format: table, json or markdown")
	cmd.Flags().StringVar(&scope, "scope", "", "only list rules of one scan mode: compose or host")
	return cmd
}

func newRulesShowCommand() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:     "show <rule-id>",
		Short:   "Explain one rule",
		Example: "  stacksentry rules show SST-SEC-001",
		Args:    cobra.ExactArgs(1),
		ValidArgsFunction: func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
			var ids []string
			for _, m := range app.Rules() {
				ids = append(ids, m.ID+"\t"+m.Title)
			}
			return ids, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			f, err := report.ParseFormat(format)
			if err != nil {
				return &usageError{err}
			}
			m, ok := app.Rule(args[0])
			if !ok {
				return &usageError{fmt.Errorf("unknown rule ID %q; run \"stacksentry rules list\" to see all rules", args[0])}
			}
			out := cmd.OutOrStdout()
			switch f {
			case report.FormatJSON:
				return writeJSON(out, toJSON(m))
			case report.FormatMarkdown:
				return writeRuleMarkdown(out, m)
			default:
				return writeRuleText(out, m)
			}
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format: table, json or markdown")
	return cmd
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func writeRuleText(w io.Writer, m engine.Metadata) error {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s\n\n", m.ID, m.Title)
	fmt.Fprintf(&b, "Default severity: %s\nCategory:         %s\nScope:            %s scan\nRule version:     %s\n",
		m.Severity, m.Category, m.Scope, m.Version)
	section := func(title, body string) {
		if body == "" {
			return
		}
		fmt.Fprintf(&b, "\n%s:\n", title)
		for _, line := range wrapText(body, "  ", report.DefaultWidth) {
			fmt.Fprintln(&b, line)
		}
	}
	section("Description", m.Description)
	section("Why it matters", m.Rationale)
	section("Remediation", m.Remediation)
	section("Detection", m.Detection)
	section("Limitations and false positives", m.Limitations)
	if len(m.References) > 0 {
		fmt.Fprintln(&b, "\nReferences:")
		for _, r := range m.References {
			fmt.Fprintf(&b, "  - %s\n", r)
		}
	}
	fmt.Fprintf(&b, "\nDocumentation: %s\n", m.DocumentationURL())
	_, err := io.WriteString(w, b.String())
	return err
}

func writeRuleMarkdown(w io.Writer, m engine.Metadata) error {
	var b strings.Builder
	esc := report.EscapeMarkdown
	fmt.Fprintf(&b, "### %s\n\n**%s**\n\n", m.ID, esc(m.Title))
	fmt.Fprintf(&b, "| Default severity | Category | Scope | Version |\n|---|---|---|---|\n| %s | %s | %s | %s |\n\n",
		m.Severity, m.Category, m.Scope, m.Version)
	fmt.Fprintf(&b, "%s\n\n", esc(m.Description))
	fmt.Fprintf(&b, "- **Detection:** %s\n", esc(m.Detection))
	fmt.Fprintf(&b, "- **Why it matters:** %s\n", esc(m.Rationale))
	fmt.Fprintf(&b, "- **Remediation:** %s\n", esc(m.Remediation))
	if m.Limitations != "" {
		fmt.Fprintf(&b, "- **Limitations and false positives:** %s\n", esc(m.Limitations))
	}
	if len(m.References) > 0 {
		fmt.Fprintf(&b, "- **References:** %s\n", strings.Join(m.References, ", "))
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// wrapText wraps body to width with every line indented by indent.
func wrapText(body, indent string, width int) []string {
	words := strings.Fields(body)
	var lines []string
	line := indent
	for _, w := range words {
		if line != indent && len(line)+1+len(w) > width {
			lines = append(lines, line)
			line = indent
		}
		if line != indent {
			line += " "
		}
		line += w
	}
	if line != indent {
		lines = append(lines, line)
	}
	return lines
}

// writeRulesReference renders the generated part of docs/rules.md: a
// summary table followed by one section per rule, Compose rules first.
func writeRulesReference(w io.Writer) error {
	all := app.Rules()
	var b strings.Builder
	for _, scope := range []engine.Scope{engine.ScopeCompose, engine.ScopeHost} {
		title := "Compose rules (`stacksentry scan compose`)"
		if scope == engine.ScopeHost {
			title = "Host rules (`stacksentry scan host`)"
		}
		fmt.Fprintf(&b, "## %s\n\n", title)
		fmt.Fprintln(&b, "| Rule ID | Severity | Category | Title |")
		fmt.Fprintln(&b, "|---|---|---|---|")
		for _, m := range all {
			if m.Scope == scope {
				fmt.Fprintf(&b, "| [%s](#%s) | %s | %s | %s |\n", m.ID, strings.ToLower(m.ID), m.Severity, m.Category, report.EscapeMarkdown(m.Title))
			}
		}
		fmt.Fprintln(&b)
		for _, m := range all {
			if m.Scope != scope {
				continue
			}
			if err := writeRuleMarkdown(&b, m); err != nil {
				return err
			}
			fmt.Fprintln(&b)
		}
	}
	_, err := io.WriteString(w, strings.TrimRight(b.String(), "\n")+"\n")
	return err
}
