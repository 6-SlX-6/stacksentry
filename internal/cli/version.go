package cli

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/6-SlX-6/stacksentry/internal/app"
)

func newVersionCommand(a *app.App) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(a.Version)
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), a.Version.String())
			return err
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print version information as JSON")
	return cmd
}
