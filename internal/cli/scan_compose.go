package cli

import (
	"github.com/spf13/cobra"

	"github.com/6-SlX-6/stacksentry/internal/app"
)

func newScanComposeCommand(a *app.App, s Streams) *cobra.Command {
	var flags scanFlags
	cmd := &cobra.Command{
		Use:   "compose <path> [<path>...]",
		Short: "Statically analyze Docker Compose files",
		Long: "Statically analyze Docker Compose files. No Docker daemon is required.\n\n" +
			"Pass one Compose file, several files to merge (like repeated \"docker compose -f\"), or a\n" +
			"directory, in which case compose.yaml, compose.yml, docker-compose.yaml or docker-compose.yml\n" +
			"and a matching override file are used, as Docker Compose would.\n\n" +
			"Variables are interpolated deterministically: the shell environment and .env files are not\n" +
			"read. Defaults written in the file are used; variables without a default are treated as empty\n" +
			"and reported by SST-CFG-001." + scanFlagsHelp,
		Example: "  stacksentry scan compose ./docker-compose.yml\n" +
			"  stacksentry scan compose ./compose.yaml --format markdown --output report.md\n" +
			"  stacksentry scan compose ./docker-compose.yml --fail-on high\n" +
			"  stacksentry scan compose ./docker-compose.yml --exclude SST-SEC-001,SST-OPS-003\n" +
			"  stacksentry scan compose compose.yaml compose.prod.yaml --severity medium",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			parsed, err := flags.parse(s)
			if err != nil {
				return err
			}
			r, err := a.ScanCompose(cmd.Context(), args, parsed.opts)
			if err != nil {
				return err
			}
			return emit(s, r, parsed)
		},
	}
	flags.register(cmd)
	return cmd
}
