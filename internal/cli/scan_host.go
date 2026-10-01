package cli

import (
	"github.com/spf13/cobra"

	"github.com/6-SlX-6/stacksentry/internal/app"
)

func newScanHostCommand(a *app.App, s Streams) *cobra.Command {
	var flags scanFlags
	cmd := &cobra.Command{
		Use:   "host",
		Short: "Inspect the local Docker daemon (read-only)",
		Long: "Inspect the Docker daemon selected by DOCKER_HOST (default: the local socket) through the\n" +
			"Docker Engine API. Only read-only API calls are made; nothing is started, stopped, removed or\n" +
			"reconfigured. On Linux, /etc/docker/daemon.json and /proc are read to find TCP listeners when\n" +
			"permissions allow. Missing permissions are reported as scan limitations.\n\n" +
			"If the daemon is not reachable, the command exits with code 2." + scanFlagsHelp,
		Example: "  stacksentry scan host\n" +
			"  stacksentry scan host --format json --output stacksentry-host-report.json\n" +
			"  DOCKER_HOST=unix:///run/user/1000/docker.sock stacksentry scan host --fail-on critical",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			parsed, err := flags.parse(s)
			if err != nil {
				return err
			}
			r, err := a.ScanHost(cmd.Context(), parsed.opts)
			if err != nil {
				return err
			}
			return emit(s, r, parsed)
		},
	}
	flags.register(cmd)
	return cmd
}
