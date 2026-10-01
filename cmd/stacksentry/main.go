// Command stacksentry is a local-first Docker Compose and Docker host
// preflight checker.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/6-SlX-6/stacksentry/internal/app"
	"github.com/6-SlX-6/stacksentry/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := cli.Execute(ctx, os.Args[1:], app.New(), cli.DefaultStreams())
	stop()
	os.Exit(code)
}
