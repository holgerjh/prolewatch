package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/holgerjh/prolewatch/internal/audit"
	"github.com/holgerjh/prolewatch/internal/scenarios"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// Restore the default disposition after the first signal. The first Ctrl+C
	// requests orderly cancellation; a second one must still be able to terminate
	// immediately if an external runtime does not finish its bounded cleanup.
	go func() {
		<-ctx.Done()
		stop()
	}()
	status := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(status)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	// The scenario command accepts explicit streams for hermetic acceptance
	// output; the regular CLI owns its terminal presentation internally.
	if len(args) > 0 && args[0] == "security-scenarios" {
		return scenarios.RunCLI(args[1:], stdout, stderr)
	}
	return audit.RunCLI(ctx, args)
}
