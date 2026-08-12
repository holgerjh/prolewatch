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
	status := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(status)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "security-scenarios" {
		return scenarios.RunCLI(args[1:], stdout, stderr)
	}
	return audit.RunCLI(ctx, args)
}
