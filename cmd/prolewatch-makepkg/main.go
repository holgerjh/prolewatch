package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/holgerjh/prolewatch/internal/audit"
)

func main() {
	// Translate termination signals into context cancellation so the wrapper
	// can tear down the complete sandbox process group before exiting.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	// Restore the default disposition after the first signal so a second Ctrl+C
	// can force termination if a child runtime does not complete graceful cleanup.
	go func() {
		<-ctx.Done()
		stop()
	}()
	status := audit.RunMakepkg(ctx, os.Args[1:])
	stop()
	os.Exit(status)
}
