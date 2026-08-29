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
	status := audit.RunMakepkg(ctx, os.Args[1:])
	stop()
	os.Exit(status)
}
