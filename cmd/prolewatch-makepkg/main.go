package main

import (
	"context"
	"github.com/holgerjh/prolewatch/internal/audit"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	status := audit.RunMakepkg(ctx, os.Args[1:])
	stop()
	os.Exit(status)
}
