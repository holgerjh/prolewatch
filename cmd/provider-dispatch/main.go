package main

import (
	"context"
	"github.com/holgerjh/prolewatch/internal/audit"
	"os"
)

func main() {
	if len(os.Args) != 1 {
		os.Stderr.WriteString("provider-dispatch accepts no arguments\n")
		os.Exit(20)
	}
	os.Exit(audit.RunProviderDispatcher(context.Background(), os.Stdin, os.Stdout, os.Stderr))
}
