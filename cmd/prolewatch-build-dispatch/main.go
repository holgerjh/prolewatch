package main

import (
	"context"
	"os"

	"github.com/holgerjh/prolewatch/internal/audit"
)

func main() { os.Exit(audit.RunBuildDispatcher(context.Background())) }
