package main

import (
	"os"

	"github.com/holgerjh/prolewatch/internal/audit"
)

// Keep the GPG wrapper as a thin process boundary: argument validation and the
// isolated GnuPG invocation live in audit.RunGPG.
func main() { os.Exit(audit.RunGPG(os.Args[1:])) }
