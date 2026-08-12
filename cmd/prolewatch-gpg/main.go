package main

import (
	"github.com/holgerjh/prolewatch/internal/audit"
	"os"
)

func main() { os.Exit(audit.RunGPG(os.Args[1:])) }
