package main

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/holgerjh/prolewatch/internal/audit"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "prolewatch-net: broker|supervise SOCKET [limits|-- command]")
		os.Exit(20)
	}
	switch os.Args[1] {
	case "broker":
		if len(os.Args) != 7 {
			os.Exit(20)
		}
		connections, err1 := strconv.Atoi(os.Args[3])
		connectTimeout, err2 := strconv.Atoi(os.Args[4])
		idleTimeout, err3 := strconv.Atoi(os.Args[5])
		transfer, err4 := strconv.ParseInt(os.Args[6], 10, 64)
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
			os.Exit(20)
		}
		os.Exit(audit.RunNetworkBroker(context.Background(), os.Args[2], audit.NetworkConfig{
			MaxConnections: connections, ConnectTimeoutSeconds: connectTimeout,
			IdleTimeoutSeconds: idleTimeout, MaxTransferBytes: transfer,
		}))
	case "supervise":
		if len(os.Args) < 5 || os.Args[3] != "--" {
			os.Exit(20)
		}
		os.Exit(audit.RunNetworkSupervisor(context.Background(), os.Args[2], os.Args[4:]))
	default:
		os.Exit(20)
	}
}
