package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/holgerjh/prolewatch/internal/egress"
)

func main() {
	// Exit 20 denotes malformed internal invocation. This binary is launched by
	// Prolewatch with one of two fixed argv shapes; it is not a general user CLI.
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "prolewatch-net: broker|supervise SOCKET [limits|-- command]")
		os.Exit(egress.ExitInvalidInvocation)
	}
	switch os.Args[1] {
	case "broker":
		// broker PROXY_SOCKET PROMPT_SOCKET MAX_CONNECTIONS CONNECT_TIMEOUT
		// IDLE_TIMEOUT MAX_BYTES PROMPT_TIMEOUT MAX_DESTINATIONS MAX_REQUESTS ALLOWED_HOSTS
		//
		// ALLOWED_HOSTS is egress.NoAllowedHosts for a phase with no host
		// restriction, otherwise a comma-separated set the broker may not
		// contact outside of.
		if len(os.Args) != 12 {
			os.Exit(egress.ExitInvalidInvocation)
		}
		connections, err1 := strconv.Atoi(os.Args[4])
		connectTimeout, err2 := strconv.Atoi(os.Args[5])
		idleTimeout, err3 := strconv.Atoi(os.Args[6])
		transfer, err4 := strconv.ParseInt(os.Args[7], 10, 64)
		promptTimeout, err5 := strconv.Atoi(os.Args[8])
		maxDestinations, err6 := strconv.Atoi(os.Args[9])
		maxRequests, err7 := strconv.Atoi(os.Args[10])
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil || err6 != nil || err7 != nil {
			os.Exit(egress.ExitInvalidInvocation)
		}
		var allowedHosts []string
		if os.Args[11] != egress.NoAllowedHosts {
			allowedHosts = strings.Split(os.Args[11], ",")
		}
		os.Exit(egress.RunNetworkBroker(context.Background(), os.Args[2], os.Args[3], egress.Config{
			MaxConnections: connections, ConnectTimeoutSeconds: connectTimeout,
			IdleTimeoutSeconds: idleTimeout, MaxTransferBytes: transfer,
			Mode: "prompt", GrantScope: "transaction", PromptTimeoutSeconds: promptTimeout, MaxDestinations: maxDestinations, MaxRequests: maxRequests,
			AllowedHosts: allowedHosts,
		}))
	case "supervise":
		// supervise PROXY_SOCKET -- COMMAND [ARG...]
		if len(os.Args) < 5 || os.Args[3] != "--" {
			os.Exit(egress.ExitInvalidInvocation)
		}
		os.Exit(egress.RunNetworkSupervisor(context.Background(), os.Args[2], os.Args[4:]))
	default:
		os.Exit(egress.ExitInvalidInvocation)
	}
}
