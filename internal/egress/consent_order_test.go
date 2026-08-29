package egress

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// swapSeams replaces the resolver, authorization and dial seams for one test.
func swapSeams(t *testing.T) {
	t.Helper()
	lookup, authorize, dial := networkLookupIPAddr, networkAuthorize, networkDialTCP
	t.Cleanup(func() { networkLookupIPAddr, networkAuthorize, networkDialTCP = lookup, authorize, dial })
}

// A DNS query is egress. Resolving a name before the user has agreed to reach
// it hands the attacker's authoritative server the query - and everything
// encoded in the label - whether or not the user then says no.
//
// The resolver records the violation itself rather than the test inspecting
// order afterwards, so the assertion cannot be satisfied by a code path that
// happens not to be exercised.
func TestNothingIsResolvedBeforeTheUserHasConsented(t *testing.T) {
	swapSeams(t)
	consented := false
	var violation string
	networkLookupIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
		if !consented {
			violation = "resolved " + host + " before the user was asked"
		}
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	}
	networkAuthorize = func(_ *networkBroker, _ context.Context, _ string, _ int, addresses []net.IPAddr) error {
		if len(addresses) != 0 {
			violation = "the prompt was given resolved addresses, so resolution already happened"
		}
		consented = true
		return nil
	}
	broker := &networkBroker{cfg: Config{ConnectTimeoutSeconds: 2, MaxDestinations: 4}}
	_, _ = broker.dialPublic(context.Background(), "collect.attacker.test", 443)
	if violation != "" {
		t.Fatal(violation)
	}
	if !consented {
		t.Fatal("the destination was reached without the prompt being raised at all")
	}
}

// Consent is refused for most packages, and a refusal must still cost the
// package one of its destinations. Otherwise the attempts themselves, each
// producing a prompt, would remain unbounded.
func TestRefusedDestinationsCountAgainstTheLimit(t *testing.T) {
	swapSeams(t)
	resolved := 0
	networkLookupIPAddr = func(_ context.Context, _ string) ([]net.IPAddr, error) {
		resolved++
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	}
	networkAuthorize = func(b *networkBroker, ctx context.Context, host string, port int, addresses []net.IPAddr) error {
		return b.authorize(ctx, host, port, addresses)
	}
	// b.authorize would talk to the prompt agent; there is none, so every
	// destination that gets as far as asking is refused. That is the case under
	// test: refusals must still be counted.
	broker := &networkBroker{cfg: Config{ConnectTimeoutSeconds: 1, MaxDestinations: 2, PromptTimeoutSeconds: 1}}
	var lastErr error
	for _, host := range []string{"a.attacker.test", "b.attacker.test", "c.attacker.test", "d.attacker.test"} {
		_, lastErr = broker.dialPublic(context.Background(), host, 443)
	}
	if lastErr == nil || !strings.Contains(lastErr.Error(), "destination limit") {
		t.Fatalf("the fourth refused destination was not stopped by the limit: %v", lastErr)
	}
	if resolved != 0 {
		t.Fatalf("%d name(s) were resolved despite every destination being refused", resolved)
	}
}

// A hostname that fails validation must be rejected before it is used at all.
func TestMalformedDestinationsAreRejectedWithoutAsking(t *testing.T) {
	swapSeams(t)
	networkLookupIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
		t.Errorf("resolved a malformed destination: %q", host)
		return nil, nil
	}
	networkAuthorize = func(_ *networkBroker, _ context.Context, host string, _ int, _ []net.IPAddr) error {
		t.Errorf("raised a prompt for a malformed destination: %q", host)
		return nil
	}
	broker := &networkBroker{cfg: Config{ConnectTimeoutSeconds: 1, MaxDestinations: 4}}
	for _, host := range []string{"", "not a host", "-leading.test", strings.Repeat("a", 300) + ".test"} {
		if _, err := broker.dialPublic(context.Background(), host, 443); err == nil {
			t.Errorf("%q was accepted as a destination", host)
		}
	}
}

// Consent binds the name and port for the transaction: a second connection to
// the same destination reuses it without a prompt, and a different port does
// not inherit it.
//
// No prompt agent is configured, so anything that reaches the prompt fails.
// That is what makes "reused" and "re-asked" distinguishable here.
func TestConsentIsScopedToHostAndPortAndReusedWithinTheTransaction(t *testing.T) {
	swapSeams(t)
	resolved := []string{}
	networkLookupIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
		resolved = append(resolved, host)
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	}
	networkDialTCP = func(_ context.Context, _ time.Duration, _ string) (net.Conn, error) {
		return nil, net.UnknownNetworkError("no peer in this test")
	}
	broker := &networkBroker{
		cfg:    Config{ConnectTimeoutSeconds: 1, PromptTimeoutSeconds: 1, MaxDestinations: 8},
		grants: map[string]bool{"example.test:443": true},
	}

	// Reaching the dial stage is the assertion: the prompt agent is absent, so
	// anything that had to ask would have failed before resolving.
	if _, err := broker.dialPublic(context.Background(), "EXAMPLE.test", 443); err == nil ||
		!strings.Contains(err.Error(), "all public destinations failed") {
		t.Fatalf("an already-granted destination was not reached: %v", err)
	}
	if len(resolved) != 1 {
		t.Fatalf("a granted destination resolved %d times, want 1: %v", len(resolved), resolved)
	}

	if _, err := broker.dialPublic(context.Background(), "example.test", 8443); err == nil {
		t.Fatal("a different port inherited consent")
	}
	if len(resolved) != 1 {
		t.Fatalf("the un-granted port was resolved anyway: %v", resolved)
	}
}

// After trusted-side acquisition, the verify phase has a frozen source set, so
// the only destination makepkg can legitimately need is a declared VCS host.
// Everything else is refused outright rather than turned into a prompt.
//
// A prompt would be worse than useless here: the user has no basis to judge a
// host the package never declared, and being asked teaches them to approve
// undeclared destinations. Resolving it would already be egress - the query
// reaches the attacker's authoritative server whether or not the answer is no.
func TestAScopedPhaseRefusesUndeclaredHostsWithoutResolvingOrAsking(t *testing.T) {
	swapSeams(t)
	var resolved, asked []string
	networkLookupIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
		resolved = append(resolved, host)
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	}
	networkAuthorize = func(_ *networkBroker, _ context.Context, host string, _ int, _ []net.IPAddr) error {
		asked = append(asked, host)
		return nil
	}
	networkDialTCP = func(_ context.Context, _ time.Duration, _ string) (net.Conn, error) {
		client, server := net.Pipe()
		t.Cleanup(func() { client.Close(); server.Close() })
		return client, nil
	}
	scoped := &networkBroker{cfg: Config{ConnectTimeoutSeconds: 2, IdleTimeoutSeconds: 2, MaxDestinations: 4,
		AllowedHosts: []string{"gitlab.com"}}}

	if _, err := scoped.dialPublic(context.Background(), "collect.attacker.test", 443); err == nil {
		t.Fatal("a host outside the frozen source set was dialled")
	}
	if len(resolved) != 0 || len(asked) != 0 {
		t.Fatalf("an undeclared host produced egress or a prompt: resolved=%v asked=%v", resolved, asked)
	}
	// The declared host still goes through the ordinary consent path; scoping
	// narrows what may be asked about, it does not grant anything by itself.
	if _, err := scoped.dialPublic(context.Background(), "GitLab.com.", 443); err != nil {
		t.Fatalf("the declared VCS host was refused: %v", err)
	}
	if len(asked) != 1 || asked[0] != "GitLab.com." {
		t.Fatalf("the declared host did not reach the prompt: %v", asked)
	}

	// A phase with no frozen set - prepare and build - keeps the prompt as its
	// anomaly detector, because a build dependency cannot be known in advance.
	open := &networkBroker{cfg: Config{ConnectTimeoutSeconds: 2, IdleTimeoutSeconds: 2, MaxDestinations: 4}}
	if _, err := open.dialPublic(context.Background(), "crates.io", 443); err != nil {
		t.Fatalf("an unscoped phase refused a destination the user could have approved: %v", err)
	}
}

// A tunnel is a byte pipe to a checked IP address, and an IP is not a host. On
// a shared reverse proxy or CDN the same address serves any number of virtual
// hosts, so a client granted approved.example can name attacker.example in its
// TLS SNI and reach a different service over the approved connection - without
// the broker ever being asked about it, and without leaving the frozen VCS host
// set that verify enforces.
func TestATunnelMustNameTheHostItWasApprovedFor(t *testing.T) {
	hello := func(name string) []byte {
		var extension []byte
		if name != "" {
			entry := append([]byte{0}, byte(len(name)>>8), byte(len(name)))
			entry = append(entry, name...)
			list := append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)
			extension = append([]byte{0, 0, byte(len(list) >> 8), byte(len(list))}, list...)
		}
		body := []byte{0x03, 0x03}
		body = append(body, make([]byte, 32)...) // random
		body = append(body, 0)                   // session id
		body = append(body, 0, 2, 0x13, 0x01)    // cipher suites
		body = append(body, 1, 0)                // compression
		body = append(body, byte(len(extension)>>8), byte(len(extension)))
		body = append(body, extension...)
		handshake := append([]byte{0x01, 0, byte(len(body) >> 8), byte(len(body))}, body...)
		return append([]byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}, handshake...)
	}

	for name, current := range map[string]struct {
		approved string
		opening  []byte
		allowed  bool
	}{
		"matching SNI":              {"approved.example", hello("approved.example"), true},
		"SNI case and trailing dot": {"approved.example", hello("Approved.Example."), true},
		"fronted SNI":               {"approved.example", hello("attacker.example"), false},
		"no SNI at all":             {"approved.example", hello(""), false},
		"not TLS and no Host":       {"approved.example", []byte("GET / HTTP/1.1\r\n\r\n"), false},
		"matching HTTP Host":        {"approved.example", []byte("GET / HTTP/1.1\r\nHost: approved.example\r\n\r\n"), true},
		"fronted HTTP Host":         {"approved.example", []byte("GET / HTTP/1.1\r\nHost: attacker.example\r\n\r\n"), false},
		// An approved IP literal promised no host, so there is nothing to check
		// and nothing for the client to contradict.
		"approved IP literal": {"93.184.216.34", hello("anything.example"), true},
	} {
		stream, err := checkTunnelHost(current.approved, bytes.NewReader(append(current.opening, []byte("payload")...)))
		if current.allowed != (err == nil) {
			t.Errorf("%s: allowed=%t err=%v", name, current.allowed, err)
			continue
		}
		if err != nil {
			continue
		}
		// The inspected bytes must still reach the upstream, or every checked
		// connection breaks at its first handshake.
		forwarded, readErr := io.ReadAll(stream)
		if readErr != nil {
			t.Errorf("%s: replay failed: %v", name, readErr)
			continue
		}
		if !bytes.Equal(forwarded, append(current.opening, []byte("payload")...)) {
			t.Errorf("%s: the opening bytes were consumed instead of replayed (%d of %d)",
				name, len(forwarded), len(current.opening)+len("payload"))
		}
	}
}
