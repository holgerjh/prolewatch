package egress

// Broker tests exercise protocol denials, the non-public address policy, the
// transfer limit, and the supervisor relay without an external network.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func shortSocketDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "prolewatch-egress-socket-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

func TestBrokerProcessAttributesRequestLimitExit(t *testing.T) {
	command := exec.Command("/usr/bin/sh", "-c", fmt.Sprintf("exit %d", ExitRequestLimit))
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	process := &BrokerProcess{command: command, done: make(chan struct{})}
	go func() {
		process.waitErr = command.Wait()
		close(process.done)
	}()
	<-process.Done()
	if err := process.Failure(); !errors.Is(err, ErrRequestLimit) {
		t.Fatalf("request-limit exit was not attributed: %v", err)
	}
}

func runBrokerExchange(t *testing.T, payload []byte) []byte {
	t.Helper()
	server, client := net.Pipe()
	broker := &networkBroker{cfg: Config{MaxConnections: 2, ConnectTimeoutSeconds: 1, IdleTimeoutSeconds: 1, MaxTransferBytes: 1024 * 1024}}
	done := make(chan struct{})
	go func() {
		broker.handle(server)
		close(done)
	}()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = client.Write(payload)
	raw, _ := io.ReadAll(client)
	client.Close()
	<-done
	return raw
}

func TestBrokerProtocolDenialsWithoutExternalNetwork(t *testing.T) {
	for _, request := range [][]byte{
		[]byte("CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n"),
		[]byte("CONNECT example.com:22 HTTP/1.1\r\nHost: example.com:22\r\n\r\n"),
		[]byte("GET /relative HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		[]byte("GET http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"),
	} {
		if raw := runBrokerExchange(t, request); !bytes.Contains(raw, []byte("403")) && !bytes.Contains(raw, []byte("502")) {
			t.Fatalf("proxy denial missing: %q", raw)
		}
	}
	server, client := net.Pipe()
	broker := &networkBroker{cfg: Config{MaxConnections: 2, ConnectTimeoutSeconds: 1, IdleTimeoutSeconds: 1, MaxTransferBytes: 1024}}
	done := make(chan struct{})
	go func() { broker.handle(server); close(done) }()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = client.Write([]byte{5, 1, 0})
	auth := make([]byte, 2)
	_, _ = io.ReadFull(client, auth)
	if !bytes.Equal(auth, []byte{5, 0}) {
		t.Fatalf("unexpected SOCKS negotiation: %v", auth)
	}
	_, _ = client.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, 1, 0})
	reply := make([]byte, 10)
	_, _ = io.ReadFull(client, reply)
	client.Close()
	<-done
	if reply[1] != 2 {
		t.Fatalf("SOCKS loopback was not denied: %v", reply)
	}
}

func TestSOCKSAddressAndAuthenticationDenials(t *testing.T) {
	exchange := func(methods, request []byte, responseSize int) []byte {
		server, client := net.Pipe()
		broker := &networkBroker{cfg: Config{ConnectTimeoutSeconds: 1, IdleTimeoutSeconds: 1, MaxTransferBytes: 1024}}
		done := make(chan struct{})
		go func() { broker.handle(server); close(done) }()
		_ = client.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = client.Write(methods)
		response := make([]byte, 2)
		_, _ = io.ReadFull(client, response)
		if request != nil && bytes.Equal(response, []byte{5, 0}) {
			_, _ = client.Write(request)
			reply := make([]byte, responseSize)
			_, _ = io.ReadFull(client, reply)
			response = append(response, reply...)
		}
		client.Close()
		<-done
		return response
	}
	if response := exchange([]byte{5, 1, 2}, nil, 0); !bytes.Equal(response, []byte{5, 0xff}) {
		t.Fatalf("authenticated SOCKS method accepted: %v", response)
	}
	domain := append([]byte{5, 1, 0, 3, 9}, []byte("localhost")...)
	domain = append(domain, 1, 187)
	if response := exchange([]byte{5, 1, 0}, domain, 10); len(response) != 12 || response[3] != 2 {
		t.Fatalf("SOCKS domain loopback was not denied: %v", response)
	}
	ipv6 := append([]byte{5, 1, 0, 4}, net.ParseIP("::1").To16()...)
	ipv6 = append(ipv6, 1, 187)
	if response := exchange([]byte{5, 1, 0}, ipv6, 10); len(response) != 12 || response[3] != 2 {
		t.Fatalf("SOCKS IPv6 loopback was not denied: %v", response)
	}
	if response := exchange([]byte{5, 1, 0}, []byte{5, 2, 0, 1}, 0); !bytes.Equal(response, []byte{5, 0}) {
		t.Fatalf("unsupported SOCKS command handling changed: %v", response)
	}
}

func TestNetworkProcessBrokerSupervisorAndRelays(t *testing.T) {
	previousListen, previousExec, previousContext, previousReady, previousDial, previousPrompt := networkListen, networkExecCommand, networkCommandContext, networkSocketReady, networkRelayDial, networkPromptAgentStart
	defer func() {
		networkListen, networkExecCommand, networkCommandContext, networkSocketReady, networkRelayDial, networkPromptAgentStart = previousListen, previousExec, previousContext, previousReady, previousDial, previousPrompt
	}()
	networkPromptAgentStart = func(string, Config, PromptFunc) (net.Listener, error) { return nil, nil }
	var brokerArgs []string
	networkExecCommand = func(_ string, args ...string) *exec.Cmd {
		brokerArgs = append([]string(nil), args...)
		return exec.Command("/usr/bin/sh", "-c", "sleep 10")
	}
	networkSocketReady = func(string) bool { return true }
	process, err := StartBroker(t.TempDir(), DefaultConfig(), DenyAll)
	if err != nil {
		t.Fatal(err)
	}
	joinedBrokerArgs := strings.Join(brokerArgs, "\x00")
	if !strings.Contains(joinedBrokerArgs, "/broker-client/proxy.sock\x00/broker-control/prompt.sock") ||
		!strings.Contains(joinedBrokerArgs, "client\x00/broker-client") || !strings.Contains(joinedBrokerArgs, "control\x00/broker-control") {
		t.Fatalf("broker data and prompt control sockets were not isolated: %q", joinedBrokerArgs)
	}
	if !strings.Contains(joinedBrokerArgs, "--unshare-all\x00--share-net\x00--unshare-user\x00--disable-userns\x00--assert-userns-disabled") {
		t.Fatalf("broker cannot enforce its nested-userns clamp: %q", joinedBrokerArgs)
	}
	if strings.Contains(joinedBrokerArgs, "--userns\x00") {
		t.Fatalf("standalone broker unexpectedly joins a caller-supplied user namespace: %q", joinedBrokerArgs)
	}
	// An unscoped phase says so explicitly rather than passing an empty argument
	// that a later reader could take either way.
	if !strings.HasSuffix(joinedBrokerArgs, "\x00"+NoAllowedHosts) {
		t.Fatalf("an unrestricted phase did not say so in the broker argv: %q", joinedBrokerArgs)
	}
	process.Stop()

	// The host set crosses a process boundary as argv, so it has to arrive
	// normalised and it has to arrive at all.
	scoped := DefaultConfig()
	scoped.AllowedHosts = []string{"GitLab.com.", "git.example.org"}
	process, err = StartBroker(t.TempDir(), scoped, DenyAll)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(strings.Join(brokerArgs, "\x00"), "\x00gitlab.com,git.example.org") {
		t.Fatalf("the frozen host set did not reach the broker: %q", brokerArgs)
	}
	process.Stop()

	rejected := DefaultConfig()
	rejected.AllowedHosts = []string{"not a host"}
	if _, err := StartBroker(t.TempDir(), rejected, DenyAll); err == nil {
		t.Fatal("an unparseable host was passed to the broker instead of failing the launch")
	}
	scopedRun := DefaultConfig()
	scopedRun.AllowedHosts = []string{"Not-Normalised.example."}
	if status := RunNetworkBroker(context.Background(), "unused", "unused-prompt", scopedRun); status != 20 {
		t.Fatalf("a broker started with a denormalised host set did not fail closed: status=%d", status)
	}
	networkExecCommand = func(string, ...string) *exec.Cmd { return exec.Command("/usr/bin/false") }
	networkSocketReady = func(string) bool { return false }
	if _, err := StartBroker(t.TempDir(), DefaultConfig(), DenyAll); err == nil {
		t.Fatal("early broker process exit was accepted")
	}
	if status := RunNetworkBroker(context.Background(), "unused", "unused-prompt", Config{}); status != 20 {
		t.Fatalf("invalid broker configuration status=%d", status)
	}
	networkListen = func(string, string) (net.Listener, error) { return nil, errors.New("listen") }
	if status := RunNetworkBroker(context.Background(), filepath.Join(t.TempDir(), "broker.sock"), filepath.Join(t.TempDir(), "prompt.sock"), DefaultConfig()); status != 23 {
		t.Fatalf("broker listen failure status=%d", status)
	}

	listener := newTestListener()
	networkListen = func(string, string) (net.Listener, error) { return listener, nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- RunNetworkBroker(ctx, filepath.Join(t.TempDir(), "broker.sock"), filepath.Join(t.TempDir(), "prompt.sock"), DefaultConfig())
	}()
	server, client := net.Pipe()
	listener.connections <- server
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.WriteString(client, "CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n")
	response, _ := io.ReadAll(client)
	client.Close()
	if !bytes.Contains(response, []byte("403")) {
		t.Fatalf("broker listener path did not deny loopback: %q", response)
	}
	cancel()
	if status := <-done; status != 0 {
		t.Fatalf("broker shutdown status=%d", status)
	}

	limitedListener := newTestListener()
	networkListen = func(string, string) (net.Listener, error) { return limitedListener, nil }
	limited := DefaultConfig()
	limited.MaxRequests = 1
	limitedDone := make(chan int, 1)
	go func() {
		limitedDone <- RunNetworkBroker(context.Background(), filepath.Join(t.TempDir(), "broker.sock"), filepath.Join(t.TempDir(), "prompt.sock"), limited)
	}()
	firstServer, firstClient := net.Pipe()
	limitedListener.connections <- firstServer
	_ = firstClient.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.WriteString(firstClient, "CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n")
	_, _ = io.ReadAll(firstClient)
	_ = firstClient.Close()
	secondServer, secondClient := net.Pipe()
	limitedListener.connections <- secondServer
	_ = secondClient.Close()
	if status := <-limitedDone; status != ExitRequestLimit {
		t.Fatalf("broker request budget exhaustion status=%d", status)
	}

	supervisorListener := newTestListener()
	networkListen = func(string, string) (net.Listener, error) { return supervisorListener, nil }
	networkCommandContext = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/usr/bin/true")
	}
	if status := RunNetworkSupervisor(context.Background(), "unused", []string{"ignored"}); status != 0 {
		t.Fatalf("supervisor success status=%d", status)
	}
	if status := RunNetworkSupervisor(context.Background(), "unused", nil); status != 20 {
		t.Fatalf("empty supervisor command status=%d", status)
	}
	networkListen = func(string, string) (net.Listener, error) { return nil, errors.New("listen") }
	if status := RunNetworkSupervisor(context.Background(), "unused", []string{"ignored"}); status != 24 {
		t.Fatalf("supervisor listen failure status=%d", status)
	}

	relayServer, relayClient := net.Pipe()
	upstreamServer, upstreamClient := net.Pipe()
	networkRelayDial = func(context.Context, string) (net.Conn, error) { return upstreamServer, nil }
	relayDone := make(chan struct{})
	go func() { relayToUnix(context.Background(), relayServer, "unused"); close(relayDone) }()
	_ = relayClient.SetDeadline(time.Now().Add(2 * time.Second))
	_ = upstreamClient.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = relayClient.Write([]byte("a"))
	forward := make([]byte, 1)
	_, _ = io.ReadFull(upstreamClient, forward)
	_, _ = upstreamClient.Write([]byte("b"))
	backward := make([]byte, 1)
	_, _ = io.ReadFull(relayClient, backward)
	if string(forward) != "a" || string(backward) != "b" {
		t.Fatalf("relay mismatch: %q %q", forward, backward)
	}
	relayClient.Close()
	upstreamClient.Close()
	<-relayDone
	failureServer, failureClient := net.Pipe()
	networkRelayDial = func(context.Context, string) (net.Conn, error) { return nil, errors.New("dial") }
	relayToUnix(context.Background(), failureServer, "unused")
	failureClient.Close()

	tunnelServer, tunnelClient := net.Pipe()
	tunnelUpstream, tunnelPeer := net.Pipe()
	tunnelDone := make(chan struct{})
	broker := &networkBroker{cfg: Config{IdleTimeoutSeconds: 1, MaxTransferBytes: 1024}}
	go func() { broker.tunnel(tunnelServer, bufio.NewReader(tunnelServer), tunnelUpstream); close(tunnelDone) }()
	_ = tunnelClient.SetDeadline(time.Now().Add(2 * time.Second))
	_ = tunnelPeer.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = tunnelClient.Write([]byte("x"))
	_, _ = io.ReadFull(tunnelPeer, forward)
	_, _ = tunnelPeer.Write([]byte("y"))
	_, _ = io.ReadFull(tunnelClient, backward)
	tunnelClient.Close()
	tunnelPeer.Close()
	<-tunnelDone
}

func TestNetworkBrokerRejectsLocalDestinations(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Keep real Unix sockets below sun_path's small pathname limit even when
	// makepkg places the Go test work tree under a long srcdir.
	socketDirectory := shortSocketDir(t)
	socket := filepath.Join(socketDirectory, "broker.sock")
	if listener, err := net.Listen("unix", socket); err != nil {
		if errors.Is(err, syscall.EPERM) {
			t.Skip("sandbox forbids Unix sockets")
		}
		t.Fatalf("test environment cannot create broker socket %q (%d bytes): %v", socket, len(socket), err)
	} else {
		listener.Close()
		_ = os.Remove(socket)
	}
	done := make(chan int, 1)
	promptSocket := filepath.Join(socketDirectory, "prompt.sock")
	go func() { done <- RunNetworkBroker(ctx, socket, promptSocket, DefaultConfig()) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Lstat(socket); err == nil {
			break
		}
		select {
		case status := <-done:
			t.Fatalf("broker exited before readiness: %d", status)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("broker did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(conn, "CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n")
	raw, _ := io.ReadAll(conn)
	conn.Close()
	if !bytes.Contains(raw, []byte("403 Forbidden")) {
		t.Fatalf("local CONNECT was not denied: %q", raw)
	}
	cancel()
	if status := <-done; status != 0 {
		t.Fatalf("broker cancellation status=%d", status)
	}
}

func TestNetworkAddressAndProxyPolicy(t *testing.T) {
	broker := &networkBroker{}
	broker.captureHostNetworks()
	for _, value := range []string{
		"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "192.0.2.1", "2001:db8::1",
		"64:ff9b::a9fe:a9fe", "64:ff9b:1::1", "100::1", "2001::1", "2002:a9fe:a9fe::1", "fec0::1",
	} {
		if broker.publicIP(net.ParseIP(value)) {
			t.Errorf("non-public address allowed: %s", value)
		}
	}
	if !broker.publicIP(net.ParseIP("8.8.8.8")) {
		t.Fatal("known public address rejected")
	}
	if _, _, err := splitHostPortDefault("example.com:22", 80); err == nil {
		t.Fatal("non-web port accepted")
	}
	if _, err := broker.dialPublic(context.Background(), "localhost", 443); err == nil {
		t.Fatal("loopback DNS answer accepted")
	}
}

func TestCountedTransferLimit(t *testing.T) {
	broker := &networkBroker{cfg: Config{MaxTransferBytes: 3}}
	var target bytes.Buffer
	writer := &countedWriter{Writer: &target, broker: broker}
	if _, err := writer.Write([]byte("four")); err == nil {
		t.Fatal("network transfer limit accepted")
	}
	reader := &countedReadCloser{ReadCloser: io.NopCloser(strings.NewReader("more")), broker: &networkBroker{cfg: Config{MaxTransferBytes: 3}}}
	if _, err := reader.Read(make([]byte, 4)); err == nil {
		t.Fatal("network upload limit accepted")
	}
}

func TestNetworkPromptDoesNotInheritShortConnectDeadline(t *testing.T) {
	previousLookup, previousAuthorize, previousDial := networkLookupIPAddr, networkAuthorize, networkDialTCP
	t.Cleanup(func() {
		networkLookupIPAddr, networkAuthorize, networkDialTCP = previousLookup, previousAuthorize, previousDial
	})
	lookupBounded, promptUnshortened, dialBounded := false, false, false
	networkLookupIPAddr = func(ctx context.Context, _ string) ([]net.IPAddr, error) {
		deadline, ok := ctx.Deadline()
		lookupBounded = ok && time.Until(deadline) > 0 && time.Until(deadline) <= 3*time.Second
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
	}
	networkAuthorize = func(_ *networkBroker, ctx context.Context, _ string, _ int, _ []net.IPAddr) error {
		_, shortened := ctx.Deadline()
		promptUnshortened = !shortened
		return nil
	}
	var peer net.Conn
	networkDialTCP = func(ctx context.Context, timeout time.Duration, _ string) (net.Conn, error) {
		deadline, ok := ctx.Deadline()
		dialBounded = timeout == 2*time.Second && ok && time.Until(deadline) > 0 && time.Until(deadline) <= 3*time.Second
		client, server := net.Pipe()
		peer = server
		return client, nil
	}
	broker := &networkBroker{cfg: Config{ConnectTimeoutSeconds: 2, IdleTimeoutSeconds: 2}}
	connection, err := broker.dialPublic(context.Background(), "example.test", 443)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if peer != nil {
		_ = peer.Close()
	}
	if !lookupBounded || !promptUnshortened || !dialBounded {
		t.Fatalf("network phase deadlines: lookup=%t prompt=%t dial=%t", lookupBounded, promptUnshortened, dialBounded)
	}
}

// --- test doubles ---
type testListener struct {
	connections chan net.Conn
	closed      chan struct{}
	once        sync.Once
}

func newTestListener() *testListener {
	return &testListener{connections: make(chan net.Conn, 4), closed: make(chan struct{})}
}
func (l *testListener) Accept() (net.Conn, error) {
	select {
	case connection := <-l.connections:
		return connection, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *testListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *testListener) Addr() net.Addr { return testAddr("test") }

type testAddr string

func (a testAddr) Network() string { return string(a) }
func (a testAddr) String() string  { return string(a) }

func TestHTTPHeaderReaderFailsClosedAtLimit(t *testing.T) {
	reader := &boundedHTTPHeaderReader{reader: strings.NewReader("123456789"), remaining: 8}
	data, err := io.ReadAll(reader)
	if err == nil || string(data) != "12345678" {
		t.Fatalf("bounded header read = %q, %v", data, err)
	}
	reader.unlimited = true
	rest, err := io.ReadAll(reader)
	if err != nil || string(rest) != "9" {
		t.Fatalf("unlimited transfer continuation = %q, %v", rest, err)
	}
}
