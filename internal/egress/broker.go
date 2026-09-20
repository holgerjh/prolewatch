package egress

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/holgerjh/prolewatch/internal/safe"
)

// SandboxProxyAddress is the loopback endpoint the build sees inside its own
// network namespace. The supervisor relays it to the broker over a
// transaction-private unix socket, so the sandbox never receives general
// access to the host network.
const SandboxProxyAddress = "127.0.0.1:18080"

const (
	// Stable child-process statuses let the trusted launcher attribute a broker
	// failure instead of reporting only a disconnected proxy to the build.
	ExitOK                = 0
	ExitInvalidInvocation = 20
	ExitListenFailure     = 23
	ExitRuntimeFailure    = 24
	ExitRequestLimit      = 25

	// net/http has no server-side header limit for ReadRequest. 128 KiB is roomy
	// enough for package-manager headers while bounding unauthenticated allocation.
	networkHTTPHeaderBytes = 128 * 1024
	brokerOutputBytes      = 1 << 20
	brokerReadyTimeout     = 5 * time.Second
	brokerReadyPoll        = 20 * time.Millisecond
	brokerStopTimeout      = 2 * time.Second
	proxyReadBufferBytes   = 4 << 10
	brokerMessageBytes     = 4 << 10
	maxHTTPHeaderFields    = 200
)

var ErrRequestLimit = errors.New("network broker request limit exhausted")

var (
	networkListen         = net.Listen
	networkExecCommand    = exec.Command
	networkCommandContext = exec.CommandContext
	networkSocketReady    = func(socket string) bool {
		info, err := os.Lstat(socket)
		return err == nil && info.Mode()&os.ModeSocket != 0
	}
	networkRelayDial = func(ctx context.Context, socket string) (net.Conn, error) {
		dialer := net.Dialer{Timeout: 15 * time.Second}
		return dialer.DialContext(ctx, "unix", socket)
	}
	networkLookupIPAddr = net.DefaultResolver.LookupIPAddr
	networkAuthorize    = func(b *networkBroker, ctx context.Context, host string, port int, addresses []net.IPAddr) error {
		return b.authorize(ctx, host, port, addresses)
	}
	networkDialTCP = func(ctx context.Context, timeout time.Duration, address string) (net.Conn, error) {
		dialer := net.Dialer{Timeout: timeout}
		return dialer.DialContext(ctx, "tcp", address)
	}
	networkPromptAgentStart = startNetworkPromptAgent
)

// This explicit denylist supplements net.IP's classification methods. It also
// covers documentation, benchmarking, transition, carrier-NAT, and reserved
// ranges so a permitted hostname cannot be used for SSRF into non-public space.
var nonPublicNetworks = func() []*net.IPNet {
	var result []*net.IPNet
	for _, value := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
		"2001::/23", "2001:db8::/32", "2002::/16", "fc00::/7", "fec0::/10", "fe80::/10", "ff00::/8",
	} {
		_, network, _ := net.ParseCIDR(value)
		result = append(result, network)
	}
	return result
}()

// BrokerProcess is a running broker and the prompt agent that serves it.
type BrokerProcess struct {
	command        *exec.Cmd
	done           chan struct{}
	waitErr        error
	stderr         *safe.LimitedBuffer
	promptListener net.Listener
}

// AuthorizationRequest is what the untrusted broker asks the trusted prompt
// agent. It carries no addresses: consent is obtained before the name is
// resolved, because resolving it is itself egress. See dialPublic.
type AuthorizationRequest struct {
	SchemaVersion int    `json:"schema_version"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
}

type AuthorizationResponse struct {
	SchemaVersion int  `json:"schema_version"`
	Allow         bool `json:"allow"`
}

// PromptFunc decides one destination request by asking the human.
//
// It is supplied by the caller rather than implemented here, because the
// decision belongs to the ui layer, and ui sits above egress, which may not
// import it. The prompt agent runs outside the network-enabled broker sandbox
// and speaks to it over a private socket, so the component holding the TTY is
// not the component holding the network.
type PromptFunc func(AuthorizationRequest, Config) bool

// DenyAll is the correct default. A broker with no way to ask must not invent
// consent, and a caller that forgets to supply a prompt should lose network
// access rather than gain unattended approval.
func DenyAll(AuthorizationRequest, Config) bool { return false }

// NoAllowedHosts is the argv token for "this phase has no host restriction". An
// empty argv element would work too, and would be one silent typo away from
// meaning the opposite of what it says. Both sides of the process boundary name
// this constant rather than the character.
const NoAllowedHosts = "-"

func StartBroker(directory string, cfg Config, prompt PromptFunc) (*BrokerProcess, error) {
	if prompt == nil {
		prompt = DenyAll
	}
	// The host set crosses a process boundary, so it is validated here, where an
	// invalid entry can still fail the launch rather than silently widening or
	// narrowing the set inside the broker.
	allowed := NoAllowedHosts
	if len(cfg.AllowedHosts) > 0 {
		normalized := make([]string, 0, len(cfg.AllowedHosts))
		for _, host := range cfg.AllowedHosts {
			host = strings.ToLower(strings.TrimSuffix(host, "."))
			if !ValidRequestHost(host) {
				return nil, fmt.Errorf("invalid brokered host %q", host)
			}
			normalized = append(normalized, host)
		}
		allowed = strings.Join(normalized, ",")
	}
	// Separate client and control directories make the trust boundary visible:
	// sandbox traffic reaches proxy.sock, while only the outer trusted prompt
	// agent owns the user-interaction side of prompt.sock.
	clientDirectory := filepath.Join(directory, "client")
	controlDirectory := filepath.Join(directory, "control")
	for _, path := range []string{clientDirectory, controlDirectory} {
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	socket := filepath.Join(clientDirectory, "proxy.sock")
	promptSocket := filepath.Join(controlDirectory, "prompt.sock")
	promptListener, err := networkPromptAgentStart(controlDirectory, cfg, prompt)
	if err != nil {
		return nil, fmt.Errorf("start network prompt agent: %w", err)
	}
	// The broker itself has a shared network namespace but almost no filesystem.
	// It can dial only after enforcing destination, prompt, connection, timeout,
	// and aggregate-byte policy below.
	args := []string{
		// --unshare-all treats the user namespace as best-effort. The explicit
		// flag is required because --disable-userns can clamp nested namespaces
		// only after Bubblewrap has definitely created this one. Unlike the build
		// sandbox, the broker does not join a pre-mapped --userns FD.
		"--die-with-parent", "--new-session", "--unshare-all", "--share-net", "--unshare-user", "--disable-userns", "--assert-userns-disabled",
		"--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
		"--symlink", "usr/lib64", "/lib64", "--dir", "/etc", "--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf",
		"--ro-bind-try", "/etc/hosts", "/etc/hosts", "--ro-bind-try", "/etc/nsswitch.conf", "/etc/nsswitch.conf",
		"--ro-bind-try", "/etc/ssl", "/etc/ssl", "--ro-bind-try", "/etc/ca-certificates", "/etc/ca-certificates",
		"--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
		"--dir", "/broker-client", "--bind", clientDirectory, "/broker-client",
		"--dir", "/broker-control", "--bind", controlDirectory, "/broker-control",
		"--clearenv", "--setenv", "PATH", "/usr/bin", "--setenv", "LANG", "C.UTF-8", "/usr/bin/prolewatch-net", "broker",
		"/broker-client/proxy.sock", "/broker-control/prompt.sock", strconv.Itoa(cfg.MaxConnections), strconv.Itoa(cfg.ConnectTimeoutSeconds),
		strconv.Itoa(cfg.IdleTimeoutSeconds), strconv.FormatInt(cfg.MaxTransferBytes, 10),
		strconv.Itoa(cfg.PromptTimeoutSeconds), strconv.Itoa(cfg.MaxDestinations), strconv.Itoa(cfg.MaxRequests), allowed,
	}
	command := networkExecCommand("/usr/bin/bwrap", args...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stderr := safe.NewLimitedBuffer(brokerOutputBytes)
	command.Stdout = safe.NewLimitedBuffer(brokerOutputBytes)
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		if promptListener != nil {
			_ = promptListener.Close()
		}
		return nil, err
	}
	process := &BrokerProcess{command: command, done: make(chan struct{}), stderr: stderr, promptListener: promptListener}
	go func() {
		process.waitErr = command.Wait()
		close(process.done)
	}()
	// Readiness is the presence of both data and control sockets. A 20 ms poll
	// keeps startup responsive; five seconds treats a wedged broker as failed.
	deadline := time.NewTimer(brokerReadyTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(brokerReadyPoll)
	defer ticker.Stop()
	for {
		select {
		case <-process.done:
			if promptListener != nil {
				_ = promptListener.Close()
			}
			return nil, fmt.Errorf("network broker exited before readiness: %w: %s", process.waitErr, safe.Inline(stderr.String(), 1000))
		case <-deadline.C:
			process.Stop()
			return nil, errors.New("network broker readiness timed out")
		case <-ticker.C:
			if networkSocketReady(socket) {
				if !networkSocketReady(promptSocket) {
					process.Stop()
					return nil, errors.New("network prompt agent lost its control socket")
				}
				return process, nil
			}
		}
	}
}

// Done closes if the broker exits before its build phase. A nil channel means
// the process was not started, which keeps zero-value test doubles inert.
func (p *BrokerProcess) Done() <-chan struct{} {
	if p == nil {
		return nil
	}
	return p.done
}

// Failure attributes a completed broker process. Reading waitErr after Done
// closes is synchronized by the channel close and therefore needs no mutex.
func (p *BrokerProcess) Failure() error {
	if p == nil || p.done == nil {
		return nil
	}
	select {
	case <-p.done:
	default:
		return nil
	}
	detail := ""
	if p.stderr != nil {
		detail = safe.Inline(strings.TrimSpace(p.stderr.String()), 1000)
	}
	if p.command != nil && p.command.ProcessState != nil && p.command.ProcessState.ExitCode() == ExitRequestLimit {
		return fmt.Errorf("%w%s", ErrRequestLimit, errorDetail(detail))
	}
	if p.waitErr == nil {
		return errors.New("network broker exited unexpectedly")
	}
	return fmt.Errorf("network broker exited: %w%s", p.waitErr, errorDetail(detail))
}

func errorDetail(detail string) string {
	if detail == "" {
		return ""
	}
	return ": " + detail
}

func startNetworkPromptAgent(directory string, cfg Config, prompt PromptFunc) (net.Listener, error) {
	promptSocket := filepath.Join(directory, "prompt.sock")
	_ = os.Remove(promptSocket)
	listener, err := networkListen("unix", promptSocket)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(promptSocket, 0o600)
	go serveNetworkPromptAgent(listener, cfg, prompt)
	return listener, nil
}

// Stop tears down the broker and closes the prompt socket.
func (p *BrokerProcess) Stop() {
	if p == nil || p.command == nil || p.command.Process == nil {
		return
	}
	if p.promptListener != nil {
		_ = p.promptListener.Close()
	}
	select {
	case <-p.done:
		return
	default:
	}
	_ = syscall.Kill(-p.command.Process.Pid, syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(brokerStopTimeout):
		_ = syscall.Kill(-p.command.Process.Pid, syscall.SIGKILL)
		<-p.done
	}
}

type networkBroker struct {
	cfg       Config
	semaphore chan struct{}
	// used is shared by all directions and connections, making the byte budget
	// transaction-wide rather than a per-connection limit that could be evaded.
	used    atomic.Int64
	policy  *AddressPolicy
	prompt  string
	grantMu sync.Mutex
	grants  map[string]bool
	// asked records every destination a prompt was raised for, approved or not,
	// so the destination limit bounds questions rather than only consents.
	asked map[string]bool
}

func RunNetworkBroker(ctx context.Context, socket, promptSocket string, cfg Config) int {
	// These exact modes prevent an internal invocation from silently widening
	// policy if new configuration modes are added elsewhere.
	if cfg.MaxConnections <= 0 || cfg.ConnectTimeoutSeconds <= 0 || cfg.IdleTimeoutSeconds <= 0 || cfg.MaxTransferBytes <= 0 ||
		cfg.PromptTimeoutSeconds <= 0 || cfg.MaxDestinations <= 0 || cfg.MaxRequests <= 0 || cfg.Mode != "prompt" || cfg.GrantScope != "transaction" {
		return ExitInvalidInvocation
	}
	// The host set arrived as argv. Re-validate it here rather than trusting the
	// launcher: an entry that is not already a normalised hostname would compare
	// unequal to every real destination, turning a scoped phase into one that
	// silently refuses everything.
	for _, host := range cfg.AllowedHosts {
		if host != strings.ToLower(strings.TrimSuffix(host, ".")) || !ValidRequestHost(host) {
			return ExitInvalidInvocation
		}
	}
	if err := os.Remove(socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return ExitListenFailure
	}
	listener, err := networkListen("unix", socket)
	if err != nil {
		return ExitListenFailure
	}
	defer listener.Close()
	_ = os.Chmod(socket, 0o600)
	if promptSocket == "" || filepath.Clean(promptSocket) == filepath.Clean(socket) {
		return ExitInvalidInvocation
	}
	broker := &networkBroker{cfg: cfg, semaphore: make(chan struct{}, cfg.MaxConnections), prompt: promptSocket, grants: map[string]bool{}}
	if err := broker.captureHostNetworks(); err != nil {
		return ExitInvalidInvocation
	}
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	requests := 0
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ExitOK
			}
			return ExitRuntimeFailure
		}
		requests++
		if requests > cfg.MaxRequests {
			_ = conn.Close()
			return ExitRequestLimit
		}
		select {
		case broker.semaphore <- struct{}{}:
			go func() {
				defer func() { <-broker.semaphore }()
				broker.handle(conn)
			}()
		default:
			conn.Close()
		}
	}
}

// captureHostNetworks fails closed. A broker that could not learn which
// addresses belong to this host must not start: it would still block the
// reserved ranges and would still look like a working policy.
// permitsHost applies the phase's closed host set, when it has one.
//
// It runs before the prompt and before resolution, and both matter. A prompt for
// a host the phase already knows is undeclared is a question the user has no
// basis to answer, and answering it wrongly is exactly the habit an attacker
// wants; resolving the name would be egress in its own right, reaching the
// attacker's authoritative server whether or not the user then says no.
func (b *networkBroker) permitsHost(host string) bool {
	if len(b.cfg.AllowedHosts) == 0 {
		return true
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, allowed := range b.cfg.AllowedHosts {
		if allowed == host {
			return true
		}
	}
	return false
}

func (b *networkBroker) captureHostNetworks() error {
	policy, err := NewAddressPolicy()
	if err != nil {
		return err
	}
	b.policy = policy
	return nil
}

func (b *networkBroker) handle(conn net.Conn) {
	defer conn.Close()
	idle := &idleConn{Conn: conn, timeout: time.Duration(b.cfg.IdleTimeoutSeconds) * time.Second}
	reader := bufio.NewReaderSize(idle, 64*1024)
	first, err := reader.Peek(1)
	if err != nil {
		return
	}
	// SOCKS5 begins with version byte 0x05. Everything else is parsed as an HTTP
	// proxy request and will fail closed if it is neither valid HTTP nor CONNECT.
	if first[0] == 5 {
		b.handleSOCKS(idle, reader)
		return
	}
	b.handleHTTP(idle, reader)
}

func (b *networkBroker) handleSOCKS(client net.Conn, reader *bufio.Reader) {
	// RFC 1928: [VER=5, NMETHODS], followed by methods. 0x00 means no
	// authentication and 0xff means no acceptable method. We cap NMETHODS at 32
	// because this private proxy needs only a tiny, fixed negotiation.
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil || header[0] != 5 || header[1] == 0 || header[1] > 32 {
		return
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return
	}
	noAuth := false
	for _, method := range methods {
		noAuth = noAuth || method == 0
	}
	if !noAuth {
		_, _ = client.Write([]byte{5, 0xff})
		return
	}
	_, _ = client.Write([]byte{5, 0})
	// Request header is [VER=5, CMD=1 (CONNECT), RSV, ATYP]. ATYP values 1, 3,
	// and 4 select IPv4 (4 bytes), a length-prefixed domain, and IPv6 (16 bytes).
	request := make([]byte, 4)
	if _, err := io.ReadFull(reader, request); err != nil || request[0] != 5 || request[1] != 1 {
		return
	}
	var host string
	switch request[3] {
	case 1:
		raw := make([]byte, 4)
		_, _ = io.ReadFull(reader, raw)
		host = net.IP(raw).String()
	case 4:
		raw := make([]byte, 16)
		_, _ = io.ReadFull(reader, raw)
		host = net.IP(raw).String()
	case 3:
		length, err := reader.ReadByte()
		if err != nil || length == 0 {
			return
		}
		raw := make([]byte, int(length))
		_, _ = io.ReadFull(reader, raw)
		host = string(raw)
	default:
		return
	}
	portRaw := make([]byte, 2)
	if _, err := io.ReadFull(reader, portRaw); err != nil {
		return
	}
	// SOCKS encodes the destination port as an unsigned 16-bit network-order value.
	port := int(binary.BigEndian.Uint16(portRaw))
	upstream, err := b.dialPublic(context.Background(), host, port)
	if err != nil {
		// REP=2 is "connection not allowed by ruleset"; the remaining bytes are
		// the required reserved/IPv4/zero-bound-address fields.
		_, _ = client.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	// REP=0 reports success. The proxy does not expose its actual bound address.
	_, _ = client.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	stream, err := checkTunnelHost(host, reader)
	if err != nil {
		return
	}
	b.tunnel(client, stream, upstream)
}

func (b *networkBroker) handleHTTP(client net.Conn, reader *bufio.Reader) {
	// http.ReadRequest has no server-side MaxHeaderBytes knob. Put a temporary
	// byte ceiling around header parsing, then disable it so legitimate package
	// transfers remain governed by the larger transaction byte quota.
	headerReader := &boundedHTTPHeaderReader{reader: reader, remaining: networkHTTPHeaderBytes}
	requestReader := bufio.NewReaderSize(headerReader, proxyReadBufferBytes)
	request, err := http.ReadRequest(requestReader)
	headerReader.unlimited = true
	if err != nil || len(request.Header) > maxHTTPHeaderFields {
		return
	}
	if request.Method == http.MethodConnect {
		host, port, err := splitHostPortDefault(request.Host, HTTPSPort)
		if err != nil || port != HTTPSPort {
			writeProxyError(client, http.StatusForbidden)
			return
		}
		upstream, err := b.dialPublic(context.Background(), host, port)
		if err != nil {
			writeProxyError(client, http.StatusForbidden)
			return
		}
		defer upstream.Close()
		_, _ = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
		// The client only speaks after the 200, so the host it names can only be
		// checked here. Failing now closes the tunnel without forwarding a byte.
		stream, err := checkTunnelHost(host, requestReader)
		if err != nil {
			return
		}
		b.tunnel(client, stream, upstream)
		return
	}
	if request.URL == nil || request.URL.Scheme != "http" || request.URL.Host == "" {
		writeProxyError(client, http.StatusForbidden)
		return
	}
	host, port, err := splitHostPortDefault(request.URL.Host, HTTPPort)
	if err != nil || port != HTTPPort {
		writeProxyError(client, http.StatusForbidden)
		return
	}
	transport := &http.Transport{
		Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: false,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return b.dialPublic(ctx, host, port) },
	}
	request.RequestURI = ""
	request.URL.Scheme = "http"
	request.URL.Host = net.JoinHostPort(host, strconv.Itoa(port))
	request.Header.Del("Proxy-Authorization")
	if request.Body != nil {
		request.Body = &countedReadCloser{ReadCloser: request.Body, broker: b}
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		writeProxyError(client, http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	response.Close = true
	response.Header.Del("Proxy-Authenticate")
	writer := &countedWriter{Writer: client, broker: b}
	_ = response.Write(writer)
}

type boundedHTTPHeaderReader struct {
	reader    io.Reader
	remaining int64
	unlimited bool
}

func (r *boundedHTTPHeaderReader) Read(value []byte) (int, error) {
	if r.unlimited {
		return r.reader.Read(value)
	}
	if r.remaining <= 0 {
		return 0, errors.New("HTTP proxy header exceeds its byte limit")
	}
	if int64(len(value)) > r.remaining {
		value = value[:r.remaining]
	}
	n, err := r.reader.Read(value)
	r.remaining -= int64(n)
	return n, err
}

func splitHostPortDefault(value string, fallback int) (string, int, error) {
	host := value
	port := fallback
	if parsedHost, parsedPort, err := net.SplitHostPort(value); err == nil {
		host = parsedHost
		parsed, parseErr := strconv.Atoi(parsedPort)
		if parseErr != nil {
			return "", 0, parseErr
		}
		port = parsed
	} else if strings.Contains(value, ":") && net.ParseIP(value) == nil {
		return "", 0, err
	}
	if host == "" || len(host) > MaxHostnameBytes || (port != HTTPPort && port != HTTPSPort) {
		return "", 0, errors.New("destination is outside the public-web policy")
	}
	return strings.Trim(host, "[]"), port, nil
}

// dialPublic resolves once, checks every returned address, binds the grant to
// that sorted answer, and then dials the addresses it checked.
//
// The single resolution is load-bearing and must not be "simplified" into a
// re-resolve later: resolving again after the check is a DNS-rebinding TOCTOU,
// where the answer that passed the non-public test is not the answer that gets
// dialled. Bind, check, and dial all refer to the same set of addresses.
func (b *networkBroker) dialPublic(ctx context.Context, host string, port int) (net.Conn, error) {
	if !b.policy.Port(port) {
		return nil, errors.New("port denied")
	}
	// Consent precedes resolution, because resolution is itself egress.
	//
	// A DNS query for <encoded-data>.attacker.example reaches the attacker's
	// authoritative server whether or not the user then denies the connection,
	// so resolving first leaks on every attempt. Denied names never entered the
	// grant map either, which left the destination limit bounding only the
	// approved names and not the queries.
	//
	// The grant binds the approved name rather than one resolved address set.
	// Every resolution is checked in full below, and any non-public address
	// rejects the whole set. A different public answer later in the transaction
	// does not cause another prompt because the user consented to the name.
	if !ValidRequestHost(host) {
		return nil, errors.New("destination is not a valid host")
	}
	if !b.permitsHost(host) {
		return nil, errors.New("destination is outside this phase's declared host set")
	}
	// A human decision has its own budget. Reusing the short DNS/connect
	// context here would reduce a configured multi-minute prompt to the connect
	// timeout and fail a long Cargo/Go build while the user is still deciding.
	if err := networkAuthorize(b, ctx, host, port, nil); err != nil {
		return nil, err
	}
	resolveCtx, cancel := context.WithTimeout(ctx, time.Duration(b.cfg.ConnectTimeoutSeconds)*time.Second)
	addresses, err := networkLookupIPAddr(resolveCtx, host)
	cancel()
	if err != nil || len(addresses) == 0 {
		return nil, errors.New("DNS resolution failed")
	}
	for _, address := range addresses {
		if !b.publicIP(address.IP) {
			return nil, errors.New("DNS answer contains a non-public address")
		}
	}
	dialCtx, cancel := context.WithTimeout(ctx, time.Duration(b.cfg.ConnectTimeoutSeconds)*time.Second)
	defer cancel()
	connectTimeout := time.Duration(b.cfg.ConnectTimeoutSeconds) * time.Second
	for _, address := range addresses {
		conn, err := networkDialTCP(dialCtx, connectTimeout, net.JoinHostPort(address.IP.String(), strconv.Itoa(port)))
		if err == nil {
			return &idleConn{Conn: conn, timeout: time.Duration(b.cfg.IdleTimeoutSeconds) * time.Second}, nil
		}
	}
	return nil, errors.New("all public destinations failed")
}

// authorize obtains phase-local consent for one destination, before any name
// resolution happens. The in-memory grant dies with this broker process. The
// addresses parameter is retained for the test seam and is unused: there are
// no addresses yet at this point, by design.
func (b *networkBroker) authorize(ctx context.Context, host string, port int, _ []net.IPAddr) error {
	key := strings.ToLower(host) + ":" + strconv.Itoa(port)
	b.grantMu.Lock()
	defer b.grantMu.Unlock()
	if b.grants[key] {
		return nil
	}
	// The limit counts destinations *asked about*, not destinations approved.
	// Counting only approvals would let a package generate unbounded prompts.
	if b.asked == nil {
		b.asked = map[string]bool{}
	}
	if !b.asked[key] {
		if len(b.asked) >= b.cfg.MaxDestinations {
			return errors.New("transaction destination limit reached")
		}
		b.asked[key] = true
	}
	request := AuthorizationRequest{SchemaVersion: 1, Host: strings.ToLower(host), Port: port}
	raw, err := safe.CanonicalJSON(request)
	if err != nil {
		return err
	}
	dialer := net.Dialer{Timeout: time.Duration(b.cfg.ConnectTimeoutSeconds) * time.Second}
	connection, err := dialer.DialContext(ctx, "unix", b.prompt)
	if err != nil {
		return errors.New("trusted network prompt agent is unavailable")
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(time.Duration(b.cfg.PromptTimeoutSeconds) * time.Second))
	if _, err := connection.Write(raw); err != nil {
		return errors.New("network prompt request failed")
	}
	if unixConnection, ok := connection.(*net.UnixConn); ok {
		_ = unixConnection.CloseWrite()
	}
	// Read limit+1 so exactly 4 KiB is accepted but any extra byte is rejected.
	responseRaw, err := io.ReadAll(io.LimitReader(connection, brokerMessageBytes+1))
	if err != nil || len(responseRaw) > brokerMessageBytes {
		return errors.New("network prompt response failed")
	}
	var response AuthorizationResponse
	if safe.DecodeJSON(responseRaw, &response) != nil || response.SchemaVersion != 1 || !response.Allow {
		return errors.New("network destination was denied")
	}
	b.grants[key] = true
	return nil
}

func serveNetworkPromptAgent(listener net.Listener, cfg Config, prompt PromptFunc) {
	// The prompt agent stays outside the network-enabled broker sandbox. It owns
	// the TTY decision and accepts only a small, strict JSON request on its private
	// socket; the broker cannot forge an implicit approval.
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		_ = connection.SetReadDeadline(time.Now().Add(10 * time.Second))
		raw, readErr := io.ReadAll(io.LimitReader(connection, brokerMessageBytes+1))
		var request AuthorizationRequest
		allowed := false
		// ValidRequestHost is part of this condition rather than left to the
		// renderer: a host that is not a hostname must never reach the prompt at
		// all. See host.go.
		if readErr == nil && len(raw) <= brokerMessageBytes && safe.DecodeJSON(raw, &request) == nil && request.SchemaVersion == 1 &&
			request.Port > 0 && request.Port <= MaxTCPPort && ValidRequestHost(request.Host) {
			allowed = prompt(request, cfg)
		}
		response, _ := safe.CanonicalJSON(AuthorizationResponse{SchemaVersion: 1, Allow: allowed})
		_ = connection.SetWriteDeadline(time.Now().Add(10 * time.Second))
		_, _ = connection.Write(response)
		_ = connection.Close()
	}
}

func (b *networkBroker) publicIP(ip net.IP) bool { return b.policy.Public(ip) }

func (b *networkBroker) tunnel(client net.Conn, buffered io.Reader, upstream net.Conn) {
	client = &idleConn{Conn: client, timeout: time.Duration(b.cfg.IdleTimeoutSeconds) * time.Second}
	clientWriter := &countedWriter{Writer: client, broker: b}
	upstreamWriter := &countedWriter{Writer: upstream, broker: b}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstreamWriter, buffered); done <- struct{}{} }()
	go func() { _, _ = io.Copy(clientWriter, upstream); done <- struct{}{} }()
	<-done
	_ = client.Close()
	_ = upstream.Close()
	<-done
}

type idleConn struct {
	net.Conn
	timeout time.Duration
}

func (c *idleConn) Read(value []byte) (int, error) {
	_ = c.SetReadDeadline(time.Now().Add(c.timeout))
	return c.Conn.Read(value)
}

func (c *idleConn) Write(value []byte) (int, error) {
	_ = c.SetWriteDeadline(time.Now().Add(c.timeout))
	return c.Conn.Write(value)
}

type countedWriter struct {
	io.Writer
	broker *networkBroker
}

type countedReadCloser struct {
	io.ReadCloser
	broker *networkBroker
}

func (r *countedReadCloser) Read(value []byte) (int, error) {
	n, err := r.ReadCloser.Read(value)
	if n > 0 && r.broker.used.Add(int64(n)) > r.broker.cfg.MaxTransferBytes {
		return 0, errors.New("network transaction byte limit exceeded")
	}
	return n, err
}

func (w *countedWriter) Write(value []byte) (int, error) {
	if w.broker.used.Add(int64(len(value))) > w.broker.cfg.MaxTransferBytes {
		return 0, errors.New("network transaction byte limit exceeded")
	}
	return w.Writer.Write(value)
}

func writeProxyError(writer io.Writer, status int) {
	_, _ = fmt.Fprintf(writer, "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", status, http.StatusText(status))
}

// tunnelHostLimit bounds what may be read before a tunnel opens. A TLS record
// carries at most 16 KiB plus its five-byte header, and an HTTP request head is
// far smaller.
const tunnelHostLimit = 16*1024 + 5

// checkTunnelHost holds an opaque tunnel to the host the user actually approved.
//
// CONNECT and SOCKS hand the client a byte pipe to a checked IP address, and an
// IP is not a host. On a shared reverse proxy or CDN one address serves any
// number of virtual hosts, so a client that asked for and was granted
// approved.example can name attacker.example in its TLS SNI - or its HTTP Host
// header - and reach a different service over the same approved connection.
// Both the prompt and the frozen VCS host set promise a host, so the first
// bytes of the tunnel are read and required to name it. They are replayed to
// the upstream, not consumed.
//
// An approved IP literal is exempt: no host guarantee was made or displayed for
// one, and there is no name for the client to contradict.
func checkTunnelHost(host string, client io.Reader) (io.Reader, error) {
	if net.ParseIP(strings.Trim(host, "[]")) != nil {
		return client, nil
	}
	var seen bytes.Buffer
	requested, err := tunnelRequestedHost(io.TeeReader(io.LimitReader(client, tunnelHostLimit), &seen))
	if err != nil {
		return nil, err
	}
	if !ValidRequestHost(requested) {
		return nil, errors.New("the tunnel named a destination that is not a host")
	}
	if !strings.EqualFold(strings.TrimSuffix(requested, "."), strings.TrimSuffix(host, ".")) {
		return nil, fmt.Errorf("tunnel was approved for %q but requests %q", host, requested)
	}
	return io.MultiReader(bytes.NewReader(seen.Bytes()), client), nil
}

// tunnelRequestedHost reads the host a tunnel's first message names: the TLS
// ClientHello's server name, or the HTTP Host header. Traffic that is neither
// carries no host to check and is refused rather than tunnelled unchecked.
//
// The ClientHello is read from one TLS record. A handshake message fragmented
// across records is legal and is refused here rather than tunnelled unchecked;
// no TLS stack the supported clients use fragments by default, so reassembly is
// deliberately not implemented ahead of evidence that something needs it.
func tunnelRequestedHost(reader io.Reader) (string, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(reader, header); err != nil {
		return "", errors.New("tunnel closed before naming a destination")
	}
	// 0x16 is the TLS handshake content type. Anything else is treated as a
	// plain HTTP request, which is what a SOCKS client to port 80 sends.
	if header[0] != 0x16 {
		return httpRequestHost(io.MultiReader(bytes.NewReader(header), reader))
	}
	length := int(binary.BigEndian.Uint16(header[3:5]))
	if length < 4 || length > 16*1024 {
		return "", errors.New("implausible TLS record length")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		return "", errors.New("truncated TLS ClientHello")
	}
	return clientHelloServerName(body)
}

// byteCursor walks a length-prefixed wire format without a bounds check at
// every step. Once it runs off the end it stays failed and yields nothing, so
// one check at the end covers the whole parse.
type byteCursor struct {
	data []byte
	err  error
}

func (c *byteCursor) take(n int) []byte {
	if c.err != nil || n < 0 || n > len(c.data) {
		c.err = errors.New("truncated TLS ClientHello")
		return nil
	}
	out := c.data[:n]
	c.data = c.data[n:]
	return out
}

func (c *byteCursor) u8() int {
	value := c.take(1)
	if value == nil {
		return 0
	}
	return int(value[0])
}

func (c *byteCursor) u16() int {
	value := c.take(2)
	if value == nil {
		return 0
	}
	return int(binary.BigEndian.Uint16(value))
}

// clientHelloServerName extracts the SNI from a ClientHello handshake message.
//
// Only the outer server name is read, because it is the only name available
// without decrypting: it selects the certificate and, at a shared frontend,
// usually the backend too. "Usually" is the whole caveat. Application-layer
// routing happens inside TLS, so a later HTTP Host or HTTP/2 :authority can
// name something else and this check will not see it. Calling SNI "the name the
// connection is routed by" overstated that. Nothing here decrypts or interprets
// anything else in the handshake, and nothing should: the alternative is
// terminating TLS, which trades a virtual-host check for the user's traffic in
// clear. See docs/architecture.md, control 2.
func clientHelloServerName(body []byte) (string, error) {
	cursor := &byteCursor{data: body}
	if handshake := cursor.take(4); handshake == nil || handshake[0] != 0x01 {
		return "", errors.New("tunnel did not open with a TLS ClientHello")
	}
	cursor.take(2)            // legacy_version
	cursor.take(32)           // random
	cursor.take(cursor.u8())  // legacy_session_id
	cursor.take(cursor.u16()) // cipher_suites
	cursor.take(cursor.u8())  // legacy_compression_methods
	extensions := &byteCursor{data: cursor.take(cursor.u16())}
	if cursor.err != nil {
		return "", cursor.err
	}
	for len(extensions.data) > 0 {
		kind := extensions.u16()
		payload := extensions.take(extensions.u16())
		if extensions.err != nil {
			return "", extensions.err
		}
		if kind != 0 { // server_name
			continue
		}
		names := &byteCursor{data: payload}
		names.take(2) // server_name_list length
		for len(names.data) > 0 {
			nameType := names.u8()
			value := names.take(names.u16())
			if names.err != nil {
				return "", names.err
			}
			if nameType == 0 { // host_name
				return string(value), nil
			}
		}
	}
	return "", errors.New("the TLS ClientHello carried no server name")
}

// httpRequestHost reads the Host header of a plain HTTP request opening a
// tunnel. Only the head is read, and only up to the first blank line.
func httpRequestHost(reader io.Reader) (string, error) {
	head := bufio.NewReaderSize(io.LimitReader(reader, 2*proxyReadBufferBytes), proxyReadBufferBytes)
	if _, err := head.ReadString('\n'); err != nil { // request line
		return "", errors.New("tunnel closed before naming a destination")
	}
	for {
		line, err := head.ReadString('\n')
		if err != nil {
			return "", errors.New("tunnel sent no Host header")
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			return "", errors.New("tunnel sent no Host header")
		}
		name, value, found := strings.Cut(trimmed, ":")
		if !found || !strings.EqualFold(strings.TrimSpace(name), "host") {
			continue
		}
		host, _, err := splitHostPortDefault(strings.TrimSpace(value), HTTPPort)
		if err != nil {
			return "", err
		}
		return host, nil
	}
}

func RunNetworkSupervisor(ctx context.Context, socket string, commandArgs []string) int {
	// This process lives inside the build's private network namespace. It owns
	// the fixed loopback listener and relays bytes to the outer broker socket that
	// was deliberately bind-mounted into the sandbox.
	if len(commandArgs) == 0 {
		return ExitInvalidInvocation
	}
	listener, err := networkListen("tcp", SandboxProxyAddress)
	if err != nil {
		return ExitRuntimeFailure
	}
	defer listener.Close()
	relayCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			go relayToUnix(relayCtx, client, socket)
		}
	}()
	command := networkCommandContext(ctx, commandArgs[0], commandArgs[1:]...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	command.Env = os.Environ()
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	err = command.Run()
	if command.Process != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return exit.ExitCode()
		}
		return ExitRuntimeFailure
	}
	return ExitOK
}

func relayToUnix(ctx context.Context, client net.Conn, socket string) {
	defer client.Close()
	upstream, err := networkRelayDial(ctx, socket)
	if err != nil {
		return
	}
	defer upstream.Close()
	var wait sync.WaitGroup
	wait.Add(2)
	go func() { defer wait.Done(); _, _ = io.Copy(upstream, client) }()
	go func() { defer wait.Done(); _, _ = io.Copy(client, upstream) }()
	wait.Wait()
}
