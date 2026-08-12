package audit

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const sandboxProxyAddress = "127.0.0.1:18080"

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
)

var nonPublicNetworks = func() []*net.IPNet {
	var result []*net.IPNet
	for _, value := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32",
	} {
		_, network, _ := net.ParseCIDR(value)
		result = append(result, network)
	}
	return result
}()

type networkBrokerProcess struct {
	command *exec.Cmd
	done    chan error
}

func startNetworkBroker(directory string, cfg NetworkConfig) (*networkBrokerProcess, error) {
	socket := filepath.Join(directory, "proxy.sock")
	args := []string{
		"--die-with-parent", "--new-session", "--unshare-all", "--share-net",
		"--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
		"--symlink", "usr/lib", "/lib64", "--dir", "/etc", "--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf",
		"--ro-bind-try", "/etc/hosts", "/etc/hosts", "--ro-bind-try", "/etc/nsswitch.conf", "/etc/nsswitch.conf",
		"--ro-bind-try", "/etc/ssl", "/etc/ssl", "--ro-bind-try", "/etc/ca-certificates", "/etc/ca-certificates",
		"--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/broker", "--bind", directory, "/broker",
		"--clearenv", "--setenv", "PATH", "/usr/bin", "--setenv", "LANG", "C.UTF-8", "/usr/bin/prolewatch-net", "broker",
		"/broker/proxy.sock", strconv.Itoa(cfg.MaxConnections), strconv.Itoa(cfg.ConnectTimeoutSeconds),
		strconv.Itoa(cfg.IdleTimeoutSeconds), strconv.FormatInt(cfg.MaxTransferBytes, 10),
	}
	command := networkExecCommand("/usr/bin/bwrap", args...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stderr := newLimitedBuffer(1024 * 1024)
	command.Stdout = newLimitedBuffer(1024 * 1024)
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		return nil, err
	}
	process := &networkBrokerProcess{command: command, done: make(chan error, 1)}
	go func() { process.done <- command.Wait() }()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-process.done:
			return nil, fmt.Errorf("network broker exited before readiness: %w: %s", err, truncate(stderr.String(), 1000))
		case <-deadline.C:
			process.stop()
			return nil, errors.New("network broker readiness timed out")
		case <-ticker.C:
			if networkSocketReady(socket) {
				return process, nil
			}
		}
	}
}

func (p *networkBrokerProcess) stop() {
	if p == nil || p.command == nil || p.command.Process == nil {
		return
	}
	_ = syscall.Kill(-p.command.Process.Pid, syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(2 * time.Second):
		_ = syscall.Kill(-p.command.Process.Pid, syscall.SIGKILL)
		<-p.done
	}
}

type networkBroker struct {
	cfg       NetworkConfig
	semaphore chan struct{}
	used      atomic.Int64
	subnets   []*net.IPNet
	addresses []net.IP
}

func RunNetworkBroker(ctx context.Context, socket string, cfg NetworkConfig) int {
	if cfg.MaxConnections <= 0 || cfg.ConnectTimeoutSeconds <= 0 || cfg.IdleTimeoutSeconds <= 0 || cfg.MaxTransferBytes <= 0 {
		return 20
	}
	if err := os.Remove(socket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return 23
	}
	listener, err := networkListen("unix", socket)
	if err != nil {
		return 23
	}
	defer listener.Close()
	_ = os.Chmod(socket, 0o600)
	broker := &networkBroker{cfg: cfg, semaphore: make(chan struct{}, cfg.MaxConnections)}
	broker.captureHostNetworks()
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return 0
			}
			return 24
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

func (b *networkBroker) captureHostNetworks() {
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		addresses, _ := iface.Addrs()
		for _, address := range addresses {
			ip, network, err := net.ParseCIDR(address.String())
			if err == nil {
				b.addresses = append(b.addresses, ip)
				b.subnets = append(b.subnets, network)
			}
		}
	}
}

func (b *networkBroker) handle(conn net.Conn) {
	defer conn.Close()
	idle := &idleConn{Conn: conn, timeout: time.Duration(b.cfg.IdleTimeoutSeconds) * time.Second}
	reader := bufio.NewReaderSize(idle, 64*1024)
	first, err := reader.Peek(1)
	if err != nil {
		return
	}
	if first[0] == 5 {
		b.handleSOCKS(idle, reader)
		return
	}
	b.handleHTTP(idle, reader)
}

func (b *networkBroker) handleSOCKS(client net.Conn, reader *bufio.Reader) {
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
	port := int(binary.BigEndian.Uint16(portRaw))
	upstream, err := b.dialPublic(context.Background(), host, port)
	if err != nil {
		_, _ = client.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	_, _ = client.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	b.tunnel(client, reader, upstream)
}

func (b *networkBroker) handleHTTP(client net.Conn, reader *bufio.Reader) {
	request, err := http.ReadRequest(reader)
	if err != nil || len(request.Header) > 200 {
		return
	}
	if request.Method == http.MethodConnect {
		host, port, err := splitHostPortDefault(request.Host, 443)
		if err != nil || port != 443 {
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
		b.tunnel(client, reader, upstream)
		return
	}
	if request.URL == nil || request.URL.Scheme != "http" || request.URL.Host == "" {
		writeProxyError(client, http.StatusForbidden)
		return
	}
	host, port, err := splitHostPortDefault(request.URL.Host, 80)
	if err != nil || port != 80 {
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
	if host == "" || len(host) > 253 || (port != 80 && port != 443) {
		return "", 0, errors.New("destination is outside the public-web policy")
	}
	return strings.Trim(host, "[]"), port, nil
}

func (b *networkBroker) dialPublic(ctx context.Context, host string, port int) (net.Conn, error) {
	if port != 80 && port != 443 {
		return nil, errors.New("port denied")
	}
	resolveCtx, cancel := context.WithTimeout(ctx, time.Duration(b.cfg.ConnectTimeoutSeconds)*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(resolveCtx, host)
	if err != nil || len(addresses) == 0 {
		return nil, errors.New("DNS resolution failed")
	}
	for _, address := range addresses {
		if !b.publicIP(address.IP) {
			return nil, errors.New("DNS answer contains a non-public address")
		}
	}
	dialer := net.Dialer{Timeout: time.Duration(b.cfg.ConnectTimeoutSeconds) * time.Second}
	for _, address := range addresses {
		conn, err := dialer.DialContext(resolveCtx, "tcp", net.JoinHostPort(address.IP.String(), strconv.Itoa(port)))
		if err == nil {
			return &idleConn{Conn: conn, timeout: time.Duration(b.cfg.IdleTimeoutSeconds) * time.Second}, nil
		}
	}
	return nil, errors.New("all public destinations failed")
}

func (b *networkBroker) publicIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	for _, network := range nonPublicNetworks {
		if network.Contains(ip) {
			return false
		}
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 0 || v4[0] == 127 || (v4[0] == 100 && v4[1]&0xc0 == 64) ||
			(v4[0] == 169 && v4[1] == 254) || v4[0] >= 224 {
			return false
		}
	}
	for _, local := range b.addresses {
		if local.Equal(ip) {
			return false
		}
	}
	for _, subnet := range b.subnets {
		if subnet.Contains(ip) {
			return false
		}
	}
	return true
}

func (b *networkBroker) tunnel(client net.Conn, buffered *bufio.Reader, upstream net.Conn) {
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

func RunNetworkSupervisor(ctx context.Context, socket string, commandArgs []string) int {
	if len(commandArgs) == 0 {
		return 20
	}
	listener, err := networkListen("tcp", sandboxProxyAddress)
	if err != nil {
		return 24
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
		return 24
	}
	return 0
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

func parseProxyURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host != sandboxProxyAddress {
		return errors.New("invalid sandbox proxy URL")
	}
	return nil
}
