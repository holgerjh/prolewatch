package audit

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func writeCurrentConfig(t *testing.T, cfg Config) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	raw, err := CanonicalJSON(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMain(m *testing.M) {
	// GitLab and other container CI runners commonly deny nested user namespaces.
	// Scanner orchestration tests replace only the external parser boundary; the
	// production Bubblewrap argument contract is asserted separately below.
	makepkgArchiveProber = func(fd int) (bool, error) {
		head := make([]byte, 512)
		n, err := syscall.Pread(fd, head, 0)
		if err != nil {
			return false, err
		}
		return archiveFormat(head[:n]) != "", nil
	}
	if info, err := os.Stat("/"); err == nil {
		trustedSystemUID = info.Sys().(*syscall.Stat_t).Uid
		installedFileOwnerUID = trustedSystemUID
	}
	os.Exit(m.Run())
}

func TestArchiveProbeProductionSandboxContract(t *testing.T) {
	args := archiveProbeBwrapArgs()
	joined := " " + strings.Join(args, " ") + " "
	for _, required := range []string{" --unshare-all ", " --ro-bind-fd 3 /input ", " --clearenv ", " /usr/bin/bsdtar -tf /input "} {
		if !strings.Contains(joined, required) {
			t.Fatalf("archive probe sandbox is missing %q: %v", required, args)
		}
	}
	if strings.Contains(joined, " --share-net ") || strings.Contains(joined, " --bind ") {
		t.Fatalf("archive probe unexpectedly exposes network or writable paths: %v", args)
	}
}

func TestArchiveProbeResultClassificationWithoutNamespaces(t *testing.T) {
	if recognized, err := classifyArchiveProbeResult(nil, nil, 0, ""); err != nil || !recognized {
		t.Fatalf("successful bsdtar probe was not recognized: recognized=%t err=%v", recognized, err)
	}
	if recognized, err := classifyArchiveProbeResult(context.DeadlineExceeded, errors.New("killed"), -1, ""); recognized || err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("timeout was misclassified: recognized=%t err=%v", recognized, err)
	}
	if recognized, err := classifyArchiveProbeResult(nil, errors.New("exit status 1"), 1, "bsdtar: Unrecognized archive format"); recognized || err != nil {
		t.Fatalf("ordinary non-archive was misclassified: recognized=%t err=%v", recognized, err)
	}
	if recognized, err := classifyArchiveProbeResult(nil, errors.New("permission denied"), -1, "bwrap: setting up uid map: Permission denied"); recognized || err == nil || !strings.Contains(err.Error(), "uid map") {
		t.Fatalf("sandbox failure was swallowed: recognized=%t err=%v", recognized, err)
	}
}

type dispatcherFakeAdapter struct {
	credential string
}

func (a *dispatcherFakeAdapter) Metadata(context.Context) (ProviderMetadata, error) {
	return ProviderMetadata{Provider: "codex", Transport: "cli", RuntimeVersion: "test", Model: "gpt", Effort: "high", AdapterPolicy: "test"}, nil
}
func (a *dispatcherFakeAdapter) Review(context.Context, ReviewSnapshot) (Verdict, error) {
	return Verdict{SchemaVersion: 1, Verdict: "allow", Confidence: "high", Summary: "safe", Findings: []ReviewFinding{}, CoverageNotes: []string{}}, nil
}
func (a *dispatcherFakeAdapter) CredentialPath() string { return a.credential }

type semanticCanaryReviewer struct{ metadata ProviderMetadata }

func (r *semanticCanaryReviewer) Probe(context.Context) (ProviderMetadata, error) {
	return r.metadata, nil
}

type failingProviderAdapter struct {
	credential  string
	metadataErr error
	reviewErr   error
}

func (a *failingProviderAdapter) Metadata(context.Context) (ProviderMetadata, error) {
	if a.metadataErr != nil {
		return ProviderMetadata{}, a.metadataErr
	}
	return ProviderMetadata{Provider: "codex", Transport: "cli", RuntimeVersion: "test", Model: "gpt", Effort: "high", AdapterPolicy: "test"}, nil
}
func (a *failingProviderAdapter) Review(context.Context, ReviewSnapshot) (Verdict, error) {
	return Verdict{}, a.reviewErr
}
func (a *failingProviderAdapter) CredentialPath() string { return a.credential }
func (r *semanticCanaryReviewer) Review(context.Context, string, string, *Inventory) (ProviderMetadata, []Verdict, error) {
	return r.metadata, []Verdict{{SchemaVersion: 1, Verdict: "block", Confidence: "high", Summary: "prompt injection blocked",
		PromptInjectionDetected: true, Findings: []ReviewFinding{}, CoverageNotes: []string{}}}, nil
}

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

type testTCPListener struct{ *testListener }

func (l *testTCPListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 43210}
}

func writeExecutable(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "helper")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nset -eu\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestProviderAdaptersWithHermeticCLIs(t *testing.T) {
	withStateAndShare(t)
	previousCodex, previousClaude, previousSandbox, previousShareRoot := codexHostBinary, claudeHostBinary, providerSandboxBinary, providerShareRoot
	defer func() {
		codexHostBinary, claudeHostBinary, providerSandboxBinary = previousCodex, previousClaude, previousSandbox
		providerShareRoot = previousShareRoot
	}()
	repositoryShare, err := filepath.Abs(filepath.Join("..", "..", "share"))
	if err != nil {
		t.Fatal(err)
	}
	providerShareRoot = func() string { return repositoryShare }
	codexHostBinary = writeExecutable(t, `
if [ "${1:-}" = "--version" ]; then
	  echo 'WARNING: provider home does not permit PATH alias creation' >&2
  echo 'codex-cli 0.146.1'
elif [ "${1:-}" = "features" ] && [ "${2:-}" = "list" ]; then
	printf 'zeta stable true\nalpha stable false\nlegacy deprecated false\ngone removed true\n'
else
  exit 2
fi`)
	providerSandboxBinary = writeExecutable(t, `
printf '%s\n' '{"schema_version":1,"verdict":"allow","confidence":"high","summary":"safe","prompt_injection_detected":false,"findings":[],"coverage_notes":[]}'`)
	cfg := DefaultConfig()
	codex := &codexAdapter{adapterBase{cfg: cfg, provider: cfg.Providers.Codex}}
	metadata, err := codex.Metadata(context.Background())
	if err != nil || metadata.RuntimeVersion != "codex-cli 0.146.1" || metadata.AdapterPolicy != "codex-cli-v2:disable-current-2" {
		t.Fatalf("hermetic Codex metadata failed: %+v %v", metadata, err)
	}
	verdict, err := codex.Review(context.Background(), ReviewSnapshot{})
	if err != nil || verdict.Verdict != "allow" {
		t.Fatalf("hermetic Codex review failed: %+v %v", verdict, err)
	}
	claudeHostBinary = writeExecutable(t, `
if [ "${1:-}" = "--version" ]; then echo 'claude 2.1.205'; else exit 2; fi`)
	providerSandboxBinary = writeExecutable(t, `
printf '%s\n' '{"subtype":"success","structured_output":{"schema_version":1,"verdict":"allow","confidence":"high","summary":"safe","prompt_injection_detected":false,"findings":[],"coverage_notes":[]}}'`)
	cfg.Provider = "anthropic"
	claude := &claudeAdapter{adapterBase{cfg: cfg, provider: cfg.Providers.Anthropic}}
	metadata, err = claude.Metadata(context.Background())
	if err != nil || metadata.Provider != "anthropic" || metadata.RuntimeVersion != "claude-code 2.1.205" {
		t.Fatalf("hermetic Claude metadata failed: %+v %v", metadata, err)
	}
	verdict, err = claude.Review(context.Background(), ReviewSnapshot{})
	if err != nil || verdict.Verdict != "allow" {
		t.Fatalf("hermetic Claude review failed: %+v %v", verdict, err)
	}
	providerSandboxBinary = writeExecutable(t, `printf '%s\n' '{"subtype":"failure"}'`)
	if _, err := claude.Review(context.Background(), ReviewSnapshot{}); err == nil {
		t.Fatal("failed Claude envelope accepted")
	}
	for _, version := range []string{"0.145.0", "0.147.0"} {
		codexHostBinary = writeExecutable(t, "echo 'codex-cli "+version+"'")
		if _, err := codex.Metadata(context.Background()); err == nil {
			t.Errorf("unsupported Codex %s accepted", version)
		}
	}
	for _, version := range []string{"2.1.204", "3.0.0"} {
		claudeHostBinary = writeExecutable(t, "echo 'claude "+version+"'")
		if _, err := claude.Metadata(context.Background()); err == nil {
			t.Errorf("unsupported Claude %s accepted", version)
		}
	}
}

func TestProviderDispatcherFullProtocolWithHermeticAdapter(t *testing.T) {
	credential := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(credential, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousLookup, previousEUID, previousLoader, previousFactory := providerUserLookup, providerEffectiveUID, providerConfigLoader, providerAdapterFactory
	previousSandbox := providerSandboxBinary
	defer func() {
		providerUserLookup, providerEffectiveUID, providerConfigLoader, providerAdapterFactory = previousLookup, previousEUID, previousLoader, previousFactory
		providerSandboxBinary = previousSandbox
	}()
	uid := os.Geteuid()
	providerUserLookup = func(string) (*user.User, error) {
		return &user.User{Uid: strconv.Itoa(uid), HomeDir: "/var/lib/prolewatch"}, nil
	}
	providerEffectiveUID = func() int { return uid }
	providerConfigLoader = func() (Config, error) { return DefaultConfig(), nil }
	providerAdapterFactory = func(Config) providerAdapter { return &dispatcherFakeAdapter{credential: credential} }
	providerSandboxBinary = "/usr/bin/true"
	run := func(request any) (int, []byte, string) {
		raw, _ := CanonicalJSON(request)
		var stdout, stderr bytes.Buffer
		status := RunProviderDispatcher(context.Background(), bytes.NewReader(raw), &stdout, &stderr)
		return status, stdout.Bytes(), stderr.String()
	}
	status, raw, stderr := run(DispatchRequest{ProtocolVersion: DispatchProtocolVersion, Operation: "probe"})
	if status != 0 || stderr != "" {
		t.Fatalf("dispatcher probe failed: status=%d stderr=%q", status, stderr)
	}
	var response DispatchResponse
	if err := DecodeStrict(raw, &response); err != nil || response.Validate("probe") != nil {
		t.Fatalf("dispatcher probe response invalid: %s %v", raw, err)
	}
	status, raw, stderr = run(DispatchRequest{ProtocolVersion: DispatchProtocolVersion, Operation: "canary"})
	if status != 0 || stderr != "" || DecodeStrict(raw, &response) != nil || response.Validate("canary") != nil {
		t.Fatalf("dispatcher canary failed: status=%d stdout=%s stderr=%q", status, raw, stderr)
	}
	record := FileRecord{Path: "PKGBUILD", PathB64: "UEtHQlVJTEQ=", Kind: "file", Mode: 0o600, Size: 12,
		SHA256: strings.Repeat("a", 64), Text: true, SelectedReason: "mandatory", BinaryMetadata: map[string]any{}}
	manifest := []map[string]any{record.ManifestValue()}
	manifestRaw, _ := CanonicalJSON(manifest)
	snapshot := ReviewSnapshot{SnapshotSchemaVersion: ReviewSnapshotVersion, PackageBase: "demo", Phase: "pre",
		ManifestHash: SHA256Bytes(manifestRaw), Coverage: Coverage{FilesSeen: 1, BytesSeen: 12, TextFiles: 1, TextBytes: 12,
			SelectedFiles: 1, SelectedBytes: 12, ReviewEligibleFiles: 1, ReviewEligibleBytes: 12, Complete: true, Notes: []string{}},
		Manifest: manifest, BatchCount: 1, Files: []SelectedFile{{File: "PKGBUILD", Content: "pkgname=demo"}}}
	status, raw, stderr = run(DispatchRequest{ProtocolVersion: DispatchProtocolVersion, Operation: "review", Snapshot: &snapshot})
	if status != 0 || stderr != "" || DecodeStrict(raw, &response) != nil || response.Validate("review") != nil {
		t.Fatalf("dispatcher review failed: status=%d stdout=%s stderr=%q", status, raw, stderr)
	}
	providerEffectiveUID = func() int { return uid + 1 }
	if status, _, _ := run(DispatchRequest{ProtocolVersion: 1, Operation: "probe"}); status != 22 {
		t.Fatalf("wrong dispatcher uid status=%d", status)
	}
	providerEffectiveUID = func() int { return uid }
	providerUserLookup = func(string) (*user.User, error) { return nil, errors.New("missing") }
	if status, _, _ := run(DispatchRequest{ProtocolVersion: 1, Operation: "probe"}); status != 22 {
		t.Fatalf("missing dispatcher user status=%d", status)
	}
	providerUserLookup = func(string) (*user.User, error) { return &user.User{Uid: strconv.Itoa(uid)}, nil }
	providerConfigLoader = func() (Config, error) { return Config{}, errors.New("config") }
	if status, _, _ := run(DispatchRequest{ProtocolVersion: 1, Operation: "probe"}); status != 20 {
		t.Fatalf("dispatcher config failure status=%d", status)
	}
	providerConfigLoader = func() (Config, error) {
		cfg := DefaultConfig()
		cfg.Review.Mode = ReviewModeDeterministicOnly
		return cfg, nil
	}
	if status, _, stderr := run(DispatchRequest{ProtocolVersion: 1, Operation: "probe"}); status != 22 || !strings.Contains(stderr, "disabled") {
		t.Fatalf("deterministic-only provider dispatch status=%d stderr=%q", status, stderr)
	}
	providerConfigLoader = func() (Config, error) { cfg := DefaultConfig(); cfg.Limits.MaxDispatchBytes = 1; return cfg, nil }
	if status, _, _ := run(DispatchRequest{ProtocolVersion: 1, Operation: "probe"}); status != 22 {
		t.Fatalf("dispatcher input limit status=%d", status)
	}
	providerConfigLoader = func() (Config, error) { return DefaultConfig(), nil }
	var invalidOut, invalidErr bytes.Buffer
	if status := RunProviderDispatcher(context.Background(), strings.NewReader("{"), &invalidOut, &invalidErr); status != 22 {
		t.Fatalf("invalid dispatcher JSON status=%d", status)
	}
	if status, _, _ := run(DispatchRequest{ProtocolVersion: 1, Operation: "unknown"}); status != 22 {
		t.Fatalf("invalid dispatcher operation status=%d", status)
	}
	providerAdapterFactory = func(Config) providerAdapter {
		return &failingProviderAdapter{credential: filepath.Join(t.TempDir(), "missing")}
	}
	if status, _, _ := run(DispatchRequest{ProtocolVersion: 1, Operation: "probe"}); status != 22 {
		t.Fatalf("missing dispatcher credential status=%d", status)
	}
	providerAdapterFactory = func(Config) providerAdapter {
		return &failingProviderAdapter{credential: credential, metadataErr: errors.New("metadata")}
	}
	if status, _, _ := run(DispatchRequest{ProtocolVersion: 1, Operation: "probe"}); status != 22 {
		t.Fatalf("dispatcher metadata failure status=%d", status)
	}
	providerAdapterFactory = func(Config) providerAdapter {
		return &failingProviderAdapter{credential: credential, reviewErr: errors.New("review")}
	}
	if status, _, _ := run(DispatchRequest{ProtocolVersion: 1, Operation: "review", Snapshot: &snapshot}); status != 22 {
		t.Fatalf("dispatcher review failure status=%d", status)
	}
}

func TestGPGAndProviderOuterSandboxHermeticLaunches(t *testing.T) {
	withStateAndShare(t)
	previousGPG, previousProvider := gpgSandboxBinary, providerSandboxBinary
	defer func() { gpgSandboxBinary, providerSandboxBinary = previousGPG, previousProvider }()
	gpgSandboxBinary = writeExecutable(t, "exit 0")
	if status := RunGPG([]string{"--list-keys", strings.Repeat("A", 16)}); status != 0 {
		t.Fatalf("hermetic GPG wrapper status=%d", status)
	}
	gpgSandboxBinary = writeExecutable(t, "exit 7")
	if status := RunGPG([]string{"--recv-keys", strings.Repeat("B", 16)}); status != 7 {
		t.Fatalf("GPG exit status not preserved: %d", status)
	}
	providerSandboxBinary = "/usr/bin/true"
	if err := providerOuterSandboxCanary(context.Background(), DefaultConfig()); err != nil {
		t.Fatal(err)
	}
	providerSandboxBinary = "/usr/bin/false"
	if err := providerOuterSandboxCanary(context.Background(), DefaultConfig()); err == nil {
		t.Fatal("failed provider outer sandbox canary succeeded")
	}
	gpgSandboxBinary = filepath.Join(t.TempDir(), "missing")
	if status := RunGPG([]string{"--list-keys", strings.Repeat("C", 16)}); status != 24 {
		t.Fatalf("missing GPG sandbox status=%d", status)
	}
}

func TestCommandAndProviderBoundaryHelpers(t *testing.T) {
	cfg := DefaultConfig()
	stdout, _, err := runProcessGroup(context.Background(), "/usr/bin/sh", []string{"-c", "printf safe"}, nil, cfg)
	if err != nil || string(stdout) != "safe" {
		t.Fatalf("process group success path failed: %q %v", stdout, err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := runProcessGroup(cancelled, "/usr/bin/sh", []string{"-c", "sleep 10"}, nil, cfg); !errors.Is(err, context.Canceled) {
		t.Fatalf("process group cancellation did not fail closed: %v", err)
	}
	if _, _, err := runProcessGroup(context.Background(), "/definitely/missing", nil, nil, cfg); err == nil {
		t.Fatal("missing provider process was accepted")
	}
	version, parsed, err := commandVersion(context.Background(), "/usr/bin/sh", "-c", "echo helper 1.2.3")
	if err != nil || version == "" || len(parsed) != 3 {
		t.Fatalf("helper version is not parseable: %q %#v %v", version, parsed, err)
	}
	if activeAdapter(cfg).CredentialPath() != "/var/lib/prolewatch/providers/codex/auth.json" {
		t.Fatal("wrong active adapter")
	}
	cfg.Provider = "anthropic"
	if activeAdapter(cfg).CredentialPath() != "/var/lib/prolewatch/providers/anthropic/.credentials.json" {
		t.Fatal("wrong alternate adapter")
	}
	if len(providerBwrapBase("/host", "/provider-home")) == 0 {
		t.Fatal("empty provider sandbox profile")
	}
}

func TestCredentialAndCanaryValidationBranches(t *testing.T) {
	credential := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(credential, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateCredential(credential, uint32(os.Getuid())); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(credential, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateCredential(credential, uint32(os.Getuid())); err == nil {
		t.Fatal("loose credential permissions accepted")
	}
	metadata := ProviderMetadata{Provider: "codex", Transport: "cli", RuntimeVersion: "v", Model: "m", Effort: "high", AdapterPolicy: "p"}
	provider := ToolIdentity{Path: "/usr/bin/codex", Version: "v", SHA256: strings.Repeat("a", 64)}
	archive := ToolIdentity{Path: "/usr/bin/bsdtar", Version: "v", SHA256: strings.Repeat("b", 64)}
	valid := ProviderAttestation{SchemaVersion: 1, CanaryVersion: providerCanaryVersion, CreatedAt: UTCNow(), PolicyFingerprint: strings.Repeat("c", 64), Metadata: metadata, ProviderBinary: provider, ArchiveProbe: archive, Checks: CanaryChecks{true, true, true, true, true}}
	if err := valid.Validate(valid.PolicyFingerprint, metadata, provider, archive); err != nil {
		t.Fatal(err)
	}
	valid.CreatedAt = "invalid"
	if err := valid.Validate(valid.PolicyFingerprint, metadata, provider, archive); err == nil {
		t.Fatal("invalid canary timestamp accepted")
	}
	valid.CreatedAt = UTCNow()
	valid.Checks.NoCommands = false
	if err := valid.Validate(valid.PolicyFingerprint, metadata, provider, archive); err == nil {
		t.Fatal("partial canary accepted")
	}
}

func runBrokerExchange(t *testing.T, payload []byte) []byte {
	t.Helper()
	server, client := net.Pipe()
	broker := &networkBroker{cfg: NetworkConfig{MaxConnections: 2, ConnectTimeoutSeconds: 1, IdleTimeoutSeconds: 1, MaxTransferBytes: 1024 * 1024}}
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
	broker := &networkBroker{cfg: NetworkConfig{MaxConnections: 2, ConnectTimeoutSeconds: 1, IdleTimeoutSeconds: 1, MaxTransferBytes: 1024}}
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
	for _, value := range []string{"http://127.0.0.1:18080", "socks5h://127.0.0.1:18080"} {
		if err := parseProxyURL(value); err != nil {
			t.Fatal(err)
		}
	}
	if err := parseProxyURL("http://127.0.0.1:1"); err == nil {
		t.Fatal("wrong proxy endpoint accepted")
	}
}

func TestSOCKSAddressAndAuthenticationDenials(t *testing.T) {
	exchange := func(methods, request []byte, responseSize int) []byte {
		server, client := net.Pipe()
		broker := &networkBroker{cfg: NetworkConfig{ConnectTimeoutSeconds: 1, IdleTimeoutSeconds: 1, MaxTransferBytes: 1024}}
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
	previousListen, previousExec, previousContext, previousReady, previousDial := networkListen, networkExecCommand, networkCommandContext, networkSocketReady, networkRelayDial
	defer func() {
		networkListen, networkExecCommand, networkCommandContext, networkSocketReady, networkRelayDial = previousListen, previousExec, previousContext, previousReady, previousDial
	}()
	networkExecCommand = func(string, ...string) *exec.Cmd {
		return exec.Command("/usr/bin/sh", "-c", "sleep 10")
	}
	networkSocketReady = func(string) bool { return true }
	process, err := startNetworkBroker(t.TempDir(), DefaultConfig().Network)
	if err != nil {
		t.Fatal(err)
	}
	process.stop()
	networkExecCommand = func(string, ...string) *exec.Cmd { return exec.Command("/usr/bin/false") }
	networkSocketReady = func(string) bool { return false }
	if _, err := startNetworkBroker(t.TempDir(), DefaultConfig().Network); err == nil {
		t.Fatal("early broker process exit was accepted")
	}
	if status := RunNetworkBroker(context.Background(), "unused", NetworkConfig{}); status != 20 {
		t.Fatalf("invalid broker configuration status=%d", status)
	}
	networkListen = func(string, string) (net.Listener, error) { return nil, errors.New("listen") }
	if status := RunNetworkBroker(context.Background(), filepath.Join(t.TempDir(), "broker.sock"), DefaultConfig().Network); status != 23 {
		t.Fatalf("broker listen failure status=%d", status)
	}

	listener := newTestListener()
	networkListen = func(string, string) (net.Listener, error) { return listener, nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- RunNetworkBroker(ctx, filepath.Join(t.TempDir(), "broker.sock"), DefaultConfig().Network)
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
	broker := &networkBroker{cfg: NetworkConfig{IdleTimeoutSeconds: 1, MaxTransferBytes: 1024}}
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

func TestBuildBoundaryConstructionAndKeyringCopy(t *testing.T) {
	job := t.TempDir()
	binds, err := snapshotMakepkgConfigs(job, Invocation{})
	rootOwned := err == nil
	if err != nil && !strings.Contains(err.Error(), "filesystem root has unsafe ownership") {
		t.Fatalf("makepkg config snapshot failed: %#v %v", binds, err)
	}
	if rootOwned {
		var dropinSnapshot string
		for _, bind := range binds {
			if bind[1] == "/etc/makepkg.conf.d" {
				dropinSnapshot = bind[0]
			}
		}
		info, statErr := os.Stat(dropinSnapshot)
		if dropinSnapshot == "" || statErr != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("makepkg drop-ins were not captured as one private directory: %#v %v", binds, statErr)
		}
		hostEntries, hostErr := os.ReadDir("/etc/makepkg.conf.d")
		snapshotEntries, snapshotErr := os.ReadDir(dropinSnapshot)
		if hostErr == nil && (snapshotErr != nil || len(snapshotEntries) != len(hostEntries)) {
			t.Fatalf("makepkg drop-in snapshot is incomplete: host=%d snapshot=%d err=%v", len(hostEntries), len(snapshotEntries), snapshotErr)
		}
	}
	var args []string
	appendReadOnlyPolicyBind(&args, "/usr/share", true)
	wantArgs := []string{"--dir", "/usr/share", "--ro-bind", "/usr/share", "/usr/share"}
	if strings.Join(args, "\x00") != strings.Join(wantArgs, "\x00") {
		t.Fatalf("read-only policy bind arguments changed: %#v", args)
	}
	args = nil
	if err := appendReadOnlyPolicyPath(&args, t.TempDir()); err == nil {
		t.Fatal("user-owned read-only path accepted")
	}
	source, destination := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "pubring.kbx"), []byte("public"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyKeyring(source, destination); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(filepath.Join(destination, "pubring.kbx")); err != nil || string(raw) != "public" {
		t.Fatalf("keyring copy mismatch: %q %v", raw, err)
	}
	runtimeSocket, err := net.Listen("unix", filepath.Join(source, "S.dirmngr"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtimeSocket.Close() })
	destination = t.TempDir()
	if err := copyKeyring(source, destination); err != nil {
		t.Fatalf("standard GnuPG runtime socket blocked public key copying: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(destination, "S.dirmngr")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("GnuPG runtime socket was copied: %v", err)
	}
	unsafeSocketSource := t.TempDir()
	unsafeSocket, err := net.Listen("unix", filepath.Join(unsafeSocketSource, "unexpected.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unsafeSocket.Close() })
	if err := copyKeyring(unsafeSocketSource, t.TempDir()); err == nil {
		t.Fatal("unexpected keyring socket accepted")
	}
	badSource := t.TempDir()
	if err := os.Symlink("missing", filepath.Join(badSource, "link")); err != nil {
		t.Fatal(err)
	}
	if err := copyKeyring(badSource, t.TempDir()); err == nil {
		t.Fatal("symlinked keyring content accepted")
	}
}

func TestSandboxRunnerRecordsEnforcementOnHostFailure(t *testing.T) {
	withStateAndShare(t)
	cfg := DefaultConfig()
	work := t.TempDir()
	stdout, stderr, enforcement, err := runMakepkgSandbox(Invocation{Profile: "info", Args: []string{"--version"}}, work, false, cfg)
	_ = stdout
	_ = stderr
	if enforcement.MemoryBytes == 0 && err != nil && strings.Contains(err.Error(), "filesystem root has unsafe ownership") {
		t.Log("container remaps root-owned system files; sandbox construction failed closed before resource launch")
		return
	}
	if enforcement.MemoryBytes <= 0 || enforcement.TasksMax != cfg.Build.TasksMax {
		t.Fatalf("resource enforcement was not constructed: %+v", enforcement)
	}
	// CI containers often lack a user systemd manager; an error there is an
	// expected fail-closed result. A configured Arch host may run successfully.
	if err != nil && enforcement.Termination == "" {
		t.Logf("sandbox failed before an explicit termination reason: %v", err)
	}
}

func TestMakepkgSandboxProfileConstruction(t *testing.T) {
	withStateAndShare(t)
	previousSnapshotter, previousRunner, previousBroker, previousValidator := makepkgConfigSnapshotter, constrainedCommandRunner, makepkgNetworkBrokerStart, preparedRootValidator
	defer func() {
		makepkgConfigSnapshotter, constrainedCommandRunner, makepkgNetworkBrokerStart, preparedRootValidator = previousSnapshotter, previousRunner, previousBroker, previousValidator
	}()
	makepkgConfigSnapshotter = func(string, Invocation) ([][2]string, error) { return nil, nil }
	makepkgNetworkBrokerStart = func(string, NetworkConfig) (*networkBrokerProcess, error) { return &networkBrokerProcess{}, nil }
	preparedRootValidator = func(string) error { return nil }
	var captured [][]string
	constrainedCommandRunner = func(args []string, _ []*os.File, _ string, cfg Config, _ *ActivityRecorder, _ commandOutputObserver) ([]byte, []byte, SandboxEnforcement, error) {
		captured = append(captured, append([]string(nil), args...))
		return nil, nil, effectiveBuildLimits(cfg.Build), nil
	}
	cfg := DefaultConfig()
	work := t.TempDir()
	root := t.TempDir()
	manifest := validTestCleanRootManifest()
	if _, _, _, err := runMakepkgSandbox(Invocation{Profile: "build", Args: []string{"--noextract", "--noprepare", "--holdver"}, CleanRootPath: root, CleanRoot: manifest, PersistentCargoHome: true}, work, false, cfg); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := runMakepkgSandbox(Invocation{Profile: "verify", Args: []string{"--verifysource"}, CleanRootPath: root, CleanRoot: manifest}, work, true, cfg); err != nil {
		t.Fatal(err)
	}
	if len(captured) != 2 {
		t.Fatalf("captured profiles=%d", len(captured))
	}
	offline, online := strings.Join(captured[0], "\x00"), strings.Join(captured[1], "\x00")
	if strings.Contains(offline, "/opt") || strings.Contains(online, "--share-net") || !strings.Contains(offline, "/usr/bin/makepkg") ||
		!strings.Contains(offline, "CARGO_HOME\x00/build/src/.prolewatch-cargo-home") {
		t.Fatalf("unsafe offline build profile: %q", offline)
	}
	if !strings.Contains(online, "/usr/bin/prolewatch-net\x00supervise\x00/broker/proxy.sock") || !strings.Contains(online, "HTTP_PROXY\x00http://"+sandboxProxyAddress) ||
		!strings.Contains(online, "\x00/build-home\x00--dir\x00/broker") {
		t.Fatalf("public-web broker was not wired into verification: %q", online)
	}
}

func TestConstrainedCommandLifecycleFailsClosedOrCompletes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Build.DiskReserveBytes = 1
	_, _, enforcement, err := runConstrainedCommand([]string{"--version"}, nil, t.TempDir(), cfg, nil, nil)
	if enforcement.MemoryBytes <= 0 || enforcement.CPUCount <= 0 || enforcement.NetworkPolicy != "isolated" {
		t.Fatalf("constrained launch omitted enforcement: %+v", enforcement)
	}
	if err != nil {
		t.Logf("user systemd manager unavailable; launch failed closed: %v", err)
	}
}

func TestPackageListEscapeAndSealFailureCleanup(t *testing.T) {
	if status := handlePackageList(context.Background(), []byte("/escape.pkg.tar.zst\n"), t.TempDir(), &Report{}, nil); status != 24 {
		t.Fatalf("escaping package list status=%d", status)
	}
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	file := filepath.Join(t.TempDir(), "bad.pkg.tar")
	if err := os.WriteFile(file, []byte("bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	report := &Report{ReportID: "20260812T010203Z-aaaaaaaaaaaa-bbbbbbbb"}
	if status := sealFailure([]string{file}, nil, report, errors.New("forced")); status != 25 || regularNoFollow(file) {
		t.Fatalf("seal failure did not quarantine: status=%d exists=%t", status, regularNoFollow(file))
	}
	if _, err := sealedPath(nil, "x"); err == nil {
		t.Fatal("nil sealing report accepted")
	}
}

func TestNetworkLeaseLifecycle(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	report := approvalFixture()
	report.ApprovalEligible = false
	report.NetworkEligible = true
	approvals := NewApprovalStore()
	if _, err := approvals.Create(report, "network", "needed for source"); err != nil {
		t.Fatal(err)
	}
	leases := NewNetworkLeaseStore()
	active, err := leases.ActiveOrConsume(report, approvals, os.Getpid())
	if err != nil || !active {
		t.Fatalf("network lease was not consumed: %t %v", active, err)
	}
	active, err = leases.ActiveOrConsume(report, approvals, os.Getpid())
	if err != nil || !active {
		t.Fatalf("live network lease was not reused: %t %v", active, err)
	}
	if _, err := leases.ActiveOrConsume(nil, approvals, 0); err == nil {
		t.Fatal("nil report authorized network")
	}
	if err := os.WriteFile(filepath.Join(leases.Root, "dead.json"), []byte("bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	leases.removeDead()
	if _, err := os.Stat(filepath.Join(leases.Root, "dead.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid dead lease was retained")
	}
}

func TestInteractiveApprovalInputBinding(t *testing.T) {
	report := approvalFixture()
	report.Findings = []Finding{{Severity: "medium", Category: "other", File: "PKGBUILD", Evidence: "review", Rationale: "manual review", RuleID: "manual"}}
	store := &ApprovalStore{Root: t.TempDir()}
	confirmation := report.PackageBase + " " + report.ContentHash[:12] + "\nreviewed carefully\n"
	var output bytes.Buffer
	path, err := interactiveApprovalInput(report, "approval", store, strings.NewReader(confirmation), &output)
	if err != nil || path == "" || !strings.Contains(output.String(), "Findings:") {
		t.Fatalf("interactive approval failed: path=%q output=%q err=%v", path, output.String(), err)
	}
	if _, err := interactiveApprovalInput(report, "approval", &ApprovalStore{Root: t.TempDir()}, strings.NewReader("wrong\n"), io.Discard); err == nil {
		t.Fatal("wrong interactive confirmation accepted")
	}
	shortReason := report.PackageBase + " " + report.ContentHash[:12] + "\nno\n"
	if _, err := interactiveApprovalInput(report, "approval", &ApprovalStore{Root: t.TempDir()}, strings.NewReader(shortReason), io.Discard); err == nil {
		t.Fatal("short interactive reason accepted")
	}
	if _, err := InteractiveApproval(nil, "approval", store); err == nil {
		t.Fatal("nil interactive report accepted")
	}
	if _, err := InteractiveApproval(report, "approval", store); err == nil {
		t.Fatal("non-TTY interactive approval succeeded")
	}
}

func TestDoctorCLIAndWrapperFailurePaths(t *testing.T) {
	withStateAndShare(t)
	previousInfoCommand := makepkgInfoCommand
	makepkgInfoCommand = func(string, ...string) *exec.Cmd { return exec.Command("/usr/bin/true") }
	defer func() { makepkgInfoCommand = previousInfoCommand }()
	cfg := DefaultConfig()
	checks := RunDoctor(context.Background(), cfg, false)
	if len(checks) < 20 || RenderChecks(checks) == "" {
		t.Fatalf("doctor omitted required checks: %#v", checks)
	}
	if DoctorOK([]Check{{Name: "required", Required: true}}) || !DoctorOK([]Check{{Name: "optional", Required: false}}) {
		t.Fatal("doctor required/optional policy is wrong")
	}
	healthy := RenderChecks([]Check{{Name: "required", OK: true, Required: true}, {Name: "optional", Required: false}})
	if !strings.Contains(healthy, "Everything is fine. Big Brother is watching the build.") {
		t.Fatalf("healthy doctor omitted success footer: %q", healthy)
	}
	unhealthy := RenderChecks([]Check{{Name: "required", Required: true}})
	if strings.Contains(unhealthy, "Everything is fine") {
		t.Fatalf("failing doctor rendered success footer: %q", unhealthy)
	}
	previous := SystemConfigPath
	SystemConfigPath = writeCurrentConfig(t, cfg)
	defer func() { SystemConfigPath = previous }()
	for _, invocation := range [][]string{nil, {"unknown"}, {"install-hook", "extra"}, {"uninstall-hook", "extra"}} {
		if RunCLI(context.Background(), invocation) == 0 {
			t.Fatalf("invalid CLI invocation succeeded: %#v", invocation)
		}
	}
	if RunCLI(context.Background(), []string{"version"}) != 0 || RunCLI(context.Background(), []string{"config-check", "--provider-only", "--path", SystemConfigPath}) != 0 {
		t.Fatal("safe CLI informational command failed")
	}
	if runConfigMigrate([]string{"--path", SystemConfigPath}) != 0 || runReport([]string{"--latest", "extra"}) == 0 || runApproval("approve", nil) == 0 || runDoctorCommand(context.Background(), cfg, []string{"extra"}) == 0 {
		t.Fatal("CLI helper status mismatch")
	}
	if RunMakepkg(context.Background(), nil) == 0 {
		t.Fatal("empty makepkg invocation succeeded")
	}
	if RunMakepkg(context.Background(), []string{"--version"}) != 0 {
		t.Fatal("makepkg informational invocation failed")
	}
	if RunGPG([]string{"--unsafe"}) == 0 || len(GPGSandboxCommand(t.TempDir(), "--list-keys", []string{strings.Repeat("A", 16)})) == 0 {
		t.Fatal("GPG boundary status mismatch")
	}
	var list stringList
	_ = list.Set("a")
	_ = list.Set("b")
	if list.String() != "a,b" {
		t.Fatal("repeatable CLI values failed")
	}
}

func TestDoctorInstalledHostBoundaryHelpersHermetically(t *testing.T) {
	previousListen, previousCommand, previousUID := doctorListen, doctorCommandContext, installedFileOwnerUID
	defer func() {
		doctorListen, doctorCommandContext, installedFileOwnerUID = previousListen, previousCommand, previousUID
	}()
	doctorListen = func(string, string) (net.Listener, error) { return &testTCPListener{newTestListener()}, nil }
	doctorCommandContext = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/usr/bin/true")
	}
	if check := bubblewrapSmoke(context.Background()); !check.OK {
		t.Fatalf("hermetic Bubblewrap smoke failed: %+v", check)
	}
	file := filepath.Join(t.TempDir(), "installed")
	if err := os.WriteFile(file, []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	installedFileOwnerUID = uint32(os.Getuid())
	if check := installedFileCheck(file); !check.OK {
		t.Fatalf("safe installed file rejected: %+v", check)
	}
	if check := installedFileCheck(filepath.Join(t.TempDir(), "missing")); check.OK {
		t.Fatal("missing installed file accepted")
	}
}

func TestDoctorLiveSemanticCanaryAndAttestationHermetically(t *testing.T) {
	withStateAndShare(t)
	// The invoking user must not need direct access to this private path.
	credential := filepath.Join(t.TempDir(), "inaccessible-provider-credential")
	adapter := &dispatcherFakeAdapter{credential: credential}
	metadata, _ := adapter.Metadata(context.Background())
	previousDoctorUser, previousAdapter, previousReviewer := doctorUserLookup, providerAdapterFactory, reviewClientFactory
	previousCanary, previousCleanRoot := doctorProviderCanary, cleanRootDispatcher
	previousProviderSandbox, previousCodex := providerSandboxBinary, codexHostBinary
	previousListen, previousCommand := doctorListen, doctorCommandContext
	defer func() {
		doctorUserLookup, providerAdapterFactory, reviewClientFactory = previousDoctorUser, previousAdapter, previousReviewer
		doctorProviderCanary, cleanRootDispatcher = previousCanary, previousCleanRoot
		providerSandboxBinary, codexHostBinary = previousProviderSandbox, previousCodex
		doctorListen, doctorCommandContext = previousListen, previousCommand
	}()
	doctorUserLookup = func(string) (*user.User, error) {
		return &user.User{Uid: strconv.Itoa(os.Getuid()), HomeDir: "/var/lib/prolewatch"}, nil
	}
	providerAdapterFactory = func(Config) providerAdapter { return adapter }
	reviewClientFactory = func(Config) ReviewClient { return &semanticCanaryReviewer{metadata: metadata} }
	doctorProviderCanary = func(context.Context, Config) (ProviderMetadata, error) { return metadata, nil }
	cleanRootDispatcher = func(context.Context, CleanRootRequest) (CleanRootResponse, error) {
		return CleanRootResponse{ProtocolVersion: CleanRootProtocolVersion, OK: true, Identity: CleanRootPolicyIdentity{Available: true, Generation: "1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ManifestSHA256: strings.Repeat("b", 64)}}, nil
	}
	providerSandboxBinary = "/usr/bin/true"
	codexHostBinary = writeExecutable(t, "echo codex")
	doctorListen = func(string, string) (net.Listener, error) { return &testTCPListener{newTestListener()}, nil }
	doctorCommandContext = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/usr/bin/true")
	}
	checks := RunDoctor(context.Background(), DefaultConfig(), true)
	foundRoot, foundAuthentication, foundMetadata, foundIsolation, foundSemantic, foundAttestation := false, false, false, false, false, false
	for _, check := range checks {
		if strings.Contains(check.Name, "sudoers") {
			t.Fatalf("doctor tried to inspect a root-private sudoers path: %+v", check)
		}
		if check.Name == "root dispatcher boundary" {
			foundRoot = check.OK
		}
		if check.Name == "dedicated provider authentication" {
			foundAuthentication = check.OK
		}
		if check.Name == "provider metadata consistency" {
			foundMetadata = check.OK
		}
		if check.Name == "provider host/workspace isolation" {
			foundIsolation = check.OK
		}
		if check.Name == "isolated provider semantic canary" {
			foundSemantic = check.OK
		}
		if check.Name == "provider semantic attestation" {
			foundAttestation = check.OK
		}
	}
	if !foundRoot || !foundAuthentication || !foundMetadata || !foundIsolation || !foundSemantic || !foundAttestation {
		t.Fatalf("live doctor canary failed: %s", RenderChecks(checks))
	}
	if _, err := os.Stat(providerAttestationPath()); err != nil {
		t.Fatal(err)
	}
}

func TestRuleFindingGenerationIsBounded(t *testing.T) {
	engine := RuleEngine{MaxFindings: 2}
	_, _, _, err := engine.ScanReader("payload.sh", bufio.NewReader(strings.NewReader(strings.Repeat("curl http://example.invalid\n", 100))), 1024)
	if err == nil || !strings.Contains(err.Error(), "finding limit") {
		t.Fatalf("finding generation was not bounded: %v", err)
	}
}

func TestAdditionalSecurityBoundaryUtilities(t *testing.T) {
	root := t.TempDir()
	writePackageFixture(t, root)
	fd, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	extractable := readExtractableSources(int(fd.Fd()), 1024*1024)
	fd.Close()
	if !extractable["local.patch"] {
		t.Fatalf("extractable source was not parsed: %#v", extractable)
	}
	if got := makepkgSourceName("https://example.invalid/payload.tar?download=1#fragment"); got != "payload.tar" {
		t.Fatalf("makepkg source filename mismatch: %q", got)
	}
	for input, expected := range map[string]string{
		"alias::https://example.invalid/value":        "alias",
		"git+https://example.invalid/repo.git#tag=v1": "repo",
		"fossil+https://example.invalid/repo":         "repo.fossil",
		"svn+https://example.invalid/project/":        "project",
	} {
		if got := makepkgSourceName(input); got != expected {
			t.Errorf("makepkgSourceName(%q)=%q, want %q", input, got, expected)
		}
	}
	raw := tarBytes(t, map[string][]byte{"usr/bin/blob": append([]byte{0x7f, 'E', 'L', 'F', 2, 1}, bytes.Repeat([]byte{0}, 40)...)})
	result := ScanArchive(bytes.NewReader(raw), "binary.pkg.tar", DefaultConfig(), RuleEngine{}, 0)
	if !result.Supported || len(result.Selected) == 0 {
		t.Fatalf("bounded binary archive inspection failed: %+v", result)
	}
	for kind, expected := range map[uint32]string{syscall.S_IFIFO: "fifo", syscall.S_IFCHR: "char-device", syscall.S_IFBLK: "block-device", syscall.S_IFSOCK: "socket", 0: "special"} {
		if fileKind(kind) != expected {
			t.Errorf("file kind %#o=%q, want %q", kind, fileKind(kind), expected)
		}
	}
	if got := SortedKeys(map[string]any{"b": true, "a": true}); strings.Join(got, "") != "ab" {
		t.Fatal(got)
	}
	metadata := StableMetadata([]ProviderMetadata{{Provider: "z"}, {Provider: "a"}})
	if metadata[0].Provider != "a" {
		t.Fatal("provider metadata order is unstable")
	}
	source, target := filepath.Join(t.TempDir(), "source"), filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(source, []byte("copy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyRegular(source, target, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyRegular(filepath.Dir(source), filepath.Join(t.TempDir(), "bad"), 0o600); err == nil {
		t.Fatal("non-regular copy source accepted")
	}
	withStateAndShare(t)
	packageRoot := t.TempDir()
	writePackageFixture(t, packageRoot)
	reviewer := NewReviewer(DefaultConfig())
	reviewer.Command = []string{os.Args[0], "-test.run=TestDispatcherHelperProcess"}
	t.Setenv("GO_WANT_DISPATCH_HELPER", "1")
	if _, err := reviewer.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	service, err := NewAuditService(context.Background(), DefaultConfig(), &fakeReviewer{})
	if err != nil {
		t.Fatal(err)
	}
	if _, status, err := service.ScanDirectory(context.Background(), "pre", packageRoot, "demo"); err != nil || status != 0 {
		t.Fatalf("report fixture failed: status=%d err=%v", status, err)
	}
	if _, err := NewReportStore().Latest(); err != nil {
		t.Fatal(err)
	}
}

func TestUtilityFailClosedAndFallbackBranches(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("HOME", home)
	if got := StateRoot(); got != filepath.Join(home, ".local", "state", "prolewatch") {
		t.Fatalf("state fallback=%q", got)
	}
	t.Setenv("PROLEWATCH_SHARE", "")
	if got := ShareRoot(); got != "/usr/share/prolewatch" {
		t.Fatalf("share fallback=%q", got)
	}
	if got := truncate(strings.Repeat("x", 20), 5); got != "xxxxx" {
		t.Fatalf("truncate result=%q", got)
	}
	if got := truncateTail("prefix-"+strings.Repeat("x", 100)+"-cause", 40); !strings.HasPrefix(got, "[earlier output omitted]") || !strings.HasSuffix(got, "-cause") || strings.Contains(got, "prefix-") {
		t.Fatalf("tail truncation hid the final cause: %q", got)
	}
	expectedMetadata := ProviderMetadata{Provider: "codex", Transport: "cli", RuntimeVersion: "codex-cli 0.146.1", Model: "gpt", Effort: "high", AdapterPolicy: "policy"}
	actualMetadata := expectedMetadata
	actualMetadata.RuntimeVersion = "WARNING\ncodex-cli 0.146.1"
	if detail := providerMetadataComparisonDetail(expectedMetadata, actualMetadata); !strings.Contains(detail, `runtime_version: local="codex-cli 0.146.1" dispatcher="WARNING\ncodex-cli 0.146.1"`) {
		t.Fatalf("provider metadata difference is not actionable: %q", detail)
	}
	validator := &contentValidator{}
	_, _ = validator.Write([]byte{0xe2, 0x82})
	validator.Finish()
	if !validator.Invalid {
		t.Fatal("trailing partial UTF-8 accepted")
	}
	if got := validUTF8OrReplacement([]byte{'a', 0xff}); !strings.Contains(got, "�") {
		t.Fatalf("invalid UTF-8 was not replaced: %q", got)
	}
	if _, err := NewReportID("short"); err == nil {
		t.Fatal("short report hash accepted")
	}
	if text := TerminalText("a\x01bc", 2); !strings.Contains(text, "\\u0001") || !strings.HasSuffix(text, "…") {
		t.Fatalf("terminal text was not escaped/truncated: %q", text)
	}
	path := filepath.Join(t.TempDir(), "value.json")
	if err := os.WriteFile(path, []byte(`{"value":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var value map[string]int
	if err := ReadJSONFile(path, 2, &value); err == nil {
		t.Fatal("oversized JSON file accepted")
	}
	link := filepath.Join(t.TempDir(), "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := ReadJSONFile(link, 1024, &value); err == nil {
		t.Fatal("symlinked JSON file accepted")
	}
	if _, err := HashFileNoFollow(link); err == nil {
		t.Fatal("symlinked artifact hash accepted")
	}
	blockingFile := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blockingFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateDir(filepath.Join(blockingFile, "child")); err == nil {
		t.Fatal("private directory creation through a file succeeded")
	}
	linkTarget := t.TempDir()
	linkDir := filepath.Join(t.TempDir(), "state-link")
	if err := os.Symlink(linkTarget, linkDir); err != nil {
		t.Fatal(err)
	}
	if err := EnsurePrivateDir(linkDir); err == nil {
		t.Fatal("symlinked private directory accepted")
	}
	if err := AtomicWrite(filepath.Join(blockingFile, "child"), []byte("x"), 0o600); err == nil {
		t.Fatal("atomic write through a file succeeded")
	}
	if err := AtomicWriteJSON(filepath.Join(t.TempDir(), "bad.json"), make(chan int)); err == nil {
		t.Fatal("unencodable JSON value was written")
	}
}

func TestArchiveMetadataAndBinaryFormatBranches(t *testing.T) {
	if !findingIDs(artifactMetadataFindings(".PKGINFO", "pkgname = x\n", "pkg!/.PKGINFO"))["pkginfo-missing"] {
		t.Fatal("incomplete PKGINFO was not reported")
	}
	if !findingIDs(artifactMetadataFindings(".BUILDINFO", "format = 2\n", "pkg!/.BUILDINFO"))["buildinfo-incomplete"] {
		t.Fatal("incomplete BUILDINFO was not reported")
	}
	if !findingIDs(artifactMetadataFindings(".MTREE", "./x mode=4755\n", "pkg!/.MTREE"))["mtree-privileged"] {
		t.Fatal("privileged MTREE was not reported")
	}
	result := ArchiveScan{}
	archiveModeFindings("usr/bin/demo", 0o4755, map[string]string{"SCHILY.xattr.security.capability": "x"}, "pkg!/usr/bin/demo", &result)
	ids := findingIDs(result.Findings)
	if !ids["artifact-setid"] || !ids["artifact-capability"] {
		t.Fatalf("archive modes were not reported: %#v", result.Findings)
	}
	pe := make([]byte, 128)
	copy(pe, "MZ")
	pe[0x3c] = 64
	copy(pe[64:], []byte{'P', 'E', 0, 0, 0x64, 0x86, 2, 0})
	metadata, finding := binaryMetadata("demo.exe", pe, 128)
	if finding != nil || metadata["format"] != "PE" {
		t.Fatalf("PE metadata failed: %#v %#v", metadata, finding)
	}
	mach := make([]byte, 32)
	copy(mach, []byte{0xfe, 0xed, 0xfa, 0xcf})
	metadata, finding = binaryMetadata("demo", mach, 32)
	if finding != nil || metadata["format"] != "Mach-O" {
		t.Fatalf("Mach-O metadata failed: %#v %#v", metadata, finding)
	}
	if _, finding := binaryMetadata("bad.exe", []byte("MZ"), 2); finding == nil {
		t.Fatal("truncated PE was accepted")
	}
	for name, head := range map[string][]byte{"bzip2": []byte("BZh"), "xz": {0xfd, '7', 'z', 'X', 'Z'}, "zstd": {0x28, 0xb5, 0x2f, 0xfd}} {
		if format := archiveFormat(head); format != name {
			t.Errorf("archive format=%q, want %q", format, name)
		}
	}
	for _, value := range []string{"", "/absolute", "../escape", "a/../../escape", "nul\x00name"} {
		if !unsafeArchiveMember(value) {
			t.Errorf("unsafe archive member accepted: %q", value)
		}
	}
	if !archiveLinkEscapes("a/link", "/etc/passwd") || !archiveLinkEscapes("a/link", "../../escape") {
		t.Fatal("archive link escape accepted")
	}
	cfg := DefaultConfig()
	for index, setup := range []func(*ArchiveScan, *Config) int64{
		func(*ArchiveScan, *Config) int64 { return -1 },
		func(r *ArchiveScan, c *Config) int64 { c.Limits.MaxArchiveEntries = 0; return 0 },
		func(r *ArchiveScan, c *Config) int64 { c.Limits.MaxArchiveUnpackedBytes = 0; return 1 },
	} {
		candidate, candidateCfg := ArchiveScan{Complete: true}, cfg
		size := setup(&candidate, &candidateCfg)
		if checkArchiveLimits(&candidate, size, candidateCfg, "member") || candidate.Complete {
			t.Errorf("archive limit mutation %d accepted: %+v", index, candidate)
		}
	}
}

func TestReportValidationRejectsEverySecurityBindingClass(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writePackageFixture(t, root)
	service, err := NewAuditService(context.Background(), DefaultConfig(), &fakeReviewer{})
	if err != nil {
		t.Fatal(err)
	}
	report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil || status != 0 || report.Validate() != nil {
		t.Fatalf("valid report fixture failed: status=%d err=%v", status, err)
	}
	store := &ReportStore{Root: t.TempDir()}
	if err := store.Save(report); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(report); err == nil {
		t.Fatal("duplicate report save succeeded")
	}
	if err := store.Save(nil); err == nil {
		t.Fatal("nil report save succeeded")
	}
	if err := store.Replace(nil); err == nil {
		t.Fatal("nil report replacement succeeded")
	}
	if _, err := store.Load("bad"); err == nil {
		t.Fatal("invalid report ID loaded")
	}
	if _, err := (&ReportStore{Root: t.TempDir()}).Latest(); err == nil {
		t.Fatal("empty report store returned a latest report")
	}
	clone := func() Report {
		raw, _ := CanonicalJSON(report)
		var result Report
		if err := DecodeStrict(raw, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	mutations := []func(*Report){
		func(r *Report) { r.SchemaVersion-- },
		func(r *Report) { r.CreatedAt = "invalid" },
		func(r *Report) { r.PackageBase = "../escape" },
		func(r *Report) { r.Phase = "unknown" },
		func(r *Report) { r.ContentHash = "bad" },
		func(r *Report) { r.ScannerVersion-- },
		func(r *Report) { r.Reviewer.Transport = "http" },
		func(r *Report) { r.Reviewer.Verdicts = []Verdict{{}} },
		func(r *Report) { r.Coverage.BytesSeen = -1 },
		func(r *Report) { r.ArchiveProbe.Version = "" },
		func(r *Report) { r.Manifest = append(r.Manifest, r.Manifest[0]) },
		func(r *Report) { r.Manifest[0]["unexpected"] = true },
		func(r *Report) { r.Findings = append(r.Findings, Finding{}) },
		func(r *Report) { r.Exclusions = []string{""} },
		func(r *Report) {
			r.SealedArtifacts = []SealedArtifact{{Path: "relative", SHA256: strings.Repeat("a", 64)}}
		},
		func(r *Report) { r.SandboxRuns = []SandboxEnforcement{{}} },
		func(r *Report) { r.ApprovalEligible = true },
		func(r *Report) { r.NetworkEligible = true },
	}
	for index, mutate := range mutations {
		candidate := clone()
		mutate(&candidate)
		if err := candidate.Validate(); err == nil {
			t.Errorf("report mutation %d was accepted", index)
		}
	}
	blocked := clone()
	blocked.Decision = "block"
	blocked.Disposition = "block"
	blocked.ApprovalEligible = true
	blocked.Findings = []Finding{{Source: "deterministic", Severity: "medium", Category: "other", File: "PKGBUILD", Rationale: "review", RuleID: "review"}}
	if text := RenderReport(&blocked); !strings.Contains(text, "Override:") || !strings.Contains(text, "Findings (critical to info):") || !strings.Contains(text, "[DETERMINISTIC]") {
		t.Fatalf("blocked report rendering omitted security detail: %s", text)
	}
}

func TestSchemaValidatorsRejectMalformedBoundaryDocuments(t *testing.T) {
	zero := 0
	for index, finding := range []Finding{
		{},
		{Severity: "high", Category: "other", File: "x", Line: &zero, Rationale: "x"},
		{Severity: "high", Category: "other", File: "x"},
	} {
		if finding.Validate() == nil {
			t.Errorf("finding mutation %d accepted", index)
		}
	}
	validVerdict := Verdict{SchemaVersion: 1, Verdict: "allow", Confidence: "high", Summary: "safe", Findings: []ReviewFinding{}, CoverageNotes: []string{}}
	verdicts := []Verdict{validVerdict, validVerdict, validVerdict, validVerdict}
	verdicts[0].SchemaVersion = 2
	verdicts[1].Confidence = "certain"
	verdicts[2].Summary = ""
	verdicts[3].Findings = []ReviewFinding{{Severity: "bad", Category: "other", Rationale: "x"}}
	for index := range verdicts {
		if verdicts[index].Validate() == nil {
			t.Errorf("verdict mutation %d accepted", index)
		}
	}
	if err := validateCoverage(Coverage{ReviewEligibleFiles: 1, SelectedFiles: 2, Notes: []string{}}); err == nil {
		t.Fatal("inconsistent coverage accepted")
	}
	record := FileRecord{Path: "PKGBUILD", PathB64: "UEtHQlVJTEQ=", Kind: "file", Mode: 0o600, Size: 12,
		SHA256: strings.Repeat("a", 64), Text: true, SelectedReason: "mandatory", BinaryMetadata: map[string]any{}}
	manifest := record.ManifestValue()
	for index, mutate := range []func(map[string]any){
		func(m map[string]any) { m["extra"] = true },
		func(m map[string]any) { m["kind"] = "unknown" },
		func(m map[string]any) { m["sha256"] = "bad" },
		func(m map[string]any) { m["path_b64"] = "%%%" },
	} {
		copyMap := map[string]any{}
		for key, value := range manifest {
			copyMap[key] = value
		}
		mutate(copyMap)
		if _, err := validateManifestRecord(copyMap); err == nil {
			t.Errorf("manifest mutation %d accepted", index)
		}
	}
	manifestList := []map[string]any{manifest}
	manifestRaw, _ := CanonicalJSON(manifestList)
	validSnapshot := ReviewSnapshot{SnapshotSchemaVersion: ReviewSnapshotVersion, PackageBase: "demo", Phase: "pre",
		ManifestHash: SHA256Bytes(manifestRaw), Coverage: Coverage{Complete: true, Notes: []string{}}, Manifest: manifestList,
		BatchCount: 1, Files: []SelectedFile{{File: "PKGBUILD", Content: "pkgname=demo"}}}
	mutateSnapshot := []func(*ReviewSnapshot){
		func(s *ReviewSnapshot) { s.SnapshotSchemaVersion-- },
		func(s *ReviewSnapshot) { s.PackageBase = "bad/name" },
		func(s *ReviewSnapshot) { s.Phase = "bad" },
		func(s *ReviewSnapshot) { s.ManifestHash = "bad" },
		func(s *ReviewSnapshot) { s.BatchCount = 0 },
		func(s *ReviewSnapshot) { s.Files = nil },
		func(s *ReviewSnapshot) { s.Files[0].File = "missing" },
	}
	for index, mutate := range mutateSnapshot {
		candidate := validSnapshot
		candidate.Files = append([]SelectedFile(nil), validSnapshot.Files...)
		mutate(&candidate)
		if err := candidate.Validate(); err == nil {
			t.Errorf("snapshot mutation %d accepted", index)
		}
	}
	if err := (DispatchRequest{ProtocolVersion: DispatchProtocolVersion, Operation: "canary"}).Validate(); err != nil {
		t.Fatalf("valid canary request rejected: %v", err)
	}
	for index, request := range []DispatchRequest{{}, {ProtocolVersion: 1, Operation: "probe", Snapshot: &validSnapshot}, {ProtocolVersion: 1, Operation: "canary", Snapshot: &validSnapshot}, {ProtocolVersion: 1, Operation: "review"}, {ProtocolVersion: 1, Operation: "unknown"}} {
		if request.Validate() == nil {
			t.Errorf("dispatch request mutation %d accepted", index)
		}
	}
	validMetadata := ProviderMetadata{Provider: "codex", Transport: "cli", RuntimeVersion: "v", Model: "m", Effort: "high", AdapterPolicy: "p"}
	for index, response := range []DispatchResponse{{}, {ProtocolVersion: 1, Metadata: validMetadata}, {ProtocolVersion: 1, Metadata: validMetadata, Verdict: &validVerdict}} {
		operation := "review"
		if index == 2 {
			operation = "probe"
		}
		if response.Validate(operation) == nil {
			t.Errorf("dispatch response mutation %d accepted", index)
		}
	}
}

func TestFindingsSortBySeveritySourceAndLocation(t *testing.T) {
	line2, line1 := 2, 1
	findings := []Finding{
		{Source: "ai", Severity: "low", Category: "other", File: "z", Rationale: "x", RuleID: "z"},
		{Source: "ai", Severity: "critical", Category: "other", File: "b", Line: &line2, Rationale: "x", RuleID: "b"},
		{Source: "deterministic", Severity: "critical", Category: "other", File: "b", Line: &line2, Rationale: "x", RuleID: "b"},
		{Source: "deterministic", Severity: "critical", Category: "other", File: "a", Line: &line1, Rationale: "x", RuleID: "a"},
	}
	sortFindings(findings)
	got := strings.Join([]string{findings[0].File, findings[1].Source, findings[2].Source, findings[3].Severity}, ",")
	if got != "a,deterministic,ai,low" {
		t.Fatalf("finding order=%s", got)
	}
}

func TestCLIAndMakepkgOrchestrationWithHermeticBoundary(t *testing.T) {
	withStateAndShare(t)
	cfg := DefaultConfig()
	previousConfig := SystemConfigPath
	SystemConfigPath = writeCurrentConfig(t, cfg)
	defer func() { SystemConfigPath = previousConfig }()
	previousFactory, previousRunner, previousCleanRoot := auditServiceFactory, makepkgSandboxRunner, cleanRootDispatcher
	auditServiceFactory = func(ctx context.Context, cfg Config, _ ReviewClient) (*AuditService, error) {
		return NewAuditService(ctx, cfg, &fakeReviewer{})
	}
	var profiles []string
	var networks []bool
	makepkgSandboxRunner = func(invocation Invocation, workdir string, network bool, cfg Config) ([]byte, []byte, SandboxEnforcement, error) {
		profiles = append(profiles, invocation.Profile)
		networks = append(networks, network)
		if invocation.Profile == "build" {
			if err := os.WriteFile(filepath.Join(workdir, "demo.pkg.tar.zst"), tarBytes(t, map[string][]byte{"usr/share/demo/data": []byte("safe\n")}), 0o600); err != nil {
				return nil, nil, SandboxEnforcement{}, err
			}
		}
		if invocation.Profile == "packagelist" {
			name := "demo-list.pkg.tar.zst"
			if err := os.WriteFile(filepath.Join(workdir, name), tarBytes(t, map[string][]byte{"usr/share/demo/list": []byte("safe\n")}), 0o600); err != nil {
				return nil, nil, SandboxEnforcement{}, err
			}
			return []byte(name + "\n"), nil, effectiveBuildLimits(cfg.Build), nil
		}
		return nil, nil, effectiveBuildLimits(cfg.Build), nil
	}
	manifest := validTestCleanRootManifest()
	cleanRootDispatcher = func(_ context.Context, request CleanRootRequest) (CleanRootResponse, error) {
		if request.Operation == "prepare" {
			copy := *manifest
			copy.PolicyFingerprint = request.PolicyFingerprint
			copy.ManifestSHA256 = ""
			raw, _ := CanonicalJSON(copy)
			copy.ManifestSHA256 = SHA256Bytes(raw)
			return CleanRootResponse{ProtocolVersion: CleanRootProtocolVersion, OK: true, Token: "1001-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", RootPath: "/var/lib/prolewatch/build-jobs/1001-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/root", Manifest: &copy}, nil
		}
		return CleanRootResponse{ProtocolVersion: CleanRootProtocolVersion, OK: true}, nil
	}
	defer func() {
		auditServiceFactory, makepkgSandboxRunner, cleanRootDispatcher = previousFactory, previousRunner, previousCleanRoot
	}()
	root := t.TempDir()
	writePackageFixture(t, root)
	if status := RunCLI(context.Background(), []string{"scan", "--phase", "pre", "--dir", root, "--package-base", "demo", "--json"}); status != 0 {
		t.Fatalf("CLI pre-scan status=%d", status)
	}
	latest, err := NewReportStore().Latest()
	if err != nil {
		t.Fatal(err)
	}
	if RunCLI(context.Background(), []string{"report", "--latest"}) != 0 || RunCLI(context.Background(), []string{"report", latest.ReportID}) != 0 {
		t.Fatal("CLI report lookup failed")
	}
	if RunCLI(context.Background(), []string{"approve", latest.ReportID}) != 23 || RunCLI(context.Background(), []string{"allow-network", latest.ReportID}) != 23 {
		t.Fatal("ineligible CLI authorization did not fail closed")
	}
	artifactPath := filepath.Join(t.TempDir(), "manual.pkg.tar")
	if err := os.WriteFile(artifactPath, tarBytes(t, map[string][]byte{"usr/share/demo/data": []byte("safe\n")}), 0o600); err != nil {
		t.Fatal(err)
	}
	if RunCLI(context.Background(), []string{"scan", "--phase", "artifact", "--package", artifactPath, "--package-base", "demo", "--json"}) != 0 {
		t.Fatal("CLI artifact scan failed")
	}
	if RunCLI(context.Background(), []string{"scan", "--phase", "bad"}) == 0 {
		t.Fatal("invalid CLI scan phase succeeded")
	}
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	if RunCLI(context.Background(), []string{"install-hook"}) != 0 || RunCLI(context.Background(), []string{"uninstall-hook"}) != 0 {
		t.Fatal("CLI hook lifecycle failed")
	}
	if RunCLI(context.Background(), []string{"doctor", "--json", "--no-probe"}) == 0 {
		t.Fatal("doctor unexpectedly passed without an installed host attestation")
	}
	oldWorkdir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWorkdir)
	if status := RunMakepkg(context.Background(), []string{"--verifysource"}); status != 0 {
		t.Fatalf("hermetic verification wrapper status=%d", status)
	}
	service, err := NewAuditService(context.Background(), cfg, &fakeReviewer{})
	if err != nil {
		t.Fatal(err)
	}
	if _, status, err := service.ScanDirectory(context.Background(), "post", root, "demo"); err != nil || status != 0 {
		t.Fatalf("post marker creation failed: status=%d err=%v", status, err)
	}
	if status := RunMakepkg(context.Background(), []string{"--nobuild"}); status != 0 {
		t.Fatalf("hermetic prepare wrapper status=%d", status)
	}
	if status := RunMakepkg(context.Background(), []string{"-f", "-c", "--noextract", "--noprepare", "--holdver"}); status != 0 {
		t.Fatalf("hermetic build wrapper status=%d", status)
	}
	if status := RunMakepkg(context.Background(), []string{"--packagelist"}); status != 0 {
		t.Fatalf("hermetic package-list wrapper status=%d", status)
	}
	if status := RunMakepkg(context.Background(), []string{"-c", "--nobuild", "--noextract"}); status != 0 {
		t.Fatalf("hermetic skip wrapper status=%d", status)
	}
	if strings.Join(profiles, ",") != "verify,prepare,build,packagelist,skip" || len(networks) != 5 || !networks[0] || networks[1] || networks[2] || networks[3] || networks[4] {
		t.Fatalf("wrong sandbox orchestration: profiles=%v network=%v", profiles, networks)
	}
}

func TestMakepkgWrapperFailureStatuses(t *testing.T) {
	withStateAndShare(t)
	cfg := DefaultConfig()
	previousConfig, previousFactory, previousRunner, previousCleanRoot := SystemConfigPath, auditServiceFactory, makepkgSandboxRunner, cleanRootDispatcher
	defer func() {
		SystemConfigPath, auditServiceFactory, makepkgSandboxRunner, cleanRootDispatcher = previousConfig, previousFactory, previousRunner, previousCleanRoot
	}()
	SystemConfigPath = writeCurrentConfig(t, cfg)
	auditServiceFactory = func(ctx context.Context, cfg Config, _ ReviewClient) (*AuditService, error) {
		return NewAuditService(ctx, cfg, &fakeReviewer{})
	}
	cleanRootDispatcher = func(_ context.Context, request CleanRootRequest) (CleanRootResponse, error) {
		manifest := validTestCleanRootManifest()
		manifest.PolicyFingerprint = request.PolicyFingerprint
		manifest.ManifestSHA256 = ""
		raw, _ := CanonicalJSON(*manifest)
		manifest.ManifestSHA256 = SHA256Bytes(raw)
		return CleanRootResponse{ProtocolVersion: CleanRootProtocolVersion, OK: true, Token: "1001-cccccccccccccccccccccccccccccccc", RootPath: "/var/lib/prolewatch/build-jobs/1001-cccccccccccccccccccccccccccccccc/root", Manifest: manifest}, nil
	}
	root := t.TempDir()
	writePackageFixture(t, root)
	oldWorkdir, _ := os.Getwd()
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWorkdir)
	if status := RunMakepkg(context.Background(), []string{"--verifysource"}); status != 24 {
		t.Fatalf("missing marker status=%d", status)
	}
	service, err := NewAuditService(context.Background(), cfg, &fakeReviewer{})
	if err != nil {
		t.Fatal(err)
	}
	if _, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo"); err != nil || status != 0 {
		t.Fatal(err)
	}
	makepkgSandboxRunner = func(Invocation, string, bool, Config) ([]byte, []byte, SandboxEnforcement, error) {
		enforcement := effectiveBuildLimits(cfg.Build)
		enforcement.Termination = "sandbox-setup"
		return []byte("partial stdout"), []byte("sandbox stderr"), enforcement, errors.New("sandbox")
	}
	if status := RunMakepkg(context.Background(), []string{"--verifysource"}); status != 24 {
		t.Fatalf("sandbox failure status=%d", status)
	}
	activities, err := NewActivityStore().List(0)
	retained := false
	for _, activity := range activities {
		retained = retained || (activity.FailureReason == ActivityFailureOperational &&
			strings.Contains(activity.Message, "sandbox execution failed (sandbox-setup): sandbox"))
	}
	if err != nil || !retained {
		t.Fatalf("sandbox failure was not retained in activity state: %#v %v", activities, err)
	}
	auditServiceFactory = func(context.Context, Config, ReviewClient) (*AuditService, error) { return nil, errors.New("provider") }
	if status := RunMakepkg(context.Background(), []string{"--verifysource"}); status != 24 {
		t.Fatalf("provider gate failure status=%d", status)
	}
	SystemConfigPath = filepath.Join(t.TempDir(), "missing")
	if status := RunMakepkg(context.Background(), []string{"--verifysource"}); status != 20 {
		t.Fatalf("configuration failure status=%d", status)
	}
}
