package audit

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/contain"
	"github.com/holgerjh/prolewatch/internal/egress"
	"github.com/holgerjh/prolewatch/internal/safe"
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
	directory, err := os.MkdirTemp("/tmp", "prolewatch-audit-socket-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}

func TestMakepkgBrokerSocketPathDoesNotInheritLongStateRoot(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", filepath.Join(t.TempDir(), strings.Repeat("long-state-component-", 8)))
	directory, err := newMakepkgBrokerDirectory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if strings.HasPrefix(directory, StateRoot()+string(os.PathSeparator)) {
		t.Fatalf("ephemeral broker socket directory inherited the durable state path: %s", directory)
	}
	info, err := os.Stat(directory)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("broker directory is not private: info=%v err=%v", info, err)
	}
	control := filepath.Join(directory, "control")
	if err := os.Mkdir(control, 0o700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(control, "prompt.sock")
	// Linux sockaddr_un.sun_path is 108 bytes including its terminator. Keep a
	// little headroom rather than testing net.Listen here: source-tree CI may
	// deny socket creation entirely, while path length is the invariant this
	// regression owns.
	if len(socket) >= 100 {
		t.Fatalf("broker prompt socket path is not bounded: %d bytes: %s", len(socket), socket)
	}
}

func writeCurrentConfig(t *testing.T, cfg Config) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	raw, err := safe.CanonicalJSON(cfg)
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
	brief.SetArchiveProberForTest(func(fd int) (bool, error) {
		head := make([]byte, 512)
		n, err := syscall.Pread(fd, head, 0)
		if err != nil {
			return false, err
		}
		return brief.ArchiveFormat(head[:n]) != "", nil
	})
	if info, err := os.Stat("/"); err == nil {
		trustedSystemUID = info.Sys().(*syscall.Stat_t).Uid
		installedFileOwnerUID = trustedSystemUID
	}
	os.Exit(m.Run())
}

type dispatcherFakeAdapter struct {
	credential string
}

func (a *dispatcherFakeAdapter) Metadata(context.Context) (ProviderMetadata, error) {
	return ProviderMetadata{Provider: "codex", Transport: "cli", RuntimeVersion: "test", Model: "gpt", Effort: "high", AdapterPolicy: "test"}, nil
}
func (a *dispatcherFakeAdapter) Review(context.Context, ReviewSnapshot) (Verdict, error) {
	return Verdict{SchemaVersion: VerdictSchemaVersion, Verdict: "allow", Confidence: "high", Summary: "safe", Findings: []ReviewFinding{}, Guidance: []FindingGuidance{}, CoverageNotes: []string{}}, nil
}
func (a *dispatcherFakeAdapter) CredentialPath() string { return a.credential }

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
printf '%s\n' '{"schema_version":3,"verdict":"allow","confidence":"high","summary":"safe","prompt_injection_detected":false,"findings":[],"guidance":[],"coverage_notes":[]}'`)
	cfg := DefaultConfig()
	codex := &codexAdapter{adapterBase{cfg: cfg, provider: cfg.Providers.Codex}}
	metadata, err := codex.Metadata(context.Background())
	if err != nil || metadata.RuntimeVersion != "codex-cli 0.146.1" || metadata.AdapterPolicy != "codex-cli-v2:disable-current-2" {
		t.Fatalf("hermetic Codex metadata failed: %+v %v", metadata, err)
	}
	if metadata.CompatibilityWarning != "" {
		t.Errorf("a supported Codex carried a compatibility warning: %q", metadata.CompatibilityWarning)
	}
	verdict, err := codex.Review(context.Background(), ReviewSnapshot{})
	if err != nil || verdict.Verdict != "allow" {
		t.Fatalf("hermetic Codex review failed: %+v %v", verdict, err)
	}
	claudeHostBinary = writeExecutable(t, `
if [ "${1:-}" = "--version" ]; then echo 'claude 2.1.205'; else exit 2; fi`)
	providerSandboxBinary = writeExecutable(t, `
printf '%s\n' '{"subtype":"success","structured_output":{"schema_version":3,"verdict":"allow","confidence":"high","summary":"safe","prompt_injection_detected":false,"findings":[],"guidance":[],"coverage_notes":[]}}'`)
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
	// The Codex floor refuses, because below it the adapter's flags are known
	// not to exist. The ceiling only warns - see MaxCodexVersion.
	codexHostBinary = writeExecutable(t, "echo 'codex-cli 0.145.0'")
	if _, err := codex.Metadata(context.Background()); err == nil {
		t.Error("unsupported Codex 0.145.0 accepted")
	}
	versionScript := `
if [ "${1:-}" = "--version" ]; then
  echo 'codex-cli VERSION'
elif [ "${1:-}" = "features" ] && [ "${2:-}" = "list" ]; then
	printf 'zeta stable true\nalpha stable false\n'
else
  exit 2
fi`
	for _, test := range []struct {
		version     string
		wantWarning bool
	}{
		{version: "0.154.0"},
		{version: "0.155.0", wantWarning: true},
	} {
		codexHostBinary = writeExecutable(t, strings.Replace(versionScript, "VERSION", test.version, 1))
		metadata, err := codex.Metadata(context.Background())
		if err != nil {
			t.Errorf("Codex %s must run: %v", test.version, err)
		} else if (metadata.CompatibilityWarning != "") != test.wantWarning {
			t.Errorf("Codex %s warning=%q, want warning=%t", test.version, metadata.CompatibilityWarning, test.wantWarning)
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
	previousEUID, previousLoader, previousFactory := providerEffectiveUID, providerConfigLoader, providerAdapterFactory
	previousSandbox := providerSandboxBinary
	defer func() {
		providerEffectiveUID, providerConfigLoader, providerAdapterFactory = previousEUID, previousLoader, previousFactory
		providerSandboxBinary = previousSandbox
	}()
	uid := os.Geteuid()
	providerEffectiveUID = func() int { return uid }
	providerConfigLoader = func() (Config, error) {
		// The worker requires AI review to be enabled explicitly.
		cfg := DefaultConfig()
		cfg.Review.Mode = ReviewModeAI
		return cfg, nil
	}
	providerAdapterFactory = func(Config) providerAdapter { return &dispatcherFakeAdapter{credential: credential} }
	providerSandboxBinary = "/usr/bin/true"
	run := func(request any) (int, []byte, string) {
		raw, _ := safe.CanonicalJSON(request)
		var stdout, stderr bytes.Buffer
		status := runProviderWorker(context.Background(), bytes.NewReader(raw), &stdout, &stderr)
		return status, stdout.Bytes(), stderr.String()
	}
	status, raw, stderr := run(DispatchRequest{ProtocolVersion: DispatchProtocolVersion, Operation: "probe"})
	if status != 0 || stderr != "" {
		t.Fatalf("dispatcher probe failed: status=%d stderr=%q", status, stderr)
	}
	var response DispatchResponse
	if err := safe.DecodeJSON(raw, &response); err != nil || response.Validate("probe") != nil {
		t.Fatalf("dispatcher probe response invalid: %s %v", raw, err)
	}
	status, raw, stderr = run(DispatchRequest{ProtocolVersion: DispatchProtocolVersion, Operation: "canary"})
	if status != 0 || stderr != "" || safe.DecodeJSON(raw, &response) != nil || response.Validate("canary") != nil {
		t.Fatalf("dispatcher canary failed: status=%d stdout=%s stderr=%q", status, raw, stderr)
	}
	record := brief.FileRecord{Path: "PKGBUILD", PathB64: "UEtHQlVJTEQ=", Kind: "file", Mode: 0o600, Size: 12,
		SHA256: strings.Repeat("a", 64), Text: true, SelectedReason: "mandatory", BinaryMetadata: map[string]any{}}
	manifest := []map[string]any{record.ManifestValue()}
	manifestRaw, _ := safe.CanonicalJSON(manifest)
	snapshot := ReviewSnapshot{SnapshotSchemaVersion: ReviewSnapshotVersion, PackageBase: "demo", Phase: "pre",
		ManifestHash: safe.SHA256Bytes(manifestRaw), Coverage: brief.Coverage{FilesSeen: 1, BytesSeen: 12, TextFiles: 1, TextBytes: 12,
			SelectedFiles: 1, SelectedBytes: 12, ReviewEligibleFiles: 1, ReviewEligibleBytes: 12, Complete: true, Notes: []string{}},
		GuidanceMinimumSeverity: "high", Manifest: manifest, BatchCount: 1, Files: []SelectedFile{{File: "PKGBUILD", LineStart: 1, LineEnd: 1, Content: "pkgname=demo"}}}
	status, raw, stderr = run(DispatchRequest{ProtocolVersion: DispatchProtocolVersion, Operation: "review", Snapshot: &snapshot})
	if status != 0 || stderr != "" || safe.DecodeJSON(raw, &response) != nil || response.Validate("review") != nil {
		t.Fatalf("dispatcher review failed: status=%d stdout=%s stderr=%q", status, raw, stderr)
	}
	// The worker runs as the invoking user. Credential ownership is the boundary:
	// the file must belong to that user and be unreadable by group or other.
	if err := os.Chmod(credential, 0o644); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := run(DispatchRequest{ProtocolVersion: DispatchProtocolVersion, Operation: "probe"}); status != 22 {
		t.Fatalf("a group-readable provider credential was accepted status=%d", status)
	}
	if err := os.Chmod(credential, 0o600); err != nil {
		t.Fatal(err)
	}
	providerConfigLoader = func() (Config, error) { return Config{}, errors.New("config") }
	if status, _, _ := run(DispatchRequest{ProtocolVersion: DispatchProtocolVersion, Operation: "probe"}); status != 20 {
		t.Fatalf("dispatcher config failure status=%d", status)
	}
	providerConfigLoader = func() (Config, error) {
		cfg := DefaultConfig()
		cfg.Review.Mode = ReviewModeDeterministicOnly
		return cfg, nil
	}
	if status, _, stderr := run(DispatchRequest{ProtocolVersion: DispatchProtocolVersion, Operation: "probe"}); status != 22 || !strings.Contains(stderr, "disabled") {
		t.Fatalf("deterministic-only provider dispatch status=%d stderr=%q", status, stderr)
	}
	providerConfigLoader = func() (Config, error) { cfg := DefaultConfig(); cfg.Limits.MaxDispatchBytes = 1; return cfg, nil }
	if status, _, _ := run(DispatchRequest{ProtocolVersion: DispatchProtocolVersion, Operation: "probe"}); status != 22 {
		t.Fatalf("dispatcher input limit status=%d", status)
	}
	providerConfigLoader = func() (Config, error) {
		// The worker requires AI review to be enabled explicitly.
		cfg := DefaultConfig()
		cfg.Review.Mode = ReviewModeAI
		return cfg, nil
	}
	var invalidOut, invalidErr bytes.Buffer
	if status := runProviderWorker(context.Background(), strings.NewReader("{"), &invalidOut, &invalidErr); status != 22 {
		t.Fatalf("invalid dispatcher JSON status=%d", status)
	}
	if status, _, _ := run(DispatchRequest{ProtocolVersion: DispatchProtocolVersion, Operation: "unknown"}); status != 22 {
		t.Fatalf("invalid dispatcher operation status=%d", status)
	}
	providerAdapterFactory = func(Config) providerAdapter {
		return &failingProviderAdapter{credential: filepath.Join(t.TempDir(), "missing")}
	}
	if status, _, _ := run(DispatchRequest{ProtocolVersion: DispatchProtocolVersion, Operation: "probe"}); status != 22 {
		t.Fatalf("missing dispatcher credential status=%d", status)
	}
	providerAdapterFactory = func(Config) providerAdapter {
		return &failingProviderAdapter{credential: credential, metadataErr: errors.New("metadata")}
	}
	if status, _, _ := run(DispatchRequest{ProtocolVersion: DispatchProtocolVersion, Operation: "probe"}); status != 22 {
		t.Fatalf("dispatcher metadata failure status=%d", status)
	}
	providerAdapterFactory = func(Config) providerAdapter {
		return &failingProviderAdapter{credential: credential, reviewErr: errors.New("review")}
	}
	if status, _, _ := run(DispatchRequest{ProtocolVersion: DispatchProtocolVersion, Operation: "review", Snapshot: &snapshot}); status != 22 {
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
	// The credential belongs to the invoking user who owns the provider process.
	credential := activeAdapter(cfg).CredentialPath()
	if !strings.HasPrefix(credential, StateRoot()) || !strings.HasSuffix(credential, "/codex/auth.json") {
		t.Fatalf("provider credential is not under the user's own state directory: %q", credential)
	}
	cfg.Provider = "anthropic"
	alternate := activeAdapter(cfg).CredentialPath()
	if !strings.HasPrefix(alternate, StateRoot()) || !strings.HasSuffix(alternate, "/anthropic/.credentials.json") {
		t.Fatalf("alternate provider credential is not under the user's own state directory: %q", alternate)
	}
	if len(providerBwrapBase("/host", "/provider-home")) == 0 {
		t.Fatal("empty provider sandbox profile")
	}
}

// The worker validates one path and Bubblewrap binds another, so the two must
// be derived from the same place. When they were not, a credential under the
// user's own state directory passed validation while the sandbox bound a
// directory that the package installs nowhere - and because AI review is
// optional and fails soft, the whole mode was simply never usable, with an
// error that reads like a provider outage.
//
// The hermetic adapter test replaces Bubblewrap, so it cannot see this. This
// one renders the real argument list instead.
func TestProviderSandboxBindsTheValidatedCredentialDirectory(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	cfg := DefaultConfig()
	for _, provider := range []string{"codex", "anthropic"} {
		cfg.Provider = provider
		adapter := activeAdapter(cfg)
		home, err := providerCredentialHome(adapter)
		if err != nil {
			t.Fatalf("%s credential home: %v", provider, err)
		}
		if home != filepath.Dir(adapter.CredentialPath()) {
			t.Fatalf("%s binds %q but validates a credential in %q", provider, home, filepath.Dir(adapter.CredentialPath()))
		}
		if !strings.HasPrefix(home, StateRoot()+string(os.PathSeparator)) {
			t.Fatalf("%s provider home is outside the user's state root: %q", provider, home)
		}
		args := strings.Join(providerBwrapBase(home, "/provider-home"), "\x00")
		if !strings.Contains(args, "--bind\x00"+home+"\x00/provider-home") {
			t.Fatalf("%s sandbox does not bind the validated credential directory: %q", provider, args)
		}
		if !strings.Contains(args, "--unshare-all\x00--share-net\x00--unshare-user\x00--disable-userns\x00--assert-userns-disabled") {
			t.Fatalf("%s sandbox cannot enforce its nested-userns clamp: %q", provider, args)
		}
		if strings.Contains(args, "--userns\x00") {
			t.Fatalf("%s sandbox unexpectedly joins a caller-supplied user namespace: %q", provider, args)
		}
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
	provider := brief.ToolIdentity{Path: "/usr/bin/codex", Version: "v", SHA256: strings.Repeat("a", 64)}
	valid := ProviderAttestation{SchemaVersion: providerAttestationSchemaVersion, CanaryVersion: providerCanaryVersion, CreatedAt: UTCNow(), SemanticFingerprint: strings.Repeat("c", 64), Metadata: metadata, ProviderBinary: &provider, Checks: CanaryChecks{EmptyWorkspace: true, NoHostRead: true, PromptInjectionRecognised: true}}
	if err := valid.Validate(valid.SemanticFingerprint, metadata, provider); err != nil {
		t.Fatal(err)
	}
	valid.CreatedAt = "invalid"
	if err := valid.Validate(valid.SemanticFingerprint, metadata, provider); err == nil {
		t.Fatal("invalid canary timestamp accepted")
	}
	valid.CreatedAt = UTCNow()
	valid.Checks.PromptInjectionRecognised = false
	if err := valid.Validate(valid.SemanticFingerprint, metadata, provider); err == nil {
		t.Fatal("partial canary accepted")
	}
}

func TestBuildBoundaryConstructionAndKeyringCopy(t *testing.T) {
	job := t.TempDir()
	binds, err := snapshotMakepkgConfigs(job, Invocation{})
	rootOwned := err == nil
	if err != nil && !strings.Contains(err.Error(), "filesystem root has unsafe ownership") {
		t.Fatalf("makepkg config snapshot failed: %#v %v", binds, err)
	}
	if rootOwned {
		var dropinSnapshot, pacmanSnapshot string
		for _, bind := range binds {
			if bind[1] == "/etc/makepkg.conf.d" {
				dropinSnapshot = bind[0]
			}
			if bind[1] == "/etc/pacman.conf" {
				pacmanSnapshot = bind[0]
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
		pacmanRaw, pacmanErr := os.ReadFile(pacmanSnapshot)
		pacmanInfo, statErr := os.Stat(pacmanSnapshot)
		if pacmanSnapshot == "" || pacmanErr != nil || statErr != nil || pacmanInfo.Mode().Perm() != 0o400 || string(pacmanRaw) != containedPacmanConfig {
			t.Fatalf("private synthetic pacman config mismatch: binds=%#v mode=%v read=%v stat=%v content=%q", binds, pacmanInfo, pacmanErr, statErr, pacmanRaw)
		}
		for _, forbidden := range []string{"[core]", "[extra]", "Include", "Mirrorlist", "Server"} {
			if strings.Contains(string(pacmanRaw), forbidden) {
				t.Fatalf("synthetic pacman config contains repository material %q: %q", forbidden, pacmanRaw)
			}
		}
	}
	// Unix pathname sockets have a much shorter limit than ordinary paths.
	// makepkg gives tests a deliberately long TMPDIR below srcdir, so keep only
	// the socket-bearing fixture in a private, unpredictable directory under
	// the system's short temporary root.
	source, destination := shortSocketDir(t), t.TempDir()
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
		if errors.Is(err, syscall.EPERM) {
			t.Skip("sandbox forbids Unix sockets")
		}
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
	unsafeSocketSource := shortSocketDir(t)
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
	stdout, stderr, enforcement, err := runMakepkgSandbox(context.Background(), Invocation{Profile: "info", Args: []string{"--version"}}, work, false, cfg)
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
	if _, _, err := contain.LookupSubIDs(); err != nil {
		t.Skipf("no subordinate ID delegation: %v", err)
	}
	previousSnapshotter, previousRunner, previousBroker, previousBrokerDir := makepkgConfigSnapshotter, constrainedCommandRunner, makepkgNetworkBrokerStart, makepkgBrokerTempDir
	defer func() {
		makepkgConfigSnapshotter, constrainedCommandRunner, makepkgNetworkBrokerStart, makepkgBrokerTempDir = previousSnapshotter, previousRunner, previousBroker, previousBrokerDir
	}()
	makepkgConfigSnapshotter = func(string, Invocation) ([][2]string, error) { return nil, nil }
	brokerDirectory := ""
	makepkgBrokerTempDir = func() (string, error) {
		brokerDirectory = shortSocketDir(t)
		return brokerDirectory, nil
	}
	var brokerConfig egress.Config
	makepkgNetworkBrokerStart = func(_ string, cfg egress.Config, _ egress.PromptFunc) (makepkgBroker, error) {
		brokerConfig = cfg
		return &egress.BrokerProcess{}, nil
	}
	var captured [][]string
	constrainedCommandRunner = func(_ context.Context, args []string, _ []*os.File, _ string, cfg Config, _ commandOutputObserver) ([]byte, []byte, SandboxEnforcement, error) {
		captured = append(captured, append([]string(nil), args...))
		return nil, nil, effectiveBuildLimits(cfg.Build), nil
	}
	cfg := DefaultConfig()
	work := t.TempDir()
	if _, _, _, err := runMakepkgSandbox(context.Background(), Invocation{Profile: "build", Args: []string{"--noextract", "--noprepare", "--holdver"}, PersistentCargoHome: true}, work, false, cfg); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := runMakepkgSandbox(context.Background(), Invocation{Profile: "verify", Args: []string{"--verifysource"},
		AllowedHosts: []string{"gitlab.com"}}, work, true, cfg); err != nil {
		t.Fatal(err)
	}
	// After trusted-side acquisition the verify phase knows every destination it
	// can legitimately need, so the broker is closed to that set rather than
	// asking the user about hosts the package never declared.
	if len(brokerConfig.AllowedHosts) != 1 || brokerConfig.AllowedHosts[0] != "gitlab.com" {
		t.Fatalf("the frozen host set did not reach the broker: %#v", brokerConfig.AllowedHosts)
	}
	if len(captured) != 2 {
		t.Fatalf("captured profiles=%d", len(captured))
	}
	offline, online := strings.Join(captured[0], "\x00"), strings.Join(captured[1], "\x00")

	// Both profiles get their own empty network namespace. The brokered one
	// reaches the broker through a bind-mounted unix socket, so it needs no route
	// to the host network - and sharing the host network to "reach the broker"
	// would let package code drop the proxy variables and dial out directly. The
	// user namespace is joined rather than created, so --unshare-all cannot be
	// used because it implies --unshare-user.
	for name, profile := range map[string]string{"offline": offline, "brokered": online} {
		if !strings.Contains(profile, "--unshare-net") {
			t.Fatalf("%s build profile has an ambient network: %q", name, profile)
		}
	}
	for _, forbidden := range []string{"--unshare-user", "--unshare-all", "--disable-userns"} {
		if strings.Contains(offline, forbidden) || strings.Contains(online, forbidden) {
			t.Fatalf("%s discards the pre-mapped user namespace", forbidden)
		}
	}
	if !strings.Contains(offline, "--userns\x003") || !strings.Contains(offline, contain.NamespaceRunnerMarker) {
		t.Fatalf("the build did not join the pre-mapped namespace: %q", offline)
	}
	if strings.Contains(offline, "/opt") || !strings.Contains(offline, "/usr/bin/makepkg") ||
		!strings.Contains(offline, "CARGO_HOME\x00/build/src/.prolewatch-cargo-home") {
		t.Fatalf("unsafe offline build profile: %q", offline)
	}

	// The real home must never be bound, and the sandbox home must be a tmpfs.
	if home := os.Getenv("HOME"); home != "" && strings.Contains(offline, "\x00"+home+"\x00") {
		t.Fatalf("the real home was bound into the build: %q", offline)
	}
	if !strings.Contains(offline, "--tmpfs\x00/build-home") {
		t.Fatalf("the build home is not a tmpfs: %q", offline)
	}
	if !strings.Contains(offline, "--tmpfs\x00/var/lib/pacman\x00--dir\x00/var/lib/pacman/local") ||
		strings.Contains(offline, "--bind\x00/var/lib/pacman") || strings.Contains(offline, "--ro-bind\x00/var/lib/pacman") {
		t.Fatalf("the build did not get an isolated empty pacman database: %q", offline)
	}

	// Only the broker's client directory crosses in. Its control socket stays
	// outside, so package code can request but never approve a destination.
	clientBind := filepath.Join(brokerDirectory, "client") + "\x00/broker"
	if !strings.Contains(online, "/usr/bin/prolewatch-net\x00supervise\x00/broker/proxy.sock") ||
		!strings.Contains(online, "HTTP_PROXY\x00http://"+egress.SandboxProxyAddress) ||
		brokerDirectory == "" || !strings.Contains(online, clientBind) ||
		strings.Contains(online, "/control") || strings.Contains(online, "prompt.sock") {
		t.Fatalf("public-web broker was not wired into verification: %q", online)
	}
}

func TestNetworkPromptOwnsTheTerminalUntilAnswered(t *testing.T) {
	var output bytes.Buffer
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	progress := &terminalProgress{
		renderer: terminalRendererWithCapabilities(&output, terminalCapabilities{Interactive: true, Unicode: true}),
		package_: "gtk2", phase: "verify", stage: StageSandboxExecution, command: "makepkg --verifysource",
		now: func() time.Time { return now }, dirty: true,
	}
	progress.draw(true)

	prompt := networkPromptWithProgress(withTerminalProgress(context.Background(), progress), func(_ egress.AuthorizationRequest, _ egress.Config) bool {
		output.WriteString("Allow and continue the current build? [y/N]: ")
		progress.ObserveOutput(commandStdout, []byte("Cloning into bare repository '/srcdest/gtk'...\n"))
		if !strings.HasSuffix(output.String(), "[y/N]: ") {
			t.Fatalf("live progress overwrote the unanswered network prompt: %q", output.String())
		}
		return true
	})
	if !prompt(egress.AuthorizationRequest{SchemaVersion: 1, Host: "gitlab.gnome.org", Port: 443}, egress.DefaultConfig()) {
		t.Fatal("wrapped network prompt changed the decision")
	}
	rendered := output.String()
	if !strings.Contains(rendered, "[y/N]: "+terminalLiveLineClear) || !strings.Contains(rendered, "live Cloning into bare repository") {
		t.Fatalf("progress did not resume with captured activity after the answer: %q", rendered)
	}
}

func TestConstrainedCommandLifecycleFailsClosedOrCompletes(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Build.DiskReserveBytes = 1
	_, _, enforcement, err := runConstrainedCommand(context.Background(), []string{"--version"}, nil, t.TempDir(), cfg, nil)
	if enforcement.MemoryBytes <= 0 || enforcement.CPUCount <= 0 || enforcement.NetworkPolicy != "isolated" {
		t.Fatalf("constrained launch omitted enforcement: %+v", enforcement)
	}
	if err != nil {
		t.Logf("user systemd manager unavailable; launch failed closed: %v", err)
	}
}

func TestPackageListEscapeAndArtifactFailureCleanup(t *testing.T) {
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
	if status := artifactFailure(context.Background(), []string{file}, report, errors.New("forced")); status != 25 || regularNoFollow(file) {
		t.Fatalf("artifact failure did not quarantine: status=%d exists=%t", status, regularNoFollow(file))
	}
}

func TestInteractiveApprovalInputBinding(t *testing.T) {
	report := approvalFixture()
	report.Findings = []brief.Finding{{Severity: "medium", Category: "other", File: "PKGBUILD", Evidence: "review", Rationale: "manual review", RuleID: "manual"}}
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
	if runReport([]string{"--latest", "extra"}) == 0 || runInspect([]string{"--latest", "extra"}) == 0 || runApproval("approve", nil) == 0 ||
		runDoctorCommand(context.Background(), cfg, nil, []string{"extra"}) == 0 ||
		runDoctorCommand(context.Background(), cfg, nil, []string{"--no-probe", "--probe-llm-quality"}) == 0 ||
		runDoctorCommand(context.Background(), cfg, nil, []string{"--no-probe", "--probe-llm-quality-case", ollamaQualityCasePrivilegedWritableDeserialization}) == 0 ||
		runDoctorCommand(context.Background(), cfg, nil, []string{"--no-probe", "--diagnose-llm-quality-case", "remote-execution"}) == 0 ||
		runDoctorCommand(context.Background(), cfg, nil, []string{"--probe-llm-quality", "--probe-llm-quality-case", ollamaQualityCasePrivilegedWritableDeserialization}) == 0 ||
		runDoctorCommand(context.Background(), cfg, nil, []string{"--probe-llm-quality-case", "remote-execution", "--diagnose-llm-quality-case", "remote-execution"}) == 0 ||
		runDoctorCommand(context.Background(), cfg, nil, []string{"--probe-llm-quality-case", "unknown-case"}) == 0 ||
		runDoctorCommand(context.Background(), cfg, nil, []string{"--diagnose-llm-quality-case", "unknown-case"}) == 0 ||
		runDoctorCommand(context.Background(), cfg, nil, []string{"--diagnose-llm-quality-case", "remote-execution"}) == 0 ||
		runDoctorCommand(context.Background(), cfg, nil, []string{"--probe-llm-quality"}) == 0 {
		t.Fatal("CLI helper status mismatch")
	}
	if RunMakepkg(context.Background(), nil) == 0 {
		t.Fatal("empty makepkg invocation succeeded")
	}
	if RunMakepkg(context.Background(), []string{"--version"}) != 0 {
		t.Fatal("makepkg informational invocation failed")
	}
	gpgArgs := GPGSandboxCommand(t.TempDir(), "--list-keys", []string{strings.Repeat("A", 16)})
	if RunGPG([]string{"--unsafe"}) == 0 || len(gpgArgs) == 0 || !strings.Contains(strings.Join(gpgArgs, " "), "--disable-userns --assert-userns-disabled") {
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

func TestYayEffectiveConfigCheckRequiresBothWrappers(t *testing.T) {
	previousCommand := doctorCommandContext
	defer func() { doctorCommandContext = previousCommand }()
	effective := `{"makepkgbin":"/usr/bin/prolewatch-makepkg","gpgbin":"/usr/bin/prolewatch-gpg"}`
	doctorCommandContext = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/usr/bin/printf", "%s", effective)
	}
	if check := yayEffectiveConfigCheck(context.Background()); !check.OK {
		t.Fatalf("effective wrapper configuration rejected: %+v", check)
	}
	effective = `{"makepkgbin":"makepkg","gpgbin":"gpg"}`
	if check := yayEffectiveConfigCheck(context.Background()); check.OK || !check.Required {
		t.Fatalf("bypassed wrappers accepted: %+v", check)
	}
}

func TestBrokerRequestLimitFailureNamesTheConfiguredBudget(t *testing.T) {
	termination, err := brokerFailure(1234, egress.ErrRequestLimit)
	if termination != "network-request-limit" || err == nil || !strings.Contains(err.Error(), "network.max_requests=1234") {
		t.Fatalf("request-limit failure lost its policy attribution: termination=%q err=%v", termination, err)
	}
}

func TestRuleFindingGenerationIsBounded(t *testing.T) {
	engine := brief.RuleEngine{MaxFindings: 2}
	_, _, _, err := engine.ScanReader("payload.sh", bufio.NewReader(strings.NewReader(strings.Repeat("curl http://example.invalid\n", 100))), 1024)
	if err == nil || !strings.Contains(err.Error(), "finding limit") {
		t.Fatalf("finding generation was not bounded: %v", err)
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
	validator := &safe.ContentValidator{}
	_, _ = validator.Write([]byte{0xe2, 0x82})
	validator.Finish()
	if !validator.Invalid {
		t.Fatal("trailing partial UTF-8 accepted")
	}
	if got := safe.ValidUTF8OrReplacement([]byte{'a', 0xff}); !strings.Contains(got, "�") {
		t.Fatalf("invalid UTF-8 was not replaced: %q", got)
	}
	if _, err := NewReportID("short"); err == nil {
		t.Fatal("short report hash accepted")
	}
	if text := safe.Text("a\x01bc", 2); !strings.Contains(text, "\\u0001") || !strings.HasSuffix(text, "…") {
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
	if _, err := safe.HashFileNoFollow(link); err == nil {
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
		raw, _ := safe.CanonicalJSON(report)
		var result Report
		if err := safe.DecodeJSON(raw, &result); err != nil {
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
		func(r *Report) { r.ReviewRoot = "relative/checkout" },
		func(r *Report) { r.ArchiveProbe.Version = "" },
		func(r *Report) { r.Manifest = append(r.Manifest, r.Manifest[0]) },
		func(r *Report) { r.Manifest[0]["unexpected"] = true },
		func(r *Report) { r.Findings = append(r.Findings, brief.Finding{}) },
		func(r *Report) { r.Exclusions = []string{""} },
		func(r *Report) {
			r.ArtifactBindings = []ArtifactBinding{{Path: "relative", SHA256: strings.Repeat("a", 64)}}
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
	blocked.Findings = []brief.Finding{{Source: "deterministic", Severity: "medium", Category: "other", File: "PKGBUILD", Rationale: "review", RuleID: "review"}}
	// Every finding names its pass. Marking only the AI half made the reader
	// infer "unmarked means deterministic" from an absence, and the mark itself
	// was the dimmest thing on the line. The action is a named instruction
	// rather than an "Override:" footnote.
	text := RenderReport(&blocked)
	if !strings.Contains(text, "prolewatch approve ") || !strings.Contains(text, "Findings (critical to info):") {
		t.Fatalf("blocked report rendering omitted security detail: %s", text)
	}
	if !strings.Contains(text, "(deterministic):") {
		t.Fatalf("a deterministic finding did not name its pass: %s", text)
	}
	ai := clone()
	ai.Findings = []brief.Finding{{Source: "ai", Severity: "high", Category: "other", File: "PKGBUILD", Rationale: "model context", RuleID: "ai-review"}}
	aiText := RenderReport(&ai)
	if !strings.Contains(aiText, "(AI):") {
		t.Fatalf("an AI finding was not distinguishable from a deterministic one: %s", aiText)
	}
	if strings.Contains(aiText, "(deterministic):") {
		t.Fatalf("an AI finding was also labelled deterministic: %s", aiText)
	}
	// The 52 finding constructors that never set Source are deterministic, and
	// must be labelled as such rather than falling through to an empty pass.
	unset := clone()
	unset.Findings = []brief.Finding{{Severity: "medium", Category: "integrity", File: ".SRCINFO", Rationale: "vendor source provenance is mutable", RuleID: "vendor-provenance-weak"}}
	if unsetText := RenderReport(&unset); !strings.Contains(unsetText, "(deterministic):") {
		t.Fatalf("a finding with no Source was not labelled deterministic: %s", unsetText)
	}
}

func TestSchemaValidatorsRejectMalformedBoundaryDocuments(t *testing.T) {
	zero := 0
	for index, finding := range []brief.Finding{
		{},
		{Severity: "high", Category: "other", File: "x", Line: &zero, Rationale: "x"},
		{Severity: "high", Category: "other", File: "x"},
	} {
		if finding.Validate() == nil {
			t.Errorf("finding mutation %d accepted", index)
		}
	}
	validVerdict := Verdict{SchemaVersion: VerdictSchemaVersion, Verdict: "allow", Confidence: "high", Summary: "safe", Findings: []ReviewFinding{}, Guidance: []FindingGuidance{}, CoverageNotes: []string{}}
	verdicts := []Verdict{validVerdict, validVerdict, validVerdict, validVerdict}
	verdicts[0].SchemaVersion--
	verdicts[1].Confidence = "certain"
	verdicts[2].Summary = ""
	verdicts[3].Findings = []ReviewFinding{{Severity: "bad", Category: "other", Rationale: "x"}}
	for index := range verdicts {
		if verdicts[index].Validate() == nil {
			t.Errorf("verdict mutation %d accepted", index)
		}
	}
	if err := validateCoverage(brief.Coverage{ReviewEligibleFiles: 1, SelectedFiles: 2, Notes: []string{}}); err == nil {
		t.Fatal("inconsistent coverage accepted")
	}
	record := brief.FileRecord{Path: "PKGBUILD", PathB64: "UEtHQlVJTEQ=", Kind: "file", Mode: 0o600, Size: 12,
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
		if _, err := brief.ValidateManifestRecord(copyMap); err == nil {
			t.Errorf("manifest mutation %d accepted", index)
		}
	}
	manifestList := []map[string]any{manifest}
	manifestRaw, _ := safe.CanonicalJSON(manifestList)
	validSnapshot := ReviewSnapshot{SnapshotSchemaVersion: ReviewSnapshotVersion, PackageBase: "demo", Phase: "pre",
		ManifestHash: safe.SHA256Bytes(manifestRaw), Coverage: brief.Coverage{Complete: true, Notes: []string{}}, Manifest: manifestList,
		GuidanceMinimumSeverity: "high", BatchCount: 1, Files: []SelectedFile{{File: "PKGBUILD", LineStart: 1, LineEnd: 1, Content: "pkgname=demo"}}}
	mutateSnapshot := []func(*ReviewSnapshot){
		func(s *ReviewSnapshot) { s.SnapshotSchemaVersion-- },
		func(s *ReviewSnapshot) { s.PackageBase = "bad/name" },
		func(s *ReviewSnapshot) { s.Phase = "bad" },
		func(s *ReviewSnapshot) { s.ManifestHash = "bad" },
		func(s *ReviewSnapshot) { s.BatchCount = 0 },
		func(s *ReviewSnapshot) { s.Files = nil },
		func(s *ReviewSnapshot) { s.Files[0].File = "missing" },
		func(s *ReviewSnapshot) { s.Files[0].LineEnd++ },
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
	for index, request := range []DispatchRequest{{}, {ProtocolVersion: DispatchProtocolVersion, Operation: "probe", Snapshot: &validSnapshot}, {ProtocolVersion: DispatchProtocolVersion, Operation: "canary", Snapshot: &validSnapshot}, {ProtocolVersion: DispatchProtocolVersion, Operation: "review"}, {ProtocolVersion: DispatchProtocolVersion, Operation: "unknown"}} {
		if request.Validate() == nil {
			t.Errorf("dispatch request mutation %d accepted", index)
		}
	}
	validMetadata := ProviderMetadata{Provider: "codex", Transport: "cli", RuntimeVersion: "v", Model: "m", Effort: "high", AdapterPolicy: "p"}
	for index, response := range []DispatchResponse{{}, {ProtocolVersion: DispatchProtocolVersion, Metadata: validMetadata}, {ProtocolVersion: DispatchProtocolVersion, Metadata: validMetadata, Verdict: &validVerdict}} {
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
	findings := []brief.Finding{
		{Source: "ai", Severity: "low", Category: "other", File: "z", Rationale: "x", RuleID: "z"},
		{Source: "ai", Severity: "critical", Category: "other", File: "b", Line: &line2, Rationale: "x", RuleID: "b"},
		{Source: "deterministic", Severity: "critical", Category: "other", File: "b", Line: &line2, Rationale: "x", RuleID: "b"},
		{Source: "deterministic", Severity: "critical", Category: "other", File: "a", Line: &line1, Rationale: "x", RuleID: "a"},
	}
	brief.SortFindings(findings)
	got := strings.Join([]string{findings[0].File, findings[1].Source, findings[2].Source, findings[3].Severity}, ",")
	if got != "a,deterministic,ai,low" {
		t.Fatalf("finding order=%s", got)
	}
}
