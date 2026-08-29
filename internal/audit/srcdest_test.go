package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The source directory is bind-mounted read/write into the untrusted sandbox
// during verification, so whatever is in it is reachable by package code. A
// single shared directory therefore let one package overwrite or delete another
// package's sources, and let two concurrent yay transactions race each other's
// acquisition through colliding basenames.
func TestSourceDirectoryIsPrivateToTheCheckout(t *testing.T) {
	withStateAndShare(t)
	first, err := transactionSourceDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	second, err := transactionSourceDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("two different checkouts share a source directory: %s", first)
	}
	// Two packages in one transaction must not be able to reach each other's
	// sources through a colliding basename.
	name := "v1.0.tar.gz"
	if err := os.WriteFile(filepath.Join(first, name), []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(second, name), []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(first, name))
	if err != nil || string(raw) != "first" {
		t.Fatalf("one checkout's source was overwritten by another: %q (%v)", raw, err)
	}
}

// The same checkout within one transaction must resolve to the same directory,
// or the sources fetched during acquisition are not the ones makepkg finds.
func TestSourceDirectoryIsStableWithinATransaction(t *testing.T) {
	withStateAndShare(t)
	checkout := t.TempDir()
	first, err := transactionSourceDir(checkout)
	if err != nil {
		t.Fatal(err)
	}
	second, err := transactionSourceDir(checkout)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("the same checkout resolved to two directories in one transaction:\n%s\n%s", first, second)
	}
}

func TestSourceDirectoryIsPrivateAndUnderState(t *testing.T) {
	withStateAndShare(t)
	directory, err := transactionSourceDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(directory, StateRoot()+string(os.PathSeparator)) {
		t.Fatalf("source directory is outside the user's state root: %s", directory)
	}
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("source directory is %v with mode %v", info.Mode().Type(), info.Mode().Perm())
	}
}

// Scoping the directory per transaction means they accumulate, which the shared
// one did not. Nothing reads one after its transaction ends, so they are pruned
// by age - but a directory still in use must never be removed, because that
// failure surfaces as a build that cannot find its sources.
func TestStaleSourceDirectoriesArePrunedAndLiveOnesAreNot(t *testing.T) {
	withStateAndShare(t)
	root := filepath.Join(StateRoot(), "srcdest")
	if err := EnsurePrivateDir(root); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(root, "staleaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	fresh := filepath.Join(root, "freshaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	for _, directory := range []string{stale, fresh} {
		if err := EnsurePrivateDir(directory); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-sourceDirRetention - time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}

	current, err := transactionSourceDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("a stale source directory survived: %v", err)
	}
	for _, directory := range []string{fresh, current} {
		if _, err := os.Stat(directory); err != nil {
			t.Fatalf("a directory that should have been kept was removed: %s (%v)", directory, err)
		}
	}
}

// yay drives makepkg as a sequence of separate processes, and only the
// --verifysource one performs the trusted-side fetch. Every later process
// therefore has to resolve the same source directory again, because its
// Invocation starts empty.
//
// This is the failure that hides: with SRCDEST unset, makepkg looks for the
// sources where it would have put them by default, finds nothing, and downloads
// them a second time - from a phase in which package code is running, against a
// host the user has every reason to approve. The build still succeeds, so
// nothing points at it.
func TestLaterPhasesReuseTheAcquiredSourceDirectory(t *testing.T) {
	withStateAndShare(t)
	checkout := t.TempDir()
	writePackageFixture(t, checkout)

	cfg := DefaultConfig()
	previousConfigPath := SystemConfigPath
	SystemConfigPath = writeCurrentConfig(t, cfg)
	defer func() { SystemConfigPath = previousConfigPath }()
	service, err := NewAuditService(context.Background(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, status, err := service.ScanDirectory(context.Background(), "post", checkout, "demo"); err != nil || status != 0 {
		t.Fatalf("fixture scan: status=%d err=%v", status, err)
	}
	previousFactory, previousRunner := auditServiceFactory, makepkgSandboxRunner
	previousManager := userManagerAvailable
	defer func() {
		auditServiceFactory, makepkgSandboxRunner = previousFactory, previousRunner
		userManagerAvailable = previousManager
	}()
	// The stub runner starts no transient unit, so the precondition that guards
	// the real one is stubbed with it.
	userManagerAvailable = func() bool { return true }
	auditServiceFactory = func(context.Context, Config, ReviewClient) (*AuditService, error) { return service, nil }
	var captured Invocation
	makepkgSandboxRunner = func(_ context.Context, invocation Invocation, _ string, _ bool, cfg Config) ([]byte, []byte, SandboxEnforcement, error) {
		captured = invocation
		return nil, nil, effectiveBuildLimits(cfg.Build), nil
	}

	t.Chdir(checkout)
	if status := RunMakepkg(context.Background(), []string{"--nobuild", "--noextract"}); status != 0 {
		t.Fatalf("skip phase failed: status=%d", status)
	}
	resolved, err := filepath.EvalSymlinks(checkout)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := transactionSourceDir(resolved)
	if err != nil {
		t.Fatal(err)
	}
	if captured.SourceDest != expected {
		t.Fatalf("a later phase did not reuse the acquired sources: got %q want %q", captured.SourceDest, expected)
	}
}
