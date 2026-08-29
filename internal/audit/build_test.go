package audit

import (
	"context"

	"github.com/holgerjh/prolewatch/internal/brief"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestInvocationClassificationDoesNotMutateProfiles(t *testing.T) {
	for range 2 {
		invocation, err := ClassifyInvocation([]string{"--verifysource", "--nocheck"})
		if err != nil || invocation.Profile != "verify" {
			t.Fatalf("unexpected classification: %+v, %v", invocation, err)
		}
	}
	if profileAllowed["verify"]["--nocheck"] {
		t.Fatal("classification mutated the global profile")
	}
}

func TestArtifactHashComesFromReviewedManifest(t *testing.T) {
	record := brief.FileRecord{Path: "demo.pkg.tar.zst", PathB64: "ZGVtby5wa2cudGFyLnpzdA==", Kind: "file", SHA256: strings.Repeat("a", 64), BinaryMetadata: map[string]any{}}
	report := &Report{Manifest: []map[string]any{record.ManifestValue()}}
	digest, err := expectedArtifactHash(report, record.Path)
	if err != nil || digest != record.SHA256 {
		t.Fatalf("unexpected artifact digest: %q, %v", digest, err)
	}
	if _, err := expectedArtifactHash(report, "other.pkg.tar.zst"); err == nil {
		t.Fatal("missing artifact manifest entry was accepted")
	}
}

func TestRootOwnedMakepkgConfigIsAcceptedByDescriptorPath(t *testing.T) {
	if _, err := os.Stat("/etc/makepkg.conf"); err != nil {
		t.Skip("makepkg configuration is not installed")
	}
	if err := validateMakepkgConfig("/etc/makepkg.conf"); err != nil {
		t.Fatal(err)
	}
	invocation, err := ClassifyInvocation([]string{"--config", "/etc/makepkg.conf", "--verifysource"})
	if err != nil || invocation.ConfigPath != "/etc/makepkg.conf" {
		t.Fatalf("safe makepkg config classification failed: %+v %v", invocation, err)
	}
	if _, err := ClassifyInvocation([]string{"--config"}); err == nil {
		t.Fatal("missing makepkg config argument accepted")
	}
}

func TestRootOwnedPathTraversesExecuteOnlyDirectories(t *testing.T) {
	previousUID := trustedSystemUID
	trustedSystemUID = uint32(os.Getuid())
	t.Cleanup(func() { trustedSystemUID = previousUID })
	root := t.TempDir()
	private := filepath.Join(root, "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(private, "active.json")
	if err := os.WriteFile(target, []byte("active"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(private, 0o111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(private, 0o700) })
	fd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	file, err := openRootOwnedComponentsMode(fd, target, []string{"private", "active.json"}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	buffer := make([]byte, 6)
	if count, readErr := file.Read(buffer); readErr != nil || count != len(buffer) || string(buffer) != "active" {
		t.Fatalf("cannot read traversed file: count=%d content=%q err=%v", count, buffer, readErr)
	}
}

func TestRootOwnedDirectoryHandleAcceptsExecuteOnlyTarget(t *testing.T) {
	previousUID := trustedSystemUID
	trustedSystemUID = uint32(os.Getuid())
	t.Cleanup(func() { trustedSystemUID = previousUID })
	root := t.TempDir()
	target := filepath.Join(root, "prepared-root")
	if err := os.Mkdir(target, 0o711); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := openRootOwnedComponentsMode(fd, target, []string{"prepared-root"}, true, false)
	if err != nil {
		t.Fatalf("execute-only prepared root was rejected: %v", err)
	}
	defer handle.Close()
	if _, err := handle.Readdirnames(1); err == nil {
		t.Fatal("path-only prepared-root handle unexpectedly allowed directory listing")
	}
}

// The info profile is the one uncontained makepkg execution. It is safe only
// because --help/-h/--version/-V do not source the PKGBUILD, so a package
// cannot execute shell through this path.
//
// Widening the profile would create an uncontained evaluation site, so the test
// pins the complete allowlist.
func TestInfoProfileNeverCarriesPackageEvaluation(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"-h"}, {"--version"}, {"-V"}} {
		invocation, err := ClassifyInvocation(args)
		if err != nil || invocation.Profile != "info" {
			t.Fatalf("%v classified as %q (%v)", args, invocation.Profile, err)
		}
	}
	// Anything else must not reach the uncontained path, including the same
	// flags combined with a real build argument.
	for _, args := range [][]string{
		{"--version", "--noextract"},
		{"--help", "-f"},
		{"--printsrcinfo"},
		{"--verifysource"},
		{"-f"},
	} {
		invocation, err := ClassifyInvocation(args)
		if err == nil && invocation.Profile == "info" {
			t.Fatalf("%v reached the uncontained info path", args)
		}
	}
}

// TestMakepkgFailsFastWithoutAUserManager binds the ordering that made a real
// first run unreadable.
//
// yay runs each phase as its own wrapper process and only the verify one
// fetches. When the resource envelope was missing, verify failed with the
// honest cause, and then the next phase - which does not fetch - found an
// empty source directory and reported one "extractable source is absent"
// finding per declared source. The user got the real error once, followed by a
// full package review derived entirely from it. The derived review is the loud
// half, so the cause was the half that got lost.
func TestMakepkgFailsFastWithoutAUserManager(t *testing.T) {
	// RunMakepkg loads the system configuration before anything else and returns
	// ExitInvalidInvocation when there is none. Without this stub the test only
	// reaches the precondition on a machine that already has Prolewatch
	// installed - it passed on the author's box and failed on a clean one, which
	// is the environment dependency it is meant to be testing the absence of.
	withStateAndShare(t)
	previousConfigPath := SystemConfigPath
	SystemConfigPath = writeCurrentConfig(t, DefaultConfig())
	previousManager := userManagerAvailable
	defer func() {
		SystemConfigPath = previousConfigPath
		userManagerAvailable = previousManager
	}()
	userManagerAvailable = func() bool { return false }

	stderr := captureStderr(t, func() {
		if status := RunMakepkg(context.Background(), []string{"--nobuild"}); status != ExitExecutionFailure {
			t.Fatalf("status=%d, want %d", status, ExitExecutionFailure)
		}
	})
	if !strings.Contains(stderr, "no systemd user manager") {
		t.Errorf("the cause is not named: %q", stderr)
	}
	if strings.Contains(stderr, "extractable source is absent") {
		t.Errorf("a derived package review was printed over the cause: %q", stderr)
	}

	// --help and --version source no PKGBUILD, so they need no envelope and must
	// keep working on a host that has none.
	if status := RunMakepkg(context.Background(), []string{"--version"}); status != ExitOK {
		t.Errorf("info profile status=%d, want %d", status, ExitOK)
	}
}
