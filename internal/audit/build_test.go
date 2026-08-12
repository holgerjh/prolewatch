package audit

import (
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

func TestSealedPathRejectsUnsafeNames(t *testing.T) {
	report := &Report{ReportID: "20260812T010203Z-aaaaaaaaaaaa-bbbbbbbb"}
	for _, name := range []string{"", ".", "..", "../escape.pkg.tar.zst", `sub\\escape.pkg.tar.zst`} {
		if _, err := sealedPath(report, name); err == nil {
			t.Fatalf("unsafe name accepted: %q", name)
		}
	}
}

func TestArtifactHashComesFromReviewedManifest(t *testing.T) {
	record := FileRecord{Path: "demo.pkg.tar.zst", PathB64: "ZGVtby5wa2cudGFyLnpzdA==", Kind: "file", SHA256: strings.Repeat("a", 64), BinaryMetadata: map[string]any{}}
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
	file, err := openRootOwnedComponents(fd, target, []string{"private", "active.json"}, false)
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
