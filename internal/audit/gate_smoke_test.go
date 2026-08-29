package audit

import (
	"context"

	"github.com/holgerjh/prolewatch/internal/contain"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The gate's two operations parse attacker-produced archives, so they must run
// inside the sandbox. This exercises that path end to end rather than calling
// brief directly, because "it runs contained" is the claim under test.
func TestGateRunsContainedEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a real package and creates a namespace")
	}
	for _, tool := range []string{"makepkg", "bwrap", "unshare"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	// The gate runs under the same resource envelope as the build, because it
	// parses an archive the package produced. Without a user manager there is no
	// envelope, and the operation fails closed rather than running unbounded -
	// which is the behaviour under test everywhere else, so it is skipped here.
	if !contain.UserManagerAvailable() {
		t.Skip("no systemd user manager: the gate's resource envelope cannot be applied")
	}

	// Build the production orchestrator binary: os.Executable() here is the test
	// binary, while an installed artifact review runs from prolewatch-makepkg and
	// re-executes that exact wrapper inside the gate. Substituting the user-facing
	// prolewatch CLI here once hid a real entrypoint mismatch.
	binary := filepath.Join(t.TempDir(), "prolewatch-makepkg")
	build := exec.Command("go", "build", "-o", binary, "github.com/holgerjh/prolewatch/cmd/prolewatch-makepkg")
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("cannot build prolewatch for the contained gate: %v\n%s", err, out)
	}
	previous := gateBinary
	gateBinary = func() (string, error) { return binary, nil }
	t.Cleanup(func() { gateBinary = previous })

	work := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(work, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("PKGBUILD", `pkgname=prolewatch-gate-contained
pkgver=1
pkgrel=1
arch=('any')
install=prolewatch-gate-contained.install
package() {
  install -Dm0644 /dev/null "$pkgdir/usr/share/contained/file"
  install -Dm0644 "$startdir/x.hook" "$pkgdir/usr/share/libalpm/hooks/zz-x.hook"
}
`)
	write("prolewatch-gate-contained.install", "post_install() { echo hi; }\n")
	write("x.hook", "[Trigger]\nExec=/usr/bin/x\n")
	fixture := exec.Command("makepkg", "-f", "--nodeps", "--noconfirm", "--nosign")
	fixture.Dir = work
	fixture.Env = append(os.Environ(), "PKGDEST="+work)
	if out, err := fixture.CombinedOutput(); err != nil {
		t.Skipf("fixture build failed: %v\n%s", err, out)
	}
	matches, _ := filepath.Glob(filepath.Join(work, "*.pkg.tar.zst"))
	if len(matches) == 0 {
		t.Skip("no package produced")
	}
	packagePath := matches[0]

	ctx := context.Background()
	surfaces, err := EnumerateSurfacesContained(ctx, packagePath)
	if err != nil {
		t.Fatalf("contained enumeration: %v", err)
	}
	if len(surfaces) != 2 {
		t.Fatalf("expected the scriptlet and the hook, got %+v", surfaces)
	}

	target := filepath.Join(t.TempDir(), "filtered.pkg.tar.zst")
	result, err := FilterArchiveContained(ctx, packagePath, target, []string{".INSTALL"})
	if err != nil {
		t.Fatalf("contained filter: %v", err)
	}
	if result.SHA256 == "" {
		t.Fatal("rewrite reported no content hash")
	}
	remaining, err := EnumerateSurfacesContained(ctx, target)
	if err != nil {
		t.Fatalf("re-enumerate: %v", err)
	}
	for _, surface := range remaining {
		if surface.Member == ".INSTALL" {
			t.Fatal("the scriptlet survived the contained rewrite")
		}
	}
	if len(remaining) != 1 {
		t.Fatalf("the rewrite removed more than it was asked to: %+v", remaining)
	}
}

// The gate must not be reachable without containment; the build path may not
// call the archive implementation directly.
func TestGateFilterRefusesAnEmptyStripSet(t *testing.T) {
	if _, err := FilterArchiveContained(context.Background(), "/nonexistent", "/nonexistent", nil); err == nil {
		t.Fatal("a rewrite with nothing to strip was accepted")
	} else if !strings.Contains(err.Error(), "nothing to strip") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// The gate must be called from the build path, not merely be available as an
// unused control.
func TestGateIsReachedFromTheBuildPath(t *testing.T) {
	source, err := os.ReadFile("build.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(source)
	// The enumeration goes through a test seam, so both halves are asserted:
	// the build path calls the seam, and the seam is the contained enumerator.
	for _, call := range []string{
		"gateEnumerator = EnumerateSurfacesContained", "gateEnumerator(",
		"FilterArchiveContained(", "gatePrompter(",
	} {
		if !strings.Contains(body, call) {
			t.Fatalf("%s is not present in the build path", call)
		}
	}
	// And the rewrite must re-bind the transaction, or an approval stays bound
	// to bytes that no longer exist.
	if !strings.Contains(body, "artifact.StrippedSurfaces = append") {
		t.Fatal("a rewrite does not record what it removed")
	}
}

// Go's filepath.Glob matches dotfiles, unlike shell globbing, so a rewrite in
// progress must not leave anything in the package directory that the
// "*.pkg.tar.*" glob would pick up as a package and hand to yay.
func TestGateScratchIsInvisibleToThePackageGlob(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "foo-1-1-any.pkg.tar.zst")
	if err := os.WriteFile(original, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	target, err := filteredPackagePath(original)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, "*.pkg.tar.*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || filepath.Base(matches[0]) != "foo-1-1-any.pkg.tar.zst" {
		t.Fatalf("an in-progress rewrite is visible to the package glob: %v", matches)
	}
	if filepath.Dir(target) == dir {
		t.Fatal("the scratch file sits directly in the package directory")
	}
}
