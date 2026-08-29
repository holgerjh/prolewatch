package egress

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/holgerjh/prolewatch/internal/contain"
)

func frozen(t *testing.T, entries ...string) *Allowance {
	t.Helper()
	var lines []string
	for _, entry := range entries {
		lines = append(lines, "\tsource = "+entry)
	}
	return &Allowance{
		sources: mustParseSources(t, strings.Join(lines, "\n")),
		frozen:  time.Now(),
	}
}

func permits(t *testing.T, a *Allowance, url string) bool {
	t.Helper()
	ok, err := a.Permits(url)
	if err != nil {
		t.Fatalf("Permits(%q): %v", url, err)
	}
	return ok
}

func TestExactSourcesMatchByteForByte(t *testing.T) {
	a := frozen(t, "https://github.com/example/demo/archive/v1.2.3.tar.gz")
	if !permits(t, a, "https://github.com/example/demo/archive/v1.2.3.tar.gz") {
		t.Fatal("the declared URL must be permitted")
	}
	for _, denied := range []string{
		"https://github.com/example/demo/archive/v1.2.4.tar.gz",     // different version
		"https://github.com/example/other/archive/v1.2.3.tar.gz",    // different repo
		"https://github.com/example/demo/archive/v1.2.3.tar.gz?x=1", // added query
		"http://github.com/example/demo/archive/v1.2.3.tar.gz",      // downgraded scheme
		"https://evil.example/example/demo/archive/v1.2.3.tar.gz",   // different host
	} {
		if permits(t, a, denied) {
			t.Fatalf("allowance widened to %q", denied)
		}
	}
}

// A `name::url` prefix renames the saved file. It is not part of the request,
// and if it were left in place the declared URL would never match.
func TestRenamePrefixIsNotPartOfTheRequest(t *testing.T) {
	a := frozen(t, "demo-1.2.3.tar.gz::https://example.com/dl/v1.2.3.tar.gz")
	if !permits(t, a, "https://example.com/dl/v1.2.3.tar.gz") {
		t.Fatal("renamed source did not match its own URL")
	}
}

// Local files are not network destinations and must remain classified as
// local allowance entries.
func TestLocalFilesAreNotInTheAllowance(t *testing.T) {
	a := frozen(t, "fix.patch", "demo.service")
	for _, source := range a.Declared() {
		if source.Kind != SourceLocal {
			t.Fatalf("%q classified as %v, expected local", source.Raw, source.Kind)
		}
	}
}

// Exact matching would deny every git+https source, because the smart HTTP
// transport appends its own paths and query strings.
func TestVCSSourcesMatchTheTransportPathsGitActuallyRequests(t *testing.T) {
	a := frozen(t, "git+https://gitlab.com/example/other.git#tag=v1.2.3")
	for _, allowed := range []string{
		"https://gitlab.com/example/other.git",
		"https://gitlab.com/example/other.git/info/refs?service=git-upload-pack",
		"https://gitlab.com/example/other.git/git-upload-pack",
	} {
		if !permits(t, a, allowed) {
			t.Fatalf("git transport request denied: %s", allowed)
		}
	}
	for _, denied := range []string{
		"https://gitlab.com/example/other-evil.git/info/refs", // prefix must not span path segments
		"https://gitlab.com/different/repo.git",
		"https://evil.example/example/other.git",
		"http://gitlab.com/example/other.git",
	} {
		if permits(t, a, denied) {
			t.Fatalf("VCS prefix match widened to %q", denied)
		}
	}
}

// The #fragment selects a VCS ref. It is never sent on the wire, so leaving it
// in the stored URL would make every real request fail to match.
func TestVCSFragmentIsStripped(t *testing.T) {
	for _, source := range frozen(t, "git+https://example.com/r.git#commit=abc123").Declared() {
		if strings.Contains(source.URL, "#") {
			t.Fatalf("fragment survived into the allowance: %q", source.URL)
		}
	}
}

// An Allowance that was never derived must deny, not permit. The zero value is
// reachable by mistake in a way a populated one is not.
func TestUnfrozenAllowanceDenies(t *testing.T) {
	var a Allowance
	if ok, err := a.Permits("https://example.com/"); ok || err == nil {
		t.Fatalf("zero-value allowance permitted a request (ok=%v err=%v)", ok, err)
	}
	var nilA *Allowance
	if ok, _ := nilA.Permits("https://example.com/"); ok {
		t.Fatal("nil allowance permitted a request")
	}
}

func TestArchitectureSpecificSourceArraysAreIncluded(t *testing.T) {
	a := &Allowance{
		sources: mustParseSources(t, "\tsource_x86_64 = https://example.com/amd64.tar.gz\n"),
		frozen:  time.Now(),
	}
	if !permits(t, a, "https://example.com/amd64.tar.gz") {
		t.Fatal("source_x86_64 entries must be part of the allowance")
	}
}

// --- end-to-end -------------------------------------------------------------

// The committed .SRCINFO is maintainer-authored and can disagree with the
// PKGBUILD. If it were ever the origin of the allowance, a package could show
// the user one set of sources and fetch another. This runs a real makepkg
// against a checkout whose .SRCINFO declares a host the PKGBUILD does not.
func TestFreezeIgnoresACommittedSrcinfoThatDisagrees(t *testing.T) {
	requireUserManager(t)
	if testing.Short() {
		t.Skip("runs a real makepkg")
	}
	for _, tool := range []string{"makepkg", "unshare", "bwrap"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	ns, err := contain.NewNamespace()
	if err != nil {
		t.Skipf("containment unavailable: %v", err)
	}
	defer ns.Close()

	checkout := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(checkout, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("PKGBUILD", `pkgname=demo
pkgver=1.2.3
pkgrel=1
arch=('any')
_host="github.com"
source=("https://$_host/example/demo/archive/v$pkgver.tar.gz"
        "local.patch"
        "git+https://gitlab.com/example/other.git")
sha256sums=('SKIP' 'SKIP' 'SKIP')
`)
	write(".SRCINFO", "pkgbase = demo\n\tsource = https://evil.example.com/attacker.tar.gz\n")
	write("local.patch", "")

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	allowance, err := FreezeDeclaredSources(ctx, ns, checkout, testFreezeLimits())
	if err != nil {
		t.Fatalf("freeze: %v", err)
	}

	if permits(t, allowance, "https://evil.example.com/attacker.tar.gz") {
		t.Fatal("the committed .SRCINFO reached the allowance")
	}
	// The URL is computed by top-level shell, so this also confirms the
	// evaluation really ran rather than a static parse of the file.
	if !permits(t, allowance, "https://github.com/example/demo/archive/v1.2.3.tar.gz") {
		t.Fatalf("computed source URL missing from the allowance: %+v", allowance.Declared())
	}
	if !permits(t, allowance, "https://gitlab.com/example/other.git/info/refs?service=git-upload-pack") {
		t.Fatal("declared git source missing from the allowance")
	}
}

// Freezing must be impossible without containment: the PKGBUILD executes
// during evaluation, so an uncontained freeze is the whole risk, not an
// optimisation.
func TestFreezeRefusesWithoutContainment(t *testing.T) {
	checkout := t.TempDir()
	os.WriteFile(filepath.Join(checkout, "PKGBUILD"), []byte("pkgname=x\n"), 0o644)
	if _, err := FreezeDeclaredSources(context.Background(), nil, checkout, testFreezeLimits()); err == nil {
		t.Fatal("freeze without a namespace must be refused")
	}
}

// A repository URL with no path would otherwise trim to an empty prefix, which
// matches every path on that host.
func TestVCSRootPathDoesNotMatchEverything(t *testing.T) {
	a := frozen(t, "git+https://example.com/")
	if permits(t, a, "https://example.com/someone/else.git/info/refs") {
		t.Fatal("an empty path prefix matched the whole host")
	}
	if !permits(t, a, "https://example.com/") {
		t.Fatal("the declared root itself must still be permitted")
	}
}

// mustParseSources is for fixtures whose parse cannot fail. Real callers must
// handle the error: a partial parse of an attacker-authored .SRCINFO shows the
// user a short source list and hides the rest.
func mustParseSources(t *testing.T, raw string) []DeclaredSource {
	t.Helper()
	sources, err := ParseSrcinfoSources([]byte(raw))
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return sources
}

// requireUserManager skips a test that must actually evaluate a PKGBUILD.
//
// Evaluation runs inside a transient systemd user unit, because it is arbitrary
// shell and must carry a resource envelope. A build host always has a user
// manager - the build itself needs one - but a bare container running the test
// suite may not.
func requireUserManager(t *testing.T) {
	t.Helper()
	if !contain.UserManagerAvailable() {
		t.Skip("no systemd user manager: contained evaluation cannot be exercised here")
	}
}

// testFreezeLimits is a small envelope for evaluating fixture PKGBUILDs.
func testFreezeLimits() contain.Limits {
	return contain.Limits{MemoryBytes: 512 * 1024 * 1024, CPUCount: 1, TasksMax: 64,
		TimeoutSeconds: 60, FileSizeBytes: 16 * 1024 * 1024, OutputBytes: 1024 * 1024}
}
