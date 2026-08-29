package egress

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/holgerjh/prolewatch/internal/contain"
)

func requireContainment(t *testing.T) *contain.Namespace {
	t.Helper()
	for _, tool := range []string{"makepkg", "unshare", "bwrap"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	namespace, err := contain.NewNamespace()
	if err != nil {
		t.Skipf("containment unavailable: %v", err)
	}
	t.Cleanup(func() { namespace.Close() })
	return namespace
}

// runContainedMakepkg runs makepkg in the checkout with zero network and the
// pre-populated SRCDEST bound in, matching the acquisition phase boundary.
func runContainedMakepkg(t *testing.T, ns *contain.Namespace, checkout, srcdest string, args ...string) (string, error) {
	t.Helper()
	log, err := os.CreateTemp(t.TempDir(), "makepkg")
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	env := contain.BaseEnv()
	env["SRCDEST"] = "/srcdest"
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	spec := contain.Spec{
		Workdir:    checkout,
		ExtraBinds: [][2]string{{srcdest, "/srcdest"}},
		Env:        env,
		Argv:       append([]string{"/usr/bin/makepkg"}, args...),
		Stdout:     log,
		Stderr:     log,
	}
	runErr := contain.Run(ctx, ns, spec)
	raw, _ := os.ReadFile(log.Name())
	return string(raw), runErr
}

// The whole point of trusted-side acquisition: once the declared sources are
// present, makepkg retrieves and verifies them with no network at all - so the
// author-written top-level shell that makepkg executes on every invocation runs
// with zero egress.
func TestAcquiredSourcesVerifyWithZeroNetwork(t *testing.T) {
	requireUserManager(t)
	if testing.Short() {
		t.Skip("runs a real makepkg")
	}
	namespace := requireContainment(t)

	payload := "acquired payload\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(payload))
	}))
	defer server.Close()

	checkout := t.TempDir()
	srcdest := t.TempDir()
	pkgbuild := `pkgname=demo
pkgver=1.0
pkgrel=1
arch=('any')
source=("` + server.URL + `/demo-1.0.tar.gz")
sha256sums=('SKIP')
package() { :; }
`
	if err := os.WriteFile(filepath.Join(checkout, "PKGBUILD"), []byte(pkgbuild), 0o644); err != nil {
		t.Fatal(err)
	}

	allowance, err := FreezeDeclaredSources(context.Background(), namespace, checkout, testFreezeLimits())
	if err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if _, err := fetchThroughTestServer(t, allowance, srcdest); err != nil {
		t.Fatalf("acquire: %v", err)
	}

	output, err := runContainedMakepkg(t, namespace, checkout, srcdest, "--verifysource", "--noconfirm")
	if err != nil {
		t.Fatalf("contained verifysource failed with no network:\n%s", output)
	}
	if !strings.Contains(output, "Found demo-1.0.tar.gz") {
		t.Fatalf("makepkg did not reuse the acquired source:\n%s", output)
	}
	if strings.Contains(output, "Downloading") || strings.Contains(output, "curl") {
		t.Fatalf("makepkg attempted a download despite a populated SRCDEST:\n%s", output)
	}
}

// A PKGBUILD can compute source= differently on a later evaluation. Under
// trusted-side acquisition that needs no policy: the file was never fetched,
// there is no network to fetch it with, and the build stops. The failure is
// structural rather than a decision that could be got wrong.
func TestDivergentSourceSetFailsClosedRatherThanWidening(t *testing.T) {
	requireUserManager(t)
	if testing.Short() {
		t.Skip("runs a real makepkg")
	}
	namespace := requireContainment(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("first variant\n"))
	}))
	defer server.Close()

	checkout := t.TempDir()
	srcdest := t.TempDir()
	// The counter must live at the path the sandbox sees, since both
	// evaluations run inside it with the checkout bound at /build.
	const counter = "/build/counter"
	pkgbuild := `pkgname=demo
pkgver=1.0
pkgrel=1
arch=('any')
_n=$(cat ` + counter + ` 2>/dev/null || echo 0)
echo $((_n+1)) > ` + counter + `
source=("` + server.URL + `/variant-${_n}.tar.gz")
sha256sums=('SKIP')
package() { :; }
`
	if err := os.WriteFile(filepath.Join(checkout, "PKGBUILD"), []byte(pkgbuild), 0o644); err != nil {
		t.Fatal(err)
	}

	allowance, err := FreezeDeclaredSources(context.Background(), namespace, checkout, testFreezeLimits())
	if err != nil {
		t.Fatalf("freeze: %v", err)
	}
	frozenURL := allowance.Declared()[0].URL
	if !strings.Contains(frozenURL, "variant-0") {
		t.Fatalf("the freeze did not capture the first evaluation: %s", frozenURL)
	}
	if _, err := fetchThroughTestServer(t, allowance, srcdest); err != nil {
		t.Fatalf("acquire: %v", err)
	}

	output, err := runContainedMakepkg(t, namespace, checkout, srcdest, "--verifysource", "--noconfirm")
	if err == nil {
		t.Fatalf("a divergent source set was satisfied instead of failing closed:\n%s", output)
	}
	if !strings.Contains(output, "variant-1") {
		t.Fatalf("expected the second evaluation to ask for variant-1:\n%s", output)
	}
	// Fails because the file is absent and unreachable - not because a policy
	// decided to deny it.
	if _, err := os.Stat(filepath.Join(srcdest, "variant-1.tar.gz")); !os.IsNotExist(err) {
		t.Fatalf("the diverged source was somehow acquired: %v", err)
	}
}
