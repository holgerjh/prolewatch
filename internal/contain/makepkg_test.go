package contain

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Under a user namespace that maps only the caller's uid,
// chown(2) to uid 0 returns EINVAL rather than EPERM. libfakeroot swallows
// EPERM but not EINVAL, so the call escapes to the kernel and any package()
// using `install -o root -g root` fails. This test exercises the shipping Go
// path and requires the namespace mapping that makes fakeroot receive EPERM.
func TestMakepkgPackageFunctionCanInstallRootOwnedFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real makepkg")
	}
	for _, tool := range []string{"makepkg", "fakeroot", "bsdtar"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	ns := requireSandbox(t)

	work := t.TempDir()
	pkgdest := t.TempDir()
	pkgbuild := `pkgname=prolewatch-contain-probe
pkgver=1
pkgrel=1
arch=('any')
source=()
package() {
  install -d "$pkgdir/usr/share/prolewatch-contain-probe"
  echo payload > "$srcdir/payload"
  # The idiom that fails with EINVAL when uid 0 is not mapped.
  install -Dm644 -o root -g root "$srcdir/payload" \
    "$pkgdir/usr/share/prolewatch-contain-probe/payload"
  # A non-root, non-caller owner: unmapped ids fail the same way, which is why
  # the whole subordinate range is mapped rather than uid 0 alone.
  install -Dm644 -o 65534 -g 65534 "$srcdir/payload" \
    "$pkgdir/usr/share/prolewatch-contain-probe/nobody-owned"
}
`
	if err := os.WriteFile(filepath.Join(work, "PKGBUILD"), []byte(pkgbuild), 0o644); err != nil {
		t.Fatal(err)
	}

	log, err := os.CreateTemp(t.TempDir(), "makepkg")
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	env := BaseEnv()
	env["PKGDEST"] = "/pkgdest"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	spec := Spec{
		Workdir:    work,
		ExtraBinds: [][2]string{{pkgdest, "/pkgdest"}},
		Env:        env,
		Argv:       []string{"/usr/bin/makepkg", "-f", "--nodeps", "--noconfirm", "--nocheck", "--nosign"},
		Stdout:     log,
		Stderr:     log,
	}
	runErr := Run(ctx, ns, spec)
	raw, _ := os.ReadFile(log.Name())
	output := string(raw)
	if runErr != nil {
		t.Fatalf("contained makepkg failed: %v\n%s", runErr, output)
	}
	if strings.Contains(output, "Invalid argument") {
		t.Fatalf("EINVAL from chown - uid 0 is not mapped in the build namespace:\n%s", output)
	}

	entries, err := os.ReadDir(pkgdest)
	if err != nil || len(entries) == 0 {
		t.Fatalf("no package produced in PKGDEST: %v\n%s", err, output)
	}

	// fakeroot's ownership database must have recorded both owners, or the
	// produced package installs everything as the invoking user.
	pkg := filepath.Join(pkgdest, entries[0].Name())
	listing, err := exec.Command("bsdtar", "-tvf", pkg).CombinedOutput()
	if err != nil {
		t.Fatalf("list produced package: %v\n%s", err, listing)
	}
	if !strings.Contains(string(listing), "root") {
		t.Fatalf("root ownership did not survive into the package:\n%s", listing)
	}
	if !strings.Contains(string(listing), "65534") && !strings.Contains(string(listing), "nobody") {
		t.Fatalf("uid 65534 ownership did not survive into the package:\n%s", listing)
	}
}
