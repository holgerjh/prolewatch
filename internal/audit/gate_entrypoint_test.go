package audit

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/safe"
)

// The contained halves of the gate speak JSON to the orchestrating half. Both
// are entry points into the same binary, so the contract between them is easy
// to break silently - a field rename compiles fine and only fails at runtime,
// inside a sandbox, with the diagnostic on a captured stream.
func TestGateEntryPointsSpeakTheContractTheOrchestratorParses(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a real package")
	}
	for _, tool := range []string{"makepkg", "bsdtar"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	work := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(work, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("PKGBUILD", `pkgname=prolewatch-entrypoint-probe
pkgver=1
pkgrel=1
arch=('any')
install=prolewatch-entrypoint-probe.install
package() {
  install -Dm0644 /dev/null "$pkgdir/usr/share/probe/keep"
  install -Dm0644 "$startdir/x.hook" "$pkgdir/usr/share/libalpm/hooks/zz-x.hook"
}
`)
	write("prolewatch-entrypoint-probe.install", "post_install() { echo probe; }\n")
	write("x.hook", "[Trigger]\nExec=/usr/bin/x\n")
	build := exec.Command("makepkg", "-f", "--nodeps", "--noconfirm", "--nosign")
	build.Dir = work
	build.Env = append(os.Environ(), "PKGDEST="+work)
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("fixture build failed: %v\n%s", err, out)
	}
	matches, _ := filepath.Glob(filepath.Join(work, "*.pkg.tar.zst"))
	if len(matches) == 0 {
		t.Skip("no package produced")
	}

	// Enumerate: exit status and a payload the orchestrator can decode.
	stdout := captureStdout(t, func() {
		if code := RunGateEnumerate([]string{matches[0]}); code != 0 {
			t.Fatalf("enumerate exited %d", code)
		}
	})
	var surfaces []brief.PrivilegedSurface
	if err := safe.DecodeJSON([]byte(stdout), &surfaces); err != nil {
		t.Fatalf("the orchestrator could not decode the enumeration: %v\n%s", err, stdout)
	}
	if len(surfaces) != 2 {
		t.Fatalf("expected the scriptlet and the hook, got %+v", surfaces)
	}

	// Production enters the contained half through prolewatch-makepkg because
	// the orchestrator re-executes itself. It must dispatch before trying to load
	// the deliberately absent normal configuration.
	previousConfigPath := SystemConfigPath
	SystemConfigPath = filepath.Join(t.TempDir(), "absent.json")
	t.Cleanup(func() { SystemConfigPath = previousConfigPath })
	stdout = captureStdout(t, func() {
		if code := RunMakepkg(context.Background(), []string{gateEnumerateCommand, matches[0]}); code != 0 {
			t.Fatalf("makepkg wrapper enumerate exited %d", code)
		}
	})
	surfaces = nil
	if err := safe.DecodeJSON([]byte(stdout), &surfaces); err != nil || len(surfaces) != 2 {
		t.Fatalf("makepkg wrapper did not speak the gate contract: surfaces=%+v err=%v output=%s", surfaces, err, stdout)
	}

	// Filter: same contract, and the hash must be one this process can verify.
	target := filepath.Join(t.TempDir(), "filtered.pkg.tar.zst")
	stdout = captureStdout(t, func() {
		if code := RunGateFilter([]string{matches[0], target, ".INSTALL"}); code != 0 {
			t.Fatalf("filter exited %d", code)
		}
	})
	var result brief.FilterResult
	if err := safe.DecodeJSON([]byte(stdout), &result); err != nil {
		t.Fatalf("the orchestrator could not decode the rewrite: %v\n%s", err, stdout)
	}
	digest, err := safe.HashFileNoFollow(target)
	if err != nil || digest != result.SHA256 {
		t.Fatalf("the reported hash does not match the file: %q vs %q (%v)", result.SHA256, digest, err)
	}
}

// Malformed invocations must fail rather than doing something approximate:
// these are internal entry points, so a wrong argument count is a bug in the
// caller, not user error to be guessed around.
func TestGateEntryPointsRejectMalformedInvocations(t *testing.T) {
	for _, args := range [][]string{{}, {"a", "b"}} {
		if code := RunGateEnumerate(args); code == 0 {
			t.Fatalf("enumerate accepted %v", args)
		}
	}
	for _, args := range [][]string{{}, {"only"}, {"src", "dst"}} {
		if code := RunGateFilter(args); code == 0 {
			t.Fatalf("filter accepted %v", args)
		}
	}
	if code := RunGateEnumerate([]string{"/nonexistent.pkg.tar.zst"}); code == 0 {
		t.Fatal("enumerate accepted a missing package")
	}
}

func TestMakepkgEarlyGateDispatchAdmitsOnlyContainedArchiveOperations(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{gatePrefixesCommand},
		{"internal-gate-enumerate-extra", "/tmp/package"},
		{"internal-gate-filter-extra", "/tmp/source", "/tmp/target", ".INSTALL"},
		{"--verifysource"},
	} {
		if status, handled := runContainedGateCommand(args); handled {
			t.Fatalf("non-gate makepkg invocation entered early dispatch: args=%v status=%d", args, status)
		}
	}
}

func captureStdout(t *testing.T, run func()) string {
	t.Helper()
	previous := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	done := make(chan string, 1)
	go func() {
		var builder strings.Builder
		buffer := make([]byte, 4096)
		for {
			n, err := reader.Read(buffer)
			if n > 0 {
				builder.Write(buffer[:n])
			}
			if err != nil {
				break
			}
		}
		done <- builder.String()
	}()
	run()
	writer.Close()
	os.Stdout = previous
	return <-done
}
