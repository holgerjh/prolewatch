package audit

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestBuildAuditsOnlyThePlannedPackages is the upgrade-shaped regression.
//
// yay's build directory is a persistent cache, not a fresh output directory:
// `cleanAfter` is off by default and the Prolewatch hook deliberately leaves
// that preference alone. So after an upgrade the previous version's archive is
// still sitting beside the new one, together with any detached signature.
//
// Selecting build output with a "*.pkg.tar.*" glob picked all of it up. An old
// package's scriptlet could raise a root-integration prompt for something yay
// was never going to install, a strip could rewrite an unrelated archive, and a
// blocked scan quarantined the good new package along with the cached ones.
func TestBuildAuditsOnlyThePlannedPackages(t *testing.T) {
	withStateAndShare(t)
	workdir := t.TempDir()
	current := filepath.Join(workdir, "demo-2-1-x86_64.pkg.tar.zst")
	stale := filepath.Join(workdir, "demo-1-1-x86_64.pkg.tar.zst")
	signature := current + ".sig"
	for _, path := range []string{current, stale, signature} {
		if err := os.WriteFile(path, []byte("archive"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := saveTransactionPackagePlan(workdir, []string{current}); err != nil {
		t.Fatal(err)
	}

	planned, err := TransactionPackagePlan(workdir)
	if err != nil {
		t.Fatal(err)
	}
	selected := []string{}
	for _, candidate := range planned {
		if regularNoFollow(candidate) {
			selected = append(selected, candidate)
		}
	}
	if !slices.Equal(selected, []string{current}) {
		t.Fatalf("the build audited %v; only the planned archive belongs to this transaction", selected)
	}
	// The shapes the old glob matched, named so a future change cannot quietly
	// re-admit them.
	for _, unrelated := range []string{stale, signature} {
		if slices.Contains(selected, unrelated) {
			t.Errorf("%s is not output of this build and was selected", filepath.Base(unrelated))
		}
	}
}

// A plan from another transaction must not be reused: it is keyed by checkout
// and yay transaction exactly so a stale one cannot name a stale archive.
func TestPackagePlanIsScopedToItsTransaction(t *testing.T) {
	withStateAndShare(t)
	first, second := t.TempDir(), t.TempDir()
	if err := saveTransactionPackagePlan(first, []string{filepath.Join(first, "demo-1-1-any.pkg.tar.zst")}); err != nil {
		t.Fatal(err)
	}
	if _, err := TransactionPackagePlan(second); err == nil {
		t.Fatal("a different checkout read another checkout's package plan")
	}
}

// makepkg --packagelist runs before a new package archive exists. VCS packages
// make the distinction especially visible: pkgver() can produce a filename that
// differs from the committed .SRCINFO version, but that future name is still the
// exact plan the later build must satisfy and audit.
func TestPackageListAllowsAPlannedFutureVCSArtifact(t *testing.T) {
	withStateAndShare(t)
	workdir := t.TempDir()
	name := "stu-git-2.18.8-1-x86_64.pkg.tar.zst"
	want := filepath.Join(workdir, name)
	status := -1
	output := captureStdout(t, func() {
		status = handlePackageList(t.Context(), []byte(name+"\n"), workdir, nil, nil)
	})
	if status != ExitOK {
		t.Fatalf("future package plan was rejected: status=%d", status)
	}
	if got := strings.TrimSpace(output); got != want {
		t.Fatalf("package-list output=%q, want %q", got, want)
	}
	planned, err := TransactionPackagePlan(workdir)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(planned, []string{want}) {
		t.Fatalf("saved package plan=%v, want %v", planned, []string{want})
	}
}

// Only absence means "the build will create this later". A pre-existing
// symlink or directory at the planned path must not be passed to yay as though
// it were a future archive.
func TestPackageListRejectsUnsafeExistingPlannedPaths(t *testing.T) {
	for _, kind := range []string{"symlink", "directory"} {
		t.Run(kind, func(t *testing.T) {
			withStateAndShare(t)
			workdir := t.TempDir()
			name := "demo-1-1-x86_64.pkg.tar.zst"
			packagePath := filepath.Join(workdir, name)
			var err error
			if kind == "symlink" {
				err = os.Symlink(filepath.Join(workdir, "absent-target"), packagePath)
			} else {
				err = os.Mkdir(packagePath, 0o700)
			}
			if err != nil {
				t.Fatal(err)
			}
			if status := handlePackageList(t.Context(), []byte(name+"\n"), workdir, nil, nil); status != ExitExecutionFailure {
				t.Fatalf("%s planned path was accepted: status=%d", kind, status)
			}
		})
	}
}

// TestUnsupportedPackageFormatIsRejectedBeforeTheBuild covers a compatibility
// boundary the code enforced three different ways and never stated.
//
// makepkg treats PKGEXT as administrator policy and supports plain tar plus
// nine compressors. The artifact scanner reads several; the mandatory
// privileged-integration gate enumerates and rewrites zstd only. A valid
// .pkg.tar.xz therefore passed inspection and then failed the gate with
// "magic number mismatch", quarantining the package with an error that says
// nothing about PKGEXT - and a plain .pkg.tar failed even earlier, because the
// old glob did not match it at all.
//
// The package list names the exact files the build will write, so the effective
// policy is readable before the build runs.
func TestUnsupportedPackageFormatIsRejectedBeforeTheBuild(t *testing.T) {
	withStateAndShare(t)
	for name, supported := range map[string]bool{
		"demo-1-1-x86_64.pkg.tar.zst": true,
		"demo-1-1-x86_64.pkg.tar.xz":  false,
		"demo-1-1-x86_64.pkg.tar":     false,
		"demo-1-1-x86_64.pkg.tar.gz":  false,
		"demo-1-1-x86_64.pkg.tar.lz4": false,
	} {
		rejected := unsupportedPackageFormat([]string{name}) != ""
		if supported && rejected {
			t.Errorf("%s is the supported format and was rejected", name)
		}
		if !supported && !rejected {
			t.Errorf("%s cannot be carried end to end and was accepted", name)
		}
	}
	// And the plan is refused as a whole, before the build, rather than the
	// unsupported archive failing later inside the mandatory gate.
	workdir := t.TempDir()
	// makepkg prints its output paths inside the sandbox; a relative name is
	// resolved against the checkout the same way.
	if status := handlePackageList(t.Context(), []byte("demo-1-1-x86_64.pkg.tar.xz\n"), workdir, nil, nil); status != ExitArtifactFailure {
		t.Fatalf("an unsupported package format reached the build: status=%d", status)
	}
	if _, err := TransactionPackagePlan(workdir); err == nil {
		t.Fatal("a rejected plan was persisted anyway")
	}
}
