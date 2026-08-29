package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A package builds in a directory it controls, and the gate writes its rewrite
// beside the package so the replacing rename stays on one filesystem. That
// makes the output path attacker-adjacent: a fixed name opened with
// O_CREATE|O_TRUNC would let package code leave a symlink there and make the
// trusted process truncate its target.
//
// The victim file is the assertion. Everything else is mechanism.
func TestRewritePathCannotBeSeededToOverwriteAUserFile(t *testing.T) {
	home := t.TempDir()
	victim := filepath.Join(home, "precious")
	const contents = "do not truncate me\n"
	if err := os.WriteFile(victim, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	packageDir := t.TempDir()
	packagePath := filepath.Join(packageDir, "demo-1-1-any.pkg.tar.zst")
	if err := os.WriteFile(packagePath, []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Model package code pre-creating a fixed scratch directory with the
	// predicted output name pointing at the victim.
	seeded := filepath.Join(packageDir, ".prolewatch-gate")
	if err := os.Mkdir(seeded, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(seeded, filepath.Base(packagePath))); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	target, err := filteredPackagePath(packagePath)
	if err != nil {
		t.Fatalf("filteredPackagePath: %v", err)
	}
	// The chosen path must not be inside anything the package pre-created.
	if strings.HasPrefix(target, seeded+string(os.PathSeparator)) {
		t.Fatalf("the gate reused a package-created directory: %s", target)
	}

	// And creating the output there must not follow a symlink, even if one is
	// planted at the exact chosen path afterwards.
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, target); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if _, err := runGate(t.Context(), packagePath, target, gateEnumerateCommand, gatePackageTarget); err == nil {
		t.Fatal("the gate opened a symlinked output path")
	}

	raw, err := os.ReadFile(victim)
	if err != nil || string(raw) != contents {
		t.Fatalf("the victim file was modified: %q (%v)", raw, err)
	}
}

// The scratch directory name must not be predictable, or pre-seeding works
// again however carefully the file is opened.
func TestRewriteScratchDirectoryIsUnpredictableAndExclusive(t *testing.T) {
	packageDir := t.TempDir()
	packagePath := filepath.Join(packageDir, "demo-1-1-any.pkg.tar.zst")
	if err := os.WriteFile(packagePath, []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := filteredPackagePath(packagePath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := filteredPackagePath(packagePath)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(first) == filepath.Dir(second) {
		t.Fatalf("two calls produced the same scratch directory: %s", filepath.Dir(first))
	}
	for _, path := range []string{first, second} {
		info, err := os.Lstat(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("%s is %v with mode %v", filepath.Dir(path), info.Mode().Type(), info.Mode().Perm())
		}
	}

	// Still invisible to the glob that finds built packages: Go's filepath.Glob
	// matches dotfiles, so an interrupted rewrite must not look like a package.
	matches, err := filepath.Glob(filepath.Join(packageDir, "*.pkg.tar.*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || matches[0] != packagePath {
		t.Fatalf("the scratch directory is visible to the package glob: %v", matches)
	}
}
