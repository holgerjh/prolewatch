package audit

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// installDestinationRE captures the destination of one `install -D...` line.
var installDestinationRE = regexp.MustCompile(`install -D[^\s]*\s+"[^"]*"\s+"\$\{pkgdir\}([^"]*)"`)

// loopHeaderRE captures the word list of a `for name in a b c; do` header.
var loopHeaderRE = regexp.MustCompile(`^\s*for name in ([^;]+); do\s*$`)

// packagedPaths returns every path the Arch recipe installs into the package.
//
// The recipe installs some payload through `for name in ...` loops, so a plain
// text search for a path would miss exactly the files that are installed
// correctly and find only the literal ones. Expanding ${name} inside the loop
// body is the smallest thing that reads the recipe the way makepkg does.
func packagedPaths(t *testing.T, recipe string) map[string]bool {
	t.Helper()
	paths := map[string]bool{}
	var loop []string
	for _, line := range strings.Split(recipe, "\n") {
		if match := loopHeaderRE.FindStringSubmatch(line); match != nil {
			loop = strings.Fields(match[1])
			continue
		}
		if strings.TrimSpace(line) == "done" {
			loop = nil
			continue
		}
		match := installDestinationRE.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		destination := match[1]
		if !strings.Contains(destination, "${name}") {
			paths[destination] = true
			continue
		}
		if loop == nil {
			t.Fatalf("recipe installs %q through ${name} outside a loop", destination)
		}
		for _, name := range loop {
			paths[strings.ReplaceAll(destination, "${name}", name)] = true
		}
	}
	return paths
}

func archRecipe(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "packaging", "arch", "PKGBUILD.in"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestArchPackageInstallsEveryRequiredPayloadFile keeps the package payload in
// lockstep with the installation health check.
func TestArchPackageInstallsEveryRequiredPayloadFile(t *testing.T) {
	recipe := archRecipe(t)
	installed := packagedPaths(t, recipe)
	for _, required := range InstalledPayloadPaths {
		if !installed[required] {
			t.Errorf("the Arch package does not install %s, which a working installation needs", required)
		}
	}
}

// AI setup deliberately moved out of the README. Keep the linked guide in the
// installed documentation rather than shipping a README whose setup link ends
// at a file pacman omitted.
func TestArchPackageInstallsLinkedAIReviewGuide(t *testing.T) {
	installed := packagedPaths(t, archRecipe(t))
	const guide = "/usr/share/doc/prolewatch/docs/ai-review.md"
	if !installed[guide] {
		t.Fatalf("the Arch package does not install the README's AI setup guide at %s", guide)
	}
}

// TestSystemConfigurationIsAPacmanBackupFile keeps an administrator's edits
// from being replaced on upgrade. A configuration pacman owns without a backup
// entry is overwritten, which silently reverts a deliberate policy change.
func TestSystemConfigurationIsAPacmanBackupFile(t *testing.T) {
	recipe := archRecipe(t)
	backup := strings.TrimPrefix(systemConfigDefaultPath, "/")
	if !strings.Contains(recipe, "backup=('"+backup+"')") {
		t.Errorf("the Arch package does not declare %s as a backup file", backup)
	}
}

// TestArchPackageDeclaresNoCleanRootDependency holds the line on a dependency
// that outlived its feature. No production path runs mkarchroot since the
// single-administrator redesign, so requiring devtools costs every user a
// package they do not need.
func TestArchPackageDeclaresNoCleanRootDependency(t *testing.T) {
	recipe := archRecipe(t)
	for _, retired := range []string{"'devtools'", "mkarchroot"} {
		if strings.Contains(recipe, retired) {
			t.Errorf("the Arch package still references the retired clean-root component %s", retired)
		}
	}
}

// Automatic, locked subordinate-ID allocation is provided by usermod -S in
// shadow 4.20. Older versions would make the safe setup advice an unknown
// option and tempt operators back toward collision-prone literal ranges.
func TestArchPackageRequiresShadowAllocator(t *testing.T) {
	recipe := archRecipe(t)
	if !strings.Contains(recipe, "'shadow>=4.20'") {
		t.Error("the Arch package does not require the shadow version that provides --add-subids")
	}
}

// renderChannel runs the shipping renderer, because a test that re-implemented
// the substitution would be checking itself.
func renderChannel(t *testing.T, args ...string) string {
	t.Helper()
	command := exec.Command("bash", append([]string{filepath.Join("..", "..", "scripts", "render-pkgbuild.sh")}, args...)...)
	rendered, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("render %v: %v\n%s", args, err, rendered)
	}
	return string(rendered)
}

const (
	testSourceDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testFingerprint  = "0123456789ABCDEF0123456789ABCDEF01234567"
)

// TestBothPackageChannelsInstallTheSamePayload is the anti-drift check for the
// trust path.
//
// A published AUR recipe and the maintainer's dev recipe differ only in where
// the source comes from and how it is authenticated. If they were two files,
// the way that ends is one of them quietly installing something the other does
// not - and the one people actually run is the one nobody tests.
func TestBothPackageChannelsInstallTheSamePayload(t *testing.T) {
	channels := map[string]string{
		"aur": renderChannel(t, "aur", "0.11.0", testSourceDigest, testFingerprint),
		"dev": renderChannel(t, "dev", "0.11.0.r1.gabcdef", testSourceDigest),
	}
	for channel, recipe := range channels {
		installed := packagedPaths(t, recipe)
		for _, required := range InstalledPayloadPaths {
			if !installed[required] {
				t.Errorf("the %s recipe does not install %s", channel, required)
			}
		}
		if !strings.Contains(recipe, "backup=('etc/prolewatch/config.yaml')") {
			t.Errorf("the %s recipe does not preserve the administrator's configuration", channel)
		}
		// A recipe that does not parse is a release that fails on the user's
		// machine, at the one moment they are being asked to trust it.
		script := filepath.Join(t.TempDir(), "PKGBUILD")
		if err := os.WriteFile(script, []byte(recipe), 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command("bash", "-n", script).CombinedOutput(); err != nil {
			t.Errorf("the %s recipe is not valid shell: %v\n%s", channel, err, output)
		}
	}
}

// TestAurChannelCarriesTheTrustPath asserts the three things that make
// `yay -S prolewatch` verifiable rather than merely convenient: the archive is
// named by release URL, its detached signature is fetched beside it, and the
// maintainer fingerprint is declared so makepkg checks that signature before
// running any of the recipe's own steps.
func TestAurChannelCarriesTheTrustPath(t *testing.T) {
	recipe := renderChannel(t, "aur", "0.11.0", testSourceDigest, testFingerprint)
	for _, required := range []string{
		"pkgname=prolewatch",
		"https://github.com/holgerjh/prolewatch/releases/download/v${pkgver}/prolewatch-${pkgver}.tar.gz",
		"prolewatch-${pkgver}.tar.gz.sig",
		"'" + testSourceDigest + "'",
		"'SKIP'",
		"validpgpkeys=('" + testFingerprint + "')",
	} {
		if !strings.Contains(recipe, required) {
			t.Errorf("the AUR recipe is missing %q", required)
		}
	}
	// The dev channel has nothing to verify against, and must not pretend
	// otherwise by carrying an empty or borrowed key.
	dev := renderChannel(t, "dev", "0.11.0.r1.gabcdef", testSourceDigest)
	if !strings.Contains(dev, "validpgpkeys=()") || strings.Contains(dev, "SKIP") {
		t.Errorf("the dev recipe claims a signature it does not have:\n%s", dev)
	}
}

// A short key id identifies a key ambiguously, and an ambiguous identity in
// validpgpkeys is not a trust path. So is a release URL a caller can choose.
func TestAurChannelRefusesAnAmbiguousIdentity(t *testing.T) {
	for _, fingerprint := range []string{"", "0123456789ABCDEF", "0123456789abcdef0123456789abcdef01234567"} {
		command := exec.Command("bash", filepath.Join("..", "..", "scripts", "render-pkgbuild.sh"),
			"aur", "0.11.0", testSourceDigest, fingerprint)
		if output, err := command.CombinedOutput(); err == nil {
			t.Errorf("the AUR channel accepted %q as a maintainer identity:\n%s", fingerprint, output)
		}
	}
}

// TestSourceArchivePrintsOnlyDigest protects the stdout contract consumed by
// both package builders. `go mod verify` writes a success message to stdout;
// allowing that through makes command substitution capture two lines and the
// PKGBUILD renderer reject the result as an invalid SHA-256.
func TestSourceArchivePrintsOnlyDigest(t *testing.T) {
	// This exercises the maintainer workflow, whose input is deliberately the
	// Git index and working tree. The published source archive has already
	// crossed that boundary and intentionally contains no .git metadata, so its
	// package-time check cannot reconstruct the workflow's input.
	if _, err := os.Lstat(filepath.Join("..", "..", ".git")); err != nil {
		if os.IsNotExist(err) {
			t.Skip("source archive construction requires a Git checkout")
		}
		t.Fatal(err)
	}
	fakeGo := filepath.Join(t.TempDir(), "go")
	fake := `#!/bin/bash
set -eu
case "${1:-}" in
  env)
    printf '/tmp/prolewatch-fake-module-cache\n'
    ;;
  -C)
    if [[ ${4:-} == verify ]]; then
      printf 'all modules verified\n'
    elif [[ ${4:-} == vendor && ${5:-} == -o ]]; then
      mkdir -p -- "$6"
    else
      printf 'unexpected fake go invocation: %q\n' "$*" >&2
      exit 1
    fi
    ;;
  *)
    printf 'unexpected fake go invocation: %q\n' "$*" >&2
    exit 1
    ;;
esac
`
	if err := os.WriteFile(fakeGo, []byte(fake), 0o700); err != nil {
		t.Fatal(err)
	}

	outputDir := t.TempDir()
	command := exec.Command("bash", filepath.Join("..", "..", "scripts", "source-archive.sh"), "0.0.0.output_contract", outputDir)
	command.Env = append(os.Environ(), "PROLEWATCH_GO="+fakeGo)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("source archive: %v\n%s", err, stderr.String())
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}\n$`).MatchString(stdout.String()) {
		t.Fatalf("source archive stdout is not exactly one SHA-256: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "all modules verified") {
		t.Fatalf("fake go verification did not exercise diagnostic routing: %q", stderr.String())
	}
	archive := filepath.Join(outputDir, "prolewatch-0.0.0.output_contract.tar.gz")
	if info, err := os.Stat(archive); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("source archive was not created: %v", err)
	}
}
