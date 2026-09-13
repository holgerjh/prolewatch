package audit

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const devPackageListing = `.PKGINFO
.BUILDINFO
.MTREE
usr/bin/prolewatch
usr/bin/prolewatch-makepkg
usr/bin/prolewatch-gpg
usr/bin/prolewatch-net
usr/share/prolewatch/default-config.yaml
usr/share/prolewatch/prolewatch.lua
usr/share/prolewatch/review-prompt.md
usr/share/prolewatch/verdict.schema.json
etc/prolewatch/config.yaml
usr/share/doc/prolewatch/docs/ai-review.md
`

type packageScriptFixture struct {
	root, bin, keyHome, packagePath, verifyLog, installLog string
}

func writeFixtureCommand(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func newPackageScriptFixture(t *testing.T) packageScriptFixture {
	t.Helper()
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	keyHome := filepath.Join(root, "dev-key")
	dist := filepath.Join(root, "dist")
	for _, directory := range []string{bin, keyHome, dist} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	packagePath := filepath.Join(dist, "prolewatch-dev-0.11.0-1-x86_64.pkg.tar.zst")
	if err := os.WriteFile(packagePath, []byte("valid package"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(packagePath+".sig", []byte("signature"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keyHome, "fingerprint"), []byte("0123456789ABCDEF0123456789ABCDEF01234567\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeFixtureCommand(t, filepath.Join(bin, "pacman-conf"), `#!/bin/bash
printf '%s\n' "${FAKE_POLICY:-Optional TrustedOnly}"
`)
	writeFixtureCommand(t, filepath.Join(bin, "gpg"), `#!/bin/bash
printf '%s\n' "$*" >>"${FAKE_VERIFY_LOG:?}"
package=${!#}
if grep -q 'tampered' "$package"; then
  printf 'BAD signature\n' >&2
  exit 1
fi
printf 'GOOD signature\n'
`)
	writeFixtureCommand(t, filepath.Join(bin, "bsdtar"), `#!/bin/bash
case "${1:-}" in
  -xOf)
    printf 'pkgname = prolewatch-dev\narch = x86_64\n'
    ;;
  -tf)
    printf '%s' "${FAKE_LISTING:?}"
    if [[ ${FAKE_EXTRA_MEMBER:-0} == 1 ]]; then
      printf 'usr/lib/systemd/system/evil.service\n'
    fi
    ;;
  -tvf)
    ;;
  *)
    printf 'unexpected bsdtar arguments: %s\n' "$*" >&2
    exit 2
    ;;
esac
`)
	writeFixtureCommand(t, filepath.Join(bin, "uname"), "#!/bin/bash\nprintf 'x86_64\\n'\n")
	writeFixtureCommand(t, filepath.Join(bin, "makepkg"), "#!/bin/bash\nexit 0\n")
	writeFixtureCommand(t, filepath.Join(bin, "pacman"), `#!/bin/bash
printf '%s\n' "$*" >>"${FAKE_INSTALL_LOG:?}"
`)
	writeFixtureCommand(t, filepath.Join(bin, "sudo"), "#!/bin/bash\nexec \"$@\"\n")
	return packageScriptFixture{
		root: root, bin: bin, keyHome: keyHome, packagePath: packagePath,
		verifyLog: filepath.Join(root, "verify.log"), installLog: filepath.Join(root, "install.log"),
	}
}

func (fixture packageScriptFixture) env(policy string) []string {
	return append(os.Environ(),
		"PATH="+fixture.bin+":"+os.Getenv("PATH"),
		"HOME="+fixture.root,
		"PROLEWATCH_DEV_GNUPGHOME="+fixture.keyHome,
		"PROLEWATCH_ARCH_DIST_DIR="+filepath.Dir(fixture.packagePath),
		"FAKE_POLICY="+policy,
		"FAKE_LISTING="+devPackageListing,
		"FAKE_VERIFY_LOG="+fixture.verifyLog,
		"FAKE_INSTALL_LOG="+fixture.installLog,
	)
}

func repoScript(t *testing.T, name string) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "scripts", name))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func runFixtureScript(t *testing.T, script string, args, env []string) (string, error) {
	t.Helper()
	command := exec.Command("bash", append([]string{script}, args...)...)
	command.Env = env
	output, err := command.CombinedOutput()
	return string(output), err
}

func TestVerifyArchPackageChecksArtifactIndependentlyOfPacmanPolicy(t *testing.T) {
	fixture := newPackageScriptFixture(t)
	script := repoScript(t, "verify-arch-package.sh")
	output, err := runFixtureScript(t, script, []string{fixture.packagePath}, fixture.env("Optional TrustedOnly"))
	if err != nil {
		t.Fatalf("optional policy blocked verification: %v\n%s", err, output)
	}
	for _, want := range []string{"GOOD signature", "this package was verified directly instead", "Signature and architecture are valid", "Payload carries only"} {
		if !strings.Contains(output, want) {
			t.Fatalf("successful verification omitted %q:\n%s", want, output)
		}
	}
	verified, err := os.ReadFile(fixture.verifyLog)
	if err != nil || !strings.Contains(string(verified), "--batch --homedir "+fixture.keyHome+" --verify "+fixture.packagePath+".sig "+fixture.packagePath) {
		t.Fatalf("signature was not bound to the private dev key home: %q %v", verified, err)
	}

	t.Run("bad signature", func(t *testing.T) {
		if err := os.WriteFile(fixture.packagePath, []byte("tampered package"), 0o600); err != nil {
			t.Fatal(err)
		}
		output, err := runFixtureScript(t, script, []string{fixture.packagePath}, fixture.env("Optional TrustedOnly"))
		if err == nil || !strings.Contains(output, "BAD signature") || strings.Contains(output, "this package was verified directly instead") {
			t.Fatalf("tampered package crossed signature verification: err=%v\n%s", err, output)
		}
	})

	t.Run("wrong package name", func(t *testing.T) {
		wrong := filepath.Join(filepath.Dir(fixture.packagePath), "wrong.pkg.tar.zst")
		if err := os.WriteFile(wrong, []byte("valid package"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(wrong+".sig", []byte("signature"), 0o600); err != nil {
			t.Fatal(err)
		}
		output, err := runFixtureScript(t, script, []string{wrong}, fixture.env("Optional TrustedOnly"))
		if err == nil || !strings.Contains(output, "Unexpected development package name") {
			t.Fatalf("wrong package name accepted: err=%v\n%s", err, output)
		}
	})

	t.Run("missing signature", func(t *testing.T) {
		unsigned := filepath.Join(filepath.Dir(fixture.packagePath), "prolewatch-dev-unsigned.pkg.tar.zst")
		if err := os.WriteFile(unsigned, []byte("valid package"), 0o600); err != nil {
			t.Fatal(err)
		}
		output, err := runFixtureScript(t, script, []string{unsigned}, fixture.env("Optional TrustedOnly"))
		if err == nil || !strings.Contains(output, "Detached package signature is missing") {
			t.Fatalf("missing signature accepted: err=%v\n%s", err, output)
		}
	})

	t.Run("allow-list violation", func(t *testing.T) {
		if err := os.WriteFile(fixture.packagePath, []byte("valid package"), 0o600); err != nil {
			t.Fatal(err)
		}
		env := append(fixture.env("Optional TrustedOnly"), "FAKE_EXTRA_MEMBER=1")
		output, err := runFixtureScript(t, script, []string{fixture.packagePath}, env)
		if err == nil || !strings.Contains(output, "usr/lib/systemd/system/evil.service") || strings.Contains(output, "this package was verified directly instead") {
			t.Fatalf("allow-list violation crossed verification: err=%v\n%s", err, output)
		}
	})
}

func TestPacmanVerifiesPackageWithPrivateDevelopmentKeyHome(t *testing.T) {
	if testing.Short() {
		t.Skip("generates an ephemeral signing key")
	}
	for _, tool := range []string{"bsdtar", "gpg", "gpgconf", "pacman"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is unavailable", tool)
		}
	}
	keyHome := t.TempDir()
	if err := os.Chmod(keyHome, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = exec.Command("gpgconf", "--homedir", keyHome, "--kill", "gpg-agent").Run()
	})
	generate := exec.Command("gpg", "--batch", "--homedir", keyHome, "--pinentry-mode", "loopback", "--passphrase", "",
		"--quick-generate-key", "Prolewatch package verification test", "ed25519", "sign", "1d")
	if output, err := generate.CombinedOutput(); err != nil {
		if strings.Contains(string(output), "failed to start gpg-agent") || strings.Contains(string(output), "No agent running") {
			t.Skipf("sandbox cannot start gpg-agent: %s", output)
		}
		t.Fatalf("generate ephemeral key: %v\n%s", err, output)
	}
	packageRoot := t.TempDir()
	pkginfo := `pkgname = prolewatch-signature-probe
pkgbase = prolewatch-signature-probe
pkgver = 1-1
pkgdesc = Prolewatch signature probe
url = https://example.invalid
builddate = 1788048000
packager = Prolewatch tests
size = 0
arch = x86_64
`
	if err := os.WriteFile(filepath.Join(packageRoot, ".PKGINFO"), []byte(pkginfo), 0o600); err != nil {
		t.Fatal(err)
	}
	packagePath := filepath.Join(t.TempDir(), "prolewatch-signature-probe-1-1-x86_64.pkg.tar.zst")
	archive := exec.Command("bsdtar", "-acf", packagePath, ".PKGINFO")
	archive.Dir = packageRoot
	if output, err := archive.CombinedOutput(); err != nil {
		t.Fatalf("create probe package: %v\n%s", err, output)
	}
	sign := exec.Command("gpg", "--batch", "--homedir", keyHome, "--pinentry-mode", "loopback", "--passphrase", "",
		"--detach-sign", packagePath)
	if output, err := sign.CombinedOutput(); err != nil {
		t.Fatalf("sign probe package: %v\n%s", err, output)
	}
	directVerify := exec.Command("gpg", "--batch", "--homedir", keyHome, "--verify", packagePath+".sig", packagePath)
	if output, err := directVerify.CombinedOutput(); err != nil {
		t.Fatalf("gpg did not verify the package against the private dev key home: %v\n%s", err, output)
	}
	pacmanVerify := exec.Command("pacman", "--gpgdir", keyHome, "-Up", "--", packagePath)
	if output, err := pacmanVerify.CombinedOutput(); err != nil {
		t.Fatalf("pacman did not accept the signed package through the private dev key home: %v\n%s", err, output)
	} else if !strings.Contains(string(output), "prolewatch-signature-probe") {
		t.Fatalf("pacman did not parse the signed probe package: %s", output)
	}
}

func copyScriptFixture(t *testing.T, source, target string) {
	t.Helper()
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, raw, 0o755); err != nil {
		t.Fatal(err)
	}
}

func runDevInstallFixture(t *testing.T, policy string, tampered bool) (string, packageScriptFixture, error) {
	t.Helper()
	fixture := newPackageScriptFixture(t)
	project := filepath.Join(fixture.root, "project")
	scripts := filepath.Join(project, "scripts")
	if err := os.MkdirAll(scripts, 0o700); err != nil {
		t.Fatal(err)
	}
	copyScriptFixture(t, repoScript(t, "dev-install.sh"), filepath.Join(scripts, "dev-install.sh"))
	copyScriptFixture(t, repoScript(t, "verify-arch-package.sh"), filepath.Join(scripts, "verify-arch-package.sh"))
	buildBody := `#!/bin/bash
set -eu
mkdir -p "${PROLEWATCH_ARCH_DIST_DIR:?}"
package=${PROLEWATCH_ARCH_DIST_DIR}/prolewatch-dev-0.11.0-1-x86_64.pkg.tar.zst
if [[ ${FAKE_TAMPER_BUILD:-0} == 1 ]]; then
  printf 'tampered package' >"$package"
else
  printf 'valid package' >"$package"
fi
printf 'signature' >"${package}.sig"
`
	writeFixtureCommand(t, filepath.Join(scripts, "build-arch-package.sh"), buildBody)
	env := fixture.env(policy)
	if tampered {
		env = append(env, "FAKE_TAMPER_BUILD=1")
	}
	output, err := runFixtureScript(t, filepath.Join(scripts, "dev-install.sh"), nil, env)
	return output, fixture, err
}

func TestDevInstallVerifiesWithoutGlobalPolicyAndStopsOnTampering(t *testing.T) {
	output, fixture, err := runDevInstallFixture(t, "Optional TrustedOnly", false)
	if err != nil {
		t.Fatalf("dev-install failed under stock local policy: %v\n%s", err, output)
	}
	if !strings.Contains(output, "this package was verified directly instead") {
		t.Fatalf("optional-policy verification warning is absent:\n%s", output)
	}
	installed, err := os.ReadFile(fixture.installLog)
	if err != nil || !strings.Contains(string(installed), "--gpgdir "+fixture.keyHome+" -U --noconfirm -- "+fixture.packagePath) {
		t.Fatalf("pacman did not receive the private dev key home: %q %v\n%s", installed, err, output)
	}

	tamperedOutput, tamperedFixture, err := runDevInstallFixture(t, "Optional TrustedOnly", true)
	if err == nil || !strings.Contains(tamperedOutput, "BAD signature") {
		t.Fatalf("tampered dev package was not rejected: err=%v\n%s", err, tamperedOutput)
	}
	if installed, readErr := os.ReadFile(tamperedFixture.installLog); !os.IsNotExist(readErr) || len(installed) != 0 {
		t.Fatalf("tampered package reached pacman: %q %v", installed, readErr)
	}
}

func TestDevInstallWarnsWhenStrictLocalPolicyBreaksMakepkgOutput(t *testing.T) {
	output, _, err := runDevInstallFixture(t, "Required TrustedOnly", false)
	if err != nil {
		t.Fatalf("signed dev package did not install under strict policy: %v\n%s", err, output)
	}
	for _, want := range []string{"rejects unsigned local packages", "normal makepkg output", "AUR installs will fail"} {
		if !strings.Contains(output, want) {
			t.Fatalf("strict-policy warning omitted %q:\n%s", want, output)
		}
	}
	raw, err := os.ReadFile(repoScript(t, "dev-install.sh"))
	if err != nil || !strings.Contains(string(raw), "PROLEWATCH_SET_PACMAN_SIGLEVEL") || !strings.Contains(string(raw), "pacman.conf.prolewatch-bak") {
		t.Fatalf("explicit strict-policy opt-in or backup was removed: %v", err)
	}
}
