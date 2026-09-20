package brief

import (
	"archive/tar"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestClassifySurfaceCoversEveryRootExecutionChannel(t *testing.T) {
	for member, want := range map[string]SurfaceKind{
		".INSTALL":                                     SurfaceScriptlet,
		"./.INSTALL":                                   SurfaceScriptlet,
		"usr/share/libalpm/hooks/zz-foo.hook":          SurfaceHook,
		"./usr/lib/systemd/system/foo.service":         SurfaceUnit,
		"etc/systemd/system/foo.service":               SurfaceUnit,
		"usr/lib/sysusers.d/foo.conf":                  SurfaceSysusers,
		"usr/lib/tmpfiles.d/foo.conf":                  SurfaceTmpfiles,
		"usr/lib/udev/rules.d/99-foo.rules":            SurfaceUdev,
		"usr/lib/security/pam_foo.so":                  SurfacePAM,
		"usr/share/polkit-1/rules.d/10-foo.rules":      SurfacePolkit,
		"usr/share/dbus-1/system-services/foo.service": SurfaceDBus,
	} {
		class, ok := ClassifySurface(member)
		if !ok || class.Kind != want {
			t.Fatalf("%s classified as %q (ok=%t), want %q", member, class.Kind, ok, want)
		}
		if class.When == "" {
			t.Fatalf("%s has no description of when it runs", member)
		}
		if class.Activation == "" {
			t.Fatalf("%s has no activation, so the gate cannot tell a question from an inventory line", member)
		}
	}
}

// A gate that reported only the scriptlet would print "no scriptlet" over the
// channel an attacker who has read the design would actually use.
func TestClassifySurfaceIgnoresOrdinaryFiles(t *testing.T) {
	for _, member := range []string{
		"usr/bin/foo", "usr/share/doc/foo/README", ".PKGINFO", ".BUILDINFO", ".MTREE",
		"usr/share/libalpm/hooks", // the directory itself is not a surface
		"usr/lib/systemd", "usr/share/applications/foo.desktop",
	} {
		if class, ok := ClassifySurface(member); ok {
			t.Fatalf("%s misclassified as %q", member, class.Kind)
		}
	}
}

// Prefix removal must preserve the leading dot in ".INSTALL"; a character-class
// trim such as Python's lstrip("./") would turn it into "INSTALL".
func TestNormalizeMemberDoesNotEatLeadingDots(t *testing.T) {
	for member, want := range map[string]string{
		"./.INSTALL":     ".INSTALL",
		".INSTALL":       ".INSTALL",
		"./usr/bin/foo":  "usr/bin/foo",
		"./usr/bin/":     "usr/bin",
		"...weird":       "...weird",
		"./.hidden/file": ".hidden/file",
	} {
		if got := NormalizeMember(member); got != want {
			t.Fatalf("NormalizeMember(%q) = %q, want %q", member, got, want)
		}
	}
}

func requireArchTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"makepkg", "bsdtar", "fakeroot", "pacman", "zstd"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
}

// buildFixture produces a real package carrying every surface class the gate
// claims to handle, plus a non-root-owned file so ownership round-tripping is
// observable.
func buildFixture(t *testing.T) string {
	t.Helper()
	requireArchTools(t)
	work := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(work, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("PKGBUILD", `pkgname=prolewatch-gate-fixture
pkgver=1
pkgrel=1
arch=('any')
install=prolewatch-gate-fixture.install
package() {
  install -Dm0755 /dev/null "$pkgdir/usr/bin/fixture"
  install -Dm0644 -o 65534 -g 65534 /dev/null "$pkgdir/usr/share/fixture/nobody-owned"
  install -Dm0644 "$startdir/evil.hook"    "$pkgdir/usr/share/libalpm/hooks/zz-evil.hook"
  install -Dm0644 "$startdir/evil.service" "$pkgdir/usr/lib/systemd/system/evil.service"
  install -Dm0644 "$startdir/evil.conf"    "$pkgdir/usr/lib/tmpfiles.d/evil.conf"
}
`)
	write("prolewatch-gate-fixture.install", "post_install() {\n  npm install -g atomic-lockfile\n}\n")
	write("evil.hook", "[Trigger]\nOperation=Install\nType=Package\nTarget=*\n[Action]\nWhen=PostTransaction\nExec=/usr/bin/evil\n")
	write("evil.service", "[Unit]\nDescription=evil\n")
	write("evil.conf", "d /var/lib/evil 0777 root root\n")

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
	return matches[0]
}

func TestEnumerateFindsEverySurfaceInARealPackage(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a real package")
	}
	surfaces, err := EnumerateSurfaces(buildFixture(t))
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	found := map[SurfaceKind]PrivilegedSurface{}
	for _, surface := range surfaces {
		found[surface.Kind] = surface
	}
	for _, kind := range []SurfaceKind{SurfaceScriptlet, SurfaceHook, SurfaceUnit, SurfaceTmpfiles} {
		if _, ok := found[kind]; !ok {
			t.Fatalf("%s not enumerated; found %+v", kind, surfaces)
		}
	}
	// The user is asked to approve code, so the code has to be shown.
	if !strings.Contains(found[SurfaceScriptlet].Body, "npm install -g atomic-lockfile") {
		t.Fatalf("scriptlet body not readable: %q", found[SurfaceScriptlet].Body)
	}
	if !strings.Contains(found[SurfaceHook].Body, "/usr/bin/evil") {
		t.Fatalf("hook body not readable: %q", found[SurfaceHook].Body)
	}
}

func TestFilterStripsEverySurfaceAndPrunesEmptiedDirectories(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a real package")
	}
	original := buildFixture(t)
	surfaces, err := EnumerateSurfaces(original)
	if err != nil {
		t.Fatalf("enumerate: %v", err)
	}
	var strip []string
	for _, surface := range surfaces {
		strip = append(strip, surface.Member)
	}
	filtered := filepath.Join(t.TempDir(), "filtered.pkg.tar.zst")
	result, err := FilterArchive(original, filtered, strip)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if result.SHA256 == "" {
		t.Fatal("rewrite produced no content binding")
	}

	remaining, err := EnumerateSurfaces(filtered)
	if err != nil {
		t.Fatalf("re-enumerate: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("surfaces survived the strip: %+v", remaining)
	}
	if len(result.Pruned) == 0 {
		t.Fatal("no directories pruned, though every file under several was removed")
	}
	// The ordinary payload must be untouched.
	listing, err := exec.Command("bsdtar", "-tf", filtered).Output()
	if err != nil {
		t.Fatalf("list filtered package: %v", err)
	}
	if !strings.Contains(string(listing), "usr/bin/fixture") {
		t.Fatalf("the strip removed ordinary files:\n%s", listing)
	}
	for _, empty := range []string{"usr/share/libalpm", "usr/lib/systemd"} {
		if strings.Contains(string(listing), empty+"/") {
			t.Fatalf("emptied directory %s survived:\n%s", empty, listing)
		}
	}
}

// The archive strip set and .MTREE filter set must be identical. pacman -Qp can
// parse a package with a stale .MTREE entry, so this checks .MTREE directly.
func TestFilteredMTreeListsNoStrippedMember(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a real package")
	}
	original := buildFixture(t)
	strip := []string{".INSTALL", "usr/share/libalpm/hooks/zz-evil.hook", "usr/lib/systemd/system/evil.service"}
	filtered := filepath.Join(t.TempDir(), "filtered.pkg.tar.zst")
	result, err := FilterArchive(original, filtered, strip)
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	mtree, err := exec.Command("bash", "-c", "bsdtar -xOf "+filtered+" .MTREE | zcat").Output()
	if err != nil {
		t.Fatalf("read .MTREE: %v", err)
	}
	text := string(mtree)
	for _, member := range append(result.Stripped, result.Pruned...) {
		if strings.Contains(text, "./"+member+" ") || strings.Contains(text, "./"+member+"\n") {
			t.Fatalf(".MTREE still lists the removed member %q", member)
		}
	}
	// The surviving entries must still be there, or the filter removed too much.
	if !strings.Contains(text, "./usr/bin/fixture") {
		t.Fatalf(".MTREE lost an ordinary member:\n%s", text)
	}
	// /set directives establish defaults every following line inherits.
	if !strings.Contains(text, "/set ") {
		t.Fatalf(".MTREE lost its /set directives:\n%s", text)
	}
}

func TestFilterRefusesToRemovePacmanMetadata(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a real package")
	}
	original := buildFixture(t)
	for _, member := range []string{".MTREE", ".PKGINFO", ".BUILDINFO"} {
		if _, err := FilterArchive(original, filepath.Join(t.TempDir(), "x.pkg.tar.zst"), []string{member}); err == nil {
			t.Fatalf("stripping %s was allowed; the package would not install", member)
		}
	}
}

func TestFilterRefusesToStripAMemberThatIsNotThere(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a real package")
	}
	original := buildFixture(t)
	if _, err := FilterArchive(original, filepath.Join(t.TempDir(), "x.pkg.tar.zst"), []string{"usr/share/libalpm/hooks/absent.hook"}); err == nil {
		t.Fatal("stripping an absent member silently succeeded")
	}
}

func TestDropSetPrunesOnlyDirectoriesLeftEmpty(t *testing.T) {
	headers := headersFor(
		dir("usr"), dir("usr/bin"), reg("usr/bin/keep"),
		dir("usr/share"), dir("usr/share/libalpm"), dir("usr/share/libalpm/hooks"),
		reg("usr/share/libalpm/hooks/evil.hook"),
	)
	drop, pruned := dropSet(headers, []string{"usr/share/libalpm/hooks/evil.hook"})
	for _, keep := range []string{"usr", "usr/bin", "usr/bin/keep"} {
		if drop[keep] {
			t.Fatalf("%s was dropped though it still has content", keep)
		}
	}
	for _, gone := range []string{"usr/share", "usr/share/libalpm", "usr/share/libalpm/hooks"} {
		if !drop[gone] {
			t.Fatalf("%s was left behind though nothing survives beneath it", gone)
		}
	}
	if len(pruned) != 3 {
		t.Fatalf("pruned = %v, want three emptied directories", pruned)
	}
}

type fixtureEntry struct {
	name string
	dir  bool
}

func dir(name string) fixtureEntry { return fixtureEntry{name: name, dir: true} }
func reg(name string) fixtureEntry { return fixtureEntry{name: name} }

func headersFor(entries ...fixtureEntry) []*tar.Header {
	headers := make([]*tar.Header, 0, len(entries))
	for _, entry := range entries {
		header := &tar.Header{Name: "./" + entry.name, Typeflag: tar.TypeReg}
		if entry.dir {
			header.Typeflag = tar.TypeDir
			header.Name += "/"
		}
		headers = append(headers, header)
	}
	return headers
}

// The filtered package must verify clean once installed.
//
// pacman -Qp only parses. -Qkk compares every installed file against .MTREE,
// which is where a strip set and a filter set that disagree finally show up.
//
// This runs pacman as namespace-root in a throwaway --root tree, mapping the
// WHOLE subordinate range. That last part is a footgun: mapping only uid 0 and
// the caller leaves 65534 unmapped, pacman cannot chown the nobody-owned file,
// and -Qkk reports a UID mismatch that looks exactly like a filter defect.
// Check the uid_map before believing an ownership finding here.
//
// It shells out to unshare rather than using internal/contain, deliberately.
// contain exists to run untrusted code as the invoking user and offers no
// run-as-namespace-root mode; adding one for a test would put a footgun in the
// production sandbox for no gain.
func TestFilteredPackageVerifiesCleanOnceInstalled(t *testing.T) {
	if testing.Short() {
		t.Skip("installs into a throwaway root")
	}
	requireArchTools(t)
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare not available")
	}
	subuid, subgid := subordinateStarts(t)

	original := buildFixture(t)
	strip := []string{".INSTALL", "usr/share/libalpm/hooks/zz-evil.hook", "usr/lib/systemd/system/evil.service"}
	work := t.TempDir()
	filtered := filepath.Join(work, "filtered.pkg.tar.zst")
	if _, err := FilterArchive(original, filtered, strip); err != nil {
		t.Fatalf("filter: %v", err)
	}

	uid, gid := os.Getuid(), os.Getgid()
	script := `set -e
mkdir -p ` + work + `/root/var/lib/pacman ` + work + `/cache
printf '[options]\nArchitecture = auto\nSigLevel = Never\n' > ` + work + `/pacman.conf
pacman --root ` + work + `/root --dbpath ` + work + `/root/var/lib/pacman \
       --cachedir ` + work + `/cache --config ` + work + `/pacman.conf \
       --noconfirm -U ` + filtered + ` >/dev/null
pacman --root ` + work + `/root --dbpath ` + work + `/root/var/lib/pacman \
       --config ` + work + `/pacman.conf -Qkk prolewatch-gate-fixture
status=$?
# Remove the installed tree from inside the namespace. Its files belong to
# subordinate uids the caller cannot unlink, so Go's TempDir cleanup would
# otherwise fail with EPERM long after the assertions passed.
rm -rf ` + work + `/root ` + work + `/cache
exit $status`
	command := exec.Command("unshare", usernsArgs(subuid, subgid, uid, gid, "bash", "-c", script)...)
	// Probe the namespace separately so an unavailable subordinate-ID mapping
	// skips, while pacman rejecting the rewritten package remains a test failure.
	probe := exec.Command("unshare", usernsArgs(subuid, subgid, uid, gid, "true")...)
	if out, err := probe.CombinedOutput(); err != nil {
		t.Skipf("subordinate id mapping unavailable here: %v\n%s", err, out)
	}

	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("pacman rejected the rewritten package: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "altered files") && !strings.Contains(string(out), "0 altered files") {
		t.Fatalf("pacman -Qkk found altered files after the rewrite:\n%s", out)
	}
	if strings.Contains(string(out), "UID mismatch") || strings.Contains(string(out), "GID mismatch") {
		t.Fatalf("ownership did not survive the stream filter:\n%s", out)
	}
	if strings.Contains(string(out), "Backup file") || strings.Contains(string(out), "warning:") {
		t.Logf("pacman -Qkk output:\n%s", out)
	}
}

// usernsArgs maps the whole subordinate range plus the caller's own id. See
// the footgun note above: a partial map presents as an ownership defect.
func usernsArgs(subuid, subgid, uid, gid int, argv ...string) []string {
	args := []string{"--user",
		"--map-user", fmt.Sprint(uid), "--map-users", fmt.Sprintf("%d,0,65536", subuid),
		"--map-group", fmt.Sprint(gid), "--map-groups", fmt.Sprintf("%d,0,65536", subgid),
		"--setuid", "0", "--setgid", "0", "--"}
	return append(args, argv...)
}

func subordinateStarts(t *testing.T) (int, int) {
	t.Helper()
	self, err := user.Current()
	if err != nil {
		t.Skip("cannot resolve current user")
	}
	lookup := func(path string) int {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Skipf("cannot read %s", path)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Split(strings.TrimSpace(line), ":")
			if len(fields) == 3 && (fields[0] == self.Username || fields[0] == self.Uid) {
				start, err := strconv.Atoi(fields[1])
				if err == nil {
					return start
				}
			}
		}
		t.Skipf("no subordinate ID delegation for this account in %s", path)
		return 0
	}
	return lookup("/etc/subuid"), lookup("/etc/subgid")
}

// TestALinkOccupyingASurfaceNameIsAsked covers what a path cannot say.
//
// A symlink at a unit name can alias, replace or mask an existing unit, and the
// enumerator had the tar header - including the link target - but classified
// from the pathname alone. A link that would otherwise have been listed is
// therefore asked about, and the target is shown, because where it points is
// the entire content of the file.
func TestALinkOccupyingASurfaceNameIsAsked(t *testing.T) {
	archive := zstdPackage(t, map[string]string{
		"usr/lib/systemd/system/ordinary.service": "[Service]\nExecStart=/usr/bin/true\n",
	}, map[string]string{
		"usr/lib/systemd/system/sshd.service": "/dev/null",
	})
	surfaces, err := EnumerateSurfaces(archive)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]PrivilegedSurface{}
	for _, surface := range surfaces {
		found[surface.Member] = surface
	}
	ordinary, ok := found["usr/lib/systemd/system/ordinary.service"]
	if !ok || ordinary.Activation != ActivationEnabled {
		t.Fatalf("an ordinary unit stopped being inventory: %#v", ordinary)
	}
	masking, ok := found["usr/lib/systemd/system/sshd.service"]
	if !ok {
		t.Fatal("a link occupying a unit name was not enumerated")
	}
	if !masking.Activation.RequiresDecision() {
		t.Errorf("a link occupying a unit name was only listed: %#v", masking)
	}
	if masking.LinkTarget != "/dev/null" {
		t.Errorf("the link target was not carried to the decision: %q", masking.LinkTarget)
	}
}

// A Polkit action does not execute code itself, but its defaults can grant a
// caller authorization and imply can extend that grant to another action. The
// gate must therefore ask about the regular policy file rather than list it as
// passive inventory.
func TestPolkitActionWithImplicitAuthorizationRequiresDecision(t *testing.T) {
	const policy = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
  "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <action id="org.example.manage">
    <defaults><allow_any>yes</allow_any><allow_active>yes</allow_active></defaults>
    <annotate key="org.freedesktop.policykit.imply">org.example.admin</annotate>
  </action>
</policyconfig>
`
	archive := zstdPackage(t, map[string]string{
		"usr/share/polkit-1/actions/org.example.manage.policy": policy,
	}, nil)
	surfaces, err := EnumerateSurfaces(archive)
	if err != nil {
		t.Fatal(err)
	}
	if len(surfaces) != 1 {
		t.Fatalf("enumerated %d surfaces, want one: %#v", len(surfaces), surfaces)
	}
	surface := surfaces[0]
	if surface.Kind != SurfacePolkit || !surface.Activation.RequiresDecision() {
		t.Fatalf("Polkit action did not require a decision: %#v", surface)
	}
	for _, want := range []string{"<allow_active>yes</allow_active>", "org.freedesktop.policykit.imply"} {
		if !strings.Contains(surface.Body, want) {
			t.Errorf("policy body omitted %q: %q", want, surface.Body)
		}
	}
}

// zstdPackage writes a minimal .pkg.tar.zst with the given regular files and
// symlinks. Built in-process because the property under test is how the
// enumerator reads a tar header, not whether makepkg can produce one.
func zstdPackage(t *testing.T, files map[string]string, links map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.pkg.tar.zst")
	handle, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	compressor, err := zstd.NewWriter(handle)
	if err != nil {
		t.Fatal(err)
	}
	archive := tar.NewWriter(compressor)
	for name, body := range files {
		if err := archive.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range links {
		if err := archive.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: target, Mode: 0o777}); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressor.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
