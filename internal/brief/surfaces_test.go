package brief

import (
	"os/exec"
	"strings"
	"testing"
)

// The gate and artifact scanner must always agree because both enforce the same
// root-execution boundary. This check keeps every consumer on one registry.
func TestScannerAndGateReadTheSameRegistry(t *testing.T) {
	for _, surface := range PrivilegedSurfaces {
		member := surface.Member
		if member == "" {
			member = surface.Prefix + "example.conf"
		}
		_, classified := ClassifySurface(member)
		if !classified {
			t.Errorf("%q is in the registry but ClassifySurface does not recognise it", member)
		}
		if classified != privilegedPackagePath(member) {
			t.Errorf("%q: gate says %t, artifact scanner says %t", member, classified, privilegedPackagePath(member))
		}
	}
	for _, ordinary := range []string{
		"usr/bin/tool", "usr/share/doc/pkg/README", "usr/lib/libfoo.so",
		".PKGINFO", ".BUILDINFO", ".MTREE", "usr/share/applications/foo.desktop",
	} {
		if ClassifySurface(ordinary); IsPrivilegedSurface(ordinary) != privilegedPackagePath(ordinary) {
			t.Errorf("%q: the two consumers disagree about an ordinary file", ordinary)
		}
	}
}

// The registry is asserted against the platform, not against itself.
//
// A fixture generated from the registry can only test internal consistency.
// pacman is the authority on where it executes hooks, so this test asks it for
// an independent platform boundary.
func TestEveryHookDirectoryPacmanReportsIsRegistered(t *testing.T) {
	binary, err := exec.LookPath("pacman-conf")
	if err != nil {
		t.Skip("pacman-conf not available")
	}
	out, err := exec.Command(binary, "HookDir").Output()
	if err != nil {
		t.Skipf("pacman-conf HookDir failed: %v", err)
	}
	directories := strings.Fields(strings.TrimSpace(string(out)))
	if len(directories) == 0 {
		t.Skip("pacman reported no hook directories")
	}
	for _, directory := range directories {
		member := strings.TrimPrefix(strings.TrimSuffix(directory, "/"), "/") + "/probe.hook"
		class, ok := ClassifySurface(member)
		if !ok {
			t.Fatalf("pacman executes hooks from %s and the registry does not cover it: %q would install unenumerated", directory, member)
		}
		if class.Kind != SurfaceHook {
			t.Fatalf("%s classified as %q, want %q", directory, class.Kind, SurfaceHook)
		}
	}
	// The compiled-in system directory is not reported by HookDir on every
	// configuration, and it is always active, so it is checked unconditionally.
	if _, ok := ClassifySurface("usr/share/libalpm/hooks/probe.hook"); !ok {
		t.Fatal("the compiled-in libalpm hook directory is not registered")
	}
}

// The unit load path is asserted against systemd, not against the registry.
//
// A fixture generated from the registry can only prove internal consistency.
// systemd is the authority on where it loads units from, and it will answer -
// so the registry is checked against that answer rather than against the belief
// that /usr/lib and /etc are the whole story. `usr/local/lib/systemd/system`
// was the concrete miss: a real load path that no fixture derived from the
// registry could ever have revealed.
func TestEverySystemdUnitPathIsRegistered(t *testing.T) {
	binary, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("systemd-analyze not available")
	}
	out, err := exec.Command(binary, "unit-paths").Output()
	if err != nil {
		t.Skipf("systemd-analyze unit-paths failed: %v", err)
	}
	paths := strings.Fields(strings.TrimSpace(string(out)))
	if len(paths) == 0 {
		t.Skip("systemd reported no unit paths")
	}
	for _, directory := range paths {
		member := strings.TrimPrefix(strings.TrimSuffix(directory, "/"), "/") + "/probe.service"
		class, ok := ClassifySurface(member)
		if !ok {
			t.Errorf("systemd loads units from %s and the registry does not cover it: %q would install unenumerated", directory, member)
			continue
		}
		if class.Kind != SurfaceUnit {
			t.Errorf("%s classified as %q, want %q", directory, class.Kind, SurfaceUnit)
		}
	}
}

// Generator and polkit-rule search paths have no command that reports them, so
// they are transcribed here from systemd.generator(7),
// systemd.environment-generator(7) and polkit(8) - a source outside the
// registry, which is the point. Both were registered in exactly one of their
// four locations, and both execute or authorise as root from all four.
func TestDocumentedRootExecutionSearchPathsAreRegistered(t *testing.T) {
	for member, want := range map[string]SurfaceKind{
		// systemd.generator(7): run/ and etc/ variants outrank the usr ones,
		// and a generator runs as root before any unit is even loaded.
		"run/systemd/system-generators/evil":                       SurfaceGenerator,
		"etc/systemd/system-generators/evil":                       SurfaceGenerator,
		"usr/local/lib/systemd/system-generators/evil":             SurfaceGenerator,
		"usr/lib/systemd/system-generators/evil":                   SurfaceGenerator,
		"run/systemd/system-environment-generators/evil":           SurfaceGenerator,
		"etc/systemd/system-environment-generators/evil":           SurfaceGenerator,
		"usr/local/lib/systemd/system-environment-generators/evil": SurfaceGenerator,
		// systemd-analyze unit-paths.
		"usr/local/lib/systemd/system/evil.service": SurfaceUnit,
		// polkit(8): a rule in any of these can grant an authorisation, and the
		// earlier directories win.
		"etc/polkit-1/rules.d/00-evil.rules":             SurfacePolkit,
		"run/polkit-1/rules.d/00-evil.rules":             SurfacePolkit,
		"usr/local/share/polkit-1/rules.d/00-evil.rules": SurfacePolkit,
		"usr/share/polkit-1/rules.d/00-evil.rules":       SurfacePolkit,
		"etc/polkit-1/actions/evil.policy":               SurfacePolkit,
		// The systemd configuration search path, which is four directories for
		// every one of these classes.
		"run/tmpfiles.d/evil.conf":           SurfaceTmpfiles,
		"usr/local/lib/sysusers.d/evil.conf": SurfaceSysusers,
		"run/udev/rules.d/99-evil.rules":     SurfaceUdev,
		"usr/local/lib/modprobe.d/evil.conf": SurfaceKernel,
		"run/binfmt.d/evil.conf":             SurfaceKernel,
		// dbus-daemon(1) system-service search path.
		"usr/local/share/dbus-1/system-services/evil.service": SurfaceDBus,
		"etc/dbus-1/system-services/evil.service":             SurfaceDBus,
	} {
		class, ok := ClassifySurface(member)
		if !ok {
			t.Errorf("%q is a documented root-execution path and the registry does not cover it", member)
			continue
		}
		if class.Kind != want {
			t.Errorf("%q classified as %q, want %q", member, class.Kind, want)
		}
	}
}

// Both locations of every systemd-style drop-in directory must be registered.
// Packages install into /usr/lib; administrators and packages alike can install
// into /etc, and /etc usually wins. Registering only one half would omit an
// equivalent root-execution path.
func TestBothUsrAndEtcVariantsAreRegistered(t *testing.T) {
	prefixes := map[string]bool{}
	for _, prefix := range SurfacePrefixes() {
		prefixes[prefix] = true
	}
	for _, pair := range [][2]string{
		{"usr/lib/tmpfiles.d/", "etc/tmpfiles.d/"},
		{"usr/lib/sysusers.d/", "etc/sysusers.d/"},
		{"usr/lib/udev/rules.d/", "etc/udev/rules.d/"},
		{"usr/lib/systemd/system/", "etc/systemd/system/"},
		{"usr/lib/systemd/user/", "etc/systemd/user/"},
		{"usr/lib/sysctl.d/", "etc/sysctl.d/"},
		{"usr/lib/modules-load.d/", "etc/modules-load.d/"},
		{"usr/lib/modprobe.d/", "etc/modprobe.d/"},
		{"usr/lib/binfmt.d/", "etc/binfmt.d/"},
		{"usr/share/libalpm/hooks/", "etc/pacman.d/hooks/"},
	} {
		for _, prefix := range pair {
			if !prefixes[prefix] {
				t.Errorf("%s is not registered, but its counterpart %s is", prefix, other(pair, prefix))
			}
		}
	}
}

func other(pair [2]string, one string) string {
	if pair[0] == one {
		return pair[1]
	}
	return pair[0]
}

// One member, one answer.
//
// The archive's safety check and the surface classifier both normalise member
// names, and they disagreed: the check cleaned the path, the classifier stripped
// one "./" first. ".//usr/lib/systemd/system-generators/evil" therefore read as
// an ordinary relative path to the check that lets it through, and as an
// absolute path matching no prefix to the classifier - so a program landing in
// systemd's generator directory produced no finding and never reached the gate,
// while systemd ran it as root on the next boot.
func TestMemberSpellingsThatExtractToTheSamePathClassifyTheSame(t *testing.T) {
	const target = "usr/lib/systemd/system-generators/evil"
	for _, spelling := range []string{
		target,
		"./" + target,
		".//" + target,
		"././" + target,
		"usr//lib/systemd//system-generators/evil",
		"./usr/lib/systemd/../systemd/system-generators/evil",
		// bsdtar strips leading slashes on extraction, so this lands in the
		// same place and must be treated the same way.
		"/" + target,
	} {
		if got := NormalizeMember(spelling); got != target {
			t.Errorf("%q normalised to %q, want %q", spelling, got, target)
		}
		class, ok := ClassifySurface(spelling)
		if !ok || class.Kind != SurfaceGenerator {
			t.Errorf("%q classified as (%q, %t); it extracts to a systemd generator", spelling, class.Kind, ok)
		}
		if !privilegedPackagePath(spelling) {
			t.Errorf("%q: the artifact scanner does not see the generator either", spelling)
		}
	}
	// The scriptlet is a bare name and must survive normalisation intact - a
	// character-class trim would leave "INSTALL" and match nothing.
	for _, spelling := range []string{".INSTALL", "./.INSTALL", ".//.INSTALL"} {
		if class, ok := ClassifySurface(spelling); !ok || class.Kind != SurfaceScriptlet {
			t.Errorf("%q is the install scriptlet, classified as (%q, %t)", spelling, class.Kind, ok)
		}
	}
	// Nothing that escapes the archive root names an installed path.
	for _, escaping := range []string{"..", "../evil", "./../evil", "/", ".", "./"} {
		if got := NormalizeMember(escaping); got != "" {
			t.Errorf("%q normalised to %q instead of nothing", escaping, got)
		}
	}
}

// A directory entry is not itself a surface: reporting it would make the gate
// offer to strip a directory, and pruning already handles empty ones.
func TestSurfaceDirectoriesThemselvesAreNotSurfaces(t *testing.T) {
	for _, prefix := range SurfacePrefixes() {
		directory := strings.TrimSuffix(prefix, "/")
		if _, ok := ClassifySurface(directory); ok {
			t.Errorf("the directory %q was classified as a surface", directory)
		}
		if _, ok := ClassifySurface(prefix); ok {
			t.Errorf("the directory %q was classified as a surface", prefix)
		}
	}
}

// Classification happens on a canonical path. Without this, a member spelled
// with . or .. segments reaches an install unenumerated while resolving to a
// registered location.
func TestClassificationIsCanonical(t *testing.T) {
	for _, alias := range []string{
		"./etc/pacman.d/hooks/x.hook",
		"etc/pacman.d/./hooks/x.hook",
		"etc/pacman.d/hooks/../hooks/x.hook",
		"etc/foo/../pacman.d/hooks/x.hook",
		"./usr/lib/systemd/system/./x.service",
	} {
		if _, ok := ClassifySurface(alias); !ok {
			t.Errorf("%q resolves to a registered surface but was not classified", alias)
		}
	}
	for _, outside := range []string{"etc/pacman.d/hooksfoo/x", "etc/pacman.d/hooks", "usr/lib/systemd/systemfoo/x"} {
		if _, ok := ClassifySurface(outside); ok {
			t.Errorf("%q is not inside a registered directory but was classified", outside)
		}
	}
}

// TestEverySurfaceDeclaresAKnownActivation keeps the gate's two buckets
// deliberate. An entry with no activation still asks the user - RequiresDecision
// fails closed - but "asks by accident" is not the same as "asks on purpose",
// and the wording shown beside it comes from the same entry.
func TestEverySurfaceDeclaresAKnownActivation(t *testing.T) {
	known := map[SurfaceActivation]bool{
		ActivationAutomatic: true, ActivationEnabled: true,
		ActivationSession: true, ActivationPassive: true,
	}
	for _, surface := range PrivilegedSurfaces {
		name := surface.Member + surface.Prefix
		if !known[surface.Activation] {
			t.Errorf("%q declares activation %q, which is not one of the four", name, surface.Activation)
		}
		if surface.When == "" {
			t.Errorf("%q says nothing about when it runs", name)
		}
	}
}

// TestAutomaticRootExecutionIsAlwaysADecision names the classes that must never
// become inventory. The value of the gate is concentrated here: these run
// package-authored code as root, or hand out privilege, with nobody doing
// anything further. A refactor that moved one of them into the listed bucket
// would remove the product's central control while every test still passed.
func TestAutomaticRootExecutionIsAlwaysADecision(t *testing.T) {
	for _, member := range []string{
		".INSTALL",
		"usr/share/libalpm/hooks/zz-foo.hook",
		"etc/pacman.d/hooks/zz-foo.hook",
		"usr/lib/systemd/system-generators/foo",
		"etc/systemd/system-generators/foo",
		"usr/lib/systemd/system-environment-generators/foo",
		"usr/lib/sysusers.d/foo.conf",
		"usr/lib/tmpfiles.d/foo.conf",
		"usr/lib/udev/rules.d/99-foo.rules",
		"usr/lib/sysctl.d/99-foo.conf",
		"usr/lib/modules-load.d/foo.conf",
		"usr/lib/modprobe.d/foo.conf",
		"usr/lib/binfmt.d/foo.conf",
		"etc/sudoers.d/foo",
		"etc/cron.d/foo",
		"etc/cron.daily/foo",
		"etc/pam.d/foo",
		"etc/profile.d/foo.sh",
		"usr/share/polkit-1/rules.d/10-foo.rules",
	} {
		class, ok := ClassifySurface(member)
		if !ok {
			t.Errorf("%q is not classified at all", member)
			continue
		}
		if !class.Activation.RequiresDecision() {
			t.Errorf("%q runs as root or grants privilege on its own, but is only listed (activation %q)", member, class.Activation)
		}
	}
}

// TestListedSurfacesAreNotAutomatic is the other half. Asking about an ordinary
// systemd unit on every service package is what teaches a person to press Enter
// without reading, which costs them the scriptlet decision above.
func TestListedSurfacesAreNotAutomatic(t *testing.T) {
	for member, want := range map[string]SurfaceActivation{
		"usr/lib/systemd/system/foo.service":           ActivationEnabled,
		"etc/systemd/system/foo.service":               ActivationEnabled,
		"usr/lib/systemd/user/foo.service":             ActivationSession,
		"usr/lib/systemd/user-generators/foo":          ActivationSession,
		"usr/share/dbus-1/system-services/foo.service": ActivationEnabled,
		"usr/share/dbus-1/system.d/foo.conf":           ActivationPassive,
		"usr/share/polkit-1/actions/org.foo.policy":    ActivationPassive,
		"usr/lib/security/pam_foo.so":                  ActivationPassive,
	} {
		class, ok := ClassifySurface(member)
		if !ok {
			t.Errorf("%q is no longer enumerated at all", member)
			continue
		}
		if class.Activation != want {
			t.Errorf("%q has activation %q, want %q", member, class.Activation, want)
		}
	}
}

// TestServiceRunExecutableDirectoriesAreRegistered names execution mechanisms
// that no platform-discovery test can find for us.
//
// `pacman-conf HookDir` and `systemd-analyze unit-paths` answer questions about
// the classes they belong to. Nothing answers "what else on this system runs
// package-installed executables as root", so these paths were absent until a
// review named them: the loader preload file, systemd's sleep and shutdown
// hooks, and NetworkManager's dispatcher directories. A literal list is the
// only assertion available, and it fails if an entry is ever dropped.
//
// Authority for each is the installed manual where one exists:
// systemd-sleep(8), systemd-shutdown(8), NetworkManager-dispatcher(8) - which
// documents "/{etc,usr/lib}/NetworkManager/dispatcher.d ... or subdirectories",
// hence the subdirectory case below. /etc/ld.so.preload is glibc's, and its
// manual is not installed on every Arch system.
func TestServiceRunExecutableDirectoriesAreRegistered(t *testing.T) {
	for _, member := range []string{
		"etc/ld.so.preload",
		"usr/lib/systemd/system-sleep/evil",
		"etc/systemd/system-sleep/evil",
		"usr/lib/systemd/system-shutdown/evil",
		"etc/systemd/system-shutdown/evil",
		"etc/NetworkManager/dispatcher.d/evil",
		"usr/lib/NetworkManager/dispatcher.d/evil",
		"etc/NetworkManager/dispatcher.d/pre-up.d/evil",
	} {
		class, ok := ClassifySurface(member)
		if !ok {
			t.Errorf("%q runs package-installed code as root and is not enumerated", member)
			continue
		}
		if !class.Activation.RequiresDecision() {
			t.Errorf("%q runs as root with no enabling step, but is only listed (activation %q)", member, class.Activation)
		}
	}
}

// TestSystemdActivationArtifactsRequireADecision is the regression for a gate
// that printed "nothing here runs on its own" over package-shipped activation.
//
// Everything under a system unit directory was classified from the directory
// prefix, so an enablement link, a dependency link and a drop-in on a running
// host service were all "runs as root once enabled or triggered" and none of
// them was asked about. A .wants link *is* the enabling step, performed by the
// package; a drop-in changes a unit the host may already run.
func TestSystemdActivationArtifactsRequireADecision(t *testing.T) {
	for _, member := range []string{
		"etc/systemd/system/multi-user.target.wants/evil.service",
		"usr/lib/systemd/system/sockets.target.wants/evil.socket",
		"etc/systemd/system/foo.service.requires/evil.service",
		"etc/systemd/system/sshd.service.d/override.conf",
		"usr/lib/systemd/system/foo.service.d/10-evil.conf",
		"usr/local/lib/systemd/system/unknown-structure/evil.conf",
	} {
		class, ok := ClassifySurface(member)
		if !ok {
			t.Errorf("%q is not enumerated at all", member)
			continue
		}
		if !class.Activation.RequiresDecision() {
			t.Errorf("%q installs activation and is only listed (activation %q)", member, class.Activation)
		}
		if class.When == "" {
			t.Errorf("%q does not say why it needs a decision", member)
		}
	}
}

// The low-noise behaviour the gate was designed for still holds: a standalone
// unit nobody has enabled runs nothing, and is inventory rather than a question.
func TestOrdinarySystemUnitsStayInventory(t *testing.T) {
	for _, member := range []string{
		"usr/lib/systemd/system/foo.service",
		"etc/systemd/system/foo.socket",
		"run/systemd/system/foo.timer",
	} {
		class, ok := ClassifySurface(member)
		if !ok {
			t.Errorf("%q is no longer enumerated", member)
			continue
		}
		if class.Activation != ActivationEnabled {
			t.Errorf("%q became activation %q; an ordinary unit should stay inventory", member, class.Activation)
		}
	}
}
