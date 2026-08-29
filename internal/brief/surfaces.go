package brief

import (
	"path"
	"sort"
	"strings"
)

// SurfaceKind names a channel through which a package gets code executed as
// root, either during the installing transaction or on some later one.
type SurfaceKind string

const (
	// SurfaceScriptlet is .INSTALL: pre/post install, upgrade and remove
	// functions, run as root by pacman during this transaction.
	SurfaceScriptlet SurfaceKind = "scriptlet"
	// SurfaceHook is a libalpm hook. It runs as root on EVERY subsequent
	// pacman transaction, and no pacman flag or configuration can suppress it:
	// pacman.conf(5) defines HookDir as adding directories in addition to the
	// compiled-in system hook directory. --hookdir adds; it never replaces.
	SurfaceHook SurfaceKind = "hook"
	// SurfaceUnit is a systemd unit: deferred privileged execution, activated
	// later by trusted machinery.
	SurfaceUnit SurfaceKind = "systemd-unit"
	// SurfaceGenerator is a systemd generator. Generators run early, as root,
	// in the system manager's context, on every boot and daemon-reload - with
	// no enablement step a user would notice.
	SurfaceGenerator SurfaceKind = "systemd-generator"
	// SurfaceSysusers creates accounts and groups at install time.
	SurfaceSysusers SurfaceKind = "sysusers"
	// SurfaceTmpfiles creates and chowns paths as root.
	SurfaceTmpfiles SurfaceKind = "tmpfiles"
	// SurfaceUdev runs rules as root on device events.
	SurfaceUdev SurfaceKind = "udev-rule"
	// SurfacePAM, SurfacePolkit and SurfaceDBus load into or are consulted by
	// root processes.
	SurfacePAM    SurfaceKind = "pam-module"
	SurfacePolkit SurfaceKind = "polkit-rule"
	SurfaceDBus   SurfaceKind = "dbus-system-service"
	// SurfaceSudoers grants privilege directly.
	SurfaceSudoers SurfaceKind = "sudoers"
	// SurfaceCron runs commands as root on a schedule.
	SurfaceCron SurfaceKind = "cron"
	// SurfaceKernel is loaded into or consulted by the kernel and early boot.
	SurfaceKernel SurfaceKind = "kernel-config"
	// SurfaceLoader is read by the dynamic loader before a program's own code
	// runs. /etc/ld.so.preload names libraries loaded into every dynamically
	// linked process on the system, root ones included.
	SurfaceLoader SurfaceKind = "loader-preload"
	// SurfaceServiceHook is an executable directory a root-owned service runs
	// on an event of its own: sleep and shutdown transitions, network changes.
	// The service is trusted; the executables it runs come from the package.
	SurfaceServiceHook SurfaceKind = "service-hook"
)

// SurfaceActivation says what has to happen before an installed surface does
// anything, which is the distinction that decides whether the user is asked.
//
// Enumerating every root-relevant path is right; making every one of them a
// mandatory question is not. A package shipping an ordinary systemd service is
// the common case, and a question the answer to which is always "keep" trains
// people to press Enter - including on the .INSTALL scriptlet that is about to
// run as root during this very transaction. The registry therefore records the
// difference rather than flattening it.
type SurfaceActivation string

const (
	// ActivationAutomatic runs package-authored code as root, or grants
	// privilege, with no further step by anyone. This is the class worth
	// interrupting an install for.
	ActivationAutomatic SurfaceActivation = "automatic"
	// ActivationEnabled runs as root only once something enables or triggers
	// it: a systemd unit nobody starts is inert.
	ActivationEnabled SurfaceActivation = "enabled"
	// ActivationSession runs in the user's own session, not as root.
	ActivationSession SurfaceActivation = "session"
	// ActivationPassive is declaration rather than execution: it changes policy
	// or is inert until something else references it.
	ActivationPassive SurfaceActivation = "passive"
)

// RequiresDecision reports whether this surface must be answered for rather
// than merely listed.
//
// It is written as "not one of the three that may be listed" rather than
// "equal to automatic" so that the failure direction is fixed. A registry entry
// added without an activation, or a value that does not survive the gate's JSON
// boundary, is then a question the user is asked - not a root-execution surface
// that quietly stopped being one because a field was left at its zero value.
func (a SurfaceActivation) RequiresDecision() bool {
	return a != ActivationEnabled && a != ActivationSession && a != ActivationPassive
}

// Surface is one entry in the canonical registry.
type Surface struct {
	// Prefix is the installed path prefix, without a leading "./". A member
	// equal to the prefix without its trailing slash is the directory itself
	// and is not a surface.
	Prefix string
	// Member, when set, matches an exact archive member rather than a prefix.
	Member string
	Kind   SurfaceKind
	// Activation decides whether this surface is a question or a line in an
	// inventory. See SurfaceActivation.
	Activation SurfaceActivation
	// When describes the moment the code runs. The distinction that matters to
	// a user is this-transaction versus every future one.
	When string
}

// Search-path roots, as the services that read them document them.
//
// Registering one variant of a search path and not the others is the failure
// this structure exists to prevent, and it is not a theoretical one:
// `etc/systemd/system-generators/evil` runs as root on every boot and every
// daemon-reload exactly like the `usr/lib` variant, and a registry naming only
// `usr/lib` reports such a package as carrying no privileged integration at
// all. Expanding one suffix across its documented roots removes the chance to
// enumerate three quarters of a search path and believe it was covered.
var (
	// systemdRoots is the unit and generator load path.
	// systemd.generator(7) and systemd.environment-generator(7) list all four;
	// `systemd-analyze unit-paths` reports the usr/local variant on a stock
	// install, and TestEverySystemdUnitPathIsRegistered asks it.
	systemdRoots = []string{"usr/lib/systemd/", "usr/local/lib/systemd/", "etc/systemd/", "run/systemd/"}
	// configRoots is systemd's standard configuration search path, shared by
	// tmpfiles.d(5), sysusers.d(5), sysctl.d(5), modules-load.d(5),
	// modprobe.d(5), binfmt.d(5) and udev(7).
	configRoots = []string{"usr/lib/", "usr/local/lib/", "etc/", "run/"}
	// polkitRoots is polkit(8)'s rules and actions search path. A rule loaded
	// from any of them can grant an authorisation.
	polkitRoots = []string{"usr/share/", "usr/local/share/", "etc/", "run/"}
	// dbusServiceRoots is dbus-daemon(1)'s system-service search path.
	dbusServiceRoots = []string{"usr/share/", "usr/local/share/", "usr/lib/", "etc/", "run/"}
	// networkManagerRoots is NetworkManager-dispatcher(8)'s search path. The
	// manual reads "/{etc,usr/lib}/NetworkManager/dispatcher.d ... or
	// subdirectories", and prefix matching covers the subdirectories.
	networkManagerRoots = []string{"etc/", "usr/lib/"}
)

// PrivilegedSurfaces is the single canonical registry of paths through which an
// installed package gets code executed as root.
//
// It is deliberately one list with one set of consumers: the artifact scanner's
// findings, the privileged-integration gate's enumeration and stripping, the
// report validator, and the probes all read it. A second list could diverge
// silently and let one consumer miss a root-execution surface.
//
// Over-enumeration is nearly free here. The cost of a false positive is a line
// in a briefing the user can keep; the cost of a miss is a package getting root
// execution that the gate reports as absent, which is worse than not having a
// gate at all. That asymmetry is why the runtime and administrator variants are
// registered even though a package would not normally ship into them.
//
// What this list is NOT is a proof that no other mechanism exists. Registering
// every documented root of a class the list already knows about is mechanical;
// discovering a class nobody thought of is not, and the two independent
// platform tests can only ask about the classes they were written for - pacman
// about its hook directories, systemd about its unit load path. Neither
// discovers `/etc/ld.so.preload`, a systemd sleep hook, or a NetworkManager
// dispatcher script, all of which were missing until they were named. Any
// service on the system may define its own executable directory.
//
// So the honest claim is bounded: these classes are enumerated structurally and
// completely, and a mechanism outside them is outside the guarantee. User-facing
// text must say that rather than promise every root-relevant surface.
var PrivilegedSurfaces = privilegedSurfaces()

func privilegedSurfaces() []Surface {
	surfaces := []Surface{
		{Member: ".INSTALL", Kind: SurfaceScriptlet, Activation: ActivationAutomatic, When: "runs as root during this pacman transaction"},

		// Both libalpm hook directories. /usr/share/libalpm/hooks is compiled
		// into libalpm; /etc/pacman.d/hooks is the default administrator
		// HookDir and is active out of the box - `pacman-conf HookDir` reports
		// it on a stock install. A package dropping a file in either location
		// gets root execution on later transactions, so both must be
		// enumerated; TestEveryHookDirectoryPacmanReportsIsRegistered asks
		// pacman rather than this list.
		{Prefix: "usr/share/libalpm/hooks/", Kind: SurfaceHook, Activation: ActivationAutomatic,
			When: "runs as root on EVERY subsequent pacman transaction; no pacman flag can suppress it"},
		{Prefix: "etc/pacman.d/hooks/", Kind: SurfaceHook, Activation: ActivationAutomatic,
			When: "runs as root on EVERY subsequent pacman transaction; no pacman flag can suppress it"},

		// systemd's runtime, transient and generator output directories are
		// unit load paths too - `systemd-analyze unit-paths` lists them - and a
		// unit dropped into one is loaded like any other.
		{Prefix: "etc/systemd/system.control/", Kind: SurfaceUnit, Activation: ActivationEnabled, When: "runs as root once enabled or triggered"},
		{Prefix: "run/systemd/system.control/", Kind: SurfaceUnit, Activation: ActivationEnabled, When: "runs as root once enabled or triggered"},
		{Prefix: "etc/systemd/system.attached/", Kind: SurfaceUnit, Activation: ActivationEnabled, When: "runs as root once enabled or triggered"},
		{Prefix: "run/systemd/system.attached/", Kind: SurfaceUnit, Activation: ActivationEnabled, When: "runs as root once enabled or triggered"},
		{Prefix: "run/systemd/transient/", Kind: SurfaceUnit, Activation: ActivationEnabled, When: "runs as root once enabled or triggered"},
		{Prefix: "run/systemd/generator/", Kind: SurfaceUnit, Activation: ActivationEnabled, When: "runs as root once enabled or triggered"},
		{Prefix: "run/systemd/generator.early/", Kind: SurfaceUnit, Activation: ActivationEnabled, When: "runs as root once enabled or triggered"},
		{Prefix: "run/systemd/generator.late/", Kind: SurfaceUnit, Activation: ActivationEnabled, When: "runs as root once enabled or triggered"},

		{Prefix: "usr/lib/security/", Kind: SurfacePAM, Activation: ActivationPassive,
			When: "a PAM module, loaded only where a PAM configuration references it"},
		{Prefix: "etc/pam.d/", Kind: SurfacePAM, Activation: ActivationAutomatic,
			When: "decides how authentication is performed, from the next login onwards"},

		{Prefix: "etc/sudoers.d/", Kind: SurfaceSudoers, Activation: ActivationAutomatic, When: "grants privilege directly"},

		{Prefix: "etc/cron.d/", Kind: SurfaceCron, Activation: ActivationAutomatic, When: "runs as root on a schedule"},
		{Prefix: "etc/cron.daily/", Kind: SurfaceCron, Activation: ActivationAutomatic, When: "runs as root on a schedule"},
		{Prefix: "etc/cron.hourly/", Kind: SurfaceCron, Activation: ActivationAutomatic, When: "runs as root on a schedule"},
		{Prefix: "etc/cron.weekly/", Kind: SurfaceCron, Activation: ActivationAutomatic, When: "runs as root on a schedule"},
		{Prefix: "etc/cron.monthly/", Kind: SurfaceCron, Activation: ActivationAutomatic, When: "runs as root on a schedule"},

		// dbus-daemon(1) documents /usr/share and /etc for bus policy; a policy
		// file there decides who may talk to a root-owned service.
		{Prefix: "usr/share/dbus-1/system.d/", Kind: SurfaceDBus, Activation: ActivationPassive,
			When: "declares who may talk to a service on the system bus; runs nothing itself"},
		{Prefix: "etc/dbus-1/system.d/", Kind: SurfaceDBus, Activation: ActivationPassive,
			When: "declares who may talk to a service on the system bus; runs nothing itself"},

		{Prefix: "etc/profile.d/", Kind: SurfaceKernel, Activation: ActivationAutomatic, When: "runs in every login shell, including root's"},

		// The dynamic loader reads this file before any program's own code runs,
		// so a library named here is loaded into every dynamically linked
		// process on the system - including every root one. It is a single
		// glibc-defined path, not a search path, so it is registered as an
		// exact member like the scriptlet.
		{Member: "etc/ld.so.preload", Kind: SurfaceLoader, Activation: ActivationAutomatic,
			When: "loads package-named libraries into every dynamically linked process, root ones included"},
	}
	add := func(roots []string, suffix string, kind SurfaceKind, activation SurfaceActivation, when string) {
		for _, root := range roots {
			surfaces = append(surfaces, Surface{Prefix: root + suffix, Kind: kind, Activation: activation, When: when})
		}
	}

	add(systemdRoots, "system/", SurfaceUnit, ActivationEnabled, "runs as root once enabled or triggered")
	add(systemdRoots, "user/", SurfaceUnit, ActivationSession, "runs in the user's systemd session, not as root")
	add(systemdRoots, "system-generators/", SurfaceGenerator, ActivationAutomatic,
		"runs as root very early, on every boot and daemon-reload, with no enablement step")
	add(systemdRoots, "user-generators/", SurfaceGenerator, ActivationSession,
		"runs in the user's systemd session on every reload, not as root")
	add(systemdRoots, "system-environment-generators/", SurfaceGenerator, ActivationAutomatic,
		"runs as root and sets the system manager's environment")
	add(systemdRoots, "user-environment-generators/", SurfaceGenerator, ActivationSession,
		"runs in the user's session and sets its environment, not as root")

	add(configRoots, "sysusers.d/", SurfaceSysusers, ActivationAutomatic, "creates accounts and groups as root at install time")
	add(configRoots, "tmpfiles.d/", SurfaceTmpfiles, ActivationAutomatic, "creates and chowns paths as root at install time and on boot")
	add(configRoots, "udev/rules.d/", SurfaceUdev, ActivationAutomatic, "runs as root on matching device events")
	add(configRoots, "sysctl.d/", SurfaceKernel, ActivationAutomatic, "sets kernel parameters as root at boot")
	add(configRoots, "modules-load.d/", SurfaceKernel, ActivationAutomatic, "loads kernel modules as root at boot")
	add(configRoots, "modprobe.d/", SurfaceKernel, ActivationAutomatic, "changes how kernel modules are loaded")
	add(configRoots, "binfmt.d/", SurfaceKernel, ActivationAutomatic, "registers an interpreter the kernel invokes for matching binaries")

	// A polkit rule is JavaScript polkitd evaluates when deciding an
	// authorisation, loaded as soon as it is on disk; an action file only
	// declares what may be asked for and its defaults. Grouping them cost the
	// second one nothing and the first one everything, so they are separated.
	add(polkitRoots, "polkit-1/rules.d/", SurfacePolkit, ActivationAutomatic, "decides privileged authorisation requests, immediately")
	add(polkitRoots, "polkit-1/actions/", SurfacePolkit, ActivationPassive, "declares privileged actions and their defaults; runs nothing itself")

	add(dbusServiceRoots, "dbus-1/system-services/", SurfaceDBus, ActivationEnabled, "can be activated as a system service on request")

	// Executable directories a root-owned service runs on its own events. These
	// are not units and have no enablement step: dropping a file in one is
	// enough. systemd-sleep(8) and systemd-shutdown(8) document the usr/lib
	// variant; the other roots follow this file's over-enumeration policy.
	add(systemdRoots, "system-sleep/", SurfaceServiceHook, ActivationAutomatic,
		"runs as root before and after every suspend or hibernate")
	add(systemdRoots, "system-shutdown/", SurfaceServiceHook, ActivationAutomatic,
		"runs as root during every power-off, reboot, halt or kexec")
	add(networkManagerRoots, "NetworkManager/dispatcher.d/", SurfaceServiceHook, ActivationAutomatic,
		"runs as root on network events, if NetworkManager is installed")

	return surfaces
}

// NormalizeMember reduces an archive member name to the path it will occupy
// once extracted: leading "./" and "/" removed, repeated slashes and . and ..
// segments resolved, trailing slash dropped.
//
// path.Clean runs first, and that ordering is the whole point. Stripping one
// "./" beforehand turned ".//usr/lib/systemd/system-generators/evil" into
// "/usr/lib/..." - an absolute-looking string that matched no registry prefix,
// so the scanner raised no finding and the gate never offered to strip it -
// while the archive's own safety check, which cleans first, saw the perfectly
// ordinary relative path that bsdtar then extracts. One member, two answers,
// and the root-execution one was the wrong one.
//
// Leading slashes are removed after cleaning rather than rejected, because that
// is what extraction does: bsdtar drops them, so an absolute member lands where
// its relative twin would and has to classify the same way.
//
// path.Clean and TrimPrefix, never a character-class trim: Python's
// lstrip("./") treats the argument as a set of characters, so ".INSTALL"
// becomes "INSTALL" and no longer matches the archive's scriptlet entry.
func NormalizeMember(name string) string {
	if name == "" {
		return ""
	}
	cleaned := strings.TrimPrefix(path.Clean(name), "/")
	// Nothing that escapes the archive root names a real installed path. The
	// archive checks reject these members outright; returning nothing here keeps
	// any other consumer from matching one against a registry prefix.
	if cleaned == "" || cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return ""
	}
	return cleaned
}

// ClassifySurface reports whether an archive member is a privileged-integration
// surface, and returns the registry entry that matched.
//
// Returning the entry rather than a few of its fields keeps kind, activation
// and wording arriving together from one place. A caller that had to look the
// activation up separately would be a second lookup able to disagree with the
// first, which is the failure this registry exists to prevent.
func ClassifySurface(member string) (Surface, bool) {
	name := NormalizeMember(member)
	if name == "" {
		return Surface{}, false
	}
	// systemd encodes activation in path structure below a unit directory, so
	// the directory prefix alone cannot answer the question the gate asks.
	if surface, ok := systemdUnitActivation(name); ok {
		return surface, true
	}
	for _, surface := range PrivilegedSurfaces {
		if surface.Member != "" {
			if name == surface.Member {
				return surface, true
			}
			continue
		}
		// The directory itself is not a surface; something inside it is.
		if strings.HasPrefix(name, surface.Prefix) && name != strings.TrimSuffix(surface.Prefix, "/") {
			return surface, true
		}
	}
	return Surface{}, false
}

// systemdUnitActivation classifies what lives *inside* a system unit directory.
//
// "Everything under system/ runs only once enabled" is true of a standalone
// unit file and false of the three things a package can put beside it:
//
//   - a link in <target>.wants/ or <unit>.requires/ is the enablement. The
//     package performs it; nobody has to run `systemctl enable`, and the unit
//     participates the next time that target is activated.
//   - a drop-in at <unit>.d/*.conf modifies a unit that may already exist and
//     already be running on the host - sshd.service.d/override.conf does not
//     need any new unit to be enabled.
//   - anything else nested below the directory is structure this function does
//     not recognise, which is not a reason to treat it as inert.
//
// Those were all reported as "enabled" and therefore never asked about, under
// an inventory line reading "Nothing here runs on its own". The false one was
// the sentence, not the enumeration: every file was listed.
//
// A standalone unit stays inventory. That is the low-noise behaviour the gate
// was designed for and it is still right - a unit nobody enables runs nothing.
func systemdUnitActivation(name string) (Surface, bool) {
	for _, root := range systemdRoots {
		prefix := root + "system/"
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		remainder := strings.TrimPrefix(name, prefix)
		directory, _, nested := strings.Cut(remainder, "/")
		if !nested || directory == "" {
			return Surface{}, false // an ordinary unit file; the registry answers
		}
		switch {
		case strings.HasSuffix(directory, ".wants"), strings.HasSuffix(directory, ".requires"):
			return Surface{Prefix: prefix, Kind: SurfaceUnit, Activation: ActivationAutomatic,
				When: "enables a unit at install time: " + directory + " participates when that target activates, with no systemctl enable"}, true
		case strings.HasSuffix(directory, ".d"):
			return Surface{Prefix: prefix, Kind: SurfaceUnit, Activation: ActivationAutomatic,
				When: "modifies " + strings.TrimSuffix(directory, ".d") + ", which may already be enabled and running"}, true
		default:
			return Surface{Prefix: prefix, Kind: SurfaceUnit, Activation: ActivationAutomatic,
				When: "sits below a systemd unit directory in a structure Prolewatch does not recognise"}, true
		}
	}
	return Surface{}, false
}

// IsPrivilegedSurface is the predicate form, for the artifact scanner.
func IsPrivilegedSurface(member string) bool {
	_, ok := ClassifySurface(member)
	return ok
}

// SurfacePrefixes lists every registered prefix, for probes and documentation
// that need to generate one fixture per surface class.
func SurfacePrefixes() []string {
	seen := map[string]bool{}
	var prefixes []string
	for _, surface := range PrivilegedSurfaces {
		if surface.Prefix != "" && !seen[surface.Prefix] {
			seen[surface.Prefix] = true
			prefixes = append(prefixes, surface.Prefix)
		}
	}
	sort.Strings(prefixes)
	return prefixes
}
