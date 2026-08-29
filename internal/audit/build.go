package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/contain"
	"github.com/holgerjh/prolewatch/internal/egress"
	"github.com/holgerjh/prolewatch/internal/safe"
	"github.com/holgerjh/prolewatch/internal/ui"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

var trustedSystemUID uint32

// Bubblewrap receives the build's user namespace on this descriptor.
const sandboxUsernsFD = 3

func snapshotMakepkgConfigs(job string, invocation Invocation) ([][2]string, error) {
	// A build must not read mutable host configuration after policy validation.
	// Resolve only root-owned system config, copy a stable snapshot into the job,
	// and later bind that snapshot over the same paths inside the sandbox.
	var sources []string
	if file, err := openRootOwnedPath("/etc/makepkg.conf", false); err == nil {
		file.Close()
		sources = append(sources, "/etc/makepkg.conf")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	directory, err := openRootOwnedPath("/etc/makepkg.conf.d", true)
	if err == nil {
		entries, readErr := directory.ReadDir(-1)
		directory.Close()
		if readErr != nil {
			return nil, readErr
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, entry := range entries {
			if strings.Contains(entry.Name(), "/") || entry.Name() == "." || entry.Name() == ".." {
				return nil, errors.New("unsafe makepkg drop-in name")
			}
			candidate := filepath.Join("/etc/makepkg.conf.d", entry.Name())
			file, err := openRootOwnedPath(candidate, false)
			if err != nil {
				return nil, fmt.Errorf("unsafe makepkg drop-in %s: %w", candidate, err)
			}
			file.Close()
			sources = append(sources, candidate)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if invocation.ConfigPath != "" {
		found := false
		for _, source := range sources {
			found = found || source == invocation.ConfigPath
		}
		if !found {
			return nil, errors.New("selected makepkg configuration was not captured")
		}
	}
	configRoot := filepath.Join(job, "makepkg-config")
	if err := os.Mkdir(configRoot, 0o700); err != nil {
		return nil, err
	}
	dropinRoot := filepath.Join(configRoot, "makepkg.conf.d")
	if err := os.Mkdir(dropinRoot, 0o700); err != nil {
		return nil, err
	}
	result := make([][2]string, 0, 2)
	for _, source := range sources {
		input, err := openRootOwnedPath(source, false)
		if err != nil {
			return nil, err
		}
		var before, after unix.Stat_t
		if err := unix.Fstat(int(input.Fd()), &before); err != nil {
			input.Close()
			return nil, err
		}
		// One MiB is ample for makepkg configuration; limit+1 distinguishes an
		// exact-limit file from an oversized one without an unbounded allocation.
		raw, err := io.ReadAll(io.LimitReader(input, 1024*1024+1))
		if err == nil {
			err = unix.Fstat(int(input.Fd()), &after)
		}
		input.Close()
		if err != nil || len(raw) > 1024*1024 || !safe.SameStat(before, after) || before.Mode != after.Mode {
			return nil, fmt.Errorf("makepkg configuration changed or exceeded its snapshot limit: %s", source)
		}
		target := filepath.Join(dropinRoot, filepath.Base(source))
		if source == "/etc/makepkg.conf" {
			target = filepath.Join(configRoot, "makepkg.conf")
		}
		if err := os.WriteFile(target, raw, 0o400); err != nil {
			return nil, err
		}
		if source == "/etc/makepkg.conf" {
			result = append(result, [2]string{target, source})
		}
	}
	result = append(result, [2]string{dropinRoot, "/etc/makepkg.conf.d"})
	return result, nil
}

type Invocation struct {
	Profile             string
	Args                []string
	ConfigPath          string
	SourceDest          string
	PersistentCargoHome bool
	PersistentGoCache   bool
	NetworkContext      []string
	// AllowedHosts closes the broker to a known destination set for phases that
	// have one. Only verify does: after trusted-side acquisition the sole
	// destination makepkg can legitimately need is a declared VCS host.
	AllowedHosts []string
	// PackageBase and DeclaredHosts describe the request when the broker has to
	// ask about a destination. Neither is authority: they say which package is
	// asking and whether the address is anywhere in its recipe, which is what a
	// person needs in order to answer at all.
	PackageBase    string
	DeclaredHosts  []string
	PromptSources  []egress.PromptSource
	outputObserver commandOutputObserver
}

// declaredSourceHosts is the set of hosts a package's own recipe names.
//
// Redirect hops are deliberately excluded: this answers "does the recipe say
// it fetches from here", and a hop the acquisition happened to follow does not.
func declaredSourceHosts(report *Report) []string {
	if report == nil {
		return nil
	}
	seen := map[string]bool{}
	var hosts []string
	for _, source := range report.Sources {
		host := sourceHost(source)
		if host == "" || host == "local" || seen[host] {
			continue
		}
		seen[host] = true
		hosts = append(hosts, host)
	}
	return hosts
}

func promptSourcesFromReport(report *Report) []egress.PromptSource {
	if report == nil {
		return nil
	}
	result := make([]egress.PromptSource, 0, len(report.Sources))
	for _, source := range report.Sources {
		// Trusted acquisition has already fetched ordinary URLs. Only VCS sources
		// can legitimately cause makepkg itself to contact a declared source host
		// during verify/prepare.
		if source.Kind != brief.SourceKindVCS {
			continue
		}
		host := sourceHost(source)
		if host == "" || host == "local" {
			continue
		}
		result = append(result, egress.PromptSource{
			Host: host, URL: source.URL, Kind: source.Kind,
			Transport: source.Transport, Binding: source.Binding,
		})
	}
	return result
}

func promptSourcesFromFrozen(sources []egress.DeclaredSource) []egress.PromptSource {
	var result []egress.PromptSource
	for _, source := range sources {
		if source.Kind != egress.SourceVCS {
			continue
		}
		host := sourceHost(brief.SourceProvenance{URL: source.URL})
		if host == "" || host == "local" {
			continue
		}
		display := source.Raw
		if _, renamed, ok := strings.Cut(display, "::"); ok {
			display = renamed
		}
		transport := "vcs"
		if index := strings.Index(display, "://"); index > 0 {
			transport = strings.ToLower(display[:index])
		}
		result = append(result, egress.PromptSource{Host: host, URL: display, Kind: brief.SourceKindVCS, Transport: transport})
	}
	return result
}

// gatePrompter is the user interaction for the privileged-integration gate.
// It is a variable so tests can drive a decision without a terminal.
var gatePrompter = ui.PromptGate

type makepkgBroker interface {
	Done() <-chan struct{}
	Failure() error
	Stop()
}

var (
	makepkgSandboxRunner      = runMakepkgSandbox
	makepkgInfoCommand        = exec.Command
	makepkgConfigSnapshotter  = snapshotMakepkgConfigs
	constrainedCommandRunner  = runConstrainedCommand
	makepkgBrokerTempDir      = newMakepkgBrokerDirectory
	makepkgNetworkBrokerStart = func(directory string, cfg egress.Config, prompt egress.PromptFunc) (makepkgBroker, error) {
		return egress.StartBroker(directory, cfg, prompt)
	}
	// gateEnumerator is a seam so the decision branch below can be tested
	// without a real package and a real namespace.
	gateEnumerator = EnumerateSurfacesContained
)

// Treat yay's makepkg command line as a small typed protocol. A closed per-phase
// allowlist prevents a new or injected makepkg option from weakening integrity,
// changing output paths, or invoking an unsupported lifecycle.
var prohibitedMakepkg = map[string]bool{"--skipchecksums": true, "--skipinteg": true}
var safeGlobal = map[string]bool{"--nocheck": true, "--check": true, "--ignorearch": true, "--noconfirm": true, "--noprogressbar": true}
var profileAllowed = map[string]map[string]bool{
	"printsrcinfo": {"--printsrcinfo": true},
	"verify":       {"--verifysource": true, "--skippgpcheck": true, "-f": true, "-C": true, "-c": true, "-Cc": true},
	"prepare":      {"--nobuild": true, "-f": true, "-C": true},
	"packagelist":  {"--packagelist": true},
	"build":        {"-f": true, "-c": true, "--noextract": true, "--noprepare": true, "--holdver": true},
	"skip":         {"-c": true, "--nobuild": true, "--noextract": true},
}

var errMakepkgCompatibility = errors.New("unsupported makepkg invocation")

// makepkgCompatibilityError identifies a command shape that the closed
// wrapper protocol does not know yet. It is deliberately distinct from a
// forbidden integrity bypass: an unfamiliar yay/makepkg version may need a
// recovery path, while a request to weaken verification must remain a plain
// security stop.
type makepkgCompatibilityError struct{ detail string }

func (e makepkgCompatibilityError) Error() string { return e.detail }
func (e makepkgCompatibilityError) Unwrap() error { return errMakepkgCompatibility }

func compatibilityError(format string, args ...any) error {
	return makepkgCompatibilityError{detail: fmt.Sprintf(format, args...)}
}

func ClassifyInvocation(args []string) (Invocation, error) {
	if len(args) == 0 {
		return Invocation{}, compatibilityError("makepkg invocation has no arguments")
	}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "--version" || args[0] == "-V") {
		return Invocation{Profile: "info", Args: args}, nil
	}
	for _, arg := range args {
		if prohibitedMakepkg[arg] {
			return Invocation{}, errors.New("checksum/integrity bypass flags are forbidden")
		}
	}
	remaining := []string{}
	configPath := ""
	for index := 0; index < len(args); index++ {
		if args[index] == "--config" {
			if index+1 >= len(args) {
				return Invocation{}, compatibilityError("--config requires a path")
			}
			configPath = args[index+1]
			if err := validateMakepkgConfig(configPath); err != nil {
				return Invocation{}, err
			}
			index++
			continue
		}
		remaining = append(remaining, args[index])
	}
	tokens := map[string]bool{}
	for _, arg := range remaining {
		tokens[arg] = true
	}
	if tokens["--skippgpcheck"] && !tokens["--verifysource"] {
		return Invocation{}, errors.New("--skippgpcheck is only permitted for yay source verification")
	}
	// Yay calls makepkg multiple times. The flag combination identifies which
	// lifecycle stage is occurring, which in turn selects the marker phase,
	// dependency set, network eligibility, and post-operation rescan behavior.
	profile := ""
	switch {
	case tokens["--printsrcinfo"]:
		profile = "printsrcinfo"
	case tokens["--verifysource"]:
		profile = "verify"
	case tokens["--packagelist"]:
		profile = "packagelist"
	case tokens["--nobuild"] && tokens["--noextract"]:
		profile = "skip"
	case tokens["--nobuild"]:
		profile = "prepare"
	case tokens["--noextract"] && tokens["--noprepare"] && tokens["--holdver"]:
		profile = "build"
	default:
		return Invocation{}, compatibilityError("unknown makepkg invocation class: %s", strings.Join(args, " "))
	}
	allowed := make(map[string]bool, len(profileAllowed[profile])+len(safeGlobal))
	for key, value := range profileAllowed[profile] {
		allowed[key] = value
	}
	for key := range safeGlobal {
		allowed[key] = true
	}
	var unknown []string
	for _, arg := range remaining {
		if !allowed[arg] {
			unknown = append(unknown, arg)
		}
	}
	if len(unknown) > 0 {
		return Invocation{}, compatibilityError("unsupported makepkg arguments for %s: %v", profile, unknown)
	}
	return Invocation{Profile: profile, Args: args, ConfigPath: configPath}, nil
}

func sourceVerificationAfterInvocation(invocation Invocation, sources []brief.SourceProvenance) (brief.SourceVerification, bool) {
	// A successful makepkg verification/preparation is the point at which static
	// checksum intent becomes an observed receipt. PGP stays pending only for
	// yay's deliberate first pass that asks the isolated key helper to fetch keys.
	if invocation.Profile != "verify" && invocation.Profile != "prepare" {
		return brief.SourceVerification{}, false
	}
	hasSignature := false
	for _, source := range sources {
		if source.Kind == brief.SourceKindSignature {
			hasSignature = true
			break
		}
	}
	pgp := "not-applicable"
	if hasSignature {
		pgp = "verified"
		if invocation.Profile == "verify" {
			for _, arg := range invocation.Args {
				if arg == "--skippgpcheck" {
					pgp = "pending"
					break
				}
			}
		}
	}
	return brief.SourceVerification{Checksums: "passed", PGP: pgp}, true
}

func validateMakepkgConfig(value string) error {
	clean := filepath.Clean(value)
	if !filepath.IsAbs(value) || clean != value || (clean != "/etc/makepkg.conf" && !strings.HasPrefix(clean, "/etc/makepkg.conf.d/")) {
		return errors.New("only system-owned makepkg configuration is supported")
	}
	file, err := openRootOwnedPath(clean, false)
	if err != nil {
		return err
	}
	file.Close()
	return nil
}

func openRootOwnedPath(value string, wantDirectory bool) (*os.File, error) {
	return openRootOwnedPathMode(value, wantDirectory, true)
}

func openRootOwnedPathMode(value string, wantDirectory, readFinalDirectory bool) (*os.File, error) {
	// Start at an opened filesystem root and resolve one component at a time with
	// O_NOFOLLOW. Checking fstatat before open and fstat after open closes the
	// symlink/path-replacement window for system files trusted by the sandbox.
	components := strings.Split(strings.TrimPrefix(filepath.Clean(value), "/"), "/")
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	var rootStat unix.Stat_t
	if err := unix.Fstat(fd, &rootStat); err != nil || rootStat.Mode&unix.S_IFMT != unix.S_IFDIR || rootStat.Uid != trustedSystemUID || rootStat.Mode&0o022 != 0 {
		unix.Close(fd)
		return nil, errors.New("filesystem root has unsafe ownership or permissions")
	}
	return openRootOwnedComponentsMode(fd, value, components, wantDirectory, readFinalDirectory)
}

func openRootOwnedComponentsMode(fd int, value string, components []string, wantDirectory, readFinalDirectory bool) (*os.File, error) {
	for index, component := range components {
		last := index == len(components)-1
		var before unix.Stat_t
		if err := unix.Fstatat(fd, component, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			unix.Close(fd)
			return nil, err
		}
		expected := uint32(unix.S_IFDIR)
		flags := unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if last && !wantDirectory {
			expected = unix.S_IFREG
			flags = unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		} else if last && readFinalDirectory {
			flags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		}
		if before.Mode&unix.S_IFMT != expected || before.Uid != trustedSystemUID || before.Mode&0o022 != 0 {
			unix.Close(fd)
			return nil, fmt.Errorf("unsafe ownership, mode, or type in system path %s", value)
		}
		next, err := unix.Openat(fd, component, flags, 0)
		if err != nil {
			unix.Close(fd)
			return nil, err
		}
		var after unix.Stat_t
		if err := unix.Fstat(next, &after); err != nil || !safe.SameStat(before, after) || before.Mode != after.Mode || before.Uid != after.Uid {
			unix.Close(next)
			unix.Close(fd)
			return nil, fmt.Errorf("system path changed during validation: %s", value)
		}
		unix.Close(fd)
		fd = next
	}
	return os.NewFile(uintptr(fd), value), nil
}

// userManagerAvailable is a seam. Tests substitute makepkgSandboxRunner and
// never start a transient unit, so the precondition has to be overridable the
// same way the runner is.
var userManagerAvailable = contain.UserManagerAvailable

func RunMakepkg(ctx context.Context, args []string) int {
	// The privileged-integration gate re-executes this exact wrapper binary
	// inside its archive-parsing sandbox. Dispatch its two private operations
	// before configuration loading or makepkg classification: neither operation
	// is a build phase or needs policy configuration, and the sandbox deliberately
	// exposes neither /etc/prolewatch nor any user state.
	if status, handled := runContainedGateCommand(args); handled {
		return status
	}
	// The wrapper is a state machine around yay's separate makepkg invocations:
	// verify a content-bound marker, prepare a disposable root, run one contained
	// phase, destroy the root, rescan newly fetched content, then review and bind
	// any package archives. A failure in any link prevents a path reaching yay.
	cfg, err := LoadConfig("")
	if err != nil {
		fmt.Fprintln(os.Stderr, "prolewatch-makepkg:", err)
		return ExitInvalidInvocation
	}
	invocation, err := ClassifyInvocation(args)
	if err != nil {
		renderMakepkgInvocationFailure(newTerminalRenderer(cfg, os.Stderr), os.Stderr, err)
		return ExitInvalidInvocation
	}
	if invocation.Profile == "info" {
		// The only makepkg execution that is not contained, and the only one that
		// may be. ClassifyInvocation admits exactly --help, -h, --version and -V,
		// as a single argument; measured, none of the four sources the PKGBUILD,
		// so no package-authored shell runs here.
		//
		// That is a property of those four flags, not of makepkg, so the profile
		// must not be widened. TestInfoProfileNeverCarriesPackageEvaluation holds
		// the line: anything that could evaluate a recipe belongs in the sandbox
		// with everything else.
		command := makepkgInfoCommand("/usr/bin/makepkg", args...)
		command.Stdin = os.Stdin
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		if err := command.Run(); err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				return exit.ExitCode()
			}
			return ExitExecutionFailure
		}
		return ExitOK
	}
	// Every remaining profile executes package-authored shell inside a transient
	// systemd user unit, so an absent user manager is a precondition rather than
	// something to discover three layers down.
	//
	// Checking it here is also what keeps the cause readable. yay runs each phase
	// as its own wrapper process and only the verify one fetches, so without this
	// the missing manager surfaces once as an acquisition failure and then again,
	// from the next phase, as one "extractable source is absent" finding per
	// declared source - a full package review derived entirely from the first
	// failure, printed after it, burying it.
	if !userManagerAvailable() {
		fmt.Fprintln(os.Stderr, "prolewatch-makepkg:", contain.ErrNoUserManager)
		return ExitExecutionFailure
	}
	renderer := newTerminalRenderer(cfg, os.Stderr)
	// Recorded for every run, not only interactive ones: the transcript is what
	// makes a failure readable in write order, and a non-interactive run is
	// exactly where nobody watched it happen.
	// Each stream has its own OutputBytes allowance, so the transcript gets the
	// sum. A tighter bound would let the display truncate while both streams
	// were still comfortably inside their own limits.
	transcript := newOutputTranscript(2 * effectiveBuildLimits(cfg.Build).OutputBytes)
	progress := newTerminalProgress(renderer, "", invocation.Profile)
	if progress != nil {
		command := "makepkg"
		if len(invocation.Args) > 0 {
			command += " " + strings.Join(invocation.Args, " ")
		}
		progress.SetCommand(command)
		defer progress.Close()
		ctx = withTerminalProgress(ctx, progress)
	}
	// progress.ObserveOutput tolerates a nil receiver, so one chain covers both.
	invocation.outputObserver = func(stream commandOutputStream, value []byte) {
		transcript.Observe(stream, value)
		progress.ObserveOutput(stream, value)
	}
	workdir, err := filepath.Abs(".")
	if err != nil {
		prepareTerminalOutput(ctx)
		fmt.Fprintln(os.Stderr, "prolewatch-makepkg:", err)
		return ExitInvalidInvocation
	}
	workdir, err = filepath.EvalSymlinks(workdir)
	if err != nil {
		prepareTerminalOutput(ctx)
		fmt.Fprintln(os.Stderr, "prolewatch-makepkg:", err)
		return ExitInvalidInvocation
	}
	// yay -B needs locally generated metadata before it can construct the event
	// that invokes the AURPreInstall hook. There cannot be an audit marker yet:
	// the package base carried by that event comes from this very output.
	//
	// This is a bootstrap evaluation, not an authorised build phase. It receives
	// no network, no source store, and no report-derived capability; it still runs
	// inside Bubblewrap and a tighter transient resource scope because makepkg
	// sources arbitrary PKGBUILD shell even for --printsrcinfo. The pre hook scans
	// the checkout after this returns, so any checkout mutation by top-level shell
	// is part of the content the user is subsequently shown and asked to accept.
	if invocation.Profile == "printsrcinfo" {
		return runPrintsrcinfoBootstrap(ctx, invocation, workdir, cfg, renderer, transcript)
	}
	service, err := auditServiceFactory(ctx, cfg, nil)
	if err != nil {
		prepareTerminalOutput(ctx)
		fmt.Fprintln(os.Stderr, "prolewatch-makepkg: audit service initialization failed:", err)
		return ExitExecutionFailure
	}
	progressStage(ctx, StageMarkerVerification)
	// Verification happens before downloaded sources exist and is bound to the
	// pre-download marker. Every later phase is bound to the post-download
	// manifest instead. Metadata generation is the markerless bootstrap above:
	// yay needs its answer before it can emit the hook event that creates a marker.
	markerPhase := "post"
	if invocation.Profile == "verify" {
		markerPhase = "pre"
	}
	report, err := service.VerifyMarker(workdir, markerPhase)
	if err != nil {
		prepareTerminalOutput(ctx)
		fmt.Fprintln(os.Stderr, "prolewatch-makepkg: audit gate failed:", err)
		if strings.Contains(strings.ToLower(err.Error()), "changed") {
			return ExitInspectionFailure
		}
		return ExitExecutionFailure
	}
	if progress != nil {
		progress.SetPackage(report.PackageBase)
	}
	invocation.PersistentCargoHome = brief.UsesPersistentCargoHome(report.Findings, report.Sources)
	invocation.PersistentGoCache = brief.UsesPersistentGoCache(report.Findings, report.Sources)
	invocation.NetworkContext = brief.KnownNetworkSteps(report.Findings, report.Sources, invocation.Profile)
	invocation.PackageBase = report.PackageBase
	invocation.DeclaredHosts = declaredSourceHosts(report)
	// Source provenance explains verify/prepare checkouts. A package() request in
	// the build phase is not source acquisition merely because it happens to use
	// the same shared host, and must not be presented as a source checkout.
	if invocation.Profile == "prepare" {
		invocation.PromptSources = promptSourcesFromReport(report)
	}
	network := invocationNetworkEnabled(invocation.Profile, report)

	// Acquisition runs on the trusted side, before any package code executes.
	//
	// Prolewatch evaluates the PKGBUILD in containment, freezes the resulting
	// source set, and fetches the declared non-VCS sources itself into SRCDEST
	// with its own HTTP client. makepkg then finds them present and verifies
	// checksums with no network at all - which matters because makepkg sources
	// the PKGBUILD on every invocation, so author-written top-level shell runs
	// during retrieval. A package with no VCS sources never has an open network
	// while its own code executes.
	//
	// Exact URL enforcement happens in egress.Acquire because an HTTPS proxy sees
	// only CONNECT host and port, not the request path.
	switch invocation.Profile {
	case "verify":
		acquisition, err := acquireDeclaredSources(ctx, workdir, cfg, &invocation)
		if err != nil {
			prepareTerminalOutput(ctx)
			fmt.Fprintln(os.Stderr, "prolewatch-makepkg: source acquisition failed:", err)
			return ExitExecutionFailure
		}
		// Network is needed only for version-control checkouts, which are a
		// protocol conversation rather than a fetch.
		network = network && len(acquisition.VCSHosts) > 0
		invocation.DeclaredHosts = acquisition.VCSHosts
		invocation.PromptSources = promptSourcesFromFrozen(acquisition.Declared)
		// The frozen VCS host set is the whole allowance for this phase. It comes
		// from the same acquisition that decided the phase needs a network at all,
		// so there is no second derivation of "which hosts are declared".
		invocation.AllowedHosts = acquisition.VCSHosts
		report.AcquiredHosts = acquisition.Hosts()
		if replaceErr := service.Reports.Replace(report); replaceErr != nil {
			prepareTerminalOutput(ctx)
			fmt.Fprintln(os.Stderr, "prolewatch-makepkg: cannot record acquisition:", replaceErr)
			return ExitExecutionFailure
		}
	case "prepare", "build", "skip":
		// yay runs each phase as its own wrapper process, and only the verify one
		// fetches. A later phase therefore has to resolve the same directory
		// again, because its Invocation starts empty and inherits nothing.
		//
		// Getting this wrong is silent. With SRCDEST unset, makepkg looks for the
		// sources where it would have put them by default, finds nothing, and
		// downloads them a second time - from a phase in which package code is
		// running, against a host the user has every reason to approve - and the
		// build still succeeds, so nothing points at it.
		//
		// This is reuse only: transactionSourceDir is keyed by checkout and yay
		// transaction, so it names the directory acquisition already filled, and a
		// non-VCS source missing from it is an absent file rather than a fetch.
		srcdest, err := transactionSourceDir(workdir)
		if err != nil {
			prepareTerminalOutput(ctx)
			fmt.Fprintln(os.Stderr, "prolewatch-makepkg: cannot locate the acquired sources:", err)
			return ExitExecutionFailure
		}
		invocation.SourceDest = srcdest
	}
	if progress != nil {
		progress.SetNetwork(network, invocation.Profile == "build" && invocation.PersistentCargoHome)
	}
	// The build uses the host's /usr read-only rather than a clean root. This is
	// no more exposure than plain yay provides and requires no privileged root
	// preparation service. See docs/architecture.md control 1.
	progressStage(ctx, StageBubblewrapLaunch)
	progressTimedStage(ctx, StageSandboxExecution, cfg.Build.TimeoutSeconds)
	if network && len(invocation.AllowedHosts) > 0 {
		progressActivity(ctx, "cloning declared VCS sources from "+strings.Join(invocation.AllowedHosts, ", "))
	}
	// Bubblewrap joins the pre-mapped user namespace under a transient user
	// service that supplies the resource limits.
	stdout, stderr, enforcement, err := makepkgSandboxRunner(ctx, invocation, workdir, network, cfg)
	if network {
		enforcement.NetworkPolicy = "public-web-broker"
	}
	if err == nil {
		if receipt, updated := sourceVerificationAfterInvocation(invocation, report.Sources); updated {
			report.SourceVerification = receipt
		}
	}
	report.SandboxRuns = append(report.SandboxRuns, enforcement)
	buildLogPath := ""
	var buildLogErr error
	if invocation.Profile == "build" {
		// The terminal replay is intentionally ephemeral, but the same bounded
		// output is often the only useful evidence when package() fails. Keep a
		// private, terminal-safe copy beside the report so debugging does not
		// require rerunning untrusted package code.
		buildLogPath, buildLogErr = saveContainedBuildLog(service.Reports, report, invocation, stdout, stderr, err)
	}
	if replaceErr := service.Reports.Replace(report); replaceErr != nil {
		prepareTerminalOutput(ctx)
		fmt.Fprintln(os.Stderr, "prolewatch-makepkg: cannot record sandbox enforcement:", replaceErr)
		printContainedBuildLogNotice(renderer, buildLogPath, buildLogErr)
		return ExitExecutionFailure
	}
	if err != nil {
		prepareTerminalOutput(ctx)
		// packagelist parses stdout as data, so it keeps the split replay that
		// prints stderr alone. Every other profile gets write order.
		if merged, droppedHead := transcript.Bytes(); len(merged) > 0 && invocation.Profile != "packagelist" {
			replayContainedMakepkgTranscript(renderer, invocation, merged, droppedHead)
		} else {
			replayContainedMakepkgOutput(renderer, invocation, stdout, stderr, true, invocation.Profile != "packagelist")
		}
		failure := sandboxFailureMessage(enforcement, err)
		packagePhase := terminalInline(invocation.PackageBase, 4096) + " / " + terminalInline(invocation.Profile, 100)
		label, role := sandboxFailureStamp(enforcement, err)
		fmt.Fprintln(os.Stderr, renderer.stampedLine(label, role, packagePhase+": "+failure))
		for _, detail := range sandboxFailureDetails(enforcement, err) {
			fmt.Fprintln(os.Stderr, renderer.detailLine(detail))
		}
		for _, detail := range sandboxOutputFailureDetails(invocation, stdout, stderr) {
			fmt.Fprintln(os.Stderr, renderer.detailLine(detail))
		}
		printContainedBuildLogNotice(renderer, buildLogPath, buildLogErr)
		return ExitExecutionFailure
	}
	if invocation.Profile == "packagelist" {
		prepareTerminalOutput(ctx)
		return handlePackageList(ctx, stdout, workdir, report, service)
	}
	prepareTerminalOutput(ctx)
	replayContainedMakepkgOutput(renderer, invocation, stdout, stderr, false, true)
	printContainedBuildLogNotice(renderer, buildLogPath, buildLogErr)
	if invocation.Profile == "prepare" {
		// prepare downloaded and unpacked attacker-controlled sources. Recompute
		// the complete manifest now; the pre-download decision cannot authorize
		// content that did not exist during the first scan.
		progressStage(ctx, StagePostDownloadRescan)
		refreshed, status, err := service.ScanDirectoryWithContext(ctx, "post", workdir, report.PackageBase, report.YayContext)
		if err != nil {
			// A scan that cannot complete produces no content hash, so there is
			// nothing an approval could be bound to. A bypass with no content
			// binding is not a meaningful user decision, so the build stops.
			prepareTerminalOutput(ctx)
			fmt.Fprintln(os.Stderr, "prolewatch-makepkg:", err)
			return ExitExecutionFailure
		}
		prepareTerminalOutput(ctx)
		// Decide whether a prompt is coming before printing the briefing, so
		// the briefing does not send the user to another shell for a question
		// they are about to be asked here.
		mode := ""
		if status != 0 {
			mode = classifyInlineDecision(refreshed, cfg)
		}
		fmt.Fprintln(os.Stderr, renderer.phaseResult(refreshed, status, mode != "" && interactiveDecisionAvailable(), status == 0))
		if status != 0 {
			if mode != "" && confirmInlineDecision(mode, refreshed, nil, workdir, cfg.Review.ManualReviewMinimumSeverity) {
				tokenPath, err := createInlineToken(mode, refreshed, service.Approvals)
				if err != nil {
					prepareTerminalOutput(ctx)
					fmt.Fprintln(os.Stderr, "prolewatch-makepkg:", err)
					return ExitExecutionFailure
				}
				refreshed, status, err = service.ScanDirectoryWithContext(ctx, "post", workdir, report.PackageBase, report.YayContext)
				if err != nil {
					_ = service.Approvals.CancelPending(tokenPath)
					prepareTerminalOutput(ctx)
					fmt.Fprintln(os.Stderr, "prolewatch-makepkg:", err)
					return ExitExecutionFailure
				}
				if err := service.Approvals.CancelPending(tokenPath); err != nil {
					prepareTerminalOutput(ctx)
					fmt.Fprintln(os.Stderr, "prolewatch-makepkg:", err)
					return ExitExecutionFailure
				}
				prepareTerminalOutput(ctx)
				fmt.Fprintln(os.Stderr, renderer.inlineDecisionResult(mode, refreshed))
			}
		}
		if status != 0 {
			return status
		}
	}
	if invocation.Profile == "build" {
		// Build output is not trusted merely because makepkg exited successfully.
		// Every produced archive is scanned and content-bound before yay receives
		// its path - and which archives those are comes from the plan makepkg
		// gave for this transaction, not from the directory's contents.
		//
		// The directory is yay's persistent build cache, not a fresh output
		// directory: `cleanAfter` is off by default and the hook deliberately
		// does not change it. A glob over "*.pkg.tar.*" therefore also picked up
		// the previous version's archive and every detached .sig beside it, so an
		// ordinary upgrade could prompt about a scriptlet in a package yay was
		// never going to install, strip an unrelated archive, or quarantine the
		// good new package along with the old one.
		planned, err := TransactionPackagePlan(workdir)
		if err != nil {
			prepareTerminalOutput(ctx)
			fmt.Fprintln(os.Stderr, "prolewatch-makepkg: no package plan for this transaction:", err)
			fmt.Fprintln(os.Stderr, "prolewatch-makepkg: yay asks makepkg --packagelist before every build; this build did not go through that step.")
			return ExitArtifactFailure
		}
		packages := []string{}
		for _, candidate := range planned {
			if regularNoFollow(candidate) {
				packages = append(packages, candidate)
			}
		}
		sort.Strings(packages)
		if len(packages) == 0 {
			prepareTerminalOutput(ctx)
			fmt.Fprintln(os.Stderr, "prolewatch-makepkg: build produced no package archive")
			return ExitArtifactFailure
		}
		return auditAndBind(ctx, packages, report, service)
	}
	return ExitOK
}

func runPrintsrcinfoBootstrap(ctx context.Context, invocation Invocation, workdir string, cfg Config, renderer terminalRenderer, transcript *outputTranscript) int {
	// Use the PKGBUILD-evaluation ceilings for the resources that can be narrowed
	// without treating a pre-existing checkout as newly written output. The
	// workspace byte/file limits and disk reserve remain the configured build
	// limits because the workspace monitor accounts the whole local checkout,
	// which may legitimately be larger than the 64 MiB per-file evaluation cap.
	limits := freezeLimits(cfg.Build)
	cfg.Build.MemoryBytes = limits.MemoryBytes
	cfg.Build.CPUCount = limits.CPUCount
	cfg.Build.TasksMax = limits.TasksMax
	cfg.Build.TimeoutSeconds = limits.TimeoutSeconds
	cfg.Build.OutputBytes = limits.OutputBytes

	if progress := terminalProgressFrom(ctx); progress != nil {
		progress.SetNetwork(false, false)
	}
	progressStage(ctx, StageBubblewrapLaunch)
	progressTimedStage(ctx, StageSandboxExecution, cfg.Build.TimeoutSeconds)
	stdout, stderr, enforcement, err := makepkgSandboxRunner(ctx, invocation, workdir, false, cfg)
	display := invocation
	display.PackageBase = "local checkout metadata"
	if err == nil {
		if validationErr := enforcement.Validate(); validationErr != nil || enforcement.NetworkPolicy != "isolated" {
			if validationErr == nil {
				validationErr = errors.New("metadata bootstrap unexpectedly received network access")
			}
			err = fmt.Errorf("invalid metadata-bootstrap containment evidence: %w", validationErr)
		}
	}
	if err != nil {
		prepareTerminalOutput(ctx)
		merged, droppedHead := transcript.Bytes()
		if len(merged) == 0 && (len(stderr) > 0 || len(stdout) > 0) {
			// Test seams and setup failures may return before the observer sees a
			// byte. Keep both streams diagnostic-only: stdout is protocol data on
			// success and must never leak to yay after a failed evaluation.
			merged = append(append([]byte(nil), stderr...), stdout...)
		}
		if len(merged) > 0 {
			replayContainedMakepkgTranscript(renderer, display, merged, droppedHead)
		}
		message := sandboxFailureMessage(enforcement, err)
		fmt.Fprintln(os.Stderr, renderer.stampedLine("METADATA STOP", "red", "local checkout metadata: "+message))
		for _, detail := range sandboxFailureDetails(enforcement, err) {
			fmt.Fprintln(os.Stderr, renderer.detailLine(detail))
		}
		return ExitExecutionFailure
	}

	// yay parses stdout as .SRCINFO protocol data. Forward it byte-for-byte with
	// no Prolewatch framing. Stderr remains package-authored diagnostics and goes
	// through the normal terminal-control neutralisation path.
	prepareTerminalOutput(ctx)
	replayContainedMakepkgOutput(renderer, display, nil, stderr, false, false)
	if writeErr := writeMakepkgProtocolOutput(os.Stdout, stdout); writeErr != nil {
		fmt.Fprintln(os.Stderr, "prolewatch-makepkg: invalid --printsrcinfo output:", writeErr)
		return ExitExecutionFailure
	}
	return ExitOK
}

func writeMakepkgProtocolOutput(output io.Writer, value []byte) error {
	if len(value) == 0 {
		return errors.New("makepkg returned no .SRCINFO data")
	}
	raw := string(value)
	// .SRCINFO is line-oriented UTF-8 text. Forwarding control bytes would let a
	// direct wrapper invocation redraw the terminal, while escaping them would
	// silently corrupt the protocol yay parses. Reject instead.
	if safe.Text(raw, utf8.RuneCountInString(raw)) != raw {
		return errors.New(".SRCINFO contains invalid UTF-8 or terminal control characters")
	}
	written, err := output.Write(value)
	if err != nil {
		return err
	}
	if written != len(value) {
		return io.ErrShortWrite
	}
	return nil
}

const containedBuildLogSuffix = ".makepkg-build.log"

// saveContainedBuildLog persists only output that has already crossed the
// sandbox runner's configured hard limit. It escapes terminal controls before
// writing so opening the log with cat cannot give package-authored bytes control
// of the user's terminal. stdout and stderr are labelled separately because the
// sandbox captures them separately and cannot truthfully reconstruct their
// original interleaving.
func saveContainedBuildLog(store *ReportStore, report *Report, invocation Invocation, stdout, stderr []byte, runErr error) (string, error) {
	if store == nil || report == nil {
		return "", errors.New("cannot save a build log without its report store and report")
	}
	if invocation.Profile != "build" {
		return "", errors.New("refusing to save a contained log for a non-build phase")
	}
	if !reportIDRE.MatchString(report.ReportID) {
		return "", errors.New("cannot save a build log with an invalid report id")
	}

	result := "success"
	if runErr != nil {
		result = "failure: " + safe.Inline(runErr, 4096)
	}
	var content strings.Builder
	fmt.Fprintln(&content, "Prolewatch contained makepkg build log")
	fmt.Fprintln(&content, "Report:", report.ReportID)
	fmt.Fprintln(&content, "Package:", safe.Inline(report.PackageBase, 4096))
	fmt.Fprintln(&content, "Result:", result)
	fmt.Fprintln(&content, "Note: stdout and stderr were captured separately; original interleaving is unavailable. Terminal controls are escaped.")
	fmt.Fprintln(&content)
	fmt.Fprintln(&content, "--- stdout ---")
	if len(stdout) > 0 {
		fmt.Fprintln(&content, safe.Text(string(stdout), utf8.RuneCount(stdout)))
	}
	fmt.Fprintln(&content, "--- stderr ---")
	if len(stderr) > 0 {
		fmt.Fprintln(&content, safe.Text(string(stderr), utf8.RuneCount(stderr)))
	}

	path := filepath.Join(store.Root, report.ReportID+containedBuildLogSuffix)
	if err := AtomicWrite(path, []byte(content.String()), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func printContainedBuildLogNotice(renderer terminalRenderer, path string, saveErr error) {
	if saveErr != nil {
		fmt.Fprintln(os.Stderr, renderer.detailLine("Could not retain contained build output: "+safe.Inline(saveErr, 4096)))
		return
	}
	if path != "" {
		fmt.Fprintln(os.Stderr, renderer.detailLine("Build log saved to "+terminalInline(path, 4096)))
	}
}

// replayContainedMakepkgTranscript replays both streams in the order they were
// observed, which is what makes a failure legible.
//
// The two-block replay below is kept for two callers. packagelist parses stdout
// as data and must not print it at all, and the success path still writes
// package stdout to stdout: moving that to stderr for the sake of ordering
// would change where output lands for anyone redirecting a successful build,
// which is not a trade a diagnostic improvement earns.
func replayContainedMakepkgTranscript(renderer terminalRenderer, invocation Invocation, merged []byte, droppedHead bool) {
	if len(merged) == 0 {
		return
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, renderer.containedMakepkgOutputHeader(invocation.PackageBase, invocation.Profile))
	fmt.Fprintln(os.Stderr, strings.TrimSuffix(renderer.containedMakepkgOutputGutter(), " "))
	gutter := renderer.containedMakepkgOutputGutter()
	replayPackageOutputWithPrefix(os.Stderr, merged, gutter)
	if droppedHead {
		// Only the display window overflowed. The saved log is written from the
		// per-stream buffers and has its own limits, so claiming it was
		// truncated too would send someone away from the one complete copy.
		fmt.Fprintln(os.Stderr, gutter+"… earlier output omitted to fit the display window; the saved build log below is not shortened by this")
	}
	resetTerminalAfterPackageOutput()
	fmt.Fprintln(os.Stderr, renderer.containedMakepkgOutputFooter())
	fmt.Fprintln(os.Stderr)
}

func replayContainedMakepkgOutput(renderer terminalRenderer, invocation Invocation, stdout, stderr []byte, stderrFirst, includeStdout bool) {
	hasStdout := includeStdout && len(stdout) > 0
	if !hasStdout && len(stderr) == 0 {
		return
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, renderer.containedMakepkgOutputHeader(invocation.PackageBase, invocation.Profile))
	fmt.Fprintln(os.Stderr, strings.TrimSuffix(renderer.containedMakepkgOutputGutter(), " "))
	// Package-authored output is useful diagnostic material, but its terminal
	// control bytes are not. Replay it as visible text so it can flow only
	// downwards: newlines survive, while cursor motion, screen switching, OSC,
	// carriage returns, styling, and other controls become visible escapes.
	// Every prompt additionally discards input typed before it was asked. See
	// safe.OpenPromptTerminal.
	gutter := renderer.containedMakepkgOutputGutter()
	if stderrFirst && len(stderr) > 0 {
		replayPackageOutputWithPrefix(os.Stderr, stderr, gutter)
	}
	if hasStdout {
		replayPackageOutputWithPrefix(os.Stdout, stdout, gutter)
	}
	if !stderrFirst && len(stderr) > 0 {
		replayPackageOutputWithPrefix(os.Stderr, stderr, gutter)
	}
	resetTerminalAfterPackageOutput()
	fmt.Fprintln(os.Stderr, renderer.containedMakepkgOutputFooter())
	fmt.Fprintln(os.Stderr)
}

// replayPackageOutput keeps compiler diagnostics readable without handing
// package-authored bytes control of the user's terminal. A final newline keeps
// Prolewatch's next status or error from being appended to an incomplete line.
func replayPackageOutput(output io.Writer, value []byte) {
	replayPackageOutputWithPrefix(output, value, "")
}

func replayPackageOutputWithPrefix(output io.Writer, value []byte, prefix string) {
	rendered := safe.Text(string(value), utf8.RuneCount(value))
	if rendered == "" {
		return
	}
	// Prefix every physical line, including intentionally empty ones, so the
	// package-authored region remains visually attributable even across long
	// compiler logs. Do not emit a phantom prefixed line after a final newline.
	terminated := strings.HasSuffix(rendered, "\n")
	if terminated {
		rendered = strings.TrimSuffix(rendered, "\n")
	}
	for _, line := range strings.Split(rendered, "\n") {
		_, _ = io.WriteString(output, prefix+line+"\n")
	}
}

// resetTerminalAfterPackageOutput restores only state that cannot reposition
// output. The replay above has already neutralized attacker-authored controls.
// In particular, do not emit DECSTBM, alternate-screen switches, cursor saves,
// or cursor restores here: all of them can move a shared yay terminal.
//
// SGR reset and cursor visibility do not change the cursor position. Writing
// them is harmless when stdout and stderr refer to the same TTY, and useful if
// a caller deliberately attached them to separate terminals.
const terminalRecoverySequence = "\x1b[0m\x1b[?25h"

func resetTerminalAfterPackageOutput() {
	for _, stream := range []*os.File{os.Stdout, os.Stderr} {
		if info, err := stream.Stat(); err != nil || info.Mode()&os.ModeCharDevice == 0 {
			continue
		}
		_, _ = stream.WriteString(terminalRecoverySequence)
	}
}

// bwrapStartupExitCodes are the statuses bubblewrap reserves for its own
// failures: it could not set the sandbox up (125), could not invoke the command
// (126), or could not find it (127). They are the only positive evidence
// available here that package code never ran, short of a handshake through the
// containment layer that this diagnostic does not justify adding.
var bwrapStartupExitCodes = map[int]bool{125: true, 126: true, 127: true}

// sandboxFailureStamp names the kind of failure so a packaging defect does not
// wear the stamp reserved for a policy decision.
//
// Every Termination the runner can produce is listed. An unrecognised value is
// treated as a containment failure rather than silently becoming one through a
// default, because the previous default quietly turned two ordinary resource
// stops - output-limit and workspace-limit - into a red SANDBOX ERROR that told
// the user containment had broken when it had in fact worked exactly as
// configured. Adding a Termination without deciding its label should be a
// visible omission here, not an inherited red stamp.
func sandboxFailureStamp(enforcement SandboxEnforcement, cause error) (string, string) {
	switch enforcement.Termination {
	case "timeout", "output-limit", "workspace-limit", "cancelled":
		// Containment worked and stopped the build. Not a defect, not an error.
		return "BUILD STOPPED", "amber"
	case "process-exit":
		if processWasKilled(cause) {
			return "BUILD STOPPED", "amber"
		}
		if exitCodeIndicatesStartupFailure(cause) {
			return "SANDBOX ERROR", "red"
		}
		return "BUILD FAILED", "amber"
	default:
		// sandbox-setup, systemd-start, workspace-accounting, and anything new.
		return "SANDBOX ERROR", "red"
	}
}

// exitCodeIndicatesStartupFailure reports whether the status is one bubblewrap
// uses for its own startup failures.
func exitCodeIndicatesStartupFailure(cause error) bool {
	var exit *exec.ExitError
	if errors.As(cause, &exit) {
		return bwrapStartupExitCodes[exit.ExitCode()]
	}
	for code := range bwrapStartupExitCodes {
		if strings.Contains(cause.Error(), fmt.Sprintf("exit status %d", code)) {
			return true
		}
	}
	return false
}

func sandboxFailureMessage(enforcement SandboxEnforcement, cause error) string {
	reason := enforcement.Termination
	if reason == "" {
		reason = "sandbox-setup"
	}
	if enforcement.Termination == "process-exit" && !processWasKilled(cause) {
		if exitCodeIndicatesStartupFailure(cause) {
			return fmt.Sprintf("containment or the contained command could not start: %s", truncate(cause.Error(), 1600))
		}
		// "sandbox execution failed" reads as though containment broke, which
		// for an ordinary non-zero exit it did not. It stops short of blaming
		// the package: process-exit is assigned to every non-zero result from
		// the runner, including one where bubblewrap started as a process and
		// then failed before makepkg was ever reached, so "the package's own
		// build failed" would be an attribution the runner cannot support.
		return fmt.Sprintf("the contained build exited non-zero: %s", truncate(cause.Error(), 1600))
	}
	return fmt.Sprintf("sandbox execution failed (%s): %s", reason, truncate(cause.Error(), 1600))
}

func sandboxFailureDetails(enforcement SandboxEnforcement, cause error) []string {
	switch {
	case enforcement.Termination == "timeout":
		return []string{
			fmt.Sprintf("The contained phase exceeded its effective %s runtime limit.", time.Duration(enforcement.TimeoutSeconds)*time.Second),
			fmt.Sprintf("Adjust build.timeout_seconds in %s if this build legitimately needs longer, then retry.", systemConfigDefaultPath),
		}
	case enforcement.Termination == "process-exit" && processWasKilled(cause):
		return []string{
			"The contained process received SIGKILL. This may indicate the memory or runtime limit, but the current systemd result does not prove which one.",
			fmt.Sprintf("Effective envelope: memory %s · swap disabled · tasks %d · CPUs %d · timeout %s.", humanBytes(enforcement.MemoryBytes), enforcement.TasksMax, enforcement.CPUCount, time.Duration(enforcement.TimeoutSeconds)*time.Second),
			fmt.Sprintf("Review build.memory_bytes, build.tasks_max, build.cpu_count, and build.timeout_seconds in %s, then retry.", systemConfigDefaultPath),
		}
	default:
		return nil
	}
}

// sandboxOutputFailureDetails explains a read-only /usr failure and points at
// the two ways out of it.
//
// Everything here is inferred from package-authored output, which a hostile
// recipe can print without having attempted the write it describes. So the
// diagnosis is offered as the usual explanation rather than asserted as fact,
// and the only categorical claim is the one Prolewatch actually enforces: the
// write to /usr did not land. It deliberately does not claim that nothing
// changed - the checkout, the source destination, and the build caches are
// writable inside the sandbox by design.
//
// It also stops short of naming the variable to set. DESTDIR, prefix, PREFIX
// and INSTALL_ROOT are all real answers for different upstreams, and the right
// one is whatever that project's own install script reads. Printing a guess
// beside a failure is how a user ends up pasting a change that silently
// installs to the wrong place, so this says where to look instead.
func sandboxOutputFailureDetails(invocation Invocation, stdout, stderr []byte) []string {
	contains := func(fragment string) bool {
		needle := []byte(fragment)
		return bytes.Contains(stdout, needle) || bytes.Contains(stderr, needle)
	}
	if invocation.Profile != "build" || !contains("Read-only file system") || !contains("/usr/") {
		return nil
	}
	details := []string{
		"This usually means the recipe's package() step ran an installer that wrote to the live filesystem instead of the staging directory.",
		"What is certain is only that the write to /usr was refused. The build's own checkout, downloaded sources, and caches are writable inside the sandbox and may have changed.",
	}
	// /usr/local is the prefix an installer falls back to when it was given
	// none, so the two paths point at genuinely different defects and narrow
	// the search differently. This is read off the reported path rather than
	// guessed.
	if contains("/usr/local/") {
		details = append(details,
			"The reported path is under /usr/local, which is where an installer writes when it was given no prefix at all. The recipe most likely never passes one through to this step.")
	} else {
		details = append(details,
			"The reported path is under /usr, so a prefix did reach the installer while the staging directory did not.")
	}
	details = append(details,
		"Package contents must land below $pkgdir. Which variable carries that differs by upstream - DESTDIR, prefix, PREFIX and INSTALL_ROOT are all used - so read the project's own Makefile or install script for the one it honours. Prolewatch does not guess it for you.")
	// The command is only offered when the name is one the recipe validator
	// already accepted, so nothing shell-significant can reach a line the user
	// is being invited to run. Same guard as ui.surfaceInspectCommand.
	if err := brief.ValidatePackageBase(invocation.PackageBase); err != nil {
		return append(details, "Preferred fix: report this build failure to the package's AUR maintainer, with the build log below. It is a packaging bug, and fixing it upstream fixes it for everyone.")
	}
	name := terminalInline(invocation.PackageBase, 256)
	return append(details,
		"Preferred fix: report this build failure to the AUR maintainer of "+name+", with the build log below. It is a packaging bug, and fixing it upstream fixes it for everyone.",
		"If you can repair a PKGBUILD yourself, you can edit it instead:   yay -S "+name+" --editmenu",
		"That opens package-authored text in your editor, and a failed build is a cheap way to get you to sit in one. Read before you change anything, edit only the install step, and do not run a command the recipe suggests. Containment stays on either way: the edited recipe is rescanned and the build still runs in the sandbox.",
	)
}

func processWasKilled(cause error) bool {
	var exit *exec.ExitError
	if errors.As(cause, &exit) {
		if status, ok := exit.Sys().(syscall.WaitStatus); ok {
			if status.Signaled() && status.Signal() == syscall.SIGKILL {
				return true
			}
		}
		if exit.ExitCode() == 128+int(syscall.SIGKILL) {
			return true
		}
	}
	message := strings.ToLower(cause.Error())
	return strings.Contains(message, "signal: killed") || strings.Contains(message, "exit status 137")
}

func renderMakepkgInvocationFailure(renderer terminalRenderer, output io.Writer, cause error) {
	if !errors.Is(cause, errMakepkgCompatibility) {
		fmt.Fprintln(output, "prolewatch-makepkg:", terminalInline(cause.Error(), 2000))
		return
	}
	fmt.Fprintln(output, renderer.errorLine("MAKEPKG COMPATIBILITY STOP"))
	fmt.Fprintln(output, renderer.detailLine("Prolewatch stopped before makepkg evaluated package code because yay requested an unreviewed command shape."))
	fmt.Fprintln(output, renderer.detailLine("Reason: "+terminalInline(cause.Error(), 2000)))
	fmt.Fprintln(output, renderer.detailLine("Run prolewatch doctor to verify the installed wrapper and supported yay version."))
	fmt.Fprintln(output, renderer.detailLine("If an update caused this incompatibility, prolewatch uninstall-hook is a deliberate escape hatch; later yay builds will run without Prolewatch containment or review."))
}

// transactionSourceDir allocates a source directory private to this checkout
// and this yay transaction.
//
// The directory is scoped because it is bind-mounted read/write into the
// untrusted sandbox during verification. Sharing it would let packages damage
// each other's sources and let concurrent transactions with colliding basenames
// race. Acquisition fetches the frozen set for every transaction, so this
// directory does not need to serve as a cache.
func transactionSourceDir(workdir string) (string, error) {
	root, directory, err := transactionSourcePath(workdir)
	if err != nil {
		return "", err
	}
	if err := EnsurePrivateDir(directory); err != nil {
		return "", err
	}
	pruneStaleSourceDirs(root, directory)
	return directory, nil
}

// transactionSourcePath derives the store's location without creating it.
//
// The path is a pure function of the resolved checkout and the yay transaction,
// which is what lets two different processes agree on it: the makepkg wrapper
// fills the store, and the scan the yay hook runs separately has to find the
// same one. Symlinks are resolved on both sides so one caller's /home/x and
// another's /var/home/x cannot produce two stores for one build.
func transactionSourcePath(workdir string) (string, string, error) {
	transaction, err := TransactionIdentity()
	if err != nil {
		return "", "", err
	}
	canonical, err := filepath.Abs(workdir)
	if err != nil {
		return "", "", err
	}
	if evaluated, err := filepath.EvalSymlinks(canonical); err == nil {
		canonical = evaluated
	}
	// The checkout path and the transaction identity together: the same package
	// rebuilt in a later transaction gets a fresh directory, and two packages in
	// one transaction never share one.
	key := safe.SHA256Bytes([]byte(fmt.Sprintf("%s\x00%d\x00%s\x00%s",
		canonical, transaction.PID, transaction.StartTime, transaction.BootID)))
	root := filepath.Join(StateRoot(), "srcdest")
	return root, filepath.Join(root, key[:32]), nil
}

// ExistingTransactionSourceDir names the store for this checkout and
// transaction when acquisition has already created it, and "" otherwise.
//
// Read-only on purpose: a scan must never create the store, only inventory what
// acquisition put there. Every failure returns "", because a scan that cannot
// find a store must behave exactly like one for a package that has no remote
// sources - the extractable-source check then reports what is genuinely absent.
func ExistingTransactionSourceDir(workdir string) string {
	_, directory, err := transactionSourcePath(workdir)
	if err != nil {
		return ""
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() {
		return ""
	}
	return directory
}

// sourceDirRetention is how long an unused source directory survives.
//
// Transaction-scoped directories accumulate, but nothing reads one after its
// transaction ends because acquisition re-fetches the frozen set. They are
// therefore pruned by age. The generous window favors keeping a directory over
// risking deletion during a long-running build.
const sourceDirRetention = 7 * 24 * time.Hour

// pruneStaleSourceDirs removes source directories untouched for longer than the
// retention window. Failures are ignored: this is housekeeping, and a build
// must not fail because an unrelated directory could not be removed.
func pruneStaleSourceDirs(root, keep string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-sourceDirRetention)
	for _, entry := range entries {
		path := filepath.Join(root, entry.Name())
		if !entry.IsDir() || path == keep {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		_ = os.RemoveAll(path)
	}
}

// pinAcquiredSources makes every file the trusted-side fetch put in the source
// store immutable from inside the sandbox, by bind-mounting each one read-only
// over itself.
//
// The store itself has to stay writable: makepkg's ensure_writable_dir refuses
// to run at all against a read-only SRCDEST, and VCS checkouts under it are
// updated in place. That left the acquired bytes deletable by package code -
// and makepkg sources the PKGBUILD on every invocation, so top-level shell
// could simply unlink a source and let the same run download it again, from a
// URL that same shell had just recomputed. "Fetched once on the trusted side"
// was true only until the package asked for it not to be.
//
// Measured: unlink and rename over a bind-mounted file return EBUSY, a write
// returns EROFS, and the directory around them stays writable.
//
// Only regular files are pinned. Directories are VCS working state that
// makepkg must be able to update, and the store is 0700 under the user's own
// state root, so nothing package-controlled reaches it outside a sandbox.
func pinAcquiredSources(store string) ([][2]string, error) {
	entries, err := os.ReadDir(store)
	if err != nil {
		return nil, fmt.Errorf("read the acquired source store: %w", err)
	}
	var pins [][2]string
	for _, entry := range entries {
		name := entry.Name()
		// Type() comes from the directory read and does not follow symlinks, so
		// a link that somehow appeared here is skipped rather than pinned to
		// whatever it points at.
		if !entry.Type().IsRegular() || name != filepath.Base(name) {
			continue
		}
		pins = append(pins, [2]string{filepath.Join(store, name), "/srcdest/" + name})
	}
	return pins, nil
}

// acquireDeclaredSources performs the contained freeze and the trusted-side
// fetch, and points the build's SRCDEST at what it retrieved.
func acquireDeclaredSources(ctx context.Context, workdir string, cfg Config, invocation *Invocation) (*egress.Acquisition, error) {
	progressTimedStage(ctx, StageSourcePlanFreeze, cfg.Build.TimeoutSeconds)
	namespace, err := contain.NewNamespace()
	if err != nil {
		if errors.Is(err, contain.ErrNoSubID) {
			return nil, fmt.Errorf("%w\n\n%s", err, contain.SubIDAdvice())
		}
		return nil, err
	}
	defer namespace.Close()

	allowance, err := egress.FreezeDeclaredSources(ctx, namespace, workdir, freezeLimits(cfg.Build))
	if err != nil {
		return nil, err
	}
	srcdest, err := transactionSourceDir(workdir)
	if err != nil {
		return nil, err
	}
	progressStage(ctx, StageSourceAcquisition)
	acquisition, err := egress.AcquireWithProgress(ctx, allowance, srcdest, cfg.Network, func(transfer egress.AcquisitionProgress) {
		progressAcquisition(ctx, transfer)
	})
	if err != nil {
		return nil, err
	}
	// Persist the plan the fetch was made from, so the post scan describes the
	// set that was actually acquired rather than the committed .SRCINFO.
	//
	// It is written outside the source store on purpose: the store is bound
	// read-write into the sandbox for makepkg's own use, and a plan the package
	// could rewrite would be no better than the file it replaces.
	if err := saveTransactionSourcePlan(workdir, allowance.DerivedSrcinfo()); err != nil {
		return nil, err
	}
	invocation.SourceDest = srcdest
	return acquisition, nil
}

// transactionSourcePlanPath names where this transaction's frozen declaration
// lives. Same key as the source store, different directory: never bind-mounted.
func transactionSourcePlanPath(workdir string) (string, error) {
	_, directory, err := transactionSourcePath(workdir)
	if err != nil {
		return "", err
	}
	return filepath.Join(StateRoot(), "source-plans", filepath.Base(directory)+".srcinfo"), nil
}

func saveTransactionSourcePlan(workdir string, derived []byte) error {
	path, err := transactionSourcePlanPath(workdir)
	if err != nil {
		return err
	}
	if err := EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	return atomicUserWrite(path, derived, 0o600)
}

// transactionPackagePlanPath names where this transaction's validated package
// list lives. Same key as the source store, and never bind-mounted.
func transactionPackagePlanPath(workdir string) (string, error) {
	_, directory, err := transactionSourcePath(workdir)
	if err != nil {
		return "", err
	}
	return filepath.Join(StateRoot(), "package-plans", filepath.Base(directory)+".json"), nil
}

// saveTransactionPackagePlan records the exact paths this build will produce.
//
// yay asks `makepkg --packagelist` immediately before the build - measured
// against 13.0.1, the sequence is printsrcinfo, verifysource, nobuild,
// packagelist, build - and the wrapper already validates that answer against
// the checkout. Persisting it is what lets the build phase audit the packages
// this transaction actually produced instead of guessing from filenames.
func saveTransactionPackagePlan(workdir string, paths []string) error {
	path, err := transactionPackagePlanPath(workdir)
	if err != nil {
		return err
	}
	if err := EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	return AtomicWriteJSON(path, paths)
}

// TransactionPackagePlan returns the paths makepkg said this build would write.
func TransactionPackagePlan(workdir string) ([]string, error) {
	path, err := transactionPackagePlanPath(workdir)
	if err != nil {
		return nil, err
	}
	var paths []string
	if err := ReadJSONFile(path, 1<<20, &paths); err != nil {
		return nil, err
	}
	return paths, nil
}

// packageExtension is the only package format this release can carry end to
// end.
//
// makepkg treats PKGEXT as administrator policy and supports plain tar plus
// nine compressors. The artifact scanner reads several of them, but the
// privileged-integration gate - the mandatory one - enumerates and rewrites
// zstd only, so a valid .pkg.tar.xz passed inspection and then failed the gate
// with "magic number mismatch", quarantining the package with an error that
// says nothing about PKGEXT. Widening it properly means carrying every
// compressor makepkg supports, because a strip has to re-emit the format its
// filename claims.
//
// The package list names the exact files the build will write, so the effective
// policy can be read from it and reported before the build runs rather than
// after the archive has been quarantined.
const packageExtension = ".pkg.tar.zst"

// unsupportedPackageFormat names the first planned output this release cannot
// carry end to end, or "" when every one of them is supported.
func unsupportedPackageFormat(paths []string) string {
	for _, path := range paths {
		if !strings.HasSuffix(path, packageExtension) {
			return path
		}
	}
	return ""
}

// TransactionSourcePlan returns the frozen declaration for this checkout and
// transaction, or nil when the contained freeze has not run yet.
//
// The pre scan legitimately has none: it runs before any evaluation, so its
// briefing describes the committed .SRCINFO and says so. By the post scan the
// freeze has happened, and this is the authority.
func TransactionSourcePlan(workdir string) []byte {
	path, err := transactionSourcePlanPath(workdir)
	if err != nil {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return raw
}

func runMakepkgSandbox(ctx context.Context, invocation Invocation, workdir string, network bool, cfg Config) ([]byte, []byte, SandboxEnforcement, error) {
	setupEnforcement := effectiveBuildLimits(cfg.Build)
	setupEnforcement.Termination = "sandbox-setup"

	// The user namespace is created before Bubblewrap and joined by it. See
	// internal/contain and docs/architecture.md control 1: bwrap's own namespace
	// maps only the caller's uid, so chown(2) to an unmapped id returns EINVAL,
	// which libfakeroot does not absorb, and any package() using
	// `install -o root -g root` fails the build.
	namespace, err := contain.NewNamespace()
	if err != nil {
		if errors.Is(err, contain.ErrNoSubID) {
			return nil, nil, setupEnforcement, fmt.Errorf("%w\n\n%s", err, contain.SubIDAdvice())
		}
		return nil, nil, setupEnforcement, err
	}
	defer namespace.Close()

	jobs := filepath.Join(StateRoot(), "jobs")
	if err := EnsurePrivateDir(jobs); err != nil {
		return nil, nil, setupEnforcement, err
	}
	job, err := os.MkdirTemp(jobs, "build-")
	if err != nil {
		return nil, nil, setupEnforcement, err
	}
	defer os.RemoveAll(job)
	gnupg := filepath.Join(job, "gnupg")
	if err := os.Mkdir(gnupg, 0o700); err != nil {
		return nil, nil, setupEnforcement, err
	}
	sourceKeyring := filepath.Join(StateRoot(), "gnupg-public")
	if info, err := os.Stat(sourceKeyring); err == nil && info.IsDir() {
		if err := copyKeyring(sourceKeyring, gnupg); err != nil {
			return nil, nil, setupEnforcement, err
		}
	}
	configBinds, err := makepkgConfigSnapshotter(job, invocation)
	if err != nil {
		return nil, nil, setupEnforcement, err
	}

	spec := contain.Spec{
		Workdir:       workdir,
		WorkdirTarget: "/build",
		Env:           contain.BaseEnv(),
	}
	for _, bind := range configBinds {
		spec.ExtraROBinds = append(spec.ExtraROBinds, [2]string{bind[0], bind[1]})
	}
	// Only the keyring is bound into the home directory. The home itself stays a
	// tmpfs, so nothing else of the user's crosses in.
	spec.ExtraBinds = append(spec.ExtraBinds, [2]string{gnupg, "/build-home/.gnupg"})
	spec.Env["GNUPGHOME"] = "/build-home/.gnupg"
	if invocation.SourceDest != "" {
		// The sources Prolewatch already fetched. makepkg finds them here and
		// does not reach for the network.
		spec.ExtraBinds = append(spec.ExtraBinds, [2]string{invocation.SourceDest, "/srcdest"})
		spec.Env["SRCDEST"] = "/srcdest"
		pins, err := pinAcquiredSources(invocation.SourceDest)
		if err != nil {
			return nil, nil, setupEnforcement, err
		}
		spec.ExtraROBinds = append(spec.ExtraROBinds, pins...)
	}
	if value := os.Getenv("LC_ALL"); value != "" {
		spec.Env["LC_ALL"] = value
	}
	if value := os.Getenv("TERM"); value != "" {
		spec.Env["TERM"] = value
	}
	if invocation.PersistentCargoHome {
		// yay splits source preparation and compilation across separate makepkg
		// processes. Keep Cargo's locked fetch inside the already monitored and
		// content-bound vendor srcdir so a later --frozen build sees the exact
		// cache without exposing the user's real Cargo home.
		spec.Env["CARGO_HOME"] = "/build/src/.prolewatch-cargo-home"
	}
	if invocation.PersistentGoCache {
		spec.Env["GOMODCACHE"] = "/build/src/.prolewatch-go-mod-cache"
		spec.Env["GOCACHE"] = "/build/src/.prolewatch-go-build-cache"
		spec.Env["GOTOOLCHAIN"] = "local"
		spec.Env["GOPROXY"] = "https://proxy.golang.org"
		spec.Env["GOSUMDB"] = "sum.golang.org"
	}
	for _, name := range []string{"MAKEFLAGS", "CFLAGS", "CXXFLAGS", "LDFLAGS", "RUSTFLAGS", "SOURCE_DATE_EPOCH"} {
		if value := os.Getenv(name); value != "" {
			spec.Env[name] = value
		}
	}

	var broker makepkgBroker
	if network {
		// The sandbox has a private, empty network namespace in every phase; see
		// contain.Spec.BwrapArgs. "Brokered" therefore adds a bind-mounted unix
		// socket and a fixed loopback proxy inside that namespace, not a route to
		// the host network.
		//
		// Only the broker's client directory enters the build. Its prompt/control
		// socket remains outside, so package code can request but cannot approve a
		// destination grant.
		brokerDir, err := makepkgBrokerTempDir()
		if err != nil {
			return nil, nil, setupEnforcement, err
		}
		defer os.RemoveAll(brokerDir)
		brokerConfig := cfg.Network
		brokerConfig.PromptContext = strings.Join(invocation.NetworkContext, ", ")
		brokerConfig.AllowedHosts = invocation.AllowedHosts
		brokerConfig.PromptPackage = invocation.PackageBase
		brokerConfig.PromptPhase = invocation.Profile
		brokerConfig.DeclaredHosts = invocation.DeclaredHosts
		brokerConfig.PromptSources = invocation.PromptSources
		broker, err = makepkgNetworkBrokerStart(brokerDir, brokerConfig, networkPromptWithProgress(ctx, ui.PromptNetworkDestination))
		if err != nil {
			return nil, nil, setupEnforcement, err
		}
		defer broker.Stop()
		spec.ExtraBinds = append(spec.ExtraBinds, [2]string{filepath.Join(brokerDir, "client"), "/broker"})
		proxy := "http://" + egress.SandboxProxyAddress
		socks := "socks5h://" + egress.SandboxProxyAddress
		for _, name := range []string{"http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"} {
			spec.Env[name] = proxy
		}
		for _, name := range []string{"all_proxy", "ALL_PROXY"} {
			spec.Env[name] = socks
		}
		spec.Env["GIT_CONFIG_COUNT"] = "1"
		spec.Env["GIT_CONFIG_KEY_0"] = "http.proxy"
		spec.Env["GIT_CONFIG_VALUE_0"] = proxy
		spec.Argv = []string{"/usr/bin/prolewatch-net", "supervise", "/broker/proxy.sock", "--", "/usr/bin/makepkg"}
	} else {
		spec.Argv = []string{"/usr/bin/makepkg"}
	}
	spec.Argv = append(spec.Argv, containedMakepkgArgs(invocation)...)

	// contain.Run is not used here: the build additionally needs the transient
	// systemd scope for memory, CPU, task and runtime limits, which the runner
	// below supplies. The namespace is handed over by path rather than by an
	// inherited descriptor; the namespace runner joins it by path.
	args := spec.BwrapArgs(sandboxUsernsFD)
	commandArgs := append([]string{contain.NamespaceRunnerMarker, namespace.Path()}, args...)
	if broker == nil {
		return constrainedCommandRunner(ctx, commandArgs, nil, workdir, cfg, invocation.outputObserver)
	}
	type commandResult struct {
		stdout, stderr []byte
		enforcement    SandboxEnforcement
		err            error
	}
	buildCtx, cancelBuild := context.WithCancelCause(ctx)
	defer cancelBuild(nil)
	result := make(chan commandResult, 1)
	go func() {
		stdout, stderr, enforcement, err := constrainedCommandRunner(buildCtx, commandArgs, nil, workdir, cfg, invocation.outputObserver)
		result <- commandResult{stdout: stdout, stderr: stderr, enforcement: enforcement, err: err}
	}()
	select {
	case completed := <-result:
		if brokerErr := broker.Failure(); brokerErr != nil {
			completed.enforcement.Termination, completed.err = brokerFailure(cfg.Network.MaxRequests, brokerErr)
		}
		return completed.stdout, completed.stderr, completed.enforcement, completed.err
	case <-broker.Done():
		brokerErr := broker.Failure()
		if brokerErr == nil {
			brokerErr = errors.New("network broker stopped during the build")
		}
		cancelBuild(brokerErr)
		completed := <-result
		completed.enforcement.Termination, completed.err = brokerFailure(cfg.Network.MaxRequests, brokerErr)
		return completed.stdout, completed.stderr, completed.enforcement, completed.err
	}
}

func newMakepkgBrokerDirectory() (string, error) {
	// AF_UNIX paths are limited to roughly 108 bytes on Linux. Durable state may
	// live below an arbitrarily long XDG_STATE_HOME, so nesting prompt.sock there
	// makes a valid configuration fail before the contained phase starts. Broker
	// sockets are ephemeral control objects, not report evidence: a private,
	// unpredictable directory directly below /tmp keeps the path bounded. The
	// sandbox sees only its client child at /broker; host /tmp remains replaced by
	// the sandbox's own tmpfs.
	return os.MkdirTemp("/tmp", "prolewatch-net-")
}

// containedMakepkgArgs suppresses makepkg's redundant pacman -T dependency
// probe for lifecycle phases yay has already dependency-resolved. The sandbox
// intentionally exposes neither /etc/pacman.conf nor /var/lib/pacman: the first
// describes administrator repositories and policy, while the second reveals
// the exact installed-package inventory. Passing either through merely to
// repeat yay's check would widen host fingerprinting and still add no build
// dependency; missing tools fail naturally when the package actually uses
// them. Verification and package-list queries do not run this probe.
func containedMakepkgArgs(invocation Invocation) []string {
	args := append([]string(nil), invocation.Args...)
	switch invocation.Profile {
	case "prepare", "build", "skip":
		return append(args, "--nodeps")
	default:
		return args
	}
}

func networkPromptWithProgress(ctx context.Context, prompt egress.PromptFunc) egress.PromptFunc {
	progress := terminalProgressFrom(ctx)
	if progress == nil {
		return prompt
	}
	return func(request egress.AuthorizationRequest, cfg egress.Config) bool {
		// A network question is written directly to /dev/tty while build output
		// continues to arrive on another goroutine. Freeze the live status before
		// the question is rendered so its trailing [y/N] remains the last thing
		// on screen until the user answers.
		progress.PrepareOutput()
		defer progress.ResumeAfterPrompt()
		return prompt(request, cfg)
	}
}

func brokerFailure(maxRequests int, cause error) (string, error) {
	if errors.Is(cause, egress.ErrRequestLimit) {
		return "network-request-limit", fmt.Errorf("network.max_requests=%d exhausted: %w", maxRequests, cause)
	}
	return "network-broker", cause
}

func invocationNetworkEnabled(profile string, report *Report) bool {
	// Network is a positive capability derived from an allowed, non-bypassed,
	// phase-correct report. Operational failure or an override always falls back
	// to an isolated namespace rather than accidentally enabling connectivity.
	if report == nil || report.Decision != "allow" {
		return false
	}
	if profile == "verify" {
		return report.Phase == "pre"
	}
	return (profile == "prepare" || profile == "build") && report.Phase == "post" && report.NetworkEligible
}

func copyKeyring(source, destination string) error {
	return filepath.WalkDir(source, func(current string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(source, current)
		target := filepath.Join(destination, relative)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("public GPG keyring contains a symlink")
		}
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if info.Mode()&os.ModeSocket != 0 && filepath.Dir(relative) == "." && publicGPGSocket(entry.Name()) {
			// GnuPG leaves its agent sockets in GNUPGHOME after the isolated
			// process namespace exits. They contain no key material and cannot
			// be copied into the next private build home.
			return nil
		}
		if !info.Mode().IsRegular() {
			return errors.New("public GPG keyring contains an unsafe entry")
		}
		input, err := os.Open(current)
		if err != nil {
			return err
		}
		defer input.Close()
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(output, input)
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
}

func publicGPGSocket(name string) bool {
	return map[string]bool{
		"S.dirmngr":           true,
		"S.gpg-agent":         true,
		"S.gpg-agent.browser": true,
		"S.gpg-agent.extra":   true,
		"S.gpg-agent.ssh":     true,
		"S.keyboxd":           true,
		"S.scdaemon":          true,
	}[name]
}

func handlePackageList(ctx context.Context, stdout []byte, workdir string, report *Report, service *AuditService) int {
	// makepkg --packagelist names future output. A path that does not exist yet
	// is returned to yay so it can run the build; the build phase later audits
	// exactly the saved plan before it returns. A cached archive is different:
	// yay may reuse it without another build, so it must be audited and bound
	// before its path is printed here.
	var hostPaths, planned, output []string
	existing := map[string]bool{}
	for _, line := range strings.Split(string(stdout), "\n") {
		if line == "" {
			continue
		}
		host := ""
		if filepath.IsAbs(line) {
			relative, err := filepath.Rel("/build", line)
			if err != nil || relative == ".." || strings.HasPrefix(relative, "../") {
				prepareTerminalOutput(ctx)
				fmt.Fprintln(os.Stderr, "prolewatch-makepkg: package path escapes /build:", line)
				return ExitExecutionFailure
			}
			host = filepath.Join(workdir, relative)
		} else {
			host = filepath.Join(workdir, line)
		}
		parent, err := filepath.EvalSymlinks(filepath.Dir(host))
		if err != nil || (parent != workdir && !strings.HasPrefix(parent, workdir+string(os.PathSeparator))) {
			prepareTerminalOutput(ctx)
			fmt.Fprintln(os.Stderr, "prolewatch-makepkg: package path escapes workdir:", line)
			return ExitExecutionFailure
		}
		planned = append(planned, host)
		info, statErr := os.Lstat(host)
		switch {
		case statErr == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0:
			hostPaths = append(hostPaths, host)
			existing[host] = true
		case errors.Is(statErr, os.ErrNotExist):
			// This is the normal pre-build case. The path is content-free now;
			// the build invocation must produce it and auditAndBind will verify
			// its bytes against the reviewed artifact manifest before returning.
		case statErr != nil:
			prepareTerminalOutput(ctx)
			fmt.Fprintln(os.Stderr, "prolewatch-makepkg: cannot inspect planned package path:", terminalInline(host, 2000), statErr)
			return ExitExecutionFailure
		default:
			prepareTerminalOutput(ctx)
			fmt.Fprintln(os.Stderr, "prolewatch-makepkg: planned package path already exists but is not a regular file:", terminalInline(host, 2000))
			return ExitExecutionFailure
		}
	}
	// The plan names the exact files the build will write, so the administrator's
	// effective PKGEXT is readable here - before the build - instead of surfacing
	// later as an opaque gate failure on an archive nobody can open.
	if unsupported := unsupportedPackageFormat(planned); unsupported != "" {
		prepareTerminalOutput(ctx)
		fmt.Fprintf(os.Stderr, "prolewatch-makepkg: this release supports %s packages only, and this build would write %s\n", packageExtension, filepath.Base(unsupported))
		fmt.Fprintln(os.Stderr, "prolewatch-makepkg: set PKGEXT='.pkg.tar.zst' in makepkg.conf, or install this package without Prolewatch.")
		return ExitArtifactFailure
	}
	if err := saveTransactionPackagePlan(workdir, planned); err != nil {
		prepareTerminalOutput(ctx)
		fmt.Fprintln(os.Stderr, "prolewatch-makepkg: cannot record the package plan:", err)
		return ExitStateFailure
	}
	if len(hostPaths) > 0 {
		if status := auditAndBind(ctx, hostPaths, report, service); status != 0 {
			return status
		}
	}
	for _, packagePath := range planned {
		if !existing[packagePath] {
			output = append(output, packagePath)
			continue
		}
		matched := ""
		for _, artifact := range report.ArtifactBindings {
			if artifact.Path == packagePath {
				matched = artifact.Path
				break
			}
		}
		if matched == "" {
			prepareTerminalOutput(ctx)
			fmt.Fprintln(os.Stderr, "prolewatch-makepkg: no reviewed artifact is available for", filepath.Base(packagePath))
			return ExitExecutionFailure
		}
		output = append(output, matched)
	}
	if len(output) > 0 {
		prepareTerminalOutput(ctx)
		fmt.Fprintln(os.Stdout, strings.Join(output, "\n"))
	}
	return ExitOK
}

func auditAndBind(ctx context.Context, packages []string, postReport *Report, service *AuditService) int {
	// The final content transition: scan the produced archives and bind the
	// decision to their hashes. Nothing is copied anywhere - the artifact stays
	// where the build wrote it - and nothing is installed on the host.
	renderer := newTerminalRenderer(service.Config, os.Stderr)
	progressStage(ctx, StageArtifactInspection)
	artifact, status, err := service.ScanArtifacts(ctx, packages, postReport.PackageBase)
	if err != nil {
		prepareTerminalOutput(ctx)
		fmt.Fprintln(os.Stderr, "prolewatch-makepkg:", err)
		return ExitArtifactFailure
	}
	prepareTerminalOutput(ctx)
	artifactMode := ""
	if status != 0 {
		artifactMode = classifyInlineDecision(artifact, service.Config)
	}
	fmt.Fprintln(os.Stderr, renderer.reportWithPrompt(artifact, artifactMode != "" && interactiveDecisionAvailable()))
	if status != 0 {
		mode := artifactMode
		if mode != "" && confirmInlineDecision(mode, artifact, nil, "", service.Config.Review.ManualReviewMinimumSeverity) {
			tokenPath, err := createInlineToken(mode, artifact, service.Approvals)
			if err != nil {
				prepareTerminalOutput(ctx)
				fmt.Fprintln(os.Stderr, "prolewatch-makepkg:", err)
				return ExitArtifactFailure
			}
			artifact, status, err = service.ScanArtifacts(ctx, packages, postReport.PackageBase)
			if err != nil {
				_ = service.Approvals.CancelPending(tokenPath)
				prepareTerminalOutput(ctx)
				fmt.Fprintln(os.Stderr, "prolewatch-makepkg:", err)
				return ExitArtifactFailure
			}
			if err := service.Approvals.CancelPending(tokenPath); err != nil {
				prepareTerminalOutput(ctx)
				fmt.Fprintln(os.Stderr, "prolewatch-makepkg:", err)
				return ExitArtifactFailure
			}
			prepareTerminalOutput(ctx)
			fmt.Fprintln(os.Stderr, renderer.inlineDecisionResult(mode, artifact))
		}
	}
	if status != 0 {
		if !quarantinePackages(ctx, packages, artifact, "Blocked package archives") {
			return ExitArtifactFailure
		}
		if status == ExitPolicyBlock {
			return ExitPolicyBlock
		}
		return ExitArtifactFailure
	}
	// The artifact stays where the build produced it. In the single-administrator
	// model, the only principal able to swap those bytes is the person about to
	// authorize installation. The transient systemd scope kills every
	// build-spawned process before installation, and the hash check below binds
	// the artifact to the review that approved it.
	progressStage(ctx, StageArtifactBinding)
	verified := map[string]string{}
	for _, pkg := range packages {
		before, err := safe.HashFileNoFollow(pkg)
		if err != nil {
			return artifactFailure(ctx, packages, artifact, err)
		}
		expected, err := expectedArtifactHash(artifact, filepath.Base(pkg))
		if err != nil || before != expected {
			if err == nil {
				err = errors.New("artifact changed after its security review")
			}
			return artifactFailure(ctx, packages, artifact, err)
		}
		verified[pkg] = before
	}

	// The privileged-integration gate. This is the one execution site
	// containment cannot reach: pacman runs this code as root by design, when
	// the user types their own sudo password, so the only available controls
	// are showing them the code and removing the surface before handoff.
	//
	// It runs after verification and before yay receives any path, because a
	// rewrite changes the bytes the briefing described - the transaction is
	// re-bound to the rewritten archive below.
	for _, pkg := range packages {
		surfaces, err := gateEnumerator(ctx, pkg)
		if err != nil {
			return artifactFailure(ctx, packages, artifact, fmt.Errorf("privileged-integration enumeration: %w", err))
		}
		if len(surfaces) == 0 {
			continue
		}
		// Enumeration is not the same thing as interruption.
		//
		// Everything found is shown. Only what runs as root, or grants
		// privilege, with no further step by anyone stops the install for an
		// answer; a systemd unit nobody has enabled, a user-session unit, a
		// polkit action declaration and a PAM module file nothing references
		// are printed and passed. Asking about all of them made the most
		// common AUR package - one with an ordinary service unit - produce the
		// same unanswerable question every time, and the habit that teaches is
		// paid back on the .INSTALL scriptlet that does run as root today.
		if len(brief.SurfacesRequiringDecision(surfaces)) == 0 {
			prepareTerminalOutput(ctx)
			fmt.Fprint(os.Stderr, ui.RenderSurfaceInventory(filepath.Base(pkg), ui.OrderSurfacesForDisplay(surfaces)))
			continue
		}
		prepareTerminalOutput(ctx)
		decision, err := gatePrompter(pkg, surfaces)
		if err != nil {
			// No answer is not "keep everything".
			//
			// This is the only decision taken immediately before pacman runs
			// package code as root, and the artifact scan does not stand in for
			// it: an integration finding is medium severity and does not block.
			// Continuing here made a redirected stdin, a missing terminal or an
			// unattended run into a silent global override for exactly the
			// choice the product exists to put in front of the user - and it
			// resolved to the most permissive option available.
			//
			// Keeping the surfaces is still a normal outcome; it just has to be
			// answered, and one Enter answers it.
			prepareTerminalOutput(ctx)
			fmt.Fprintln(os.Stderr, "prolewatch-makepkg: install stopped: the privileged-integration gate got no answer:", err)
			// A timeout and an absent terminal fail the same way and need
			// different advice. Telling someone who walked away to "run this on
			// a terminal" sends them to fix something that was never wrong.
			if errors.Is(err, ui.ErrGatePromptTimeout) {
				fmt.Fprintln(os.Stderr, "prolewatch-makepkg: nothing was installed and nothing was changed; run the same yay command again when you can answer the prompt.")
			} else {
				fmt.Fprintln(os.Stderr, "prolewatch-makepkg: this package installs code that runs as root with no further step by anyone; run the install on a terminal so it can be shown to you.")
			}
			return ExitPolicyBlock
		}
		if decision.Cancel {
			fmt.Fprintln(os.Stderr, "prolewatch-makepkg: install cancelled at the privileged-integration gate")
			return ExitPolicyBlock
		}
		if len(decision.Strip) == 0 {
			continue
		}
		target, err := filteredPackagePath(pkg)
		if err != nil {
			return artifactFailure(ctx, packages, artifact, err)
		}
		defer os.RemoveAll(filepath.Dir(target))
		result, err := FilterArchiveContained(ctx, pkg, target, decision.Strip)
		if err != nil {
			os.Remove(target)
			return artifactFailure(ctx, packages, artifact, fmt.Errorf("privileged-integration rewrite: %w", err))
		}
		// Replace the original so yay installs the rewritten archive, and
		// re-bind the transaction to its hash: the approval was bound to bytes
		// that no longer exist.
		if err := os.Rename(target, pkg); err != nil {
			os.Remove(target)
			return artifactFailure(ctx, packages, artifact, err)
		}
		rebound, err := safe.HashFileNoFollow(pkg)
		if err != nil || rebound != result.SHA256 {
			if err == nil {
				err = errors.New("rewritten package changed while being installed in place")
			}
			return artifactFailure(ctx, packages, artifact, err)
		}
		verified[pkg] = rebound
		artifact.StrippedSurfaces = append(artifact.StrippedSurfaces, StrippedSurfaces{
			Package: filepath.Base(pkg),
			Members: result.Stripped,
			SHA256:  rebound,
		})
	}
	for _, pkg := range packages {
		artifact.ArtifactBindings = append(artifact.ArtifactBindings, ArtifactBinding{pkg, verified[pkg]})
	}
	if err := service.Reports.Replace(artifact); err != nil {
		return artifactFailure(ctx, packages, artifact, err)
	}
	postReport.ArtifactBindings = append([]ArtifactBinding(nil), artifact.ArtifactBindings...)
	if err := service.Reports.Replace(postReport); err != nil {
		return artifactFailure(ctx, packages, artifact, err)
	}
	prepareTerminalOutput(ctx)
	if line := renderer.artifactReadyLine(len(packages)); line != "" {
		fmt.Fprintln(os.Stderr, line)
	}
	return ExitOK
}
func expectedArtifactHash(report *Report, name string) (string, error) {
	if report == nil || filepath.Base(name) != name || name == "" {
		return "", errors.New("invalid artifact manifest lookup")
	}
	result := ""
	for _, raw := range report.Manifest {
		record, err := brief.ValidateManifestRecord(raw)
		if err != nil {
			return "", err
		}
		if record.Kind == "file" && record.Path == name {
			if result != "" {
				return "", errors.New("duplicate artifact manifest entry")
			}
			result = record.SHA256
		}
	}
	if result == "" {
		return "", fmt.Errorf("artifact %q is missing from its reviewed manifest", name)
	}
	return result, nil
}
func artifactFailure(ctx context.Context, packages []string, artifact *Report, cause error) int {
	prepareTerminalOutput(ctx)
	fmt.Fprintln(os.Stderr, "prolewatch-makepkg: artifact validation failed:", cause)
	quarantinePackages(ctx, packages, artifact, "Package archives from the failed review")
	return ExitArtifactFailure
}

// quarantinePackages moves archives out of yay's reach and says what happened
// to each one. It reports whether every file was accounted for.
//
// There were two of these. One created the directory carefully, reported each
// failed move and printed the destination; the other discarded the
// directory-creation result and every move result and printed only the cause,
// so a user could not tell whether an archive had been moved, left in the build
// directory, or half-handled - and had no idea where to look for it. Failing
// closed is right; leaving someone unable to find their package afterwards is
// not part of that.
func quarantinePackages(ctx context.Context, packages []string, artifact *Report, subject string) bool {
	quarantine := filepath.Join(StateRoot(), "quarantine", artifact.ReportID)
	prepareTerminalOutput(ctx)
	if err := EnsurePrivateDir(quarantine); err != nil {
		fmt.Fprintf(os.Stderr, "prolewatch-makepkg: cannot create the quarantine directory %s: %v\n", quarantine, err)
		fmt.Fprintln(os.Stderr, "prolewatch-makepkg: the package archives are still in the build directory; yay remains blocked.")
		return false
	}
	moved, complete := 0, true
	for _, pkg := range packages {
		if !regularNoFollow(pkg) {
			// Nothing to move: the file the plan named was never produced, or
			// something else already handled it.
			continue
		}
		if err := moveVerified(pkg, filepath.Join(quarantine, filepath.Base(pkg))); err != nil {
			complete = false
			fmt.Fprintf(os.Stderr, "prolewatch-makepkg: %s stayed in the build directory: %v\n", pkg, err)
			continue
		}
		moved++
	}
	if moved > 0 {
		fmt.Fprintf(os.Stderr, "%s moved to %s (%d file(s))\n", subject, quarantine, moved)
		fmt.Fprintln(os.Stderr, "prolewatch-makepkg: nothing removes them; delete that directory when you no longer need the evidence.")
	}
	if !complete {
		fmt.Fprintln(os.Stderr, "prolewatch-makepkg: not every archive could be quarantined; yay remains blocked.")
	}
	return complete
}
func regularNoFollow(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}
func moveVerified(source, destination string) error {
	// Prefer an atomic rename on the same mount. EXDEV requires copy-and-hash;
	// deleting the source only after verification preserves quarantine semantics.
	if !regularNoFollow(source) {
		return fmt.Errorf("refusing to move non-regular artifact: %s", source)
	}
	before, err := safe.HashFileNoFollow(source)
	if err != nil {
		return err
	}
	if err := os.Rename(source, destination); err == nil {
		after, hashErr := safe.HashFileNoFollow(destination)
		if hashErr == nil && after == before {
			return nil
		}
		_ = os.Rename(destination, source)
		if hashErr != nil {
			return hashErr
		}
		return errors.New("artifact hash changed while moving")
	} else if link, ok := err.(*os.LinkError); !ok || link.Err != syscall.EXDEV {
		return err
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	// Every unsuccessful path removes the partial destination, not only the
	// hash check below. A copy or close that fails part way otherwise leaves a
	// truncated archive in the quarantine directory beside intact ones, with
	// nothing saying which is which.
	if copyErr != nil {
		_ = os.Remove(destination)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(destination)
		return closeErr
	}
	after, err := safe.HashFileNoFollow(destination)
	if err != nil || after != before {
		_ = os.Remove(destination)
		return errors.New("quarantine copy verification failed")
	}
	return os.Remove(source)
}
