package audit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

var trustedSystemUID uint32

func snapshotMakepkgConfigs(job string, invocation Invocation) ([][2]string, error) {
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
		raw, err := io.ReadAll(io.LimitReader(input, 1024*1024+1))
		if err == nil {
			err = unix.Fstat(int(input.Fd()), &after)
		}
		input.Close()
		if err != nil || len(raw) > 1024*1024 || !sameStat(before, after) || before.Mode != after.Mode {
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

func appendReadOnlyPolicyPath(args *[]string, hostPath string) error {
	info, err := os.Lstat(hostPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || (!info.Mode().IsRegular() && !info.IsDir()) {
		return fmt.Errorf("sandbox read-only policy path is unsafe: %s", hostPath)
	}
	validated, err := openRootOwnedPath(hostPath, info.IsDir())
	if err != nil {
		return err
	}
	validated.Close()
	appendReadOnlyPolicyBind(args, hostPath, info.IsDir())
	return nil
}

// appendReadOnlyPolicyBind constructs the Bubblewrap arguments only after the
// caller has validated the complete host path with openRootOwnedPath.
func appendReadOnlyPolicyBind(args *[]string, hostPath string, directory bool) {
	parent := filepath.Dir(hostPath)
	components := strings.Split(strings.TrimPrefix(parent, "/"), "/")
	current := ""
	known := map[string]bool{"/usr": true, "/etc": true, "/var": true, "/home": true, "/root": true, "/run": true, "/tmp": true}
	for _, component := range components {
		if component == "" || component == "." {
			continue
		}
		current += "/" + component
		if !known[current] {
			*args = append(*args, "--dir", current)
		}
	}
	if directory {
		*args = append(*args, "--dir", hostPath)
	}
	*args = append(*args, "--ro-bind", hostPath, hostPath)
}

type Invocation struct {
	Profile             string
	Args                []string
	ConfigPath          string
	CleanRootPath       string
	CleanRoot           *CleanRootManifest
	PersistentCargoHome bool
	activity            *ActivityRecorder
	outputObserver      commandOutputObserver
}

var (
	makepkgSandboxRunner      = runMakepkgSandbox
	makepkgInfoCommand        = exec.Command
	makepkgConfigSnapshotter  = snapshotMakepkgConfigs
	constrainedCommandRunner  = runConstrainedCommand
	makepkgNetworkBrokerStart = startNetworkBroker
	cleanRootDispatcher       = invokeCleanRootDispatcher
	preparedRootValidator     = validatePreparedRoot
)

var prohibitedMakepkg = map[string]bool{"--skipchecksums": true, "--skipinteg": true}
var safeGlobal = map[string]bool{"--nocheck": true, "--check": true, "--ignorearch": true, "--noconfirm": true, "--noprogressbar": true}
var profileAllowed = map[string]map[string]bool{
	"verify":  {"--verifysource": true, "--skippgpcheck": true, "-f": true, "-C": true, "-c": true, "-Cc": true},
	"prepare": {"--nobuild": true, "-f": true, "-C": true}, "packagelist": {"--packagelist": true},
	"build": {"-f": true, "-c": true, "--noextract": true, "--noprepare": true, "--holdver": true},
	"skip":  {"-c": true, "--nobuild": true, "--noextract": true},
}

func ClassifyInvocation(args []string) (Invocation, error) {
	if len(args) == 0 {
		return Invocation{}, errors.New("makepkg invocation has no arguments")
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
				return Invocation{}, errors.New("--config requires a path")
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
	profile := ""
	switch {
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
		return Invocation{}, fmt.Errorf("unknown makepkg invocation class: %s", strings.Join(args, " "))
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
		return Invocation{}, fmt.Errorf("unsupported makepkg arguments for %s: %v", profile, unknown)
	}
	if tokens["--skippgpcheck"] && profile != "verify" {
		return Invocation{}, errors.New("--skippgpcheck is only permitted for yay source verification")
	}
	return Invocation{Profile: profile, Args: args, ConfigPath: configPath}, nil
}

func sourceVerificationAfterInvocation(invocation Invocation, sources []SourceProvenance) (SourceVerification, bool) {
	if invocation.Profile != "verify" && invocation.Profile != "prepare" {
		return SourceVerification{}, false
	}
	hasSignature := false
	for _, source := range sources {
		if source.Kind == SourceKindSignature {
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
	return SourceVerification{Checksums: "passed", PGP: pgp}, true
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

func openRootOwnedDirectoryHandle(value string) (*os.File, error) {
	return openRootOwnedPathMode(value, true, false)
}

func openRootOwnedPathMode(value string, wantDirectory, readFinalDirectory bool) (*os.File, error) {
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

// openRootOwnedComponents consumes fd. O_PATH lets callers traverse secure
// execute-only directories without granting directory listing access.
func openRootOwnedComponents(fd int, value string, components []string, wantDirectory bool) (*os.File, error) {
	return openRootOwnedComponentsMode(fd, value, components, wantDirectory, true)
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
		if err := unix.Fstat(next, &after); err != nil || !sameStat(before, after) || before.Mode != after.Mode || before.Uid != after.Uid {
			unix.Close(next)
			unix.Close(fd)
			return nil, fmt.Errorf("system path changed during validation: %s", value)
		}
		unix.Close(fd)
		fd = next
	}
	return os.NewFile(uintptr(fd), value), nil
}

func RunMakepkg(ctx context.Context, args []string) (status int) {
	cfg, err := LoadConfig("")
	if err != nil {
		fmt.Fprintln(os.Stderr, "prolewatch-makepkg:", err)
		return 20
	}
	invocation, err := ClassifyInvocation(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "prolewatch-makepkg:", err)
		return 20
	}
	if invocation.Profile == "info" {
		command := makepkgInfoCommand("/usr/bin/makepkg", args...)
		command.Stdin = os.Stdin
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		if err := command.Run(); err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				return exit.ExitCode()
			}
			return 24
		}
		return 0
	}
	renderer := newTerminalRenderer(cfg, os.Stderr)
	progress := newTerminalProgress(renderer, "", invocation.Profile)
	if progress != nil {
		command := "makepkg"
		if len(invocation.Args) > 0 {
			command += " " + strings.Join(invocation.Args, " ")
		}
		progress.SetCommand(command)
		invocation.outputObserver = progress.ObserveOutput
		defer progress.Close()
		ctx = withTerminalProgress(ctx, progress)
	}
	recorder, activityErr := NewActivityRecorder("", "makepkg", invocation.Profile)
	if activityErr != nil {
		prepareTerminalOutput(ctx)
		fmt.Fprintln(os.Stderr, "prolewatch-makepkg: cannot start activity tracking:", activityErr)
	}
	if recorder != nil {
		defer func() { recorder.Finish(activityResult(status), "") }()
		ctx = withActivity(ctx, recorder)
		invocation.activity = recorder
	}
	workdir, err := filepath.Abs(".")
	if err != nil {
		prepareTerminalOutput(ctx)
		fmt.Fprintln(os.Stderr, "prolewatch-makepkg:", err)
		return 20
	}
	workdir, err = filepath.EvalSymlinks(workdir)
	if err != nil {
		prepareTerminalOutput(ctx)
		fmt.Fprintln(os.Stderr, "prolewatch-makepkg:", err)
		return 20
	}
	service, err := auditServiceFactory(ctx, cfg, nil)
	if err != nil {
		prepareTerminalOutput(ctx)
		fmt.Fprintln(os.Stderr, "prolewatch-makepkg: audit service initialization failed:", err)
		return 24
	}
	markerPhase := "post"
	if invocation.Profile == "verify" {
		markerPhase = "pre"
	}
	report, err := service.VerifyMarker(workdir, markerPhase)
	if err != nil {
		prepareTerminalOutput(ctx)
		fmt.Fprintln(os.Stderr, "prolewatch-makepkg: audit gate failed:", err)
		if strings.Contains(strings.ToLower(err.Error()), "changed") {
			return 21
		}
		return 24
	}
	if recorder != nil {
		recorder.SetPackage(report.PackageBase)
		recorder.LinkReport(report.ReportID)
	}
	if progress != nil {
		progress.SetPackage(report.PackageBase)
	}
	invocation.PersistentCargoHome = usesPersistentCargoHome(report)
	network := invocation.Profile == "verify"
	automaticSteps, automaticNetwork := automaticKnownToolNetwork(cfg, invocation.Profile, report)
	if markerPhase == "post" {
		network, err = NewNetworkLeaseStore().ActiveOrConsume(report, NewApprovalStore(), 0)
		if err != nil {
			prepareTerminalOutput(ctx)
			fmt.Fprintln(os.Stderr, "prolewatch-makepkg: cannot resolve network lease:", err)
			return 23
		}
		if !network && automaticNetwork {
			network = true
			prepareTerminalOutput(ctx)
			fmt.Fprintln(os.Stderr, renderer.automaticNetwork(report.PackageBase, invocation.Profile, automaticSteps))
		}
	}
	if progress != nil {
		progress.SetNetwork(network, invocation.Profile == "build" && invocation.PersistentCargoHome)
	}
	activityTimedStage(ctx, StageCleanRootPrepare, cfg.Build.CleanRootPrepareTimeoutSeconds)
	activityContainment(ctx, func(containment *ActivityContainment) { containment.CleanRootState = "preparing" })
	prepareContext, cancelPrepare := cleanRootWithTimeout(ctx, cfg.Build.CleanRootPrepareTimeoutSeconds)
	prepareRequest := cleanRootRequestFor("prepare")
	prepareRequest.Dependencies = cleanRootDependenciesForProfile(invocation.Profile, report.YayContext)
	prepareRequest.PolicyFingerprint = service.PolicyFingerprint
	prepared, err := cleanRootDispatcher(prepareContext, prepareRequest)
	cancelPrepare()
	if err != nil {
		activityContainment(ctx, func(containment *ActivityContainment) { containment.CleanRootState = "failed" })
		prepareTerminalOutput(ctx)
		fmt.Fprintln(os.Stderr, "prolewatch-makepkg: clean-root preparation failed:", err)
		return 24
	}
	invocation.CleanRootPath, invocation.CleanRoot = prepared.RootPath, prepared.Manifest
	activityContainment(ctx, func(containment *ActivityContainment) {
		containment.CleanRootState = "prepared"
		containment.CleanRootGeneration = prepared.Manifest.Generation
		containment.CleanRootManifest = prepared.Manifest.ManifestSHA256
		containment.PackageCount = len(prepared.Manifest.Packages)
		containment.ArtifactCount = len(prepared.Manifest.ArtifactHashes)
		containment.Supervisor = "systemd-user"
		containment.NetworkPolicy = "isolated"
		if network {
			containment.NetworkPolicy = "public-web-broker"
		}
		containment.SandboxState = "launching"
	})
	activityStage(ctx, StageBubblewrapLaunch)
	activityTimedStage(ctx, StageSandboxExecution, cfg.Build.TimeoutSeconds)
	stdout, stderr, enforcement, err := makepkgSandboxRunner(invocation, workdir, network, cfg)
	enforcement.CleanRoot = invocation.CleanRoot
	activityContainment(ctx, func(containment *ActivityContainment) {
		if err == nil {
			containment.SandboxState = "completed"
		} else {
			containment.SandboxState = "failed"
		}
	})
	activityTimedStage(ctx, StageCleanRootCleanup, cfg.Build.CleanRootPrepareTimeoutSeconds)
	activityContainment(ctx, func(containment *ActivityContainment) { containment.CleanRootState = "cleaning" })
	// A canceled build still has to release its root-owned disposable job. Keep
	// request values but detach cleanup from the build cancellation signal.
	cleanupContext, cancelCleanup := cleanRootWithTimeout(context.WithoutCancel(ctx), cfg.Build.CleanRootPrepareTimeoutSeconds)
	cleanupRequest := cleanRootRequestFor("cleanup")
	cleanupRequest.Token = prepared.Token
	_, cleanupErr := cleanRootDispatcher(cleanupContext, cleanupRequest)
	cancelCleanup()
	activityContainment(ctx, func(containment *ActivityContainment) {
		if cleanupErr == nil {
			containment.CleanRootState = "cleaned"
		} else {
			containment.CleanRootState = "failed"
		}
	})
	if cleanupErr != nil && err == nil {
		err = fmt.Errorf("clean-root cleanup failed: %w", cleanupErr)
		enforcement.Termination = "sandbox-setup"
	}
	if network {
		enforcement.NetworkPolicy = "public-web-broker"
	}
	if err == nil {
		if receipt, updated := sourceVerificationAfterInvocation(invocation, report.Sources); updated {
			report.SourceVerification = receipt
		}
	}
	report.SandboxRuns = append(report.SandboxRuns, enforcement)
	if replaceErr := service.Reports.Replace(report); replaceErr != nil {
		prepareTerminalOutput(ctx)
		fmt.Fprintln(os.Stderr, "prolewatch-makepkg: cannot record sandbox enforcement:", replaceErr)
		return 24
	}
	if err != nil {
		prepareTerminalOutput(ctx)
		if len(stderr) > 0 {
			_, _ = os.Stderr.Write(stderr)
		}
		if len(stdout) > 0 && invocation.Profile != "packagelist" {
			_, _ = os.Stdout.Write(stdout)
		}
		failure := sandboxFailureMessage(enforcement, err)
		activityFailure(ctx, ActivityFailureOperational, failure)
		fmt.Fprintln(os.Stderr, "prolewatch-makepkg:", failure)
		if !network && enforcement.Termination == "process-exit" && (invocation.Profile == "prepare" || invocation.Profile == "build") {
			fmt.Fprintf(os.Stderr, "Build network was disabled. Grant a lease only if the log shows intentional network access: prolewatch allow-network %s\n", report.ReportID)
		}
		return 24
	}
	if invocation.Profile == "packagelist" {
		prepareTerminalOutput(ctx)
		return handlePackageList(ctx, stdout, workdir, report, service)
	}
	prepareTerminalOutput(ctx)
	if len(stdout) > 0 {
		_, _ = os.Stdout.Write(stdout)
	}
	if len(stderr) > 0 {
		_, _ = os.Stderr.Write(stderr)
	}
	if invocation.Profile == "prepare" {
		activityStage(ctx, StagePostDownloadRescan)
		refreshed, status, err := service.ScanDirectoryWithContext(ctx, "post", workdir, report.PackageBase, report.YayContext)
		if err != nil {
			prepareTerminalOutput(ctx)
			if cfg.Overrides.AllowUnsafe && confirmInlineDecision(inlineBypass, nil, err) {
				refreshed, err = service.CreateUnscannedBypass(workdir, "post", report.PackageBase, report.YayContext, err)
				status = 0
			} else {
				prepareTerminalOutput(ctx)
				fmt.Fprintln(os.Stderr, "prolewatch-makepkg:", err)
				return 24
			}
		}
		prepareTerminalOutput(ctx)
		fmt.Fprintln(os.Stderr, renderer.report(refreshed))
		if status != 0 {
			mode := classifyInlineDecision(refreshed, cfg)
			if mode != "" && confirmInlineDecision(mode, refreshed, nil) {
				tokenPath, err := createInlineToken(mode, refreshed, service.Approvals)
				if err != nil {
					prepareTerminalOutput(ctx)
					fmt.Fprintln(os.Stderr, "prolewatch-makepkg:", err)
					return 24
				}
				refreshed, status, err = service.ScanDirectoryWithContext(ctx, "post", workdir, report.PackageBase, report.YayContext)
				if err != nil {
					_ = service.Approvals.CancelPending(tokenPath)
					prepareTerminalOutput(ctx)
					fmt.Fprintln(os.Stderr, "prolewatch-makepkg:", err)
					return 24
				}
				if err := service.Approvals.CancelPending(tokenPath); err != nil {
					prepareTerminalOutput(ctx)
					fmt.Fprintln(os.Stderr, "prolewatch-makepkg:", err)
					return 24
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
		matches, _ := filepath.Glob(filepath.Join(workdir, "*.pkg.tar.*"))
		packages := []string{}
		for _, candidate := range matches {
			if regularNoFollow(candidate) {
				packages = append(packages, candidate)
			}
		}
		sort.Strings(packages)
		if len(packages) == 0 {
			prepareTerminalOutput(ctx)
			fmt.Fprintln(os.Stderr, "prolewatch-makepkg: build produced no package archive")
			return 25
		}
		return auditAndSeal(ctx, packages, report, service)
	}
	return 0
}

func sandboxFailureMessage(enforcement SandboxEnforcement, cause error) string {
	reason := enforcement.Termination
	if reason == "" {
		reason = "sandbox-setup"
	}
	return fmt.Sprintf("sandbox execution failed (%s): %s", reason, truncate(cause.Error(), 1600))
}

func cleanRootDependenciesForProfile(profile string, yayContext YayContext) []string {
	if profile == "verify" {
		return []string{}
	}
	return cleanRootDependencies(yayContext)
}

func runMakepkgSandbox(invocation Invocation, workdir string, network bool, cfg Config) ([]byte, []byte, SandboxEnforcement, error) {
	setupEnforcement := effectiveBuildLimits(cfg.Build)
	setupEnforcement.Termination = "sandbox-setup"
	setupEnforcement.CleanRoot = invocation.CleanRoot
	if invocation.CleanRoot == nil || invocation.CleanRoot.Validate() != nil {
		return nil, nil, setupEnforcement, errors.New("build requires a valid clean-root manifest")
	}
	if err := preparedRootValidator(invocation.CleanRootPath); err != nil {
		return nil, nil, setupEnforcement, err
	}
	jobs := filepath.Join(StateRoot(), "jobs")
	if err := EnsurePrivateDir(jobs); err != nil {
		return nil, nil, setupEnforcement, err
	}
	job, err := os.MkdirTemp(jobs, "build-")
	if err != nil {
		return nil, nil, setupEnforcement, err
	}
	defer os.RemoveAll(job)
	buildHome := filepath.Join(job, "home")
	if err := os.Mkdir(buildHome, 0o700); err != nil {
		return nil, nil, setupEnforcement, err
	}
	gnupg := filepath.Join(buildHome, ".gnupg")
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
	args := []string{"--die-with-parent", "--new-session", "--unshare-all", "--unshare-user", "--disable-userns", "--assert-userns-disabled", "--ro-bind", invocation.CleanRootPath, "/", "--dir", "/etc", "--dir", "/etc/makepkg.conf.d"}
	for _, bind := range configBinds {
		args = append(args, "--ro-bind", bind[0], bind[1])
	}
	args = append(args, "--ro-bind", "/usr/bin/prolewatch-net", "/usr/bin/prolewatch-net", "--dir", "/var/tmp", "--tmpfs", "/var/tmp", "--dir", "/home", "--tmpfs", "/home", "--dir", "/root", "--tmpfs", "/root", "--dir", "/run", "--tmpfs", "/run", "--dir", "/tmp", "--tmpfs", "/tmp", "--proc", "/proc", "--dev", "/dev", "--dir", "/build", "--bind", workdir, "/build", "--dir", "/build-home", "--bind", buildHome, "/build-home")
	var broker *networkBrokerProcess
	if network {
		brokerDir := filepath.Join(job, "broker")
		if err := os.Mkdir(brokerDir, 0o700); err != nil {
			return nil, nil, setupEnforcement, err
		}
		broker, err = makepkgNetworkBrokerStart(brokerDir, cfg.Network)
		if err != nil {
			return nil, nil, setupEnforcement, err
		}
		defer broker.stop()
		args = append(args, "--dir", "/broker", "--bind", brokerDir, "/broker")
	}
	args = append(args, "--chdir", "/build", "--clearenv")
	environment := map[string]string{"HOME": "/build-home", "GNUPGHOME": "/build-home/.gnupg", "PATH": "/usr/local/sbin:/usr/local/bin:/usr/bin", "LANG": valueOr(os.Getenv("LANG"), "C.UTF-8"), "LC_ALL": os.Getenv("LC_ALL"), "TERM": valueOr(os.Getenv("TERM"), "dumb")}
	if invocation.PersistentCargoHome {
		// yay splits source preparation and compilation across separate makepkg
		// processes. Keep Cargo's locked fetch inside the already monitored and
		// content-bound vendor srcdir so a later --frozen build sees the exact
		// cache without exposing the user's real Cargo home.
		environment["CARGO_HOME"] = "/build/src/.prolewatch-cargo-home"
	}
	for _, name := range []string{"MAKEFLAGS", "CFLAGS", "CXXFLAGS", "LDFLAGS", "RUSTFLAGS", "SOURCE_DATE_EPOCH"} {
		if value := os.Getenv(name); value != "" {
			environment[name] = value
		}
	}
	if network {
		proxy := "http://" + sandboxProxyAddress
		socks := "socks5h://" + sandboxProxyAddress
		for _, name := range []string{"http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"} {
			environment[name] = proxy
		}
		for _, name := range []string{"all_proxy", "ALL_PROXY"} {
			environment[name] = socks
		}
		environment["NO_PROXY"] = ""
		environment["no_proxy"] = ""
		environment["GIT_CONFIG_COUNT"] = "1"
		environment["GIT_CONFIG_KEY_0"] = "http.proxy"
		environment["GIT_CONFIG_VALUE_0"] = proxy
	}
	keys := make([]string, 0, len(environment))
	for key := range environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if environment[key] != "" {
			args = append(args, "--setenv", key, environment[key])
		}
	}
	if network {
		args = append(args, "/usr/bin/prolewatch-net", "supervise", "/broker/proxy.sock", "--", "/usr/bin/makepkg")
	} else {
		args = append(args, "/usr/bin/makepkg")
	}
	args = append(args, invocation.Args...)
	stdout, stderr, enforcement, err := constrainedCommandRunner(args, nil, workdir, cfg, invocation.activity, invocation.outputObserver)
	enforcement.CleanRoot = invocation.CleanRoot
	return stdout, stderr, enforcement, err
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
	var hostPaths, output []string
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
				return 24
			}
			host = filepath.Join(workdir, relative)
		} else {
			host = filepath.Join(workdir, line)
		}
		parent, err := filepath.EvalSymlinks(filepath.Dir(host))
		if err != nil || (parent != workdir && !strings.HasPrefix(parent, workdir+string(os.PathSeparator))) {
			prepareTerminalOutput(ctx)
			fmt.Fprintln(os.Stderr, "prolewatch-makepkg: package path escapes workdir:", line)
			return 24
		}
		sealed, err := sealedPath(report, filepath.Base(host))
		if err != nil {
			prepareTerminalOutput(ctx)
			fmt.Fprintln(os.Stderr, "prolewatch-makepkg:", err)
			return 24
		}
		output = append(output, sealed)
		if regularNoFollow(host) {
			hostPaths = append(hostPaths, host)
		}
	}
	if len(hostPaths) > 0 {
		if status := auditAndSeal(ctx, hostPaths, report, service); status != 0 {
			return status
		}
	}
	if len(output) > 0 {
		prepareTerminalOutput(ctx)
		fmt.Fprintln(os.Stdout, strings.Join(output, "\n"))
	}
	return 0
}

func auditAndSeal(ctx context.Context, packages []string, postReport *Report, service *AuditService) int {
	renderer := newTerminalRenderer(service.Config, os.Stderr)
	activityStage(ctx, StageArtifactInspection)
	artifact, status, err := service.ScanArtifacts(ctx, packages, postReport.PackageBase)
	if err != nil {
		prepareTerminalOutput(ctx)
		if service.Config.Overrides.AllowUnsafe && confirmInlineDecision(inlineBypass, nil, err) {
			artifact, err = service.CreateArtifactBypass(packages, postReport.PackageBase, err)
			status = 0
		} else {
			prepareTerminalOutput(ctx)
			fmt.Fprintln(os.Stderr, "prolewatch-makepkg:", err)
			return 25
		}
	}
	prepareTerminalOutput(ctx)
	fmt.Fprintln(os.Stderr, renderer.report(artifact))
	activityReport(ctx, artifact.ReportID)
	if status != 0 {
		mode := classifyInlineDecision(artifact, service.Config)
		if mode != "" && confirmInlineDecision(mode, artifact, nil) {
			tokenPath, err := createInlineToken(mode, artifact, service.Approvals)
			if err != nil {
				prepareTerminalOutput(ctx)
				fmt.Fprintln(os.Stderr, "prolewatch-makepkg:", err)
				return 25
			}
			artifact, status, err = service.ScanArtifacts(ctx, packages, postReport.PackageBase)
			if err != nil && mode == inlineBypass {
				artifact, err = service.CreateArtifactBypass(packages, postReport.PackageBase, err)
				status = 0
			}
			if err != nil {
				_ = service.Approvals.CancelPending(tokenPath)
				prepareTerminalOutput(ctx)
				fmt.Fprintln(os.Stderr, "prolewatch-makepkg:", err)
				return 25
			}
			if err := service.Approvals.CancelPending(tokenPath); err != nil {
				prepareTerminalOutput(ctx)
				fmt.Fprintln(os.Stderr, "prolewatch-makepkg:", err)
				return 25
			}
			prepareTerminalOutput(ctx)
			fmt.Fprintln(os.Stderr, renderer.inlineDecisionResult(mode, artifact))
			activityReport(ctx, artifact.ReportID)
		}
	}
	if status != 0 {
		quarantine := filepath.Join(StateRoot(), "quarantine", artifact.ReportID)
		if err := EnsurePrivateDir(quarantine); err != nil {
			prepareTerminalOutput(ctx)
			fmt.Fprintln(os.Stderr, err)
			return 25
		}
		quarantineFailed := false
		for _, pkg := range packages {
			if err := moveVerified(pkg, filepath.Join(quarantine, filepath.Base(pkg))); err != nil {
				quarantineFailed = true
				prepareTerminalOutput(ctx)
				fmt.Fprintf(os.Stderr, "prolewatch-makepkg: cannot quarantine %s: %v\n", pkg, err)
			}
		}
		if quarantineFailed {
			prepareTerminalOutput(ctx)
			fmt.Fprintln(os.Stderr, "Blocked package archives were not fully quarantined; yay remains blocked.")
			return 25
		}
		prepareTerminalOutput(ctx)
		fmt.Fprintln(os.Stderr, "Blocked package archives moved to", quarantine)
		if status == 10 {
			return 10
		}
		return 25
	}
	var sealed []string
	activityStage(ctx, StageArtifactSealing)
	for _, pkg := range packages {
		destination, err := sealedPath(postReport, filepath.Base(pkg))
		if err != nil {
			return sealFailureWithContext(ctx, packages, sealed, artifact, err)
		}
		if err := EnsurePrivateDir(filepath.Dir(destination)); err != nil {
			return sealFailureWithContext(ctx, packages, sealed, artifact, err)
		}
		if _, err := os.Lstat(destination); err == nil {
			return sealFailureWithContext(ctx, packages, sealed, artifact, fmt.Errorf("refusing to replace existing sealed artifact: %s", destination))
		}
		before, err := HashFileNoFollow(pkg)
		if err != nil {
			return sealFailureWithContext(ctx, packages, sealed, artifact, err)
		}
		expected, err := expectedArtifactHash(artifact, filepath.Base(pkg))
		if err != nil || before != expected {
			if err == nil {
				err = errors.New("artifact changed after its security review")
			}
			return sealFailureWithContext(ctx, packages, sealed, artifact, err)
		}
		if err := moveVerified(pkg, destination); err != nil {
			return sealFailureWithContext(ctx, packages, sealed, artifact, err)
		}
		sealed = append(sealed, destination)
		if err := os.Chmod(destination, 0o400); err != nil {
			return sealFailureWithContext(ctx, packages, sealed, artifact, err)
		}
		after, err := HashFileNoFollow(destination)
		if err != nil || before != after {
			return sealFailureWithContext(ctx, packages, sealed, artifact, errors.New("sealed artifact hash changed"))
		}
		activityStage(ctx, StageArtifactImport)
		importContext, cancelImport := cleanRootWithTimeout(ctx, service.Config.Build.CleanRootPrepareTimeoutSeconds)
		request := cleanRootRequestFor("import-artifact")
		request.PolicyFingerprint = service.PolicyFingerprint
		request.ArtifactPath = destination
		request.ArtifactSHA256 = after
		_, importErr := cleanRootDispatcher(importContext, request)
		cancelImport()
		if importErr != nil {
			return sealFailureWithContext(ctx, packages, sealed, artifact, fmt.Errorf("import sealed dependency artifact: %w", importErr))
		}
		activityStage(ctx, StageArtifactSealing)
	}
	for _, path := range sealed {
		hash, _ := HashFileNoFollow(path)
		artifact.SealedArtifacts = append(artifact.SealedArtifacts, SealedArtifact{path, hash})
	}
	if err := service.Reports.Replace(artifact); err != nil {
		return sealFailureWithContext(ctx, packages, sealed, artifact, err)
	}
	prepareTerminalOutput(ctx)
	if line := renderer.sealedLine(len(sealed)); line != "" {
		fmt.Fprintln(os.Stderr, line)
	}
	return 0
}
func expectedArtifactHash(report *Report, name string) (string, error) {
	if report == nil || filepath.Base(name) != name || name == "" {
		return "", errors.New("invalid artifact manifest lookup")
	}
	result := ""
	for _, raw := range report.Manifest {
		record, err := validateManifestRecord(raw)
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
func sealFailure(packages, sealed []string, artifact *Report, cause error) int {
	return sealFailureWithContext(context.Background(), packages, sealed, artifact, cause)
}

func sealFailureWithContext(ctx context.Context, packages, sealed []string, artifact *Report, cause error) int {
	quarantine := filepath.Join(StateRoot(), "quarantine", artifact.ReportID)
	_ = EnsurePrivateDir(quarantine)
	for _, candidate := range append(append([]string{}, packages...), sealed...) {
		if regularNoFollow(candidate) {
			_ = moveVerified(candidate, filepath.Join(quarantine, filepath.Base(candidate)))
		}
	}
	prepareTerminalOutput(ctx)
	fmt.Fprintln(os.Stderr, "prolewatch-makepkg: artifact sealing failed:", cause)
	return 25
}
func sealedPath(report *Report, name string) (string, error) {
	if report == nil || report.ReportID == "" {
		return "", errors.New("cannot seal an artifact without a report ID")
	}
	if filepath.Base(name) != name || name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return "", errors.New("unsafe package artifact name")
	}
	return filepath.Join(StateRoot(), "sealed", report.ReportID, name), nil
}
func regularNoFollow(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}
func moveVerified(source, destination string) error {
	if !regularNoFollow(source) {
		return fmt.Errorf("refusing to move non-regular artifact: %s", source)
	}
	before, err := HashFileNoFollow(source)
	if err != nil {
		return err
	}
	if err := os.Rename(source, destination); err == nil {
		after, hashErr := HashFileNoFollow(destination)
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
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	after, err := HashFileNoFollow(destination)
	if err != nil || after != before {
		_ = os.Remove(destination)
		return errors.New("quarantine copy verification failed")
	}
	return os.Remove(source)
}
