package audit

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/holgerjh/prolewatch/internal/brief"
	"io"
	"os"
	"strings"
)

type stringList []string

func (s *stringList) String() string         { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error { *s = append(*s, value); return nil }

func RunCLI(ctx context.Context, args []string) int {
	// Exit statuses are intentionally stable for wrappers; status.go names the
	// protocol shared with yay and the helper binaries.
	if len(args) == 0 {
		printUsage()
		return ExitInvalidInvocation
	}
	switch args[0] {
	case "scan":
		cfg, err := LoadConfig("")
		if err != nil {
			return cliError(ExitInvalidInvocation, err)
		}
		return runScan(ctx, cfg, args[1:])
	case "report":
		return runReport(args[1:])
	case "approve":
		return runApproval(args[0], args[1:])
	case "doctor":
		// doctor is the command a person runs when the installation is broken,
		// so it must survive the most common way one breaks. Refusing to start
		// on an unreadable configuration made the missing-configuration failure
		// undiagnosable by the tool whose job is diagnosing it; the load error
		// becomes the first check instead.
		cfg, cfgErr := LoadConfig("")
		if cfgErr != nil {
			cfg = DefaultConfig()
		}
		return runDoctorCommand(ctx, cfg, cfgErr, args[1:])
	case gatePrefixesCommand:
		return RunGatePrefixes(args[1:])
	case gateEnumerateCommand:
		// Internal, and deliberately absent from the usage line: these are the
		// contained halves of the privileged-integration gate, executed by
		// prolewatch inside the build sandbox rather than typed by anyone.
		status, _ := runContainedGateCommand(args)
		return status
	case gateFilterCommand:
		status, _ := runContainedGateCommand(args)
		return status
	case "config-check":
		return runConfigCheck(args[1:])
	case "setup":
		// One command that ends in a known state.
		//
		// `install-hook` writing a file and printing READY says only that a
		// file was written. It does not say whether the sandbox can be built,
		// whether the account has the subordinate IDs the build namespace
		// needs, or whether this yay is one the wrapper has been checked
		// against - and every one of those fails later, inside somebody else's
		// package(), where it reads as a broken AUR package rather than a
		// Prolewatch that was never going to work.
		if len(args) != 1 {
			return cliError(ExitInvalidInvocation, errors.New("setup accepts no arguments"))
		}
		return runSetup(ctx)
	case "install-hook":
		if len(args) != 1 {
			return cliError(ExitInvalidInvocation, errors.New("install-hook accepts no arguments"))
		}
		// Refuse rather than install a hook that cannot work. The hook makes
		// every yay transaction call `prolewatch scan`, so installing it while
		// the configuration is unreadable does not leave the user unprotected -
		// it leaves their package manager unable to install anything, after a
		// branded line saying the setup succeeded.
		if _, err := LoadConfig(""); err != nil {
			return cliError(ExitInvalidInvocation, fmt.Errorf("refusing to install the yay hook: %w", err))
		}
		module, backup, err := InstallHook()
		if err != nil {
			return cliError(ExitStateFailure, err)
		}
		renderer := rendererFor(os.Stdout)
		fmt.Println(renderer.successLine("Installed hook module: " + terminalInline(module, 4096)))
		if backup != "" {
			fmt.Println(renderer.detailLine("Backed up existing init.lua: " + terminalInline(backup, 4096)))
		}
		return ExitOK
	case "uninstall-hook":
		if len(args) != 1 {
			return cliError(ExitInvalidInvocation, errors.New("uninstall-hook accepts no arguments"))
		}
		if err := UninstallHook(); err != nil {
			return cliError(ExitStateFailure, err)
		}
		fmt.Println(rendererFor(os.Stdout).successLine("Removed the managed yay hook; backups were preserved."))
		return ExitOK
	case "version", "--version", "-V":
		fmt.Println("prolewatch", ApplicationVersion)
		return ExitOK
	default:
		printUsage()
		return cliError(ExitInvalidInvocation, fmt.Errorf("unknown command %q", args[0]))
	}
}

func runSetup(ctx context.Context) int {
	cfg, err := LoadConfig("")
	if err != nil {
		return cliError(ExitInvalidInvocation, err)
	}
	renderer := newTerminalRenderer(cfg, os.Stdout)
	// Preflight before changing yay: a failed setup must not leave the package
	// manager pointing at an installation that doctor already knows is unusable.
	checks := checksExcept(doctorChecks(ctx, cfg, false), yayHookCheckName)
	checks = checksExcept(checks, yayEffectiveCheckName)
	if !DoctorOK(checks) {
		fmt.Println(renderer.checks(checks))
		fmt.Println(renderer.detailLine("Setup made no changes: fix the failing checks above, then run prolewatch setup again."))
		return ExitReviewUnavailable
	}
	module, backup, err := InstallHook()
	if err != nil {
		return cliError(ExitStateFailure, err)
	}
	fmt.Println(renderer.successLine("Installed hook module: " + terminalInline(module, 4096)))
	if backup != "" {
		fmt.Println(renderer.detailLine("Backed up existing init.lua: " + terminalInline(backup, 4096)))
	}
	checks = append(checks, yayHookCheck(), yayEffectiveCheck(ctx))
	fmt.Println(renderer.checks(checks))
	if !DoctorOK(checks) {
		// Undo the activation rather than leaving it half-done.
		//
		// The failure this guards is not hypothetical: a yay that renames or
		// stops accepting makepkg_bin rejects the whole configuration and exits
		// 1, so the hook this command just wrote would break every subsequent
		// yay invocation - `yay -S`, `yay -Syu`, all of it. Telling the user to
		// go and repair it by hand, having broken their package manager one line
		// earlier, is not "one command that ends in a known state".
		//
		// UninstallHook removes the managed init.lua block and the module when
		// it still matches the packaged bytes, which is exactly what InstallHook
		// wrote a moment ago. Backups it made are deliberately left in place.
		if err := UninstallHook(); err != nil {
			fmt.Println(renderer.detailLine("Setup could not undo the hook it just installed: " + terminalInline(err.Error(), 2000)))
			fmt.Println(renderer.detailLine("Run prolewatch uninstall-hook before using yay again."))
			return ExitStateFailure
		}
		fmt.Println(renderer.detailLine("Setup removed the hook again; yay is as it was. Fix the failing checks above, then run prolewatch setup again."))
		return ExitReviewUnavailable
	}
	fmt.Println(renderer.detailLine("The next yay -S runs contained. Nothing else has to be done."))
	return ExitOK
}

func checksExcept(checks []Check, name string) []Check {
	filtered := make([]Check, 0, len(checks))
	for _, check := range checks {
		if check.Name != name {
			filtered = append(filtered, check)
		}
	}
	return filtered
}

func runConfigCheck(args []string) int {
	flags := flag.NewFlagSet("config-check", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	path := flags.String("path", SystemConfigPath, "configuration file")
	providerOnly := flags.Bool("provider-only", false, "print only the active provider")
	reviewModeOnly := flags.Bool("review-mode-only", false, "print only the review mode")
	minimumConfidenceOnly := flags.Bool("minimum-confidence-only", false, "print only the minimum confidence")
	terminalStyleOnly := flags.Bool("terminal-style-only", false, "print only the terminal style")
	if err := flags.Parse(args); err != nil {
		return ExitInvalidInvocation
	}
	if flags.NArg() != 0 {
		return cliError(ExitInvalidInvocation, errors.New("unexpected config-check arguments"))
	}
	selected := 0
	for _, value := range []bool{*providerOnly, *reviewModeOnly, *minimumConfidenceOnly, *terminalStyleOnly} {
		if value {
			selected++
		}
	}
	if selected > 1 {
		return cliError(ExitInvalidInvocation, errors.New("config-check output selectors are mutually exclusive"))
	}
	cfg, err := LoadConfig(*path)
	if err != nil {
		return cliError(ExitInvalidInvocation, err)
	}
	if *providerOnly {
		fmt.Println(cfg.Provider)
	} else if *reviewModeOnly {
		fmt.Println(cfg.Review.Mode)
	} else if *minimumConfidenceOnly {
		fmt.Println(cfg.Review.MinimumConfidence)
	} else if *terminalStyleOnly {
		fmt.Println(cfg.Terminal.Style)
	} else {
		detail := fmt.Sprintf("Configuration is valid; review mode: %s; minimum confidence: %s; manual review threshold: %s; active provider: %s; vendor scan depth: %d; build network: phase-scoped interactive prompts; terminal style: %s", cfg.Review.Mode, cfg.Review.MinimumConfidence, cfg.Review.ManualReviewMinimumSeverity, cfg.Provider, cfg.Vendor.ScanDepth, cfg.Terminal.Style)
		fmt.Println(newTerminalRenderer(cfg, os.Stdout).successLine(detail))
	}
	return ExitOK
}

func runScan(ctx context.Context, cfg Config, args []string) int {
	// One entry point serves three distinct gates. Pre/post operate on a directory
	// snapshot; artifact operates on explicit package files. Their argument shapes
	// are kept disjoint so one phase cannot accidentally inherit another's inputs.
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	phase := flags.String("phase", "", "pre, post, or artifact")
	dir := flags.String("dir", "", "directory to scan")
	packageBase := flags.String("package-base", "", "AUR package base")
	yayContextRaw := flags.String("yay-context", "", "bounded JSON context supplied by the yay hook")
	jsonOutput := flags.Bool("json", false, "write the report as JSON")
	interactive := flags.Bool("interactive", false, "offer an exact one-time decision on a real TTY")
	announceTransaction := flags.Bool("announce-transaction", false, "announce the protected yay transaction")
	var packages stringList
	flags.Var(&packages, "package", "package artifact (repeatable)")
	if err := flags.Parse(args); err != nil {
		return ExitInvalidInvocation
	}
	if flags.NArg() != 0 {
		return cliError(ExitInvalidInvocation, errors.New("unexpected positional arguments"))
	}
	var report *Report
	var status int
	base := *packageBase
	var yayContext brief.YayContext
	if *phase == "pre" || *phase == "post" {
		if *dir == "" || *packageBase == "" || len(packages) > 0 {
			return cliError(ExitInvalidInvocation, errors.New("pre/post scans require --dir and --package-base only"))
		}
		var contextErr error
		yayContext, contextErr = DecodeYayContext(*yayContextRaw)
		if contextErr != nil {
			return cliError(ExitInvalidInvocation, contextErr)
		}
	} else if *phase == "artifact" {
		if *dir != "" || len(packages) == 0 || *yayContextRaw != "" {
			return cliError(ExitInvalidInvocation, errors.New("artifact scans require one or more --package arguments"))
		}
		if base == "" {
			base = "artifact"
		}
	} else {
		return cliError(ExitInvalidInvocation, errors.New("--phase must be pre, post, or artifact"))
	}
	if *announceTransaction && (*phase != "pre" || *yayContextRaw == "") {
		return cliError(ExitInvalidInvocation, errors.New("--announce-transaction is valid only for a yay pre-scan"))
	}
	renderer := newTerminalRenderer(cfg, os.Stderr)
	if *announceTransaction {
		if line := renderer.activation(); line != "" {
			fmt.Fprintln(os.Stderr, line)
		}
	}
	progress := newTerminalProgress(renderer, base, *phase)
	if progress != nil {
		defer progress.Close()
	}
	ctx = withTerminalProgress(ctx, progress)
	service, err := auditServiceFactory(ctx, cfg, nil)
	if err != nil {
		prepareTerminalOutput(ctx)
		status = ExitReviewUnavailable
		return cliError(status, err)
	}
	if *phase == "pre" || *phase == "post" {
		report, status, err = service.ScanDirectoryWithContext(ctx, *phase, *dir, *packageBase, yayContext)
	} else {
		report, status, err = service.ScanArtifacts(ctx, packages, base)
	}
	if err != nil {
		prepareTerminalOutput(ctx)
		if status == 0 {
			status = ExitStateFailure
		}
		return cliError(status, err)
	}
	prepareTerminalOutput(ctx)
	// Decide whether a prompt is coming before printing, so a briefing that is
	// about to be followed by the same question does not send the user to
	// another shell to answer it.
	mode := ""
	if status != 0 && *interactive {
		mode = classifyInlineDecision(report, cfg)
	}
	handoff := *interactive && status == 0 && (*phase == "pre" || *phase == "post")
	// Branded full and compact results both own their handoff now. Plain output
	// keeps the explicit follow-up line below for scripts and redirected logs.
	handoffRendered := renderer.enabled() && handoff
	fmt.Fprintln(os.Stderr, renderer.phaseResult(report, status, mode != "" && interactiveDecisionAvailable(), handoff))
	if status != 0 && *interactive {
		// Approval is deliberately two-pass: create a content-bound pending token,
		// rerun the complete gate so policy consumes it, then remove any leftover
		// token on success or failure.
		if mode != "" && confirmInlineDecision(mode, report, nil, *dir, cfg.Review.ManualReviewMinimumSeverity) {
			tokenPath, createErr := createInlineToken(mode, report, service.Approvals)
			if createErr != nil {
				prepareTerminalOutput(ctx)
				return cliError(ExitStateFailure, createErr)
			}
			if *phase == "pre" || *phase == "post" {
				report, status, err = service.ScanDirectoryWithContext(ctx, *phase, *dir, *packageBase, yayContext)
			} else {
				report, status, err = service.ScanArtifacts(ctx, packages, base)
			}
			if err != nil {
				_ = service.Approvals.CancelPending(tokenPath)
				prepareTerminalOutput(ctx)
				return cliError(ExitStateFailure, err)
			}
			if cancelErr := service.Approvals.CancelPending(tokenPath); cancelErr != nil {
				prepareTerminalOutput(ctx)
				return cliError(ExitStateFailure, cancelErr)
			}
			prepareTerminalOutput(ctx)
			fmt.Fprintln(os.Stderr, renderer.inlineDecisionResult(mode, report))
		}
	}
	if status == 0 && *interactive && (*phase == "pre" || *phase == "post") && !handoffRendered {
		// The handoff is explicit even after an uneventful compact report. yay may
		// immediately switch to dependency prompts or sudo, so a subtle footer
		// makes it look as though Prolewatch silently disappeared mid-transaction.
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, renderer.guardComplete(report))
		fmt.Fprintln(os.Stderr)
	}
	if *jsonOutput {
		raw, _ := json.Marshal(report)
		fmt.Println(string(raw))
	}
	return status
}
func runReport(args []string) int {
	flags := flag.NewFlagSet("report", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	latest := flags.Bool("latest", false, "show latest report")
	if err := flags.Parse(args); err != nil {
		return ExitInvalidInvocation
	}
	store := NewReportStore()
	var report *Report
	var err error
	if *latest {
		if flags.NArg() != 0 {
			return cliError(ExitInvalidInvocation, errors.New("--latest does not accept a report id"))
		}
		report, err = store.Latest()
	} else {
		if flags.NArg() != 1 {
			return cliError(ExitInvalidInvocation, errors.New("report requires REPORT_ID or --latest"))
		}
		report, err = store.Load(flags.Arg(0))
	}
	if err != nil {
		return cliError(ExitInvalidInvocation, err)
	}
	fmt.Println(rendererFor(os.Stdout).report(report))
	return ExitOK
}
func runApproval(command string, args []string) int {
	if len(args) != 1 {
		return cliError(ExitInvalidInvocation, fmt.Errorf("%s requires REPORT_ID", command))
	}
	report, err := NewReportStore().Load(args[0])
	if err != nil {
		return cliError(ExitInvalidInvocation, err)
	}
	kind := "approval"
	if !report.ApprovalEligible {
		// The refusal is correct and stays. What it lacked was anywhere to go
		// next: a user who reaches this after a structural failure has now been
		// turned away twice with no reason and no route, which is exactly the
		// state that makes removing the boundary look like the only option.
		renderer := rendererFor(os.Stderr)
		fmt.Fprintln(os.Stderr, renderer.errorLine("This report is not eligible for an approval."))
		if report.Decision != "block" {
			// Not a structural failure at all: nothing blocked, so there is
			// nothing an approval would authorise.
			fmt.Fprintln(os.Stderr, renderer.detailLine("This report did not block anything, so there is nothing to approve."))
			return ExitStateFailure
		}
		fmt.Fprintln(os.Stderr, renderer.detailLine("A structural failure is decided from the package's own bytes, so no approval crosses it."))
		for _, class := range structuralRecovery(report) {
			fmt.Fprintln(os.Stderr, renderer.detailLine(class.title))
			for _, step := range class.steps {
				fmt.Fprintln(os.Stderr, renderer.detailLine("  "+step))
			}
		}
		return ExitStateFailure
	}
	path, err := InteractiveApproval(report, kind, NewApprovalStore())
	if err != nil {
		return cliError(ExitStateFailure, err)
	}
	fmt.Printf("Created one-time %s token: %s\n", kind, path)
	return ExitOK
}
func runDoctorCommand(ctx context.Context, cfg Config, cfgErr error, args []string) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	jsonOutput := flags.Bool("json", false, "JSON output")
	noProbe := flags.Bool("no-probe", false, "skip a real provider request")
	if err := flags.Parse(args); err != nil {
		return ExitInvalidInvocation
	}
	if flags.NArg() != 0 {
		return cliError(ExitInvalidInvocation, errors.New("unexpected doctor arguments"))
	}
	// --no-probe still validates the stored semantic attestation; it skips only
	// the live provider request that can consume network/quota.
	var configuration []Check
	if cfgErr != nil {
		// First, and required: every other check was run against defaults, so
		// the reader has to know the file itself never loaded.
		configuration = []Check{{Name: "configuration", OK: false, Required: true,
			Detail: terminalInline(cfgErr.Error(), 2000)}}
	}
	renderer := newTerminalRenderer(cfg, os.Stdout)
	// Stream only to a terminal. A pipe gets the block it has always got, so
	// anything parsing this output is unaffected, and --json is untouched.
	stream := !*jsonOutput && renderer.enabled()
	emit := func(Check) {}
	if stream {
		fmt.Println(renderer.checksHeading())
		for _, check := range configuration {
			fmt.Println(renderer.checkLine(check))
		}
		emit = func(check Check) { fmt.Println(renderer.checkLine(check)) }
	}
	checks := append(configuration, RunDoctorStream(ctx, cfg, !*noProbe, emit)...)
	switch {
	case *jsonOutput:
		raw, _ := json.MarshalIndent(checks, "", "  ")
		fmt.Println(string(raw))
	case stream:
		fmt.Println(renderer.checksVerdict(checks))
	default:
		fmt.Println(renderer.checks(checks))
	}
	if DoctorOK(checks) {
		return ExitOK
	}
	return ExitReviewUnavailable
}
func cliError(code int, err error) int {
	if code == 0 {
		code = ExitStateFailure
	}
	renderer := rendererFor(os.Stderr)
	if renderer.enabled() {
		fmt.Fprintln(os.Stderr, renderer.errorLine(terminalInline(err.Error(), 4000)))
	} else {
		fmt.Fprintln(os.Stderr, "prolewatch:", err)
	}
	return code
}

func rendererFor(out *os.File) terminalRenderer {
	return rendererForWriter(out)
}

func rendererForWriter(out io.Writer) terminalRenderer {
	cfg, err := LoadConfig("")
	if err != nil {
		cfg = DefaultConfig()
	}
	return newTerminalRenderer(cfg, out)
}
func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: prolewatch <setup|scan|report|approve|doctor|config-check|install-hook|uninstall-hook|security-scenarios|version> [options]")
}
