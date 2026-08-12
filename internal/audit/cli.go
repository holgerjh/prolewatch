package audit

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

type stringList []string

func (s *stringList) String() string         { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error { *s = append(*s, value); return nil }

func RunCLI(ctx context.Context, args []string) int {
	if len(args) == 0 {
		printUsage()
		return 20
	}
	switch args[0] {
	case "scan":
		cfg, err := LoadConfig("")
		if err != nil {
			return cliError(20, err)
		}
		return runScan(ctx, cfg, args[1:])
	case "report":
		return runReport(args[1:])
	case "approve", "allow-network":
		return runApproval(args[0], args[1:])
	case "doctor":
		cfg, err := LoadConfig("")
		if err != nil {
			return cliError(20, err)
		}
		return runDoctorCommand(ctx, cfg, args[1:])
	case "config-check":
		return runConfigCheck(args[1:])
	case "config-migrate":
		return runConfigMigrate(args[1:])
	case "clean-root":
		return runCleanRootCLI(ctx, args[1:])
	case "web":
		return runWeb(ctx, args[1:])
	case "install-hook":
		if len(args) != 1 {
			return cliError(20, errors.New("install-hook accepts no arguments"))
		}
		module, backup, err := InstallHook()
		if err != nil {
			return cliError(23, err)
		}
		renderer := rendererFor(os.Stdout)
		fmt.Println(renderer.successLine("Installed hook module: " + terminalInline(module, 4096)))
		if backup != "" {
			fmt.Println(renderer.detailLine("Backed up existing init.lua: " + terminalInline(backup, 4096)))
		}
		return 0
	case "uninstall-hook":
		if len(args) != 1 {
			return cliError(20, errors.New("uninstall-hook accepts no arguments"))
		}
		if err := UninstallHook(); err != nil {
			return cliError(23, err)
		}
		fmt.Println(rendererFor(os.Stdout).successLine("Removed the managed yay hook; backups were preserved."))
		return 0
	case "version", "--version", "-V":
		fmt.Println("prolewatch", ApplicationVersion)
		return 0
	default:
		printUsage()
		return cliError(20, fmt.Errorf("unknown command %q", args[0]))
	}
}

func runConfigMigrate(args []string) int {
	flags := flag.NewFlagSet("config-migrate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	path := flags.String("path", SystemConfigPath, "configuration file")
	reviewMode := flags.String("review-mode", "", "set review mode while migrating (ai or deterministic-only)")
	minimumConfidence := flags.String("minimum-confidence", "", "set minimum AI confidence (low, medium, or high)")
	terminalStyle := flags.String("terminal-style", "", "set terminal style (brand or plain)")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 20
	}
	cfg, err := MigrateConfig(*path)
	if err != nil {
		return cliError(20, err)
	}
	if *reviewMode != "" {
		cfg.Review.Mode = *reviewMode
	}
	if *minimumConfidence != "" {
		cfg.Review.MinimumConfidence = *minimumConfidence
	}
	if *terminalStyle != "" {
		cfg.Terminal.Style = *terminalStyle
	}
	if err := cfg.Validate(); err != nil {
		return cliError(20, err)
	}
	raw, err := CanonicalJSON(cfg)
	if err != nil {
		return cliError(20, err)
	}
	fmt.Println(string(raw))
	return 0
}

func runConfigCheck(args []string) int {
	flags := flag.NewFlagSet("config-check", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	path := flags.String("path", SystemConfigPath, "configuration file")
	providerOnly := flags.Bool("provider-only", false, "print only the active provider")
	reviewModeOnly := flags.Bool("review-mode-only", false, "print only the review mode")
	minimumConfidenceOnly := flags.Bool("minimum-confidence-only", false, "print only the minimum confidence")
	unsafeOverridesOnly := flags.Bool("unsafe-overrides-only", false, "print whether unsafe overrides are enabled")
	terminalStyleOnly := flags.Bool("terminal-style-only", false, "print only the terminal style")
	if err := flags.Parse(args); err != nil {
		return 20
	}
	if flags.NArg() != 0 {
		return cliError(20, errors.New("unexpected config-check arguments"))
	}
	selected := 0
	for _, value := range []bool{*providerOnly, *reviewModeOnly, *minimumConfidenceOnly, *unsafeOverridesOnly, *terminalStyleOnly} {
		if value {
			selected++
		}
	}
	if selected > 1 {
		return cliError(20, errors.New("config-check output selectors are mutually exclusive"))
	}
	cfg, err := LoadConfig(*path)
	if err != nil {
		return cliError(20, err)
	}
	if *providerOnly {
		fmt.Println(cfg.Provider)
	} else if *reviewModeOnly {
		fmt.Println(cfg.Review.Mode)
	} else if *minimumConfidenceOnly {
		fmt.Println(cfg.Review.MinimumConfidence)
	} else if *unsafeOverridesOnly {
		fmt.Println(cfg.Overrides.AllowUnsafe)
	} else if *terminalStyleOnly {
		fmt.Println(cfg.Terminal.Style)
	} else {
		detail := fmt.Sprintf("Configuration is valid; review mode: %s; minimum confidence: %s; active provider: %s; vendor scan depth: %d; automatic known-tool network: %t; unsafe overrides: %t; terminal style: %s", cfg.Review.Mode, cfg.Review.MinimumConfidence, cfg.Provider, cfg.Vendor.ScanDepth, cfg.Network.AutoEnableKnownTools, cfg.Overrides.AllowUnsafe, cfg.Terminal.Style)
		fmt.Println(newTerminalRenderer(cfg, os.Stdout).successLine(detail))
	}
	return 0
}

func runScan(ctx context.Context, cfg Config, args []string) (status int) {
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
		return 20
	}
	if flags.NArg() != 0 {
		return cliError(20, errors.New("unexpected positional arguments"))
	}
	var report *Report
	base := *packageBase
	var yayContext YayContext
	if *phase == "pre" || *phase == "post" {
		if *dir == "" || *packageBase == "" || len(packages) > 0 {
			return cliError(20, errors.New("pre/post scans require --dir and --package-base only"))
		}
		var contextErr error
		yayContext, contextErr = DecodeYayContext(*yayContextRaw)
		if contextErr != nil {
			return cliError(20, contextErr)
		}
	} else if *phase == "artifact" {
		if *dir != "" || len(packages) == 0 || *yayContextRaw != "" {
			return cliError(20, errors.New("artifact scans require one or more --package arguments"))
		}
		if base == "" {
			base = "artifact"
		}
	} else {
		return cliError(20, errors.New("--phase must be pre, post, or artifact"))
	}
	if *announceTransaction && (*phase != "pre" || *yayContextRaw == "") {
		return cliError(20, errors.New("--announce-transaction is valid only for a yay pre-scan"))
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
	recorder, activityErr := NewActivityRecorder(base, "scan", *phase)
	if activityErr != nil {
		prepareTerminalOutput(ctx)
		fmt.Fprintln(os.Stderr, "prolewatch: cannot start activity tracking:", activityErr)
	}
	if recorder != nil {
		defer func() { recorder.Finish(activityResult(status), "") }()
		ctx = withActivity(ctx, recorder)
	}
	service, err := auditServiceFactory(ctx, cfg, nil)
	if err != nil {
		prepareTerminalOutput(ctx)
		status = 22
		return cliError(status, err)
	}
	if *phase == "pre" || *phase == "post" {
		report, status, err = service.ScanDirectoryWithContext(ctx, *phase, *dir, *packageBase, yayContext)
	} else {
		report, status, err = service.ScanArtifacts(ctx, packages, base)
	}
	if err != nil {
		prepareTerminalOutput(ctx)
		if *interactive && cfg.Overrides.AllowUnsafe && (*phase == "pre" || *phase == "post") && confirmInlineDecision(inlineBypass, nil, err) {
			bypassed, bypassErr := service.CreateUnscannedBypass(*dir, *phase, *packageBase, yayContext, err)
			if bypassErr != nil {
				return cliError(23, bypassErr)
			}
			fmt.Fprintln(os.Stderr, renderer.report(bypassed))
			fmt.Fprintln(os.Stderr, renderer.guardComplete(bypassed))
			fmt.Fprintln(os.Stderr)
			if *jsonOutput {
				raw, _ := json.Marshal(bypassed)
				fmt.Println(string(raw))
			}
			return 0
		}
		if status == 0 {
			status = 23
		}
		return cliError(status, err)
	}
	prepareTerminalOutput(ctx)
	fmt.Fprintln(os.Stderr, renderer.report(report))
	if status != 0 && *interactive {
		mode := classifyInlineDecision(report, cfg)
		if mode != "" && confirmInlineDecision(mode, report, nil) {
			tokenPath, createErr := createInlineToken(mode, report, service.Approvals)
			if createErr != nil {
				prepareTerminalOutput(ctx)
				return cliError(23, createErr)
			}
			if *phase == "pre" || *phase == "post" {
				report, status, err = service.ScanDirectoryWithContext(ctx, *phase, *dir, *packageBase, yayContext)
			} else {
				report, status, err = service.ScanArtifacts(ctx, packages, base)
			}
			if err != nil {
				_ = service.Approvals.CancelPending(tokenPath)
				prepareTerminalOutput(ctx)
				return cliError(23, err)
			}
			if cancelErr := service.Approvals.CancelPending(tokenPath); cancelErr != nil {
				prepareTerminalOutput(ctx)
				return cliError(23, cancelErr)
			}
			prepareTerminalOutput(ctx)
			fmt.Fprintln(os.Stderr, renderer.inlineDecisionResult(mode, report))
		}
	}
	if status == 0 && *interactive && (*phase == "pre" || *phase == "post") {
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
		return 20
	}
	store := NewReportStore()
	var report *Report
	var err error
	if *latest {
		if flags.NArg() != 0 {
			return cliError(20, errors.New("--latest does not accept a report id"))
		}
		report, err = store.Latest()
	} else {
		if flags.NArg() != 1 {
			return cliError(20, errors.New("report requires REPORT_ID or --latest"))
		}
		report, err = store.Load(flags.Arg(0))
	}
	if err != nil {
		return cliError(20, err)
	}
	fmt.Println(rendererFor(os.Stdout).report(report))
	return 0
}
func runApproval(command string, args []string) int {
	if len(args) != 1 {
		return cliError(20, fmt.Errorf("%s requires REPORT_ID", command))
	}
	report, err := NewReportStore().Load(args[0])
	if err != nil {
		return cliError(20, err)
	}
	kind := "approval"
	if command == "approve" && !report.ApprovalEligible {
		return cliError(23, errors.New("this report is not eligible for an approval"))
	}
	if command == "allow-network" {
		kind = "network"
		if !report.NetworkEligible {
			return cliError(23, errors.New("this report is not eligible for a network approval"))
		}
	}
	path, err := InteractiveApproval(report, kind, NewApprovalStore())
	if err != nil {
		return cliError(23, err)
	}
	fmt.Printf("Created one-time %s token: %s\n", kind, path)
	return 0
}
func runDoctorCommand(ctx context.Context, cfg Config, args []string) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	jsonOutput := flags.Bool("json", false, "JSON output")
	noProbe := flags.Bool("no-probe", false, "skip a real provider request")
	if err := flags.Parse(args); err != nil {
		return 20
	}
	if flags.NArg() != 0 {
		return cliError(20, errors.New("unexpected doctor arguments"))
	}
	checks := RunDoctor(ctx, cfg, !*noProbe)
	if *jsonOutput {
		raw, _ := json.MarshalIndent(checks, "", "  ")
		fmt.Println(string(raw))
	} else {
		fmt.Println(newTerminalRenderer(cfg, os.Stdout).checks(checks))
	}
	if DoctorOK(checks) {
		return 0
	}
	return 22
}
func cliError(code int, err error) int {
	if code == 0 {
		code = 23
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
	fmt.Fprintln(os.Stderr, "Usage: prolewatch <scan|report|approve|allow-network|doctor|web|clean-root|config-check|config-migrate|install-hook|uninstall-hook|security-scenarios|version> [options]")
}
