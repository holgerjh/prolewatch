package audit

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTerminalCapabilityMatrix(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		present map[string]bool
		want    terminalCapabilities
	}{
		{name: "dumb", env: map[string]string{"TERM": "dumb"}, want: terminalCapabilities{}},
		{name: "truecolor unicode", env: map[string]string{"TERM": "xterm-256color", "COLORTERM": "truecolor", "LANG": "en_US.UTF-8"}, want: terminalCapabilities{Interactive: true, Unicode: true, Color: terminalColorTrue}},
		{name: "256 ascii", env: map[string]string{"TERM": "screen-256color", "LANG": "C"}, want: terminalCapabilities{Interactive: true, Color: terminalColor256}},
		{name: "sixteen", env: map[string]string{"TERM": "xterm", "LANG": "C.UTF-8"}, want: terminalCapabilities{Interactive: true, Unicode: true, Color: terminalColor16}},
		{name: "no color by presence", env: map[string]string{"TERM": "xterm-256color", "LANG": "C.UTF-8"}, present: map[string]bool{"NO_COLOR": true}, want: terminalCapabilities{Interactive: true, Unicode: true, Color: terminalColorNone}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			getenv := func(key string) string { return test.env[key] }
			lookup := func(key string) (string, bool) { return test.env[key], test.present[key] || test.env[key] != "" }
			if got := terminalEnvironmentCapabilities(getenv, lookup); got != test.want {
				t.Fatalf("capabilities=%+v, want %+v", got, test.want)
			}
		})
	}
}

func TestTerminalProgressShowsCommandAndOneOfflineHint(t *testing.T) {
	var output bytes.Buffer
	renderer := terminalRendererWithCapabilities(&output, terminalCapabilities{Interactive: true, Unicode: true})
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	p := &terminalProgress{
		renderer: renderer, package_: "demo", phase: "prepare", stage: StageSandboxExecution,
		stageAt: now.Add(-16 * time.Second), command: "makepkg --nobuild", offline: true,
		now: func() time.Time { return now }, stop: make(chan struct{}), done: make(chan struct{}),
	}
	p.draw(true)
	p.lastDraw = time.Time{}
	p.draw(true)
	rendered := output.String()
	if !strings.Contains(rendered, "command makepkg --nobuild") || !strings.Contains(rendered, "still running") || !strings.Contains(rendered, "only after a concrete fetch failure") {
		t.Fatalf("progress omitted command or offline hint: %q", rendered)
	}
	if strings.Count(rendered, "still running") != 1 {
		t.Fatalf("offline hint was not one-shot: %q", rendered)
	}
}

func TestTerminalProgressExplainsPrefetchedOfflineBuild(t *testing.T) {
	var output bytes.Buffer
	renderer := terminalRendererWithCapabilities(&output, terminalCapabilities{Interactive: true, Unicode: true})
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	p := &terminalProgress{
		renderer: renderer, package_: "demo", phase: "build", stage: StageSandboxExecution,
		stageAt: now.Add(-16 * time.Second), command: "makepkg --noextract", offline: true, prefetched: true,
		now: func() time.Time { return now }, stop: make(chan struct{}), done: make(chan struct{}),
	}
	p.draw(true)
	rendered := output.String()
	if !strings.Contains(rendered, "locked dependencies were prefetched") || !strings.Contains(rendered, "compilation can take a while") || strings.Contains(rendered, "fetch failure") {
		t.Fatalf("prefetched build hint was misleading: %q", rendered)
	}
}

func TestTerminalProgressShowsSanitizedLiveSandboxActivity(t *testing.T) {
	var output bytes.Buffer
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	p := &terminalProgress{
		renderer: terminalRendererWithCapabilities(&output, terminalCapabilities{Interactive: true, Unicode: true}),
		package_: "demo", phase: "build", stage: StageSandboxExecution, command: "makepkg --noextract",
		stageAt: now, now: func() time.Time { return now }, stop: make(chan struct{}), done: make(chan struct{}),
	}
	p.ObserveOutput(commandStdout, []byte("Compiling aws-"))
	p.ObserveOutput(commandStdout, []byte("lc-sys v0.40.0\nnext partial"))
	line := p.lineLocked(now)
	if !strings.Contains(line, "live Compiling aws-lc-sys v0.40.0") || strings.Contains(line, "command makepkg") {
		t.Fatalf("progress did not replace the wrapper command with live activity: %q", line)
	}
	p.ObserveOutput(commandStderr, []byte("\x1b[2JPROLEWATCH BLOCK\n"))
	line = p.lineLocked(now)
	if !strings.Contains(line, `live \u001b[2JPROLEWATCH BLOCK`) || strings.Contains(line, "\x1b[2JPROLEWATCH BLOCK") {
		t.Fatalf("sandbox output could inject terminal control sequences: %q", line)
	}
}

func TestTerminalReportExplainsAutomaticKnownToolNetwork(t *testing.T) {
	var output bytes.Buffer
	renderer := terminalRendererWithCapabilities(&output, terminalCapabilities{Interactive: true, Unicode: true})
	renderer.autoEnableKnownTools = true
	report := &Report{
		ReportID: "20260816T120000Z-aaaaaaaaaaaa-bbbbbbbb", PackageBase: "demo", Phase: "post", Decision: "allow", NetworkEligible: true,
		Reviewer: ReviewerReport{Mode: ReviewModeDeterministicOnly}, Findings: []Finding{{RuleID: "shell-known-network-step-prepare", Evidence: "cargo fetch --locked"}},
	}
	rendered := renderer.report(report)
	if !strings.Contains(rendered, "network auto-detected") || !strings.Contains(rendered, "cargo fetch --locked") || strings.Contains(rendered, "prolewatch allow-network") {
		t.Fatalf("automatic network policy was not explained: %q", rendered)
	}
}

func TestTerminalRendererPresentationBranches(t *testing.T) {
	var output bytes.Buffer
	trueColor := terminalRendererWithCapabilities(&output, terminalCapabilities{Interactive: true, Unicode: true, Color: terminalColorTrue})
	color256 := terminalRendererWithCapabilities(&output, terminalCapabilities{Interactive: true, Color: terminalColor256})
	color16 := terminalRendererWithCapabilities(&output, terminalCapabilities{Interactive: true, Color: terminalColor16})
	for _, rendered := range []string{
		trueColor.paint("blue", "blue"), color256.paint("amber", "amber"), color16.paint("green", "green"), color16.paint("unknown", "plain"),
		trueColor.activation(), trueColor.successLine("done"), trueColor.detailLine("detail"), trueColor.errorLine("failure"), trueColor.blockLine("blocked"), trueColor.sealedLine(2),
	} {
		if rendered == "" {
			t.Fatal("presentation branch rendered an empty value")
		}
	}
	if got := trueColor.paint("blue", "brand"); !strings.Contains(got, "38;2;23;147;209") {
		t.Fatalf("true-color brand accent is not Arch blue: %q", got)
	}
	plain := terminalRendererWithCapabilities(&output, terminalCapabilities{})
	if plain.activation() != "" || plain.sealedLine(1) != "" || plain.successLine("ok") != "ok" || plain.detailLine("detail") != "detail" || plain.blockLine("blocked") != "blocked" || plain.errorLine("bad") != "prolewatch: bad" {
		t.Fatal("plain presentation did not preserve legacy messages")
	}

	line := 7
	report := &Report{
		ReportID: "20260816T120000Z-aaaaaaaaaaaa-bbbbbbbb", PackageBase: "demo", Phase: "post", Decision: "allow", UnsafeBypass: true,
		Disposition: "unsafe_bypass", Summary: "explicit bypass", NetworkEligible: true, ContentHash: strings.Repeat("a", 64),
		Reviewer: ReviewerReport{Mode: ReviewModeDeterministicOnly}, Coverage: Coverage{FilesSeen: 12, BytesSeen: 12},
		Findings: []Finding{{Severity: "critical", Source: "deterministic", Category: "persistence", File: "PKGBUILD", Line: &line, Rationale: "reason", Evidence: "evidence"}},
	}
	if rendered := trueColor.report(report); !strings.Contains(rendered, "[ BYPASS ]") || !strings.Contains(rendered, "CRITICAL") || !strings.Contains(rendered, "network:") {
		t.Fatalf("allow/bypass report branches missing: %q", rendered)
	}
	report.Decision, report.UnsafeBypass, report.NetworkEligible, report.ApprovalEligible, report.UnsafeBypassEligible = "block", false, false, true, true
	if rendered := trueColor.report(report); !strings.Contains(rendered, "override:") || !strings.Contains(rendered, "unsafe bypass:") {
		t.Fatalf("blocked report actions missing: %q", rendered)
	}

	ready := trueColor.checks([]Check{{Name: "required", OK: true, Required: true, Detail: "ready"}})
	blocked := trueColor.checks([]Check{{Name: "required", Required: true, Detail: "failed"}, {Name: "optional", Required: false, Detail: "missing"}})
	if !strings.Contains(ready, "[ READY ]") || !strings.Contains(blocked, "[ BLOCK ]") || !strings.Contains(blocked, "[WARN]") {
		t.Fatalf("doctor presentation branches missing: ready=%q blocked=%q", ready, blocked)
	}
	if plain.checks(nil) != RenderChecks(nil) {
		t.Fatal("plain doctor rendering changed")
	}

	presentation := NewTerminalPresentation(DefaultConfig(), &output)
	// A bytes.Buffer is deliberately non-interactive.
	if presentation.Enabled() {
		t.Fatal("buffer unexpectedly detected as a terminal")
	}
	presentation = TerminalPresentation{renderer: trueColor}
	if !strings.Contains(presentation.Header("HEADER", "READY", true), "HEADER") ||
		!strings.Contains(presentation.Header("HEADER", "BLOCK", false), "BLOCK") ||
		!strings.Contains(presentation.Status("PASS", "message", true), "PASS") ||
		!strings.Contains(presentation.Status("FAIL", "message", false), "FAIL") ||
		!strings.Contains(presentation.Detail("detail"), "detail") {
		t.Fatal("shared presentation helpers omitted content")
	}
}

func TestTerminalReportUsesBrandGrammarAndSanitizesContent(t *testing.T) {
	report := &Report{
		ReportID: "20260816T120000Z-aaaaaaaaaaaa-bbbbbbbb", PackageBase: "demo\x1b[31m", Phase: "pre",
		Decision: "block", Disposition: "blocked", ContentHash: strings.Repeat("a", 64),
		Summary: "blocked\nspoofed", Reviewer: ReviewerReport{Mode: ReviewModeAI, Provider: "codex", Model: "gpt", MinimumConfidence: "high", Verdicts: []Verdict{{CoverageNotes: []string{"generated file was unavailable\nspoofed"}}}},
		Coverage: Coverage{FilesSeen: 4, BytesSeen: 4096, SelectedFiles: 2},
	}
	renderer := terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{Interactive: true, Unicode: true, Color: terminalColorTrue})
	rendered := renderer.report(report)
	for _, want := range []string{"◆", "INSPECTION", "demo\\u001b[31m", " / pre", "[ BLOCK ]", "AI coverage gaps", "batch 1", "generated file was unavailable spoofed", "4 files", "4.0 KiB"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("rendered report is missing %q: %q", want, rendered)
		}
	}
	if strings.Contains(rendered, "demo\x1b[31m") || strings.Contains(rendered, "blocked\nspoofed") || strings.Contains(rendered, "unavailable\nspoofed") {
		t.Fatalf("terminal control content was not flattened: %q", rendered)
	}
	plain := RenderReport(report)
	for _, want := range []string{"AI coverage gaps:", "Batch 1: generated file was unavailable spoofed"} {
		if !strings.Contains(plain, want) {
			t.Fatalf("plain report is missing %q: %q", want, plain)
		}
	}
}

func TestTerminalInlineDecisionResultIsCompactAndNamesPackage(t *testing.T) {
	report := &Report{
		ReportID: "20260816T120000Z-aaaaaaaaaaaa-bbbbbbbb", PackageBase: "demo", Phase: "pre",
		Decision: "allow", Disposition: "override", Overridden: true,
		Findings: []Finding{{Severity: "high", Source: "ai", Category: "other", File: "PKGBUILD", Rationale: "already shown"}},
	}
	renderer := terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{Interactive: true, Unicode: true, Color: terminalColorTrue})
	rendered := renderer.inlineDecisionResult(inlineOverride, report)
	for _, want := range []string{"OVERRIDE ACCEPTED", "demo / pre", "[ ALLOW ]", "exact one-time user override", report.ReportID} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("inline result is missing %q: %q", want, rendered)
		}
	}
	if strings.Contains(rendered, "already shown") || !strings.HasSuffix(rendered, "\n") {
		t.Fatalf("inline result repeated the report or omitted separation: %q", rendered)
	}
	plain := terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{})
	if got := plain.inlineDecisionResult(inlineConfidence, report); !strings.Contains(got, "APPROVAL ACCEPTED: demo / pre") || !strings.HasSuffix(got, "\n") {
		t.Fatalf("plain inline result is unclear: %q", got)
	}
}

func TestTerminalGuardCompletionSeparatesYayOutput(t *testing.T) {
	report := &Report{PackageBase: "demo", Phase: "pre"}
	renderer := terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{Interactive: true, Unicode: true, Color: terminalColorTrue})
	rendered := renderer.guardComplete(report)
	for _, want := range []string{"└─", "guard complete", "demo / pre", "yay resumes"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("guard completion is missing %q: %q", want, rendered)
		}
	}
	plain := terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{})
	if got, want := plain.guardComplete(report), "Guard complete: demo / pre; control returned to yay"; got != want {
		t.Fatalf("plain guard completion=%q, want %q", got, want)
	}
	if got := renderer.guardComplete(nil); got != "" {
		t.Fatalf("nil report produced guard completion: %q", got)
	}
}

func TestTerminalPlainAndNoColorFallbacks(t *testing.T) {
	report := &Report{PackageBase: "demo", Phase: "pre", Decision: "allow", Disposition: "allowed", Reviewer: ReviewerReport{Mode: ReviewModeDeterministicOnly}}
	plain := terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{})
	if got, want := plain.report(report), RenderReport(report); got != want {
		t.Fatalf("non-interactive rendering changed\ngot:  %q\nwant: %q", got, want)
	}
	noColor := terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{Interactive: true, Unicode: true})
	if got := noColor.report(report); !strings.Contains(got, "◆") || strings.Contains(got, "\x1b[") {
		t.Fatalf("NO_COLOR grammar mismatch: %q", got)
	}
	ascii := terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{Interactive: true, Color: terminalColor16})
	if got := ascii.report(report); !strings.Contains(got, "#") || strings.Contains(got, "◆") {
		t.Fatalf("ASCII fallback mismatch: %q", got)
	}
}

func TestTerminalProgressUsesRealCountersBatchesAndDeadline(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	p := &terminalProgress{
		renderer: terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{Interactive: true, Unicode: true}),
		package_: "demo", phase: "post", stage: StageAIReview, batch: 2, batches: 3,
		deadline: now.Add(90 * time.Second), scan: ActivityScanProgress{FilesSeen: 42, BytesSeen: 2048, ArchivesSeen: 2, ArchiveEntries: 7}, now: func() time.Time { return now },
	}
	line := p.lineLocked(now)
	for _, want := range []string{"demo/post", "ai review", "batch 2/3", "42 files", "2.0 KiB", "2 archives", "7 entries", "deadline 1m30s"} {
		if !strings.Contains(line, want) {
			t.Fatalf("progress line is missing %q: %q", want, line)
		}
	}
	if strings.Contains(strings.ToLower(line), "stuck") || strings.Contains(line, "%") {
		t.Fatalf("progress line made an unsupported progress claim: %q", line)
	}
	p.frame++
	next := p.lineLocked(now)
	if line == next || !strings.Contains(line, "◐") || !strings.Contains(next, "◓") {
		t.Fatalf("progress wheel did not advance: first=%q next=%q", line, next)
	}
	ascii := &terminalProgress{renderer: terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{Interactive: true}), stage: StageInitializing}
	if got := ascii.lineLocked(now); !strings.Contains(got, "|") || strings.Contains(got, "◐") {
		t.Fatalf("ASCII progress wheel mismatch: %q", got)
	}
}

func TestTerminalProgressLifecycleAndActivityBridge(t *testing.T) {
	var output bytes.Buffer
	renderer := terminalRendererWithCapabilities(&output, terminalCapabilities{Interactive: true, Unicode: true})
	progress := newTerminalProgress(renderer, "demo", "pre")
	if progress == nil {
		t.Fatal("interactive progress was not created")
	}
	ctx := withTerminalProgress(context.Background(), progress)
	if terminalProgressFrom(ctx) != progress || terminalProgressFrom(nil) != nil {
		t.Fatal("terminal progress context did not round-trip")
	}
	activityTimedStage(ctx, StageDeterministicScan, 30)
	activityScan(ctx, ActivityScanProgress{Operation: ScanOperationInventory, FilesSeen: 3, BytesSeen: 1024}, true)
	activityAI(ctx, 1, 2, 60)
	progress.SetPackage("renamed")
	prepareTerminalOutput(ctx)
	activityStage(ctx, StageComplete)
	progress.Close()
	progress.Close()
	if !strings.Contains(output.String(), "GUARD") || !strings.Contains(output.String(), "\x1b[2K") {
		t.Fatalf("live line was not drawn and cleared: %q", output.String())
	}
	if newTerminalProgress(terminalRendererWithCapabilities(&output, terminalCapabilities{}), "demo", "pre") != nil {
		t.Fatal("plain output created live progress")
	}
	var absent *terminalProgress
	absent.Stage(StageComplete, 0)
	absent.AI(1, 1, 1)
	absent.Scan(ActivityScanProgress{})
	absent.SetPackage("demo")
	absent.PrepareOutput()
	absent.Close()
	background := context.Background()
	if withTerminalProgress(background, nil) != background {
		t.Fatal("nil progress changed its context")
	}
	prepareTerminalOutput(background)

	now := time.Now()
	expired := &terminalProgress{renderer: renderer, stage: StageAIReview, deadline: now.Add(-time.Second)}
	if line := expired.lineLocked(now); !strings.Contains(line, "deadline reached") {
		t.Fatalf("expired deadline not shown: %q", line)
	}
	for value, want := range map[int64]string{0: "0 B", 1024: "1.0 KiB", 10 * 1024: "10 KiB", 1024 * 1024 * 1024 * 1024: "1.0 TiB"} {
		if got := humanBytes(value); got != want {
			t.Fatalf("humanBytes(%d)=%q, want %q", value, got, want)
		}
	}
}

func TestTerminalDetectionRejectsNonTTYFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "output")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	getenv := func(key string) string {
		if key == "TERM" {
			return "xterm-256color"
		}
		return ""
	}
	lookup := func(string) (string, bool) { return "", false }
	if isTerminalFile(nil) || isTerminalFile(file) {
		t.Fatal("regular file detected as a terminal")
	}
	if caps := detectTerminalCapabilities(file, getenv, lookup); caps.Interactive {
		t.Fatalf("regular file received terminal capabilities: %+v", caps)
	}
	if caps := detectTerminalCapabilities(&bytes.Buffer{}, getenv, lookup); caps.Interactive {
		t.Fatalf("generic writer received terminal capabilities: %+v", caps)
	}
	cfg := DefaultConfig()
	cfg.Terminal.Style = TerminalStylePlain
	if newTerminalRenderer(cfg, file).enabled() {
		t.Fatal("plain configuration enabled terminal presentation")
	}
}
