package audit

import (
	"bytes"
	"context"
	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/egress"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func terminalRendererWithCapabilities(out *bytes.Buffer, caps terminalCapabilities) terminalRenderer {
	return terminalRenderer{out: out, caps: caps}
}

func RenderReport(report *Report) string { return renderReportText(report, false) }

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

func TestTerminalProgressKeepsAQuietCommandCompact(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 51, 0, time.UTC)
	p := &terminalProgress{
		renderer: terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{Interactive: true, Unicode: true}),
		package_: "gtk2", phase: "verify", stage: StageSandboxExecution, command: "makepkg --verifysource",
		activity: "Cloning into bare repository '/srcdest/gtk'...", stageAt: now.Add(-51 * time.Second),
		networkSet: true, now: func() time.Time { return now },
	}
	line := p.lineLocked(now)
	for _, want := range []string{"running 51s", "live Cloning into bare repository"} {
		if !strings.Contains(line, want) {
			t.Fatalf("quiet command omitted %q: %q", want, line)
		}
	}
	for _, noise := range []string{"last output", "brokered network"} {
		if strings.Contains(line, noise) {
			t.Fatalf("quiet command retained redundant status %q: %q", noise, line)
		}
	}
	fitted := terminalFitLine(line, 100)
	if !strings.Contains(fitted, "live Cloning") || strings.HasSuffix(fitted, p.renderer.divider()+"…") {
		t.Fatalf("compact quiet status hid its useful activity: %q", fitted)
	}
}

func TestTerminalProgressRefreshesAQuietDeadline(t *testing.T) {
	var output bytes.Buffer
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	p := &terminalProgress{
		renderer: terminalRendererWithCapabilities(&output, terminalCapabilities{Interactive: true, Unicode: true}),
		package_: "gtk2", phase: "verify", stage: StageSandboxExecution, command: "makepkg --verifysource",
		deadline: now.Add(2 * time.Hour), now: func() time.Time { return now }, dirty: true,
	}
	p.draw(true)
	now = now.Add(time.Second)
	p.draw(false)
	rendered := output.String()
	if strings.Count(rendered, terminalLiveLineClear) != 2 || !strings.HasSuffix(rendered, "deadline 1h59m59s") {
		t.Fatalf("quiet command left its deadline display frozen: %q", rendered)
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

func TestTerminalReportKeepsSandboxPolicyCompact(t *testing.T) {
	var output bytes.Buffer
	renderer := terminalRendererWithCapabilities(&output, terminalCapabilities{Interactive: true, Unicode: true})
	report := &Report{
		ReportID: "20260816T120000Z-aaaaaaaaaaaa-bbbbbbbb", PackageBase: "demo", Phase: "post", Decision: "allow", NetworkEligible: true,
		// A high finding, because the containment line is printed where it does
		// work - against alarming news - rather than on every report.
		Reviewer: ReviewerReport{Mode: ReviewModeDeterministicOnly}, Findings: []brief.Finding{{Severity: "high", RuleID: "shell-known-network-step-prepare", Evidence: "cargo fetch --locked"}},
	}
	rendered := renderer.report(report)
	for _, want := range []string{"sandbox", "upcoming build", "temporary empty home", "host identity hidden", "network prompts before contact"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("compact sandbox policy omitted %q: %q", want, rendered)
		}
	}
	for _, noise := range []string{"later network requests", "each new destination", "recognized later step"} {
		if strings.Contains(rendered, noise) {
			t.Fatalf("report retained deferred network noise %q: %q", noise, rendered)
		}
	}
}

func TestTerminalReportGroupsOverviewAndShowsSuccessfulAIReview(t *testing.T) {
	report := &Report{
		ReportID: "20260816T120000Z-aaaaaaaaaaaa-bbbbbbbb", PackageBase: "stu-git", Phase: "pre",
		Decision: "allow", Disposition: "allow", Summary: "No blocking findings. Read the description below before installing.",
		Reviewer: ReviewerReport{
			Mode: ReviewModeAI, Provider: "codex", Model: "gpt-5.6-sol", MinimumConfidence: "high",
			Verdicts: []Verdict{{SchemaVersion: VerdictSchemaVersion, Verdict: "allow", Confidence: "high", Summary: "no additional concerns", Findings: []ReviewFinding{}, Guidance: []FindingGuidance{}, CoverageNotes: []string{}}},
		},
		Coverage:   brief.Coverage{FilesSeen: 2, BytesSeen: 1024, SelectedFiles: 2},
		YayContext: brief.YayContext{Packages: []brief.YayPackageContext{{Name: "stu-git", Version: "2.5.80-1", Reason: "explicit"}}},
		Sources:    []brief.SourceProvenance{{Name: "stu", URL: "git+https://github.com/example/stu.git"}},
		Findings:   []brief.Finding{{Severity: "medium", Source: "deterministic", Category: "integrity", File: "PKGBUILD", Rationale: "source integrity verification is disabled"}},
	}
	renderer := terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{Interactive: true, Unicode: true, Color: terminalColorTrue})
	rendered := renderer.report(report)
	for _, want := range []string{
		"Overview", "change", "new install 2.5.80-1", "sources", "github.com",
		"Findings", "AI review", "completed", "codex/gpt-5.6-sol", "1 batch",
		"no additional findings", "confidence high",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("grouped report is missing %q:\n%s", want, rendered)
		}
	}
	for before, after := range map[string]string{"Overview": "Findings", "Findings": "AI review"} {
		if strings.Index(rendered, before) >= strings.Index(rendered, after) {
			t.Fatalf("%q does not appear before %q:\n%s", before, after, rendered)
		}
	}
	// Nothing here is alarming enough to need reassuring about, and the
	// containment line is a constant: printed on every gate of every package it
	// is advertising, and the reader learns to skip the block it sits in.
	if strings.Contains(rendered, "host identity hidden") {
		t.Fatalf("a medium-only allow carried the constant containment line:\n%s", rendered)
	}
	plain := RenderReport(report)
	if !strings.Contains(plain, "AI review: completed; codex/gpt-5.6-sol; 1 batch; no additional findings; confidence high") {
		t.Fatalf("plain report hides the successful AI review:\n%s", plain)
	}
	if _, role := aiReviewStatus(report, " · "); role != "green" {
		t.Fatalf("successful no-finding AI review uses %q, want green", role)
	}
}

func TestInspectionFooterHintAppearsOnlyWhenNoPromptOwnsFindings(t *testing.T) {
	report := &Report{
		ReportID: "20260816T120000Z-aaaaaaaaaaaa-bbbbbbbb", PackageBase: "demo", Phase: "pre",
		Decision: "allow", Disposition: "allow", Summary: "A warning is worth reading.", ContentHash: strings.Repeat("a", 64),
		Reviewer: ReviewerReport{Mode: ReviewModeDeterministicOnly},
		Findings: []brief.Finding{{Source: "deterministic", Severity: "medium", Category: "integrity", File: ".SRCINFO", Evidence: "source.tar: unbound", Rationale: "vendor source provenance is mutable", RuleID: "vendor-provenance-weak"}},
	}
	renderer := terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{Interactive: true, Unicode: true})
	for name, rendered := range map[string]string{
		"branded": renderer.reportWithPrompt(report, false),
		"plain":   renderReportText(report, false),
	} {
		if !strings.Contains(rendered, "inspect: prolewatch inspect --latest") {
			t.Fatalf("%s passing report with findings omitted inspection hint:\n%s", name, rendered)
		}
	}
	for name, rendered := range map[string]string{
		"branded prompt": renderer.reportWithPrompt(report, true),
		"plain prompt":   renderReportText(report, true),
	} {
		if strings.Contains(rendered, "inspect: prolewatch inspect --latest") {
			t.Fatalf("%s duplicated the prompt inspection route:\n%s", name, rendered)
		}
	}
	clean := *report
	clean.Findings = nil
	if rendered := renderer.reportWithPrompt(&clean, false); strings.Contains(rendered, "inspect: prolewatch inspect --latest") {
		t.Fatalf("finding-free report advertised inspection:\n%s", rendered)
	}
}

func TestTerminalReportMarksCarriedFindingsWithoutChangingSeverityOrder(t *testing.T) {
	criticalLine, lowLine := 7, 2
	critical := brief.Finding{Severity: "critical", Source: "deterministic", Category: "obfuscation", File: "PKGBUILD", Line: &criticalLine, Rationale: "previously reviewed command", Evidence: "eval", RuleID: "critical-review"}
	low := brief.Finding{Severity: "low", Source: "deterministic", Category: "integrity", File: ".SRCINFO", Line: &lowLine, Rationale: "new informational finding", RuleID: "low-info"}
	report := &Report{
		ReportID: "20260816T120000Z-aaaaaaaaaaaa-bbbbbbbb", PackageBase: "demo", Phase: "post",
		Decision: "allow", Disposition: "allow", Summary: "No new decision is required.", ContentHash: strings.Repeat("a", 64), NetworkEligible: true,
		Reviewer: ReviewerReport{Mode: ReviewModeDeterministicOnly}, Findings: []brief.Finding{critical, low},
		CarriedDecision: &CarriedDecision{SourceReportID: "20260816T115900Z-bbbbbbbbbbbb-cccccccc", SourcePhase: "pre", SourceContentHash: strings.Repeat("b", 64), Findings: []CarriedFindingBinding{{FindingID: findingGuidanceID(critical), Path: "PKGBUILD", ManifestEntryHash: strings.Repeat("c", 64)}}},
	}
	renderer := terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{Interactive: true, Unicode: true, Color: terminalColorTrue})
	rendered := renderer.report(report)
	for _, want := range []string{"[ NO NEW DECISION NEEDED ]", "approved at recipe gate", "exact bytes unchanged", "new informational finding"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("carried report omitted %q:\n%s", want, rendered)
		}
	}
	if strings.Index(rendered, "CRITICAL") >= strings.Index(rendered, "LOW") {
		t.Fatalf("decidedness reordered findings ahead of severity:\n%s", rendered)
	}
	carriedHeading := renderer.paint("blue", renderer.anchor()+" CRITICAL (deterministic · approved at recipe gate): previously reviewed command")
	if !strings.Contains(rendered, carriedHeading) {
		t.Fatalf("carried finding was not visibly blue:\n%s", rendered)
	}
	if uneventful(report, 0) {
		t.Fatal("carried-only decision report collapsed into the clean-report UI")
	}
	plain := RenderReport(report)
	if !strings.Contains(plain, "Outcome: NO NEW DECISION NEEDED") || strings.Contains(plain, "Outcome: NO BLOCKING FINDINGS") {
		t.Fatalf("plain report claimed a carried finding was a clean scan:\n%s", plain)
	}
}

func TestInteractiveReportOmitsRedundantSummaryAndDoesNotInventAnAIRun(t *testing.T) {
	report := &Report{
		ReportID: "20260816T120000Z-aaaaaaaaaaaa-bbbbbbbb", PackageBase: "moon-buggy", Phase: "pre",
		Decision: "block", Disposition: "block", ApprovalEligible: true,
		Summary:  "No blocking findings. Read the description below before installing.",
		Reviewer: ReviewerReport{Mode: ReviewModeAI, Provider: "codex", Model: "gpt-5.6-sol", MinimumConfidence: "high", Skipped: "recipe phase skipped"},
		Coverage: brief.Coverage{FilesSeen: 5, BytesSeen: 136 * 1024, SelectedFiles: 5},
		Findings: []brief.Finding{{Severity: "high", Source: "deterministic", Category: "obfuscation", File: "config.patch", Rationale: "indirect command execution requires review"}},
	}
	renderer := terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{Interactive: true, Unicode: true})
	rendered := renderer.reportWithPrompt(report, true)
	if strings.Contains(rendered, report.Summary) || strings.Contains(rendered, "selected for AI review") {
		t.Fatalf("interactive report retained a contradictory summary or invented AI work:\n%s", rendered)
	}
	for _, want := range []string{"NEEDS YOUR DECISION", "AI review not run", "not run"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("interactive report omitted %q:\n%s", want, rendered)
		}
	}
	plain := RenderReport(report)
	if !strings.Contains(plain, "AI review not run") {
		t.Fatalf("plain coverage invented a completed AI selection:\n%s", plain)
	}
}

func TestAIReviewStatusDistinguishesUnavailableAndSkippedRuns(t *testing.T) {
	tests := []struct {
		name   string
		report *Report
		want   string
		role   string
	}{
		{
			name: "unavailable",
			report: &Report{Reviewer: ReviewerReport{
				Mode: ReviewModeAI, Provider: "codex", Model: "gpt", Error: "provider timed out",
			}},
			want: "disabled for this run · codex/gpt · provider timed out · deterministic findings only · run 'prolewatch doctor'",
			role: "amber",
		},
		{
			name: "unavailable Ollama",
			report: &Report{Reviewer: ReviewerReport{
				Mode: ReviewModeAI, Provider: "ollama", Model: "local", Error: "provider attestation is stale",
			}},
			want: "disabled for this run · ollama/local · provider attestation is stale · deterministic findings only · run 'prolewatch doctor --probe-llm-quality'",
			role: "amber",
		},
		{
			name:   "structural stop",
			report: &Report{Reviewer: ReviewerReport{Mode: ReviewModeAI}},
			want:   "not run · structural finding already stopped this phase",
			role:   "muted",
		},
		{
			name:   "approval",
			report: &Report{Overridden: true, Reviewer: ReviewerReport{Mode: ReviewModeAI}},
			want:   "not repeated · exact one-time approval applied",
			role:   "muted",
		},
	}
	for _, current := range tests {
		t.Run(current.name, func(t *testing.T) {
			got, role := aiReviewStatus(current.report, " · ")
			if got != current.want {
				t.Fatalf("status=%q, want %q", got, current.want)
			}
			if role != current.role {
				t.Fatalf("role=%q, want %q", role, current.role)
			}
		})
	}
}

func TestTerminalRendererPresentationBranches(t *testing.T) {
	var output bytes.Buffer
	trueColor := terminalRendererWithCapabilities(&output, terminalCapabilities{Interactive: true, Unicode: true, Color: terminalColorTrue})
	color256 := terminalRendererWithCapabilities(&output, terminalCapabilities{Interactive: true, Color: terminalColor256})
	color16 := terminalRendererWithCapabilities(&output, terminalCapabilities{Interactive: true, Color: terminalColor16})
	for _, rendered := range []string{
		trueColor.paint("blue", "blue"), color256.paint("amber", "amber"), color16.paint("green", "green"), color16.paint("unknown", "plain"),
		trueColor.activation(), trueColor.successLine("done"), trueColor.detailLine("detail"), trueColor.errorLine("failure"), trueColor.artifactReadyLine(2),
	} {
		if rendered == "" {
			t.Fatal("presentation branch rendered an empty value")
		}
	}
	if got := trueColor.paint("blue", "brand"); !strings.Contains(got, "38;2;23;147;209") {
		t.Fatalf("true-color brand accent is not Arch blue: %q", got)
	}
	if got := trueColor.activation(); !strings.Contains(got, "reviewing this yay transaction") {
		t.Fatalf("activation marker omitted the review status: %q", got)
	}
	plain := terminalRendererWithCapabilities(&output, terminalCapabilities{})
	if plain.activation() != "" || plain.artifactReadyLine(1) != "" || plain.successLine("ok") != "ok" || plain.detailLine("detail") != "detail" || plain.errorLine("bad") != "prolewatch: bad" {
		t.Fatal("plain presentation did not preserve legacy messages")
	}

	line := 7
	report := &Report{
		ReportID: "20260816T120000Z-aaaaaaaaaaaa-bbbbbbbb", PackageBase: "demo", Phase: "post", Decision: "allow",
		Disposition: "allow", Summary: "described", NetworkEligible: true, ContentHash: strings.Repeat("a", 64),
		Reviewer: ReviewerReport{Mode: ReviewModeDeterministicOnly}, Coverage: brief.Coverage{FilesSeen: 12, BytesSeen: 12},
		Findings: []brief.Finding{{Severity: "critical", Source: "deterministic", Category: "persistence", File: "PKGBUILD", Line: &line, Rationale: "reason", Evidence: "evidence"}},
	}
	if rendered := trueColor.report(report); !strings.Contains(rendered, "[ NO BLOCKING FINDINGS ]") || !strings.Contains(rendered, "CRITICAL") || !strings.Contains(rendered, "network prompts before contact") || !strings.Contains(rendered, "sandbox") {
		t.Fatalf("allow report branches missing: %q", rendered)
	} else if rail := trueColor.paint("blue", "│"); strings.Count(rendered, rail) < 5 || !strings.Contains(rendered, "PROLEWATCH") || !strings.Contains(rendered, "PACKAGE REVIEW ENDED") {
		t.Fatalf("full report omitted its continuous blue ownership frame: %q", rendered)
	}
	report.Decision, report.NetworkEligible, report.ApprovalEligible = "block", false, true
	if rendered := trueColor.report(report); !strings.Contains(rendered, "To approve this exact snapshot, once:") || !strings.Contains(rendered, "prolewatch approve ") {
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
		ApprovalEligible: true,
		Summary:          "blocked\nspoofed", Reviewer: ReviewerReport{Mode: ReviewModeAI, Provider: "codex", Model: "gpt", MinimumConfidence: "high", Verdicts: []Verdict{{CoverageNotes: []string{"generated file was unavailable\nspoofed"}}}},
		Coverage: brief.Coverage{FilesSeen: 4, BytesSeen: 4096, SelectedFiles: 2},
	}
	renderer := terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{Interactive: true, Unicode: true, Color: terminalColorTrue})
	rendered := renderer.report(report)
	for _, want := range []string{"◆", "demo\\u001b[31m", " · recipe", "before any source is fetched", "[ NEEDS YOUR DECISION ]", "AI coverage gaps", "batch 1", "generated file was unavailable spoofed", "4 files", "4.0 KiB"} {
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
		Findings: []brief.Finding{{Severity: "high", Source: "ai", Category: "other", File: "PKGBUILD", Rationale: "already shown"}},
	}
	renderer := terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{Interactive: true, Unicode: true, Color: terminalColorTrue})
	rendered := renderer.inlineDecisionResult(inlineOverride, report)
	for _, want := range []string{"OVERRIDE ACCEPTED", "demo / pre", "[ APPROVED BY YOU ]", "exact one-time user override", report.ReportID} {
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
	for _, want := range []string{"◆", "PROLEWATCH", "PHASE COMPLETE", "demo", "· recipe", "yay resumes"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("guard completion is missing %q: %q", want, rendered)
		}
	}
	if strings.Contains(rendered, "\n") || strings.Contains(rendered, "└─") {
		t.Fatalf("a completed phase rendered its context as a child block: %q", rendered)
	}
	if !strings.Contains(rendered, "38;2;23;147;209") {
		t.Fatalf("guard completion omitted the blue Prolewatch marker: %q", rendered)
	}
	plain := terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{})
	if got, want := plain.guardComplete(report), "Prolewatch phase complete: demo / pre; yay resumes · next: source acquisition"; got != want {
		t.Fatalf("plain guard completion=%q, want %q", got, want)
	}
	if got := renderer.guardComplete(nil); got != "" {
		t.Fatalf("nil report produced guard completion: %q", got)
	}
}

func TestFullPackageReviewOwnsItsStartEndAndSuccessfulHandoff(t *testing.T) {
	renderer := terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{Interactive: true, Unicode: true, Color: terminalColorTrue})
	report := &Report{
		ReportID: "20260816T120000Z-aaaaaaaaaaaa-bbbbbbbb", PackageBase: "stu-git", Phase: "post",
		Decision: "allow", Disposition: "allow", Summary: "No blocking findings.", Reviewer: ReviewerReport{Mode: ReviewModeDeterministicOnly},
		Findings: []brief.Finding{{Severity: "medium", Category: "integrity", File: "PKGBUILD", Rationale: "mutable source"}},
	}
	rendered := renderer.phaseResult(report, 0, false, true)
	for _, want := range []string{"PROLEWATCH", "PACKAGE REVIEW", "stu-git · sources", "before the build runs", "MEDIUM", "PACKAGE REVIEW ENDED", "yay resumes"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("live package review omitted %q: %q", want, rendered)
		}
	}
	closing := rendered[strings.LastIndex(rendered, "\n")+1:]
	if !strings.Contains(closing, "next: contained build") {
		t.Fatalf("source handoff did not name the quiet next operation: %q", closing)
	}
	for _, want := range []string{"PACKAGE REVIEW ENDED", "stu-git · sources", "yay resumes"} {
		if !strings.Contains(closing, want) {
			t.Errorf("review closing line does not own %q: %q", want, closing)
		}
	}
	if strings.Contains(closing, "└─") {
		t.Fatalf("review context remained a child of its closing boundary: %q", closing)
	}
	if standalone := renderer.report(report); strings.Contains(standalone, "yay resumes") || !strings.Contains(standalone, "PACKAGE REVIEW ENDED") {
		t.Fatalf("standalone report claimed a yay handoff or lost its end boundary: %q", standalone)
	}
}

func TestRunningLineAcknowledgesLongTransitions(t *testing.T) {
	renderer := terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{Interactive: true, Unicode: true, Color: terminalColorTrue})
	rendered := renderer.runningLine("Decision received · validating demo / built package against the exact snapshot")
	for _, want := range []string{"Decision received", "validating demo / built package", "[ RUNNING ]"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("running transition omitted %q: %q", want, rendered)
		}
	}
	plain := terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{})
	if got := plain.runningLine("contained build starting"); got != "Prolewatch: contained build starting" {
		t.Fatalf("plain running line=%q", got)
	}
}

func TestContainedMakepkgOutputHasClearOwnershipBoundaries(t *testing.T) {
	renderer := terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{Interactive: true, Unicode: true, Color: terminalColorTrue})
	header := renderer.containedMakepkgOutputHeader("gtk2", "verify")
	for _, want := range []string{"◆", "PROLEWATCH", "CONTAINED MAKEPKG OUTPUT", "gtk2 / verify", "package-authored text follows", "captured in sandbox", "terminal controls escaped"} {
		if !strings.Contains(header, want) {
			t.Fatalf("contained output header omitted %q: %q", want, header)
		}
	}
	if !strings.Contains(header, "38;2;23;147;209") {
		t.Fatalf("contained output header omitted the blue Prolewatch marker: %q", header)
	}
	if gutter := renderer.containedMakepkgOutputGutter(); !strings.Contains(gutter, "│") || !strings.Contains(gutter, "38;2;23;147;209") {
		t.Fatalf("contained output gutter is not visually distinct: %q", gutter)
	}
	if footer := renderer.containedMakepkgOutputFooter(); !strings.Contains(footer, "OUTPUT ENDED") || !strings.Contains(footer, "guard resumes") || !strings.Contains(footer, "PROLEWATCH") {
		t.Fatalf("contained output footer is unclear: %q", footer)
	} else if strings.Contains(footer, "\n") || strings.Contains(footer, "└─") {
		t.Fatalf("guard state rendered as a child of an ended output block: %q", footer)
	}
	plain := terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{})
	if header := plain.containedMakepkgOutputHeader("gtk2", "verify"); !strings.Contains(header, "Prolewatch:") || !strings.Contains(header, "gtk2 / verify") {
		t.Fatalf("plain contained output header is unclear: %q", header)
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
		package_: "demo", phase: "pre", stage: StageAIReview, batch: 2, batches: 3, reviewTrigger: reviewTriggerOnDemand,
		deadline: now.Add(90 * time.Second), scan: brief.ScanProgress{FilesSeen: 42, BytesSeen: 2048, ArchivesSeen: 2, ArchiveEntries: 7, ArchiveUnpackedBytes: 8192}, now: func() time.Time { return now },
	}
	line := p.lineLocked(now)
	for _, want := range []string{"demo/pre", "AI review", "batch 2/3", "42 files", "2.0 KiB input", "2 archives", "7 entries", "8.0 KiB unpacked", "deadline 1m30s"} {
		if !strings.Contains(line, want) {
			t.Fatalf("progress line is missing %q: %q", want, line)
		}
	}
	if strings.Contains(strings.ToLower(line), "stuck") || strings.Contains(line, "%") {
		t.Fatalf("progress line made an unsupported progress claim: %q", line)
	}
	next := p.lineLocked(now)
	if line != next || !strings.Contains(line, "•") {
		t.Fatalf("live progress marker is unstable: first=%q next=%q", line, next)
	}
	ascii := &terminalProgress{renderer: terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{Interactive: true}), stage: StageInitializing}
	if got := ascii.lineLocked(now); !strings.Contains(got, "*") || strings.Contains(got, "•") {
		t.Fatalf("ASCII progress marker mismatch: %q", got)
	}
}

func TestSourceProgressShowsOnlyMeasuredTransferFacts(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	p := &terminalProgress{
		renderer:   terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{Interactive: true, Unicode: true}),
		stage:      StageSourceAcquisition,
		sourceName: terminalInline("demo\x1b[2J.tar.gz", 512), sourcePart: 2, sourceAll: 3,
		sourceRead: 5 << 20, sourceSize: 20 << 20, sourceRate: 2 << 20,
	}
	line := p.lineLocked(now)
	for _, want := range []string{"source acquisition", "source 2/3", `demo\u001b[2J.tar.gz`, "5.0 MiB / 20 MiB (25%)", "2.0 MiB/s"} {
		if !strings.Contains(line, want) {
			t.Fatalf("source progress is missing %q: %q", want, line)
		}
	}
	if strings.Contains(line, "\x1b[2J") || strings.Contains(line, "downloaded") {
		t.Fatalf("source progress forged control/completion state: %q", line)
	}
	p.sourceSize, p.sourceDone = 0, true
	line = p.lineLocked(now)
	if strings.Contains(line, "%") || !strings.Contains(line, "downloaded") {
		t.Fatalf("unknown-size source invented a percentage or hid completion: %q", line)
	}
}

func TestSourceProgressRefreshesOneLiveLine(t *testing.T) {
	var output bytes.Buffer
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	p := &terminalProgress{
		renderer: terminalRendererWithCapabilities(&output, terminalCapabilities{Interactive: true, Unicode: true}),
		stage:    StageSourceAcquisition, now: func() time.Time { return now },
	}
	p.Source("source.tar", 1, 1, 0, 100, 0, false)
	p.Source("source.tar", 1, 1, 10, 100, 10, false)
	if refreshes := strings.Count(output.String(), terminalLiveLineClear); refreshes != 1 {
		t.Fatalf("sub-second percentage update was not coalesced: %q", output.String())
	}
	now = now.Add(time.Second)
	p.Source("source.tar", 1, 1, 25, 100, 10, false)
	p.Source("source.tar", 1, 1, 30, 100, 10, false)
	if refreshes := strings.Count(output.String(), terminalLiveLineClear); refreshes != 2 {
		t.Fatalf("one-second percentage refresh was missing or repeated: %q", output.String())
	}
	now = now.Add(time.Second)
	p.Source("source.tar", 1, 1, 60, 100, 1, false)
	p.Source("source.tar", 1, 1, 100, 100, 1, true)
	if refreshes := strings.Count(output.String(), terminalLiveLineClear); refreshes != 4 || strings.Contains(output.String(), "\n") || !strings.HasSuffix(output.String(), "downloaded") {
		t.Fatalf("source progress did not refresh one current line through completion: %q", output.String())
	}
}

func TestTerminalProgressFitsTheCurrentPhysicalLine(t *testing.T) {
	var output bytes.Buffer
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	p := &terminalProgress{
		renderer: terminalRendererWithCapabilities(&output, terminalCapabilities{Interactive: true, Unicode: true, Color: terminalColorTrue, Columns: 32}),
		package_: "a-very-long-package-name", phase: "verify", stage: StageSourceAcquisition,
		now: func() time.Time { return now }, dirty: true,
	}
	p.draw(true)
	rendered := strings.TrimPrefix(output.String(), terminalLiveLineClear)
	if cells := terminalDisplayCells(rendered); cells > 31 {
		t.Fatalf("live status occupies %d terminal cells, want at most 31: %q", cells, rendered)
	}
	if !strings.Contains(rendered, "…") || !strings.HasSuffix(rendered, "\x1b[0m") {
		t.Fatalf("truncated coloured status is not visibly and stylistically closed: %q", rendered)
	}
}

func TestInitializationProgressNamesTheConcreteWork(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	p := &terminalProgress{
		renderer: terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{Interactive: true}),
		now:      func() time.Time { return now },
	}
	for stage, want := range map[string]string{
		StageArchiveParserCheck: "archive parser check",
		StagePolicyFingerprint:  "policy fingerprint",
		StageAIProviderIdentity: "AI provider identity",
		StageAIProviderAttest:   "AI provider attestation",
		StageMarkerVerification: "decision marker verification",
		StageSourcePlanFreeze:   "source plan freeze",
		StageSourceAcquisition:  "source acquisition",
	} {
		p.stage = stage
		if line := p.lineLocked(now); !strings.Contains(line, want) {
			t.Fatalf("stage %q rendered no concrete status %q: %q", stage, want, line)
		}
	}
}

func TestTerminalRecoveryNeverMovesTheCursorOrSwitchesScreens(t *testing.T) {
	if terminalRecoverySequence != "\x1b[0m\x1b[?25h" {
		t.Fatalf("terminal recovery is not position-neutral: %q", terminalRecoverySequence)
	}
	for _, forbidden := range []string{"\x1b[r", "\x1b7", "\x1b8", "?1049", "\x1b[H", "\x1b[2J"} {
		if strings.Contains(terminalRecoverySequence, forbidden) {
			t.Fatalf("terminal recovery contains cursor/screen control %q: %q", forbidden, terminalRecoverySequence)
		}
	}
}

func TestPackageOutputReplayIsAppendOnlyTerminalText(t *testing.T) {
	var output bytes.Buffer
	replayPackageOutput(&output, []byte("compile\x1b[2JFORGED\r50%\x1b]0;title\a"))
	rendered := output.String()
	for _, visible := range []string{`\u001b[2J`, `\u000d`, `\u001b]0;title`, `\u0007`} {
		if !strings.Contains(rendered, visible) {
			t.Fatalf("replay hid terminal control %q: %q", visible, rendered)
		}
	}
	if strings.ContainsAny(rendered, "\x1b\r\a") || !strings.HasSuffix(rendered, "\n") {
		t.Fatalf("replay retained terminal authority or no final newline: %q", rendered)
	}
}

func TestPackageOutputReplayPrefixesEveryPhysicalLine(t *testing.T) {
	var output bytes.Buffer
	replayPackageOutputWithPrefix(&output, []byte("first\n\nthird\n"), "│ ")
	if got, want := output.String(), "│ first\n│ \n│ third\n"; got != want {
		t.Fatalf("prefixed replay=%q, want %q", got, want)
	}
}

func TestTerminalProgressLifecycle(t *testing.T) {
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
	progressTimedStage(ctx, StageDeterministicScan, 30)
	progressScan(ctx, brief.ScanProgress{Operation: brief.ScanOperationInventory, FilesSeen: 3, BytesSeen: 1024})
	progressAI(ctx, 1, 2, 60, reviewTriggerOnDemand)
	progressAcquisition(ctx, egress.AcquisitionProgress{Filename: "source.tar", SourceIndex: 1, SourceCount: 1, Bytes: 10, Total: 20})
	progressActivity(ctx, "cloning source")
	progress.SetPackage("renamed")
	prepareTerminalOutput(ctx)
	progressStage(ctx, StageComplete)
	progress.mu.Lock()
	resumed := !progress.suspended && progress.stage == StageComplete
	progress.mu.Unlock()
	if !resumed {
		t.Fatal("a stage after terminal output did not resume the live progress line")
	}
	progress.Close()
	progress.Close()
	rendered := output.String()
	if !strings.Contains(rendered, "GUARD") || strings.Contains(rendered, "\n") || !strings.Contains(rendered, terminalLiveLineClear) {
		t.Fatalf("progress did not stay on and clean up one live line: %q", rendered)
	}
	for _, forbidden := range []string{"\x1b[A", "\x1b[H", "\x1b[2J", "?1049"} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("live progress used position-changing terminal control %q: %q", forbidden, rendered)
		}
	}
	if newTerminalProgress(terminalRendererWithCapabilities(&output, terminalCapabilities{}), "demo", "pre") != nil {
		t.Fatal("plain output created live progress")
	}
	var absent *terminalProgress
	absent.Stage(StageComplete, 0)
	absent.AI(1, 1, 1, "")
	absent.Scan(brief.ScanProgress{})
	absent.SetPackage("demo")
	absent.SetActivity("work")
	absent.Source("source", 1, 1, 1, 1, 1, true)
	absent.PrepareOutput()
	absent.ResumeAfterPrompt()
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

func TestTerminalProgressReleasesTheLiveLineOnCancellation(t *testing.T) {
	var output bytes.Buffer
	renderer := terminalRendererWithCapabilities(&output, terminalCapabilities{Interactive: true, Unicode: true})
	progress := newTerminalProgress(renderer, "demo", "pre")
	if progress == nil {
		t.Fatal("interactive progress was not created")
	}
	defer progress.Close()
	ctx, cancel := context.WithCancel(context.Background())
	ctx = withTerminalProgress(ctx, progress)
	progressAI(ctx, 1, 1, 300, reviewTriggerOnDemand)
	cancel()

	deadline := time.Now().Add(time.Second)
	for {
		progress.mu.Lock()
		closed, live := progress.closed, progress.liveLine
		progress.mu.Unlock()
		if closed && !live {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cancelled progress retained ownership of the terminal line")
		}
		time.Sleep(time.Millisecond)
	}
	written := output.String()
	progressStage(ctx, StageComplete)
	if got := output.String(); got != written {
		t.Fatalf("a late progress callback reclaimed the terminal after cancellation: before=%q after=%q", written, got)
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

// The outcome line states what happens next; it is not a verdict on the
// package. Prolewatch describes, the user decides, and containment protects, so
// the vocabulary must not claim safety or credit the model with a decision.
func TestOutcomeVocabularyDoesNotClaimAVerdict(t *testing.T) {
	base := func() *Report {
		return &Report{ReportID: "20260816T120000Z-aaaaaaaaaaaa-bbbbbbbb", PackageBase: "demo", Phase: "pre",
			ContentHash: strings.Repeat("a", 64), Summary: "described",
			Reviewer: ReviewerReport{Mode: ReviewModeDeterministicOnly}}
	}
	cases := map[string]func(*Report){
		"NO BLOCKING FINDINGS": func(r *Report) { r.Decision, r.Disposition = "allow", "allow" },
		"APPROVED BY YOU": func(r *Report) {
			r.Decision, r.Disposition, r.Overridden = "allow", "override", true
		},
		"NEEDS YOUR DECISION": func(r *Report) {
			r.Decision, r.Disposition, r.ApprovalEligible = "block", "block", true
		},
		"STRUCTURAL FAILURE": func(r *Report) { r.Decision, r.Disposition = "block", "block" },
	}
	for want, mutate := range cases {
		report := base()
		mutate(report)
		if got := reportOutcome(report); !strings.HasPrefix(got, want) {
			t.Fatalf("outcome = %q, want %q", got, want)
		}
		rendered := RenderReport(report)
		for _, forbidden := range []string{"Decision: ALLOW", "Decision: BLOCK", "AUTO-ALLOW"} {
			if strings.Contains(rendered, forbidden) {
				t.Fatalf("%s: verdict vocabulary survived: %q", want, forbidden)
			}
		}
	}
}

// The briefing has to say where the package's material comes from before it
// lists what is wrong with it: the sources are what make the findings
// interpretable.
func TestBriefingNamesSourcesContactedHostsAndStrippedSurfaces(t *testing.T) {
	report := &Report{
		ReportID: "20260816T120000Z-aaaaaaaaaaaa-bbbbbbbb", PackageBase: "demo", Phase: "post",
		Decision: "allow", Disposition: "allow", ContentHash: strings.Repeat("a", 64),
		Summary: "described", Reviewer: ReviewerReport{Mode: ReviewModeDeterministicOnly},
		Sources: []brief.SourceProvenance{
			{Name: "a.tar.gz", URL: "https://github.com/example/a/archive/v1.tar.gz"},
			{Name: "b.tar.gz", URL: "https://cdn.example.tld/b.tar.gz"},
			{Name: "c.tar.gz", URL: "https://cdn.example.tld/c.tar.gz"},
			{Name: "fix.patch"},
		},
		AcquiredHosts:    []string{"codeload.github.com", "github.com"},
		StrippedSurfaces: []StrippedSurfaces{{Package: "demo.pkg.tar.zst", Members: []string{".INSTALL"}, SHA256: strings.Repeat("b", 64)}},
	}
	rendered := RenderReport(report)
	for _, want := range []string{
		"4 source(s)", "github.com", "cdn.example.tld (x2)", "local",
		"Contacted: codeload.github.com, github.com",
		"Stripped: .INSTALL from demo.pkg.tar.zst",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("briefing is missing %q:\n%s", want, rendered)
		}
	}
}

// A source host reaches the terminal from an attacker-authored PKGBUILD.
func TestSourceBriefingSanitizesHostiveHosts(t *testing.T) {
	report := &Report{Sources: []brief.SourceProvenance{
		{Name: "x", URL: "https://evil\x1b[2Kexample.com/x.tar.gz"},
		{Name: "y", URL: "https://ok.example.com/y.tar.gz"},
	}}
	if summary := sourceBriefing(report); strings.Contains(summary, "\x1b") {
		t.Fatalf("a raw escape reached the source line: %q", summary)
	}
}

// Findings carry attacker-authored text: the rationale comes from a rule, but
// the evidence is a slice of the package's own source, and the file path is
// whatever the package named its files. The briefing must escape all three at
// every rendering path.
func TestBriefingSanitizesEveryAttackerControlledField(t *testing.T) {
	line := 7
	report := &Report{
		ReportID: "20260816T120000Z-aaaaaaaaaaaa-bbbbbbbb", PackageBase: "demo\x1b[31m", Phase: "pre",
		Decision: "block", Disposition: "block", ApprovalEligible: true,
		ContentHash: strings.Repeat("a", 64), Summary: "summary\x1b[2Kforged",
		Reviewer: ReviewerReport{Mode: ReviewModeDeterministicOnly},
		Sources:  []brief.SourceProvenance{{Name: "x", URL: "https://evil\x1b[2K.example.com/x.tar.gz"}},
		// The transaction context and the manifest diff are printed now, so
		// they are attacker-controlled fields like any other: yay takes the
		// version from the package's own .SRCINFO, and the changed paths come
		// from the checkout.
		YayContext: brief.YayContext{Packages: []brief.YayPackageContext{
			{Name: "demo\x1b[31m", Version: "1.0\x1b[2K[ NO BLOCKING FINDINGS ]", LocalVersion: "0.9\rforged", Reason: "explicit", Upgrade: true},
		}},
		ManifestDiff: []brief.ManifestChange{{Path: "PKGBUILD\x1b[2K\rforged", Status: "changed"}},
		Findings: []brief.Finding{{
			Severity: "critical", Source: "deterministic", Category: "other",
			File:      "PKGBUILD\x1b[2K",
			Line:      &line,
			Rationale: "rationale\x1b[31mforged",
			Evidence:  "curl x | bash\rProlewatch: no findings.\n[ NO BLOCKING FINDINGS ]",
		}},
	}
	for name, rendered := range map[string]string{
		"plain":  RenderReport(report),
		"colour": terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{Interactive: true, Unicode: true, Color: terminalColorTrue}).report(report),
	} {
		// The colour renderer emits its own escapes, so the test is not "no
		// escapes at all" - it is that the package's escapes arrive as visible
		// backslash-u text rather than as control characters.
		if !strings.Contains(rendered, "\\u001b") {
			t.Fatalf("%s: attacker escapes were dropped rather than shown: %q", name, rendered)
		}
		if strings.Contains(rendered, "\r") {
			t.Fatalf("%s: a carriage return survived and can overwrite a line: %q", name, rendered)
		}
		// Package content cannot be stopped from repeating the tool's words.
		// What it must not do is begin a line: everything Prolewatch writes
		// itself starts at column zero, so content stuck behind an indent and a
		// location prefix cannot be mistaken for output.
		for _, row := range strings.Split(rendered, "\n") {
			if strings.HasPrefix(strings.TrimLeft(row, " "), "[ NO BLOCKING FINDINGS ]") {
				t.Fatalf("%s: package content began a line of tool output: %q", name, row)
			}
		}
	}
}

func upgradeReport(phase string) *Report {
	return &Report{
		ReportID: "20260816T120000Z-aaaaaaaaaaaa-bbbbbbbb", PackageBase: "demo", Phase: phase,
		Decision: "allow", Disposition: "allow", ContentHash: strings.Repeat("a", 64),
		Summary:  "no blocking findings",
		Reviewer: ReviewerReport{Mode: ReviewModeDeterministicOnly},
		YayContext: brief.YayContext{Packages: []brief.YayPackageContext{
			{Name: "demo", Version: "1.3.0", LocalVersion: "1.2.3", Reason: "explicit", Upgrade: true},
		}},
		ManifestDiff: []brief.ManifestChange{
			{Path: "notes/CHANGELOG", Status: "changed"},
			{Path: "PKGBUILD", Status: "changed"},
			{Path: "demo.install", Status: "added"},
		},
		Sources: []brief.SourceProvenance{
			{Name: "demo.tar.gz", Kind: brief.SourceKindArchive, URL: "https://example.com/demo.tar.gz", Transport: "https", Binding: "fixed-digest"},
			{Name: "demo-git", Kind: brief.SourceKindVCS, URL: "git+https://example.com/demo.git", Transport: "git", Binding: "mutable-vcs"},
		},
		SourceVerification: brief.SourceVerification{Checksums: "passed", PGP: "not-applicable"},
	}
}

// TestBriefingShowsTheChangeBeingInstalled is the "the data was there all
// along" regression. The hook has always supplied the version transition, the
// install reason and the manifest diff; the terminal printed the package base
// and an internal phase name and left the rest in the JSON.
func TestBriefingShowsTheChangeBeingInstalled(t *testing.T) {
	report := upgradeReport("post")
	report.Findings = []brief.Finding{{Severity: "high", Source: "deterministic", Category: "other", File: "PKGBUILD", Rationale: "something to read"}}
	for name, rendered := range map[string]string{
		"plain":  RenderReport(report),
		"colour": terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{Interactive: true, Unicode: true, Color: terminalColorTrue}).report(report),
	} {
		for _, want := range []string{"1.2.3", "1.3.0", "explicitly installed"} {
			if !strings.Contains(rendered, want) {
				t.Errorf("%s: the briefing does not say %q:\n%s", name, want, rendered)
			}
		}
		// The recipe and the scriptlet outrank an alphabetically earlier file.
		if !strings.Contains(rendered, "PKGBUILD") || !strings.Contains(rendered, "demo.install") {
			t.Errorf("%s: the changed control files are not named:\n%s", name, rendered)
		}
		// Pinning is what makes a finding in that material mean anything.
		if !strings.Contains(rendered, "1 pinned to exact bytes") || !strings.Contains(rendered, "1 mutable") {
			t.Errorf("%s: the briefing does not say how firmly the sources are pinned:\n%s", name, rendered)
		}
	}
}

// TestUneventfulPhaseCollapsesToOneLine holds the prompt-fatigue line from the
// other side: a package nobody has a question about must not produce three full
// briefings before the one that matters.
func TestUneventfulPhaseCollapsesToOneLine(t *testing.T) {
	renderer := terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{Interactive: true, Unicode: true, Color: terminalColorTrue})
	quiet := renderer.phaseResult(upgradeReport("pre"), 0, false, false)
	if lines := strings.Count(strings.TrimRight(quiet, "\n"), "\n") + 1; lines != 1 {
		t.Fatalf("a clean pre phase rendered %d lines:\n%s", lines, quiet)
	}
	// It still carries the decision context and a way back to the full report.
	for _, want := range []string{"demo", "1.2.3", "1.3.0", "20260816T120000Z-aaaaaaaaaaaa-bbbbbbbb"} {
		if !strings.Contains(quiet, want) {
			t.Errorf("the compact line drops %q:\n%s", want, quiet)
		}
	}
	// When control returns to yay, the compact result owns that handoff on the
	// same line. It must not float between an ended output block and a separate
	// completion footer with no visible Prolewatch owner.
	handoff := renderer.phaseResult(upgradeReport("post"), 0, false, true)
	if strings.Contains(handoff, "\n") || strings.Contains(handoff, "└─") {
		t.Fatalf("compact handoff expanded into a detached or child block:\n%s", handoff)
	}
	for _, want := range []string{"◆", "PROLEWATCH", "PHASE COMPLETE", "demo", "· sources", "1.2.3", "1.3.0", "20260816T120000Z-aaaaaaaaaaaa-bbbbbbbb", "yay resumes"} {
		if !strings.Contains(handoff, want) {
			t.Errorf("compact handoff does not own %q:\n%s", want, handoff)
		}
	}
	// The artifact phase is the last word before pacman receives the archive,
	// so it is never collapsed.
	full := renderer.phaseResult(upgradeReport("artifact"), 0, false, false)
	if strings.Count(full, "\n") < 3 {
		t.Fatalf("the pre-install briefing was collapsed:\n%s", full)
	}
	// Neither is anything that found something or needs an answer.
	withFinding := upgradeReport("pre")
	withFinding.Findings = []brief.Finding{{Severity: "high", Source: "deterministic", Category: "other", File: "PKGBUILD", Rationale: "read me"}}
	if strings.Count(renderer.phaseResult(withFinding, 0, false, false), "\n") < 3 {
		t.Fatal("a phase with findings was collapsed to one line")
	}
	blocked := upgradeReport("pre")
	blocked.Decision, blocked.Disposition = "block", "block"
	if strings.Count(renderer.phaseResult(blocked, 10, false, false), "\n") < 3 {
		t.Fatal("a blocking phase was collapsed to one line")
	}
}

// The progress line renders stage constants by replacing hyphens with spaces,
// which turned StageAIReview into "ai review".
func TestProgressStageLabelCapitalisesTheAcronym(t *testing.T) {
	for stage, want := range map[string]string{
		StageAIReview:           "AI review",
		StageAIProviderCheck:    "AI provider check",
		StageAIProviderIdentity: "AI provider identity",
		StageAIProviderAttest:   "AI provider attestation",
		StageDeterministicScan:  "deterministic scan",
		StageSourceAcquisition:  "source acquisition",
	} {
		if got := stageLabel(stage); got != want {
			t.Errorf("stageLabel(%q) = %q, want %q", stage, got, want)
		}
	}
}

// TestDegradedAIReviewIsAlwaysStatedSomewhere binds where a skipped scan is
// reported, which is a balance rather than a single rule.
//
// The common degradation is persistent, not transient: the semantic fingerprint
// and provider identity bind behavior-shaping changes such as a provider CLI
// upgrade, so an ordinary upgrade can disable AI review until doctor is re-run.
// Refusing to collapse those phases printed the same full block once per gate
// per package, which is how a warning becomes wallpaper. Collapsing them
// silently would be worse. So: the compact line says it, and the artifact gate
// - the last word before pacman gets the archive - still says why.
func TestDegradedAIReviewIsAlwaysStatedSomewhere(t *testing.T) {
	degraded := func(phase string) *Report {
		return &Report{PackageBase: "demo", Phase: phase, Decision: "allow", ReportID: "r1",
			Reviewer: ReviewerReport{Mode: ReviewModeAI, Provider: "codex", Model: "gpt",
				Error: "provider attestation validation failed; AI review disabled for this run"}}
	}
	renderer := terminalRenderer{caps: terminalCapabilities{Interactive: true, Unicode: true, Columns: 100}}

	// A clean recipe or sources gate collapses - and still says it.
	compact := renderer.phaseResult(degraded("pre"), 0, false, false)
	if strings.Count(compact, "\n") != 0 {
		t.Errorf("a degraded but otherwise clean phase did not collapse:\n%s", compact)
	}
	for _, want := range []string{"AI review off", "prolewatch doctor"} {
		if !strings.Contains(compact, want) {
			t.Errorf("the collapsed line omitted %q: %s", want, compact)
		}
	}
	// The plain, non-terminal form says it too.
	plain := terminalRenderer{}.phaseResult(degraded("post"), 0, false, false)
	if !strings.Contains(plain, "AI review off") {
		t.Errorf("the plain collapsed line hid the skipped scan: %s", plain)
	}

	// The artifact gate never collapses, so the reason is stated once per
	// package immediately before installation.
	full := renderer.phaseResult(degraded("artifact"), 0, false, false)
	for _, want := range []string{"DEGRADED", "disabled for this run", "provider attestation validation failed"} {
		if !strings.Contains(full, want) {
			t.Errorf("the built-package gate did not explain the degradation (%q):\n%s", want, full)
		}
	}
	// A healthy reviewer adds nothing to the compact line.
	healthy := degraded("pre")
	healthy.Reviewer.Error = ""
	if clean := renderer.phaseResult(healthy, 0, false, false); strings.Contains(clean, "AI review off") {
		t.Errorf("a healthy phase claimed AI review was off: %s", clean)
	}
}

// TestRecipeGateExplainsWhatTheModelCouldSee binds the note that stops a
// correct empty result from reading as a broken one.
func TestRecipeGateExplainsWhatTheModelCouldSee(t *testing.T) {
	reviewed := func(phase string, files int) *Report {
		return &Report{PackageBase: "demo", Phase: phase, Decision: "allow",
			Coverage: brief.Coverage{SelectedFiles: files},
			Reviewer: ReviewerReport{Mode: ReviewModeAI, Provider: "codex", Model: "gpt",
				Verdicts: []Verdict{{Verdict: "allow", Confidence: "high"}}}}
	}
	if note := aiReviewScopeNote(reviewed("pre", 2)); !strings.Contains(note, "2 files") || !strings.Contains(note, "next gate") {
		t.Errorf("the recipe gate did not say what it saw: %q", note)
	}
	if note := aiReviewScopeNote(reviewed("pre", 1)); !strings.Contains(note, "1 file.") {
		t.Errorf("singular not handled: %q", note)
	}
	// Only the recipe gate. The others have no surprising scope to explain, and
	// a note on every report is noise.
	for _, phase := range []string{"post", "artifact"} {
		if note := aiReviewScopeNote(reviewed(phase, 140)); note != "" {
			t.Errorf("the %s gate carried a scope note: %q", phase, note)
		}
	}
	// Nothing to explain when the model never ran.
	skipped := reviewed("pre", 2)
	skipped.Reviewer.Verdicts = nil
	if note := aiReviewScopeNote(skipped); note != "" {
		t.Errorf("a phase the model never saw carried a scope note: %q", note)
	}
}
