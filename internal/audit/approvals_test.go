package audit

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestUsedApprovalHistoryIsBounded(t *testing.T) {
	store := &ApprovalStore{Root: t.TempDir()}
	used := filepath.Join(store.Root, "used")
	if err := os.MkdirAll(used, 0o700); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < usedApprovalRetention+3; index++ {
		id := fmt.Sprintf("20260812T%06dZ-aaaaaaaaaaaa-bbbbbbbb", index)
		if err := os.WriteFile(filepath.Join(used, "approval-"+id+".json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	unknown := filepath.Join(used, "operator-note")
	if err := os.WriteFile(unknown, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	store.PruneUsed()
	entries, err := os.ReadDir(used)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != usedApprovalRetention+1 {
		t.Fatalf("used approval directory contains %d entries", len(entries))
	}
	if _, err := os.Stat(unknown); err != nil {
		t.Fatalf("unknown operator file was pruned: %v", err)
	}
}

func approvalFixture() *Report {
	return &Report{
		SchemaVersion:     ReportSchemaVersion,
		ReportID:          "20260812T010203Z-aaaaaaaaaaaa-bbbbbbbb",
		PackageBase:       "demo",
		Phase:             "post",
		Decision:          "block",
		ContentHash:       strings.Repeat("a", 64),
		PolicyFingerprint: strings.Repeat("b", 64),
		ApprovalEligible:  true,
	}
}

func TestCancelPendingRemovesOnlyExactPendingToken(t *testing.T) {
	store := &ApprovalStore{Root: t.TempDir()}
	path, err := store.Create(approvalFixture(), "approval", "inline decision")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CancelPending(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("pending token still exists: %v", err)
	}
	if err := store.CancelPending(store.Root + "/outside.json"); err == nil {
		t.Fatal("accepted cancellation outside pending directory")
	}
}

// Both decision kinds ask the same way and default to no. The severity lives
// in the briefing above; a ceremony that fires on ordinary packages becomes
// muscle memory, and typing a word by reflex is not a more considered decision
// than pressing a key by reflex.
//
// What bounds a mistake is the shape of the approval - this exact content, this
// policy, once, and never across a structural finding - not the shape of the
// question.
func TestInlineDecisionsAskOnceAndDefaultToNo(t *testing.T) {
	for _, current := range []struct {
		mode   string
		input  string
		accept bool
	}{
		{inlineConfidence, "y\n", true},
		{inlineConfidence, "Y\n", true},
		{inlineConfidence, "yes\n", true},
		{inlineConfidence, "\n", false},
		{inlineOverride, "y\n", true},
		{inlineOverride, "\n", false},
		{inlineOverride, "n\n", false},
		{inlineOverride, "OVERRIDE\n", false},
		{inlineOverride, "yeah\n", false},
	} {
		var output bytes.Buffer
		if got := confirmInlineDecisionInput(current.mode, approvalFixture(), nil, strings.NewReader(current.input), &output, inlineFindingPreviews{}, "high"); got != current.accept {
			t.Fatalf("mode=%s input=%q accepted=%t want=%t output=%q", current.mode, current.input, got, current.accept, output.String())
		}
	}
}

func TestInlineDecisionClassificationAndTokenKinds(t *testing.T) {
	cfg := DefaultConfig()
	confidence := approvalFixture()
	confidence.Reviewer = ReviewerReport{Mode: ReviewModeAI, MinimumConfidence: "high", Verdicts: []Verdict{{SchemaVersion: VerdictSchemaVersion, Verdict: "allow", Confidence: "medium", Summary: "safe", Findings: []ReviewFinding{}, Guidance: []FindingGuidance{}, CoverageNotes: []string{}}}}
	if mode := classifyInlineDecision(confidence, cfg); mode != inlineConfidence {
		t.Fatalf("confidence decision classified as %q", mode)
	}
	store := &ApprovalStore{Root: t.TempDir()}
	path, err := createInlineToken(inlineConfidence, confidence, store)
	if err != nil || !strings.Contains(filepath.Base(path), "approval-") {
		t.Fatalf("confidence token: path=%q err=%v", path, err)
	}
	if err := store.CancelPending(path); err != nil {
		t.Fatal(err)
	}

	override := approvalFixture()
	if mode := classifyInlineDecision(override, cfg); mode != inlineOverride {
		t.Fatalf("override decision classified as %q", mode)
	}
	// A report that is not approval-eligible has no interactive path at all.
	// This keeps every structural boundary ineligible for an override.
	ineligible := approvalFixture()
	ineligible.ApprovalEligible = false
	if mode := classifyInlineDecision(ineligible, cfg); mode != "" {
		t.Fatalf("an approval-ineligible report offered %q", mode)
	}
	if _, err := createInlineToken("bypass", ineligible, store); err == nil {
		t.Fatal("a bypass token was created; the kind no longer exists")
	}
}

func TestApprovalTokenIsConsumedAtMostOnce(t *testing.T) {
	store := &ApprovalStore{Root: t.TempDir()}
	if _, err := store.Create(approvalFixture(), "approval", "reviewed carefully"); err != nil {
		t.Fatal(err)
	}
	results := make(chan *ApprovalToken, 2)
	errors := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			token, err := store.Consume("approval", "demo", "post", strings.Repeat("a", 64), strings.Repeat("b", 64))
			results <- token
			errors <- err
		}()
	}
	wait.Wait()
	close(results)
	close(errors)
	consumed := 0
	for token := range results {
		if token != nil {
			consumed++
		}
	}
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if consumed != 1 {
		t.Fatalf("token consumed %d times", consumed)
	}
}

func TestLegacyReportCannotCreateApproval(t *testing.T) {
	report := approvalFixture()
	report.SchemaVersion--
	if _, err := (&ApprovalStore{Root: t.TempDir()}).Create(report, "approval", "reviewed"); err == nil {
		t.Fatal("legacy report created an approval")
	}
}

func TestApprovalCreationRejectsInvalidKindsEligibilityAndDuplicates(t *testing.T) {
	store := &ApprovalStore{Root: t.TempDir()}
	if _, err := store.Create(nil, "approval", "reviewed"); err == nil {
		t.Fatal("nil report was accepted")
	}
	if _, err := store.Create(approvalFixture(), "invalid", "reviewed"); err == nil {
		t.Fatal("invalid approval kind was accepted")
	}
	ineligible := approvalFixture()
	ineligible.ApprovalEligible = false
	if _, err := store.Create(ineligible, "approval", "reviewed"); err == nil {
		t.Fatal("ineligible report was accepted")
	}
	if _, err := store.Create(approvalFixture(), "approval", "no"); err == nil {
		t.Fatal("short reason was accepted")
	}
	if _, err := store.Create(approvalFixture(), "approval", "reviewed once"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(approvalFixture(), "approval", "reviewed twice"); err == nil {
		t.Fatal("duplicate pending approval was accepted")
	}
}

// The user should not be told to run a command in another shell when a prompt
// is about to ask them the same question. This pairs with
// confirmInlineDecision: the briefing suppresses the command-line instructions
// exactly when an interactive decision is coming.
func TestBriefingOffersTheCommandOnlyWhenNoPromptFollows(t *testing.T) {
	report := approvalFixture()
	report.Decision, report.Disposition, report.ApprovalEligible = "block", "block", true

	standalone := RenderReport(report)
	if !strings.Contains(standalone, "prolewatch approve ") {
		t.Fatalf("a standalone briefing must say how to act:\n%s", standalone)
	}
	withPrompt := renderReportText(report, true)
	if strings.Contains(withPrompt, "To approve this exact snapshot") {
		t.Fatalf("the briefing sent the user to another shell before prompting:\n%s", withPrompt)
	}
}

// The prompt reads /dev/tty rather than stdin, because the wrapper runs beneath
// yay and yay is free to redirect makepkg's streams. A prompt that only appears
// when stdin happens to be a terminal would silently vanish.
func TestInlineDecisionUsesTheControllingTerminal(t *testing.T) {
	previous := openControllingTerminal
	defer func() { openControllingTerminal = previous }()

	openControllingTerminal = func() (io.ReadWriteCloser, error) { return nil, errors.New("no controlling terminal") }
	if interactiveDecisionAvailable() {
		t.Fatal("an interactive decision was claimed with no terminal")
	}
	if confirmInlineDecision(inlineOverride, approvalFixture(), nil, "", "high") {
		t.Fatal("a decision was confirmed with nobody to ask")
	}
}

// Declining names the command-line path so the user knows how to revisit the
// decision after the inline prompt closes.
func TestDecliningAPromptStillNamesTheCommandLinePath(t *testing.T) {
	report := approvalFixture()
	var out bytes.Buffer
	confirmInlineDecisionInput(inlineOverride, report, nil, strings.NewReader("no\n"), &out, inlineFindingPreviews{}, "high")
	rendered := out.String()
	if !strings.Contains(rendered, "prolewatch approve "+report.ReportID) {
		t.Fatalf("the prompt does not say how to approve later:\n%s", rendered)
	}
	if !strings.Contains(rendered, "stops the install") {
		t.Fatalf("the prompt does not say what declining does:\n%s", rendered)
	}
}

func TestInlineDecisionCanViewEvidenceWithoutAuthorizing(t *testing.T) {
	report := approvalFixture()
	views := 0
	preview := func() string {
		views++
		return "trusted frame · untrusted context"
	}
	var out bytes.Buffer
	if confirmInlineDecisionInput(inlineOverride, report, nil, strings.NewReader("i\nn\n"), &out, inlineFindingPreviews{decision: preview}, "high") {
		t.Fatal("viewing evidence authorized the package")
	}
	if views != 1 || !strings.Contains(out.String(), "[i] Inspect HIGH/CRITICAL findings") || !strings.Contains(out.String(), "untrusted context") || strings.Count(out.String(), "MANUAL REVIEW REQUIRED") != 2 {
		t.Fatalf("view action did not return to the decision prompt: views=%d output=%q", views, out.String())
	}
}

func TestInlineDecisionCanInspectAllFindingsWithoutAuthorizing(t *testing.T) {
	report := approvalFixture()
	decisionViews, allViews := 0, 0
	previews := inlineFindingPreviews{
		decision: func() string { decisionViews++; return "decision findings" },
		all:      func() string { allViews++; return "all findings including metadata" },
		allCount: 7,
	}
	var out bytes.Buffer
	if confirmInlineDecisionInput(inlineOverride, report, nil, strings.NewReader("a\nn\n"), &out, previews, "high") {
		t.Fatal("viewing all findings authorized the package")
	}
	if decisionViews != 0 || allViews != 1 || !strings.Contains(out.String(), "[a] Inspect all 7 findings") || !strings.Contains(out.String(), "all findings including metadata") || strings.Count(out.String(), "MANUAL REVIEW REQUIRED") != 2 {
		t.Fatalf("all-findings action did not return to the decision prompt: decision=%d all=%d output=%q", decisionViews, allViews, out.String())
	}
}

func TestInlineDecisionOffersOnDemandAIReviewOnlyOnce(t *testing.T) {
	report := approvalFixture()
	report.Reviewer = ReviewerReport{Mode: ReviewModeAI, Skipped: "recipe phase is not included in AI review"}
	var output bytes.Buffer
	reviews := 0
	previews := inlineFindingPreviews{review: func(io.Writer) (string, bool) {
		reviews++
		report.ReportID = "20260831T010204Z-" + report.ContentHash[:12] + "-bbbbbbbb"
		return "AI review completed for the refreshed snapshot", true
	}}
	if confirmInlineDecisionInput(inlineOverride, report, nil, strings.NewReader("r\nn\n"), &output, previews, "high") {
		t.Fatal("review followed by the default answer authorized the package")
	}
	rendered := output.String()
	if reviews != 1 || strings.Count(rendered, "[r] Run AI review now") != 1 || !strings.Contains(rendered, "AI review completed for the refreshed snapshot") || !strings.Contains(rendered, report.ReportID) {
		t.Fatalf("on-demand review was not one-shot or did not refresh the prompt: reviews=%d output=%q", reviews, rendered)
	}
}

func TestManualReviewPromptUsesTheBlueProlewatchBlock(t *testing.T) {
	var out bytes.Buffer
	renderer := terminalRendererWithCapabilities(&out, terminalCapabilities{Interactive: true, Unicode: true, Color: terminalColorTrue})
	writeInlineDecisionPrompt(renderer, &out, "demo", "The findings above need your decision.", "prolewatch approve report", true, false, 7, "high")
	rendered := out.String()
	for _, want := range []string{"PROLEWATCH", "MANUAL REVIEW REQUIRED", "The findings above need your decision.", "[i] Inspect HIGH/CRITICAL findings · [a] Inspect all 7 findings · [y] Continue · [N] Abort", "38;2;23;147;209"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("manual review block omitted %q: %q", want, rendered)
		}
	}
	if strings.Contains(rendered, "Approving covers") {
		t.Fatalf("manual review block retained redundant approval text: %q", rendered)
	}
	out.Reset()
	writeInlineDecisionPrompt(renderer, &out, "demo", "review", "later", true, true, 3, "medium")
	if !strings.Contains(out.String(), "Inspect MEDIUM+ findings") || !strings.Contains(out.String(), "[r] Run AI review now") || strings.Contains(out.String(), "HIGH/CRITICAL") {
		t.Fatalf("manual review action did not follow configured threshold: %q", out.String())
	}
	out.Reset()
	writeInlineDecisionPrompt(renderer, &out, "demo", "review", "later", false, false, 0, "high")
	if strings.Contains(out.String(), "[i]") || strings.Contains(out.String(), "[a]") {
		t.Fatalf("a prompt with no previewable findings offered inspection keys: %q", out.String())
	}
	if !strings.Contains(out.String(), "[y] Continue · [N] Abort") || strings.Contains(out.String(), "[y/N]") {
		t.Fatalf("a decision-only prompt did not spell out its safe default: %q", out.String())
	}
}
