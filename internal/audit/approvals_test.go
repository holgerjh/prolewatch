package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

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

func TestInlineDecisionConfirmationsAreTiered(t *testing.T) {
	for _, current := range []struct {
		mode   string
		input  string
		accept bool
	}{
		{inlineConfidence, "y\n", true},
		{inlineConfidence, "\n", false},
		{inlineOverride, "OVERRIDE\n", true},
		{inlineOverride, "override\n", false},
		{inlineBypass, "BYPASS\n", true},
		{inlineBypass, "OVERRIDE\n", false},
	} {
		var output bytes.Buffer
		if got := confirmInlineDecisionInput(current.mode, approvalFixture(), nil, strings.NewReader(current.input), &output); got != current.accept {
			t.Fatalf("mode=%s input=%q accepted=%t want=%t output=%q", current.mode, current.input, got, current.accept, output.String())
		}
	}
}

func TestInlineDecisionClassificationAndTokenKinds(t *testing.T) {
	cfg := DefaultConfig()
	confidence := approvalFixture()
	confidence.Reviewer = ReviewerReport{Mode: ReviewModeAI, MinimumConfidence: "high", Verdicts: []Verdict{{SchemaVersion: 1, Verdict: "allow", Confidence: "medium", Summary: "safe", Findings: []ReviewFinding{}, CoverageNotes: []string{}}}}
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
	bypass := approvalFixture()
	bypass.ApprovalEligible = false
	bypass.UnsafeBypassEligible = true
	cfg.Overrides.AllowUnsafe = true
	if mode := classifyInlineDecision(bypass, cfg); mode != inlineBypass {
		t.Fatalf("bypass decision classified as %q", mode)
	}
	path, err = createInlineToken(inlineBypass, bypass, store)
	if err != nil || !strings.Contains(filepath.Base(path), "unsafe-") {
		t.Fatalf("unsafe token: path=%q err=%v", path, err)
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
