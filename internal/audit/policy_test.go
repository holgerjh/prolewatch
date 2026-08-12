package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeReviewer struct {
	err      error
	probeErr error
	calls    int
	verdicts []Verdict
}

func (f *fakeReviewer) Probe(context.Context) (ProviderMetadata, error) {
	metadata := ProviderMetadata{Provider: "codex", Transport: "cli", RuntimeVersion: "codex-cli test", Model: "gpt", Effort: "high", AdapterPolicy: "test-v1"}
	return metadata, f.probeErr
}

func TestProviderInitializationFailureRequiresUnsafeBypassPolicy(t *testing.T) {
	withStateAndShare(t)
	probeFailure := errors.New("provider probe unavailable")
	if _, err := NewAuditService(context.Background(), DefaultConfig(), &fakeReviewer{probeErr: probeFailure}); !errors.Is(err, probeFailure) {
		t.Fatalf("default policy accepted provider initialization failure: %v", err)
	}

	cfg := DefaultConfig()
	cfg.Overrides.AllowUnsafe = true
	service, err := NewAuditService(context.Background(), cfg, &fakeReviewer{probeErr: probeFailure})
	if err != nil || !strings.Contains(service.InitializationError, probeFailure.Error()) {
		t.Fatalf("unsafe policy did not preserve initialization failure: service=%+v err=%v", service, err)
	}
	root := t.TempDir()
	writePackageFixture(t, root)
	blocked, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil || status != 22 || blocked.ApprovalEligible || !blocked.UnsafeBypassEligible {
		t.Fatalf("initialization failure classification: report=%+v status=%d err=%v", blocked, status, err)
	}
	if _, err := service.Approvals.Create(blocked, "unsafe", "explicit BYPASS"); err != nil {
		t.Fatal(err)
	}
	bypassed, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil || status != 0 || !bypassed.UnsafeBypass || bypassed.Reviewer.Error == "" || !hasExplicitUnsafeBypassFinding(bypassed.Findings) {
		t.Fatalf("initialization bypass lost provenance: report=%+v status=%d err=%v", bypassed, status, err)
	}
}

func TestProviderFailureIsBoundedIntoValidReport(t *testing.T) {
	withStateAndShare(t)
	reviewer := &fakeReviewer{err: errors.New(strings.Repeat("provider failure ", 700))}
	service, err := NewAuditService(context.Background(), DefaultConfig(), reviewer)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	writePackageFixture(t, root)
	report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil || status != 22 || report == nil {
		t.Fatalf("provider failure did not produce a report: report=%+v status=%d err=%v", report, status, err)
	}
	if len(report.Reviewer.Error) > 4*1024 || len(report.Summary) > 8192 || report.Validate() != nil {
		t.Fatalf("provider failure escaped report bounds: error=%d summary=%d", len(report.Reviewer.Error), len(report.Summary))
	}
}

func TestArtifactBypassCreatesHashBoundNonNetworkReport(t *testing.T) {
	withStateAndShare(t)
	cfg := DefaultConfig()
	cfg.Overrides.AllowUnsafe = true
	service, err := NewAuditService(context.Background(), cfg, &fakeReviewer{})
	if err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(t.TempDir(), "demo.pkg.tar.zst")
	if err := os.WriteFile(artifact, []byte("uninspected artifact bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := service.CreateArtifactBypass([]string{artifact}, "demo", errors.New("artifact scanner unavailable"))
	if err != nil {
		t.Fatal(err)
	}
	if err := report.Validate(); err != nil || report.ContentHash == "" || report.NetworkEligible || !report.UnsafeBypass || report.UnscannedBypass || !hasExplicitUnsafeBypassFinding(report.Findings) {
		t.Fatalf("invalid artifact bypass report: %+v err=%v", report, err)
	}
	if _, err := service.CreateArtifactBypass([]string{artifact, artifact}, "demo", nil); err == nil {
		t.Fatal("duplicate artifact name was accepted")
	}
}
func (f *fakeReviewer) Review(_ context.Context, _ string, _ string, _ *Inventory) (ProviderMetadata, []Verdict, error) {
	f.calls++
	metadata, _ := f.Probe(context.Background())
	if f.err != nil {
		return metadata, nil, f.err
	}
	if f.verdicts != nil {
		return metadata, f.verdicts, nil
	}
	return metadata, []Verdict{{SchemaVersion: 1, Verdict: "allow", Confidence: "high", Summary: "safe", Findings: []ReviewFinding{}, CoverageNotes: []string{}}}, nil
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
			cfg := DefaultConfig()
			cfg.Review.MinimumConfidence = current.minimum
			reviewer := &fakeReviewer{verdicts: []Verdict{{SchemaVersion: 1, Verdict: "allow", Confidence: "medium", Summary: "looks safe", Findings: []ReviewFinding{}, CoverageNotes: []string{}}}}
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
			if current.status == 0 && report.Disposition != "auto_allow" {
				t.Fatalf("threshold allow did not expose AUTO-ALLOW: %+v", report)
			}
			if current.status == 0 {
				rendered := RenderReport(report)
				if !strings.Contains(rendered, "Decision: AUTO-ALLOW") || !strings.Contains(rendered, "AI confidence: medium") || !strings.Contains(rendered, "Minimum confidence: "+current.minimum) {
					t.Fatalf("automatic threshold feedback is incomplete:\n%s", rendered)
				}
			}
		})
	}
}

func TestPromptInjectionRequiresConfiguredUnsafeBypass(t *testing.T) {
	for _, allowUnsafe := range []bool{false, true} {
		withStateAndShare(t)
		root := t.TempDir()
		writePackageFixture(t, root)
		cfg := DefaultConfig()
		cfg.Overrides.AllowUnsafe = allowUnsafe
		reviewer := &fakeReviewer{verdicts: []Verdict{{SchemaVersion: 1, Verdict: "block", Confidence: "high", Summary: "injection", PromptInjectionDetected: true, Findings: []ReviewFinding{}, CoverageNotes: []string{}}}}
		service, err := NewAuditService(context.Background(), cfg, reviewer)
		if err != nil {
			t.Fatal(err)
		}
		report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
		if err != nil || status != 10 || report.ApprovalEligible || report.UnsafeBypassEligible != allowUnsafe {
			t.Fatalf("unsafe=%t report=%+v status=%d err=%v", allowUnsafe, report, status, err)
		}
	}
}

func TestAICoverageGapOffersExactInteractiveOverride(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writePackageFixture(t, root)
	reviewer := &fakeReviewer{verdicts: []Verdict{{
		SchemaVersion: 1,
		Verdict:       "allow",
		Confidence:    "high",
		Summary:       "reviewed selected files",
		Findings:      []ReviewFinding{},
		CoverageNotes: []string{"generated commands could not be inspected"},
	}}}
	service, err := NewAuditService(context.Background(), DefaultConfig(), reviewer)
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
	if !strings.Contains(rendered, "AI coverage gaps:") || !strings.Contains(rendered, "generated commands could not be inspected") || !strings.Contains(rendered, "Override: prolewatch approve ") {
		t.Fatalf("coverage gap report omitted its reason or override: %s", rendered)
	}
	if _, err := service.Approvals.Create(report, "approval", "reviewed coverage gap"); err != nil {
		t.Fatal(err)
	}
	overridden, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil || status != 0 || overridden.Decision != "allow" || !overridden.Overridden || overridden.UnsafeBypass {
		t.Fatalf("coverage-gap override was not consumed exactly once: status=%d report=%+v err=%v", status, overridden, err)
	}
}

func TestAIHighFindingCannotRenderAutomaticAllowSummary(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writePackageFixture(t, root)
	cfg := DefaultConfig()
	cfg.Review.MinimumConfidence = "medium"
	reviewer := &fakeReviewer{verdicts: []Verdict{{SchemaVersion: 1, Verdict: "allow", Confidence: "medium", Summary: "review needed", Findings: []ReviewFinding{{Severity: "high", Category: "other", File: "PKGBUILD", Rationale: "high-risk behavior"}}, CoverageNotes: []string{}}}}
	service, err := NewAuditService(context.Background(), cfg, reviewer)
	if err != nil {
		t.Fatal(err)
	}
	report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil || status != 10 || report.Disposition != "block" || !strings.Contains(report.Summary, "AI high-severity") || strings.Contains(report.Summary, "Automatically allowed") {
		t.Fatalf("misleading AI finding decision: report=%+v status=%d err=%v", report, status, err)
	}
}

func TestUnsafeBypassTokenAllowsExactBlockedSnapshotOnce(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writePackageFixture(t, root)
	cfg := DefaultConfig()
	cfg.Overrides.AllowUnsafe = true
	reviewer := &fakeReviewer{verdicts: []Verdict{{SchemaVersion: 1, Verdict: "block", Confidence: "high", Summary: "injection", PromptInjectionDetected: true, Findings: []ReviewFinding{}, CoverageNotes: []string{}}}}
	service, err := NewAuditService(context.Background(), cfg, reviewer)
	if err != nil {
		t.Fatal(err)
	}
	blocked, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil || status != 10 || !blocked.UnsafeBypassEligible {
		t.Fatalf("blocked=%+v status=%d err=%v", blocked, status, err)
	}
	if _, err := service.Approvals.Create(blocked, "unsafe", "test BYPASS"); err != nil {
		t.Fatal(err)
	}
	bypassed, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil || status != 0 || !bypassed.UnsafeBypass || bypassed.Disposition != "unsafe_bypass" || bypassed.NetworkEligible {
		t.Fatalf("bypassed=%+v status=%d err=%v", bypassed, status, err)
	}
	if len(bypassed.Reviewer.Verdicts) != 1 || !bypassed.Reviewer.Verdicts[0].PromptInjectionDetected || !hasExplicitUnsafeBypassFinding(bypassed.Findings) {
		t.Fatalf("unsafe bypass lost its source decision or warning: %+v", bypassed)
	}
	if _, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo"); err != nil || status != 10 {
		t.Fatalf("unsafe token was reusable: status=%d err=%v", status, err)
	}
}

func TestUnscannedBypassIsTransactionBoundAndExplicit(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	cfg := DefaultConfig()
	cfg.Overrides.AllowUnsafe = true
	service, err := NewAuditService(context.Background(), cfg, &fakeReviewer{})
	if err != nil {
		t.Fatal(err)
	}
	report, err := service.CreateUnscannedBypass(root, "pre", "demo", YayContext{}, errors.New("forced scanner failure"))
	if err != nil {
		t.Fatal(err)
	}
	if report.Validate() != nil || !report.UnscannedBypass || report.ContentHash != "" || report.Disposition != "unsafe_bypass" {
		t.Fatalf("unexpected unscanned bypass: %+v", report)
	}
	verified, err := service.VerifyMarker(root, "pre")
	if err != nil || verified.ReportID != report.ReportID {
		t.Fatalf("unscanned marker did not verify in its live transaction: report=%+v err=%v", verified, err)
	}
	service.Config.Overrides.AllowUnsafe = false
	if _, err := service.VerifyMarker(root, "pre"); err == nil {
		t.Fatal("unscanned bypass survived disabling unsafe policy")
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
	service, err := NewAuditService(context.Background(), DefaultConfig(), &fakeReviewer{})
	if err != nil {
		t.Fatal(err)
	}
	report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil || status != 0 {
		t.Fatalf("pre-scan failed: report=%+v status=%d err=%v", report, status, err)
	}
	canonical, marker, err := markerLocation(root, "pre")
	if err != nil {
		t.Fatal(err)
	}
	if canonical != root || !regularNoFollow(marker) || strings.HasPrefix(marker, root+string(os.PathSeparator)) {
		t.Fatalf("marker was not stored outside the checkout: root=%q canonical=%q marker=%q", root, canonical, marker)
	}
	if _, err := os.Lstat(filepath.Join(root, markerPrefix+"pre.json")); !errors.Is(err, os.ErrNotExist) {
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

func TestUnscannedBypassRejectsOrdinaryPolicyAndInvalidIdentity(t *testing.T) {
	withStateAndShare(t)
	ordinary, err := NewAuditService(context.Background(), DefaultConfig(), &fakeReviewer{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ordinary.CreateUnscannedBypass(t.TempDir(), "pre", "demo", YayContext{}, nil); err == nil {
		t.Fatal("ordinary policy created an unscanned bypass")
	}
	cfg := DefaultConfig()
	cfg.Overrides.AllowUnsafe = true
	unsafeService, err := NewAuditService(context.Background(), cfg, &fakeReviewer{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unsafeService.CreateUnscannedBypass(t.TempDir(), "artifact", "demo", YayContext{}, nil); err == nil {
		t.Fatal("directory bypass accepted artifact phase")
	}
	if _, err := unsafeService.CreateUnscannedBypass(t.TempDir(), "pre", "bad/base", YayContext{}, nil); err == nil {
		t.Fatal("directory bypass accepted invalid package base")
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
	service, err := NewAuditService(context.Background(), DefaultConfig(), reviewer)
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
func TestPolicyProviderErrorFailsClosed(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writePackageFixture(t, root)
	service, err := NewAuditService(context.Background(), DefaultConfig(), &fakeReviewer{err: errors.New("offline")})
	if err != nil {
		t.Fatal(err)
	}
	report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if status != 22 || report.Decision != "block" || !strings.Contains(report.Reviewer.Error, "offline") {
		t.Fatalf("unexpected failure: %d %+v", status, report)
	}
}

func TestProviderTimeoutIsClassifiedOnActivity(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writePackageFixture(t, root)
	recorder, err := NewActivityRecorder("demo", "scan", "pre")
	if err != nil {
		t.Fatal(err)
	}
	ctx := withActivity(context.Background(), recorder)
	service, err := NewAuditService(ctx, DefaultConfig(), &fakeReviewer{err: ErrProviderTimeout})
	if err != nil {
		t.Fatal(err)
	}
	_, status, err := service.ScanDirectory(ctx, "pre", root, "demo")
	if err != nil || status != 22 {
		t.Fatalf("unexpected timeout result: status=%d err=%v", status, err)
	}
	recorder.Finish(activityResult(status), "")
	stored, err := recorder.store.Load(recorder.activity.ActivityID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != ActivityFailed || stored.FailureReason != ActivityFailureProviderTimeout || !strings.Contains(stored.Message, "timeout") {
		t.Fatalf("provider timeout activity=%#v", stored)
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
	if status != 10 || report.Decision != "block" || !report.ApprovalEligible || structuralBlock(&Inventory{Findings: report.Findings, Coverage: report.Coverage}) {
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

func TestDeterministicAssessmentMatchesPolicyBoundaries(t *testing.T) {
	complete := Coverage{Complete: true}
	cases := []struct {
		name       string
		inventory  *Inventory
		decision   string
		approval   bool
		structural bool
	}{
		{name: "nil", inventory: nil, decision: "block", structural: true},
		{name: "safe", inventory: &Inventory{Coverage: complete, ManifestHash: strings.Repeat("a", 64)}, decision: "allow"},
		{name: "warning", inventory: &Inventory{Coverage: complete, ManifestHash: strings.Repeat("a", 64), Findings: []Finding{{Severity: "medium"}}}, decision: "allow"},
		{name: "high", inventory: &Inventory{Coverage: complete, ManifestHash: strings.Repeat("a", 64), Findings: []Finding{{Severity: "high"}}}, decision: "block", approval: true},
		{name: "hard", inventory: &Inventory{Coverage: complete, ManifestHash: strings.Repeat("a", 64), Findings: []Finding{{Severity: "critical", HardBlock: true}}}, decision: "block", structural: true},
		{name: "incomplete", inventory: &Inventory{Coverage: Coverage{Complete: false}, ManifestHash: strings.Repeat("a", 64)}, decision: "block", structural: true},
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

func TestDeterministicFingerprintIgnoresProviderIdentityAndAssets(t *testing.T) {
	withStateAndShare(t)
	cfg := DefaultConfig()
	cfg.Review.Mode = ReviewModeDeterministicOnly
	archive, err := archiveProbeIdentity(context.Background())
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
	aiCfg := DefaultConfig()
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
	aiCfg = DefaultConfig()
	networkDefaultFingerprint, err := ComputePolicyFingerprint(aiCfg, metadata, archive)
	if err != nil {
		t.Fatal(err)
	}
	aiCfg.Network.AutoEnableKnownTools = false
	leaseOnlyFingerprint, err := ComputePolicyFingerprint(aiCfg, metadata, archive)
	if err != nil {
		t.Fatal(err)
	}
	if leaseOnlyFingerprint == networkDefaultFingerprint {
		t.Fatal("automatic known-tool network policy did not change the security policy fingerprint")
	}
}

func TestPostReportCarriesVerificationReceiptAndBindsVendorBytes(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	archive := vendorTarBytes(t, map[string][]byte{"safe.txt": []byte("safe\n")})
	writeRemoteSourceFixture(t, root, archive)
	service, err := NewAuditService(context.Background(), DefaultConfig(), &fakeReviewer{})
	if err != nil {
		t.Fatal(err)
	}
	pre, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil || status != 0 {
		t.Fatalf("pre report: status=%d report=%+v err=%v", status, pre, err)
	}
	pre.SourceVerification = SourceVerification{Checksums: "passed", PGP: "not-applicable"}
	if err := service.Reports.Replace(pre); err != nil {
		t.Fatal(err)
	}
	post, status, err := service.ScanDirectory(context.Background(), "post", root, "demo")
	if err != nil || status != 0 {
		t.Fatalf("post report: status=%d report=%+v err=%v", status, post, err)
	}
	if post.SourceVerification != pre.SourceVerification || len(post.Sources) != 1 || post.Sources[0].ObservedSHA256 != SHA256Bytes(archive) || post.Sources[0].ContentInspected {
		t.Fatalf("post report lost verification or binding: %+v %#v", post.SourceVerification, post.Sources)
	}
	post.SourceVerification = SourceVerification{Checksums: "passed", PGP: "verified"}
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
	service, err := NewAuditService(context.Background(), DefaultConfig(), reviewer)
	if err != nil {
		t.Fatal(err)
	}
	report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if status != 10 || reviewer.calls != 0 || report.ApprovalEligible {
		t.Fatalf("unexpected hard-block policy: status=%d calls=%d approval=%t", status, reviewer.calls, report.ApprovalEligible)
	}
}

func TestProviderMetadataChangeFailsClosed(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writePackageFixture(t, root)
	reviewer := &changingReviewer{}
	service, err := NewAuditService(context.Background(), DefaultConfig(), reviewer)
	if err != nil {
		t.Fatal(err)
	}
	report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil {
		t.Fatal(err)
	}
	if status != 22 || report.Decision != "block" || !strings.Contains(report.Reviewer.Error, "metadata changed") {
		t.Fatalf("metadata change did not fail closed: status=%d report=%+v", status, report)
	}
}

type changingReviewer struct{}

func (*changingReviewer) Probe(context.Context) (ProviderMetadata, error) {
	return ProviderMetadata{Provider: "codex", Transport: "cli", RuntimeVersion: "codex-cli before", Model: "gpt", Effort: "high", AdapterPolicy: "test-v1"}, nil
}
func (*changingReviewer) Review(context.Context, string, string, *Inventory) (ProviderMetadata, []Verdict, error) {
	metadata, _ := (&changingReviewer{}).Probe(context.Background())
	metadata.RuntimeVersion = "codex-cli after"
	return metadata, []Verdict{{SchemaVersion: 1, Verdict: "allow", Confidence: "high", Summary: "safe", Findings: []ReviewFinding{}, CoverageNotes: []string{}}}, nil
}
