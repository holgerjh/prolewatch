package audit

import (
	"context"
	"errors"
	"fmt"
	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/safe"
	"os"
	"path/filepath"
	"strings"
)

type ReviewClient interface {
	Probe(context.Context) (ProviderMetadata, error)
	Review(context.Context, string, string, *brief.Inventory, ReviewOptions) (ProviderMetadata, []Verdict, error)
}

var (
	auditServiceFactory = NewAuditService
	reviewClientFactory = func(cfg Config) ReviewClient { return NewReviewer(cfg) }
)

type AuditService struct {
	Config              Config
	Scanner             *brief.Scanner
	Reviewer            ReviewClient
	Reports             *ReportStore
	Approvals           *ApprovalStore
	Metadata            ProviderMetadata
	PolicyFingerprint   string
	ArchiveProbe        brief.ToolIdentity
	InitializationError string
	// CoverageError records a failure that leaves package content uninspected,
	// as opposed to an optional reviewer that merely went missing.
	CoverageError string
}

// DeterministicAssessment is the policy disposition produced without an AI
// reviewer. Scenario and acceptance tooling uses the same assessment as the
// production deterministic-only path instead of reimplementing policy rules.
type DeterministicAssessment struct {
	Decision         string
	ApprovalEligible bool
	HardBlock        bool
	DecisionBlock    bool
	StructuralBlock  bool
}

func AssessDeterministic(inv *brief.Inventory) DeterministicAssessment {
	return AssessDeterministicAt(inv, "high")
}

func AssessDeterministicAt(inv *brief.Inventory, minimumSeverity string) DeterministicAssessment {
	return assessDeterministicAt(inv, minimumSeverity, nil)
}

func assessDeterministicAt(inv *brief.Inventory, minimumSeverity string, carried map[string]bool) DeterministicAssessment {
	// Deterministic-only allows only complete coverage with neither a hard block
	// nor a finding at the configured decision threshold. Approval eligibility
	// is narrower: structural failures cannot become ordinary one-time approvals.
	assessment := DeterministicAssessment{Decision: "block", StructuralBlock: structuralBlock(inv)}
	if inv == nil || !brief.ValidSeverity(minimumSeverity) {
		return assessment
	}
	for _, finding := range inv.Findings {
		assessment.HardBlock = assessment.HardBlock || finding.HardBlock
		if !carried[findingGuidanceID(finding)] {
			assessment.DecisionBlock = assessment.DecisionBlock || severityAtLeast(finding.Severity, minimumSeverity)
		}
	}
	if inv.Coverage.Complete && !assessment.HardBlock && !assessment.DecisionBlock {
		assessment.Decision = "allow"
	}
	assessment.ApprovalEligible = assessment.Decision == "block" && inv.ManifestHash != "" && !assessment.StructuralBlock
	return assessment
}

func NewAuditService(ctx context.Context, cfg Config, reviewer ReviewClient) (*AuditService, error) {
	// Freeze all decision inputs before scanning: provider metadata/attestation,
	// archive parser identity, threat bundle, and policy. An
	// unsafe-enabled initialization failure remains visible in every report.
	requireAttestation := cfg.Review.Mode == ReviewModeAI && reviewer == nil
	var metadata ProviderMetadata
	initializationError, coverageError := "", ""
	if cfg.Review.Mode == ReviewModeAI {
		progressTimedStage(ctx, StageAIProviderCheck, cfg.Review.TimeoutSeconds)
		if reviewer == nil {
			reviewer = reviewClientFactory(cfg)
		}
		var err error
		metadata, err = reviewer.Probe(ctx)
		if err != nil {
			// AI review is enrichment. A provider outage degrades to a briefing
			// without an AI section; it never blocks an install. Release
			// invariant 6.
			initializationError = "provider compatibility probe failed; AI review disabled for this run: " + err.Error()
			reviewer = nil
			active := cfg.ActiveProvider()
			metadata = ProviderMetadata{Provider: cfg.Provider, Transport: "cli", RuntimeVersion: "unavailable", Model: active.Model, Effort: active.Effort, AdapterPolicy: "unavailable"}
			requireAttestation = false
		}
	} else {
		reviewer = nil
	}
	progressStage(ctx, StageArchiveParserCheck)
	archiveProbe, err := brief.ArchiveProbeIdentity(ctx)
	if err != nil {
		// The archive probe identifies the bsdtar that recognises archive
		// formats. Without it, archive contents go uninspected - which is a
		// briefing line about reduced coverage, not a reason to refuse to
		// describe the package at all.
		// Coverage, not enrichment: this one legitimately gates an approval,
		// because approving a package whose archives were never opened is
		// approving something nobody looked at. It is tracked separately from
		// the provider errors below for exactly that reason.
		coverageError = "archive probe unavailable: " + err.Error()
		archiveProbe = brief.ToolIdentity{Path: "/usr/bin/bsdtar", Version: "unavailable", SHA256: safe.SHA256Bytes([]byte(err.Error()))}
	}
	progressStage(ctx, StagePolicyFingerprint)
	fingerprint, err := ComputePolicyFingerprint(cfg, metadata, archiveProbe)
	if err != nil {
		return nil, err
	}
	if requireAttestation {
		progressStage(ctx, StageAIProviderIdentity)
		providerBinary, err := providerBinaryIdentity(ctx, cfg, metadata)
		// An unattested provider is not a provider whose verdicts may be used.
		//
		// Degrading here means dropping the reviewer entirely, not keeping it
		// and noting a problem: attestation binds the provider binary's
		// identity to this policy, so without it there is nothing establishing
		// that the verdicts came from the reviewer the user configured. The
		// briefing then carries no AI section and says why. That is release
		// invariant 6 - an optional component failing never blocks an install -
		// without quietly widening what "optional" is allowed to contribute.
		if err != nil {
			initializationError = "provider identity validation failed; AI review disabled for this run: " + err.Error()
			reviewer = nil
			requireAttestation = false
		}
		if requireAttestation {
			progressStage(ctx, StageAIProviderAttest)
			if err := loadProviderAttestation(fingerprint, metadata, providerBinary, archiveProbe); err != nil {
				initializationError = "provider attestation validation failed; AI review disabled for this run: " + err.Error()
				reviewer = nil
			}
		}
	}
	return &AuditService{Config: cfg, Scanner: brief.NewScanner(BriefConfig(cfg)), Reviewer: reviewer, Reports: NewReportStore(), Approvals: NewApprovalStore(), Metadata: metadata, PolicyFingerprint: fingerprint, ArchiveProbe: archiveProbe, InitializationError: strings.TrimPrefix(initializationError, "; "), CoverageError: coverageError}, nil
}

func (s *AuditService) ScanDirectoryWithContext(ctx context.Context, phase, root, packageBase string, yayContext brief.YayContext) (*Report, int, error) {
	if err := yayContext.Validate(); err != nil {
		return nil, ExitInvalidInvocation, err
	}
	progressTimedStage(ctx, StageDeterministicScan, s.Config.Limits.ScanTimeoutSeconds)
	// The post phase inventories the checkout and the transaction source store
	// together: after trusted acquisition the declared remote sources live in
	// the store, not in the checkout, and a decision taken without them would be
	// a decision about material the build will not use.
	sourceRoot, sourcePlan := "", []byte(nil)
	if phase == "post" {
		sourceRoot, sourcePlan = ExistingTransactionSourceDir(root), TransactionSourcePlan(root)
	}
	inventory, err := s.Scanner.ScanDirectoryWithSources(root, sourceRoot, sourcePlan, phase, func(progress brief.ScanProgress, _ bool) {
		progressScan(ctx, progress)
	})
	if err != nil {
		return nil, ExitInspectionFailure, err
	}
	inventory.YayContext = yayContext
	for index := range inventory.Findings {
		inventory.Findings[index].Source = "deterministic"
	}
	if phase == "post" {
		// Prefer a receipt advanced by a successful prepare invocation. On the
		// initial post scan no post report exists yet, so the preliminary pre
		// receipt (usually PGP pending until yay imports the key) is inherited.
		for _, receiptPhase := range []string{"post", "pre"} {
			if previous, loadErr := s.Reports.LatestFor(packageBase, receiptPhase); loadErr == nil {
				if current, identityErr := TransactionIdentity(); identityErr == nil && previous.Transaction == current {
					inventory.Verification = previous.SourceVerification
					break
				}
			}
		}
	}
	currentManifest := make([]map[string]any, len(inventory.Files))
	for i, item := range inventory.Files {
		currentManifest[i] = item.ManifestValue()
	}
	if previous, err := s.Reports.LatestFor(packageBase, phase); err == nil {
		inventory.ManifestDiff = CompareManifests(previous.Manifest, currentManifest)
	}
	var carried *CarriedDecision
	if phase == "post" {
		carried = s.carriedDecision(root, packageBase, inventory, currentManifest)
	}
	report, status, err := s.evaluate(ctx, packageBase, phase, inventory, carried, inventory.Root)
	if err != nil {
		return nil, status, err
	}
	if err := writeMarker(root, phase, report); err != nil {
		return nil, ExitStateFailure, err
	}
	return report, status, nil
}

func (s *AuditService) carriedDecision(root, packageBase string, inventory *brief.Inventory, currentManifest []map[string]any) *CarriedDecision {
	// Carry-over is an ergonomic optimization. Any absent, stale, malformed, or
	// mismatched evidence falls back to the ordinary post-phase question rather
	// than becoming either authority or a transaction failure.
	source, _, err := s.loadLiveMarkerReport(root, "pre")
	if err != nil || source.PackageBase != packageBase || source.Phase != "pre" || source.Decision != "allow" ||
		source.Disposition != "override" || !source.Overridden || !source.Coverage.Complete ||
		structuralBlock(&brief.Inventory{Findings: source.Findings, Coverage: source.Coverage}) || reportHasPromptInjection(source) {
		return nil
	}
	before, ok := manifestEntryHashes(source.Manifest)
	if !ok {
		return nil
	}
	after, ok := manifestEntryHashes(currentManifest)
	if !ok {
		return nil
	}
	approved := map[string]brief.Finding{}
	for _, finding := range source.Findings {
		if carryEligibleFinding(finding, s.Config.Review.ManualReviewMinimumSeverity) {
			approved[findingGuidanceID(finding)] = finding
		}
	}
	bindings := make([]CarriedFindingBinding, 0)
	seen := map[string]bool{}
	for _, finding := range inventory.Findings {
		if !carryEligibleFinding(finding, s.Config.Review.ManualReviewMinimumSeverity) {
			continue
		}
		id := findingGuidanceID(finding)
		previous, existed := approved[id]
		if seen[id] || !existed || previous.File != finding.File || before[finding.File] == "" || before[finding.File] != after[finding.File] {
			continue
		}
		seen[id] = true
		bindings = append(bindings, CarriedFindingBinding{FindingID: id, Path: finding.File, ManifestEntryHash: after[finding.File]})
	}
	if len(bindings) == 0 {
		return nil
	}
	return &CarriedDecision{SourceReportID: source.ReportID, SourcePhase: source.Phase, SourceContentHash: source.ContentHash, Findings: bindings}
}

func manifestEntryHashes(manifest []map[string]any) (map[string]string, bool) {
	result := make(map[string]string, len(manifest))
	for _, value := range manifest {
		record, err := brief.ValidateManifestRecord(value)
		if err != nil || result[record.Path] != "" {
			return nil, false
		}
		hash, err := manifestEntryHash(value)
		if err != nil {
			return nil, false
		}
		result[record.Path] = hash
	}
	return result, true
}

func carryEligibleFinding(finding brief.Finding, minimumSeverity string) bool {
	return finding.Source == "deterministic" && severityAtLeast(finding.Severity, minimumSeverity) && !finding.HardBlock && finding.Category != "coverage"
}

func carriedFindingIDSet(carried *CarriedDecision) map[string]bool {
	if carried == nil {
		return nil
	}
	ids := make(map[string]bool, len(carried.Findings))
	for _, binding := range carried.Findings {
		ids[binding.FindingID] = true
	}
	return ids
}

func (s *AuditService) ScanArtifacts(ctx context.Context, packages []string, packageBase string) (*Report, int, error) {
	progressTimedStage(ctx, StageArtifactInspection, s.Config.Limits.ScanTimeoutSeconds)
	inventory, err := s.Scanner.ScanArtifactsWithProgress(packages, func(progress brief.ScanProgress, _ bool) {
		progressScan(ctx, progress)
	})
	if err != nil {
		return nil, ExitInspectionFailure, err
	}
	return s.evaluate(ctx, packageBase, "artifact", inventory, nil, "")
}

func (s *AuditService) evaluate(ctx context.Context, packageBase, phase string, inv *brief.Inventory, carried *CarriedDecision, reviewRoot string) (*Report, int, error) {
	// Evaluation combines deterministic evidence, exact earlier-phase findings
	// already decided in this live transaction, a current one-time token if
	// present, and then AI review when eligible. Root effects do not consume this
	// decision directly; it protects the honest-user workflow.
	if err := brief.ValidatePackageBase(packageBase); err != nil {
		return nil, ExitInvalidInvocation, err
	}
	for index := range inv.Findings {
		inv.Findings[index].Source = "deterministic"
	}
	carriedIDs := carriedFindingIDSet(carried)
	deterministic := assessDeterministicAt(inv, s.Config.Review.ManualReviewMinimumSeverity, carriedIDs)
	hard := deterministic.HardBlock
	metadata := s.Metadata
	verdicts := []Verdict{}
	// Both reach the briefing; only one of them may remove the user's decision.
	reviewError := joinDegradations(s.InitializationError, s.CoverageError)
	overridden := false
	var authorizationSource *Report
	if !overridden && !deterministic.StructuralBlock {
		token, err := s.Approvals.Consume("approval", packageBase, phase, inv.ManifestHash, s.PolicyFingerprint)
		if err != nil {
			return nil, ExitStateFailure, err
		}
		if token != nil && inv.ManifestHash != "" {
			authorizationSource, err = s.authorizationSource(token, "approval")
			if err != nil {
				return nil, ExitStateFailure, err
			}
			overridden = true
		}
	}
	if authorizationSource != nil {
		verdicts = append(verdicts, authorizationSource.Reviewer.Verdicts...)
		reviewError = authorizationSource.Reviewer.Error
		// A current exact-snapshot approval supersedes earlier-phase carry-over.
		carried = nil
		carriedIDs = nil
	}
	// A clean recipe phase is reviewed only when the user asked for every recipe.
	// Decision-requiring deterministic evidence gets one guidance call by default:
	// that is where cross-file judgment can explain an ambiguous generated patch
	// without granting the model authority to clear the deterministic decision.
	// The required sources gate is never skipped.
	reviewSkipped := ""
	guideRecipe := s.Config.Review.GuideDecisionFindings && hasFindingAtOrAbove(inv.Findings, s.Config.Review.ManualReviewMinimumSeverity)
	reviewTrigger := conditionalReviewTrigger(s.Config, phase, inv.Findings)
	if s.Config.Review.Mode == ReviewModeAI && phase == "pre" && !s.Config.Review.IncludeRecipePhase && !guideRecipe {
		if s.Config.Review.GuideDecisionFindings {
			reviewSkipped = "recipe has no findings at the " + strings.ToUpper(s.Config.Review.ManualReviewMinimumSeverity) + " decision threshold · set review.include_recipe_phase to review every recipe"
		} else {
			reviewSkipped = "recipe phase is not included in AI review · set review.include_recipe_phase to add it"
		}
	}
	// Deterministic hard blocks already decide the phase and cannot be softened by
	// AI, so skip remote review and avoid unnecessary disclosure/quota use.
	if s.Config.Review.Mode == ReviewModeAI && !hard && !overridden && reviewError == "" && reviewSkipped == "" {
		progressStage(ctx, StageAIReview)
		reviewMetadata, reviewVerdicts, err := s.Reviewer.Review(ctx, packageBase, phase, inv, ReviewOptions{SkipGuidanceFindingIDs: carriedIDs})
		if err != nil {
			reviewError = err.Error()
		} else if reviewMetadata != s.Metadata {
			reviewError = "provider metadata changed between compatibility probe and review"
		} else if len(reviewVerdicts) == 0 {
			reviewError = "provider review returned no verdict"
		} else {
			metadata = reviewMetadata
			verdicts = reviewVerdicts
		}
	}
	// Provider stderr is advisory evidence, not an unbounded report field. Keep
	// enough context for diagnosis while leaving room for the policy summary's
	// explanatory prefix and preserving a valid fail-closed report.
	reviewError = truncate(reviewError, 4*1024)
	modelFindings := []brief.Finding{}
	modelBlocks := false
	for _, verdict := range verdicts {
		if verdict.Verdict != "allow" || !confidenceAtLeast(verdict.Confidence, s.Config.Review.MinimumConfidence) || verdict.PromptInjectionDetected || len(verdict.CoverageNotes) > 0 {
			modelBlocks = true
		}
		for _, finding := range verdict.Findings {
			if severityAtLeast(finding.Severity, s.Config.Review.ManualReviewMinimumSeverity) {
				modelBlocks = true
			}
			modelFindings = append(modelFindings, brief.Finding{Source: "ai", Severity: finding.Severity, Category: finding.Category, File: finding.File, Line: finding.Line, Evidence: finding.Evidence, Rationale: finding.Rationale, RuleID: "ai-review", HardBlock: false})
		}
	}
	// The deterministic assessment is the base in both review modes, and an
	// exact content-bound token is the only thing that can authorise an
	// exception to it.
	//
	// AI review can only tighten the deterministic decision. Allowing a model
	// verdict to clear a deterministic finding would make the model a gate in
	// the permissive direction, which control 5 forbids: AI review contributes
	// context to the briefing and never decides.
	allowed := overridden || deterministic.Decision == "allow"
	if s.Config.Review.Mode == ReviewModeAI && !overridden && modelBlocks {
		allowed = false
	}
	decision := "block"
	disposition := "block"
	if allowed {
		decision = "allow"
		disposition = "allow"
		// There is deliberately no separate disposition for "the AI agreed but
		// with less than high confidence". The allow comes from the deterministic
		// pass; AI review can only tighten, and its confidence is reported on its
		// own line.
		if overridden {
			disposition = "override"
		}
	}
	reportID, err := NewReportID(inv.ManifestHash)
	if err != nil {
		return nil, ExitStateFailure, err
	}
	transaction, err := TransactionIdentity()
	if err != nil {
		return nil, ExitStateFailure, err
	}
	manifest := make([]map[string]any, len(inv.Files))
	for i, item := range inv.Files {
		manifest[i] = item.ManifestValue()
	}
	findings := append(append([]brief.Finding{}, inv.Findings...), modelFindings...)
	brief.SortFindings(findings)
	// Losing an optional reviewer must not remove authority the user has without
	// one. In deterministic-only mode a non-structural high finding is an
	// ordinary decision they may take after reading; enabling AI review and then
	// failing its probe, identity check or attestation used to make that same
	// finding unapprovable, so yay aborted with no question asked - the opposite
	// of "failure of an optional component never blocks an install".
	//
	// CoverageError is different in kind and still gates: it means the archive
	// probe is unavailable, so nobody looked inside the archives there is now
	// nothing to approve on.
	approvalEligible := !allowed && inv.ManifestHash != "" && !deterministic.StructuralBlock && s.CoverageError == "" && !verdictsHavePromptInjection(verdicts)
	report := &Report{SchemaVersion: ReportSchemaVersion, ReportID: reportID, CreatedAt: UTCNow(), Transaction: transaction, PackageBase: packageBase, Phase: phase, Decision: decision, Disposition: disposition, Summary: policySummary(s.Config.Review.Mode, s.Config.Review.MinimumConfidence, s.Config.Review.ManualReviewMinimumSeverity, inv, verdicts, reviewError, overridden, carriedIDs), ContentHash: inv.ManifestHash, PolicyFingerprint: s.PolicyFingerprint, ScannerVersion: ScannerVersion, RulesVersion: RulesVersion, ApplicationVersion: ApplicationVersion, Reviewer: ReviewerReport{Mode: s.Config.Review.Mode, MinimumConfidence: aiMinimumConfidence(s.Config), Provider: metadata.Provider, Transport: metadata.Transport, RuntimeVersion: metadata.RuntimeVersion, Model: metadata.Model, Effort: metadata.Effort, AdapterPolicy: metadata.AdapterPolicy, Error: reviewError, Trigger: reviewTrigger, Skipped: reviewSkipped, Verdicts: verdicts}, Coverage: inv.Coverage, Exclusions: inv.Exclusions, Manifest: manifest, ReviewRoot: reviewRoot, Findings: findings, Overridden: overridden, ApprovalEligible: approvalEligible, NetworkEligible: allowed && phase == "post" && inv.ManifestHash != "", CarriedDecision: carried, ArchiveProbe: s.ArchiveProbe, YayContext: inv.YayContext, ManifestDiff: inv.ManifestDiff, Sources: inv.Sources, SourceVerification: inv.Verification}
	if err := s.Reports.Save(report); err != nil {
		return nil, ExitStateFailure, err
	}
	if allowed {
		return report, 0, nil
	}
	if reviewError != "" {
		return report, ExitReviewUnavailable, nil
	}
	return report, ExitPolicyBlock, nil
}

func hasFindingAtOrAbove(findings []brief.Finding, minimumSeverity string) bool {
	for _, finding := range findings {
		if severityAtLeast(finding.Severity, minimumSeverity) {
			return true
		}
	}
	return false
}

func conditionalReviewTrigger(cfg Config, phase string, findings []brief.Finding) string {
	if cfg.Review.Mode == ReviewModeAI && phase == "pre" && !cfg.Review.IncludeRecipePhase && cfg.Review.GuideDecisionFindings && hasFindingAtOrAbove(findings, cfg.Review.ManualReviewMinimumSeverity) {
		return reviewTriggerDecisionFindings
	}
	return ""
}

func (s *AuditService) authorizationSource(token *ApprovalToken, kind string) (*Report, error) {
	// Reopen and validate the originating report after consuming the token. The
	// token is only a reference; its copied fields cannot replace report evidence.
	if token == nil || token.Kind != kind {
		return nil, errors.New("invalid authorization token")
	}
	report, err := s.Reports.Load(token.SourceReportID)
	if err != nil {
		return nil, fmt.Errorf("load authorization source report: %w", err)
	}
	if report.PackageBase != token.PackageBase || report.Phase != token.Phase || report.ContentHash != token.ContentHash || report.PolicyFingerprint != token.PolicyFingerprint {
		return nil, errors.New("authorization source report does not match token")
	}
	if kind != "approval" || !report.ApprovalEligible {
		return nil, errors.New("authorization source report is not eligible")
	}
	return report, nil
}

type Marker struct {
	SchemaVersion     int             `json:"schema_version"`
	Root              string          `json:"root"`
	Phase             string          `json:"phase"`
	PackageBase       string          `json:"package_base"`
	ReportID          string          `json:"report_id"`
	ContentHash       string          `json:"content_hash"`
	PolicyFingerprint string          `json:"policy_fingerprint"`
	Decision          string          `json:"decision"`
	Disposition       string          `json:"disposition"`
	Transaction       ProcessIdentity `json:"transaction"`
}

// markerLocation names the marker file for one checkout, phase and transaction.
//
// The transaction identity is part of the filename, not only the body. yay uses
// a persistent build directory, so two live yay processes working on the same
// package base resolve to the same checkout: with a checkout-scoped name they
// wrote the same file, and the second one replaced the first. Verification then
// correctly rejected the identity mismatch and the first transaction failed
// closed - two valid scans, unchanged content, and one of them dies because
// state described as transaction-local was stored in a shared slot.
//
// The filename is namespace separation and nothing more. Every existing check -
// identity equality, liveness, policy fingerprint, report match and the full
// directory re-bind - still runs against the body.
func markerLocation(root, phase string, transaction ProcessIdentity) (string, string, error) {
	// Store markers outside the package tree under a SHA-256 of its canonical
	// path. Package code cannot replace the marker, and unusual path bytes never
	// become a state filename.
	if phase != "pre" && phase != "post" {
		return "", "", errors.New("marker phase must be pre or post")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return "", "", err
	}
	canonical, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", "", fmt.Errorf("resolve audit root: %w", err)
	}
	canonical = filepath.Clean(canonical)
	info, err := os.Stat(canonical)
	if err != nil {
		return "", "", fmt.Errorf("stat audit root: %w", err)
	}
	if !info.IsDir() || len(canonical) > 8192 {
		return "", "", errors.New("audit root is not a valid directory")
	}
	if transaction.PID <= 0 || transaction.StartTime == "" || transaction.BootID == "" {
		return "", "", errors.New("marker location requires a complete transaction identity")
	}
	key := safe.SHA256Bytes([]byte(fmt.Sprintf("%s\x00%d\x00%s\x00%s",
		canonical, transaction.PID, transaction.StartTime, transaction.BootID)))
	name := key + "-" + phase + ".json"
	return canonical, filepath.Join(StateRoot(), "decision-markers", name), nil
}

func writeMarker(root, phase string, report *Report) error {
	if report == nil {
		return errors.New("cannot write marker for a nil report")
	}
	canonical, path, err := markerLocation(root, phase, report.Transaction)
	if err != nil {
		return err
	}
	marker := Marker{SchemaVersion: MarkerSchemaVersion, Root: canonical, Phase: phase, PackageBase: report.PackageBase, ReportID: report.ReportID, ContentHash: report.ContentHash, PolicyFingerprint: report.PolicyFingerprint, Decision: report.Decision, Disposition: report.Disposition, Transaction: report.Transaction}
	return AtomicWriteJSON(path, marker)
}

func (s *AuditService) VerifyMarker(root, phase string) (*Report, error) {
	// A marker is a transaction-local pointer, not cached trust. Revalidate its
	// report, current policy, live process identity, and the directory's complete
	// byte/metadata binding before allowing the next build phase.
	// The current identity is needed before the marker can be found, because it
	// is part of where the marker lives. A different transaction's marker is now
	// a different file rather than one this transaction has to reject.
	report, canonical, err := s.loadLiveMarkerReport(root, phase)
	if err != nil {
		return nil, err
	}
	// Bind exactly what was scanned. A post marker's content hash covers the
	// source store as well, so re-binding the checkout alone would report the
	// same untouched material as changed.
	sourceRoot := ""
	if phase == "post" {
		sourceRoot = ExistingTransactionSourceDir(canonical)
	}
	inventory, err := s.Scanner.BindDirectoryWithSources(canonical, sourceRoot, phase)
	if err != nil {
		return nil, err
	}
	expectedBinding, err := brief.BindingHashManifest(report.Manifest)
	if err != nil {
		return nil, err
	}
	actualBinding, err := brief.BindingHashFiles(inventory.Files)
	if err != nil {
		return nil, err
	}
	if actualBinding != expectedBinding {
		return nil, errors.New("package content changed after audit")
	}
	return report, nil
}

// loadLiveMarkerReport validates the marker as a transaction-scoped pointer to
// a current-policy allow report. It deliberately does not bind today's files:
// VerifyMarker does that before executing a phase, while carry-over compares
// individual current manifest entries with an earlier approved phase.
func (s *AuditService) loadLiveMarkerReport(root, phase string) (*Report, string, error) {
	current, err := TransactionIdentity()
	if err != nil {
		return nil, "", err
	}
	canonical, path, err := markerLocation(root, phase, current)
	if err != nil {
		return nil, "", err
	}
	if err := EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return nil, "", fmt.Errorf("validate audit marker directory: %w", err)
	}
	var marker Marker
	if err := ReadJSONFile(path, 64*1024, &marker); err != nil {
		return nil, "", fmt.Errorf("load %s audit marker: %w", phase, err)
	}
	if marker.SchemaVersion != MarkerSchemaVersion || marker.Root != canonical || marker.Phase != phase || marker.Decision != "allow" {
		return nil, "", errors.New("invalid, legacy, or non-allow audit marker")
	}
	report, err := s.Reports.Load(marker.ReportID)
	if err != nil {
		return nil, "", err
	}
	if marker.PackageBase != report.PackageBase || marker.ContentHash != report.ContentHash || marker.PolicyFingerprint != report.PolicyFingerprint || marker.Decision != report.Decision || marker.Disposition != report.Disposition {
		return nil, "", errors.New("audit marker does not match protected report")
	}
	if marker.PolicyFingerprint != s.PolicyFingerprint {
		return nil, "", errors.New("audit policy changed after approval")
	}
	if marker.Transaction != current || report.Transaction != current || !IdentityIsLive(marker.Transaction) {
		return nil, "", errors.New("audit marker belongs to a stale or different yay transaction")
	}
	return report, canonical, nil
}

func ComputePolicyFingerprint(cfg Config, metadata ProviderMetadata, archiveProbe brief.ToolIdentity) (string, error) {
	// Hash every input that can change a decision or containment claim. Terminal
	// styling is intentionally absent; AI prompt/schema/runtime fields appear only
	// in AI mode, where they are part of the actual reviewer behavior.
	threatBundle, err := brief.EmbeddedThreatBundleIdentity()
	if err != nil {
		return "", err
	}
	material := map[string]any{"application_version": ApplicationVersion, "report_schema_version": ReportSchemaVersion, "review_snapshot_version": ReviewSnapshotVersion, "scanner_version": ScannerVersion, "rules_version": RulesVersion, "review_mode": cfg.Review.Mode, "limits": cfg.Limits, "build": cfg.Build, "network": cfg.Network, "vendor": cfg.Vendor, "archive_probe": archiveProbe, "threat_bundle": threatBundle}
	if cfg.Review.Mode == ReviewModeAI {
		prompt, err := os.ReadFile(filepath.Join(ShareRoot(), "review-prompt.md"))
		if err != nil {
			return "", err
		}
		schema, err := os.ReadFile(filepath.Join(ShareRoot(), "verdict.schema.json"))
		if err != nil {
			return "", err
		}
		material["provider"] = cfg.Provider
		material["provider_config"] = cfg.ActiveProvider()
		material["review"] = cfg.Review
		material["runtime_version"] = metadata.RuntimeVersion
		material["adapter_policy"] = metadata.AdapterPolicy
		material["prompt_sha256"] = safe.SHA256Bytes(prompt)
		material["schema_sha256"] = safe.SHA256Bytes(schema)
	}
	raw, err := CanonicalJSON(material)
	if err != nil {
		return "", err
	}
	return safe.SHA256Bytes(raw), nil
}

func structuralBlock(inv *brief.Inventory) bool {
	// Structural means the scan cannot establish a trustworthy content boundary,
	// not merely that suspicious behaviour was found. Ordinary approvals never
	// overrule these conditions.
	//
	// The test is enforced-versus-recognised. Path traversal, an escaping
	// symlink, a special file, a setid archive member: these are properties of
	// the bytes that no amount of obfuscation changes, and deciding them needs
	// no judgement about intent. Everything that depends on recognising
	// attacker-authored text - a shell pattern, an IOC identifier - is described
	// instead, however severe, because recognition has a false-positive cliff
	// and a cliff is what makes people want a global break-glass.
	if inv == nil || !inv.Coverage.Complete {
		return true
	}
	ids := map[string]bool{"special-file": true, "symlink-escape": true, "source-reference-escape": true, "binary-header-invalid": true, "archive-depth-limit": true}
	for _, finding := range inv.Findings {
		if finding.HardBlock {
			return true
		}
		severeCategory := finding.HardBlock && (finding.Category == "credential_access" || finding.Category == "process_injection" || finding.Category == "persistence")
		if finding.Category == "archive_escape" || severeCategory || ids[finding.RuleID] || strings.HasPrefix(finding.Rationale, "TOCTOU") {
			return true
		}
	}
	return false
}

// joinDegradations combines the reported failures without inventing one. An
// empty result must stay empty: it is what decides whether AI review runs.
func joinDegradations(values ...string) string {
	present := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			present = append(present, trimmed)
		}
	}
	return strings.Join(present, "; ")
}

func policySummary(mode, minimumConfidence, minimumSeverity string, inv *brief.Inventory, verdicts []Verdict, reviewError string, overridden bool, carried map[string]bool) string {
	if overridden {
		return "Allowed by an exact, one-time user approval."
	}
	if reviewError != "" {
		// AI review is enrichment; its failure produces a briefing without an
		// AI section rather than a block, so the summary must preserve the
		// deterministic allow decision.
		return "AI review unavailable; this briefing is deterministic only: " + reviewError
	}
	hard := 0
	for _, finding := range inv.Findings {
		if finding.HardBlock {
			hard++
		}
	}
	if hard > 0 {
		return fmt.Sprintf("Blocked by %d structural finding(s), which an approval may not cross.", hard)
	}
	if !inv.Coverage.Complete {
		return "Blocked because audit coverage is incomplete."
	}
	decisionFindings := 0
	for _, finding := range inv.Findings {
		if severityAtLeast(finding.Severity, minimumSeverity) && !carried[findingGuidanceID(finding)] {
			decisionFindings++
		}
	}
	carriedCount := len(carried)
	if mode == ReviewModeDeterministicOnly {
		if decisionFindings > 0 {
			return fmt.Sprintf("%d finding(s) at %s or above need your decision; read them before approving.", decisionFindings, strings.ToUpper(minimumSeverity))
		}
		if carriedCount > 0 {
			return fmt.Sprintf("No new decision is required; %d unchanged finding(s) were approved at the recipe gate.", carriedCount)
		}
		return "No blocking findings. Medium and low findings below are worth reading."
	}
	aiSevere := 0
	for _, verdict := range verdicts {
		if verdict.PromptInjectionDetected {
			return "Blocked because AI review detected prompt injection."
		}
		if len(verdict.CoverageNotes) > 0 {
			return "Blocked because AI review reported incomplete coverage."
		}
		if verdict.Verdict == "block" {
			return "Blocked by AI security review."
		}
		if !confidenceAtLeast(verdict.Confidence, minimumConfidence) {
			return fmt.Sprintf("Blocked because AI confidence %s is below the configured minimum %s.", verdict.Confidence, minimumConfidence)
		}
		for _, finding := range verdict.Findings {
			if severityAtLeast(finding.Severity, minimumSeverity) {
				aiSevere++
			}
		}
	}
	if decisionFindings > 0 {
		return fmt.Sprintf("%d deterministic finding(s) at %s or above need your decision; read them before approving.", decisionFindings, strings.ToUpper(minimumSeverity))
	}
	if aiSevere > 0 {
		return fmt.Sprintf("%d AI finding(s) at %s or above need your decision.", aiSevere, strings.ToUpper(minimumSeverity))
	}
	if carriedCount > 0 {
		return fmt.Sprintf("No new decision is required; %d unchanged finding(s) were approved at the recipe gate.", carriedCount)
	}
	if lowest := lowestVerdictConfidence(verdicts); lowest != "" && lowest != "high" {
		// Not "automatically allowed": nothing about the AI allowed anything.
		// The deterministic pass found nothing blocking and the model agreed
		// with less than high confidence, which is worth saying plainly.
		return fmt.Sprintf("No blocking findings. AI review agreed at %s confidence (minimum %s); it did not decide this.", lowest, minimumConfidence)
	}
	return "No blocking findings. Read the description below before installing."
}

func confidenceAtLeast(actual, minimum string) bool {
	rank := map[string]int{"low": 1, "medium": 2, "high": 3}
	return rank[actual] >= rank[minimum] && rank[minimum] != 0
}

func aiMinimumConfidence(cfg Config) string {
	if cfg.Review.Mode == ReviewModeAI {
		return cfg.Review.MinimumConfidence
	}
	return ""
}

func verdictsHavePromptInjection(verdicts []Verdict) bool {
	for _, verdict := range verdicts {
		if verdict.PromptInjectionDetected {
			return true
		}
	}
	return false
}

func lowestVerdictConfidence(verdicts []Verdict) string {
	lowest, lowestRank := "", 4
	ranks := map[string]int{"low": 1, "medium": 2, "high": 3}
	for _, verdict := range verdicts {
		rank := ranks[verdict.Confidence]
		if rank > 0 && rank < lowestRank {
			lowest, lowestRank = verdict.Confidence, rank
		}
	}
	return lowest
}

func reportHasPromptInjection(report *Report) bool {
	return report != nil && verdictsHavePromptInjection(report.Reviewer.Verdicts)
}
