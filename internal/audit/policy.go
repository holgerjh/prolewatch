package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type ReviewClient interface {
	Probe(context.Context) (ProviderMetadata, error)
	Review(context.Context, string, string, *Inventory) (ProviderMetadata, []Verdict, error)
}

var (
	auditServiceFactory = NewAuditService
	reviewClientFactory = func(cfg Config) ReviewClient { return NewReviewer(cfg) }
)

type AuditService struct {
	Config              Config
	Scanner             *Scanner
	Reviewer            ReviewClient
	Reports             *ReportStore
	Approvals           *ApprovalStore
	Metadata            ProviderMetadata
	PolicyFingerprint   string
	ArchiveProbe        ToolIdentity
	InitializationError string
}

// DeterministicAssessment is the policy disposition produced without an AI
// reviewer. Scenario and acceptance tooling uses the same assessment as the
// production deterministic-only path instead of reimplementing policy rules.
type DeterministicAssessment struct {
	Decision          string
	ApprovalEligible  bool
	HardBlock         bool
	HighSeverityBlock bool
	StructuralBlock   bool
}

func AssessDeterministic(inv *Inventory) DeterministicAssessment {
	assessment := DeterministicAssessment{Decision: "block", StructuralBlock: structuralBlock(inv)}
	if inv == nil {
		return assessment
	}
	for _, finding := range inv.Findings {
		assessment.HardBlock = assessment.HardBlock || finding.HardBlock
		assessment.HighSeverityBlock = assessment.HighSeverityBlock || finding.Severity == "critical" || finding.Severity == "high"
	}
	if inv.Coverage.Complete && !assessment.HardBlock && !assessment.HighSeverityBlock {
		assessment.Decision = "allow"
	}
	assessment.ApprovalEligible = assessment.Decision == "block" && inv.ManifestHash != "" && !assessment.StructuralBlock
	return assessment
}

func NewAuditService(ctx context.Context, cfg Config, reviewer ReviewClient) (*AuditService, error) {
	requireAttestation := cfg.Review.Mode == ReviewModeAI && reviewer == nil
	var metadata ProviderMetadata
	initializationError := ""
	if cfg.Review.Mode == ReviewModeAI {
		activityTimedStage(ctx, StageAIProviderCheck, cfg.Review.TimeoutSeconds)
		if reviewer == nil {
			reviewer = reviewClientFactory(cfg)
		}
		var err error
		metadata, err = reviewer.Probe(ctx)
		if err != nil {
			recordProviderActivityFailure(ctx, err, "AI provider compatibility check failed")
			if !cfg.Overrides.AllowUnsafe {
				return nil, err
			}
			initializationError = "provider compatibility probe failed: " + err.Error()
			active := cfg.ActiveProvider()
			metadata = ProviderMetadata{Provider: cfg.Provider, Transport: "cli", RuntimeVersion: "unavailable", Model: active.Model, Effort: active.Effort, AdapterPolicy: "unavailable"}
			requireAttestation = false
		}
		activityStage(ctx, StageInitializing)
	} else {
		reviewer = nil
	}
	archiveProbe, err := archiveProbeIdentity(ctx)
	if err != nil {
		activityFailure(ctx, ActivityFailureOperational, "Scan initialization failed")
		if !cfg.Overrides.AllowUnsafe {
			return nil, err
		}
		initializationError = strings.TrimSpace(initializationError + "; archive probe unavailable: " + err.Error())
		archiveProbe = ToolIdentity{Path: "/usr/bin/bsdtar", Version: "unavailable", SHA256: SHA256Bytes([]byte(err.Error()))}
	}
	fingerprint, err := ComputePolicyFingerprint(cfg, metadata, archiveProbe)
	if err != nil {
		activityFailure(ctx, ActivityFailureOperational, "Scan initialization failed")
		return nil, err
	}
	if requireAttestation {
		providerBinary, err := providerBinaryIdentity(ctx, cfg, metadata)
		if err != nil {
			activityFailure(ctx, ActivityFailureOperational, "Provider identity validation failed")
			if !cfg.Overrides.AllowUnsafe {
				return nil, err
			}
			initializationError = "provider identity validation failed: " + err.Error()
			requireAttestation = false
		}
		if requireAttestation {
			if err := loadProviderAttestation(fingerprint, metadata, providerBinary, archiveProbe); err != nil {
				activityFailure(ctx, ActivityFailureProvider, "Provider attestation validation failed")
				if !cfg.Overrides.AllowUnsafe {
					return nil, err
				}
				initializationError = "provider attestation validation failed: " + err.Error()
			}
		}
	}
	return &AuditService{Config: cfg, Scanner: NewScanner(cfg), Reviewer: reviewer, Reports: NewReportStore(), Approvals: NewApprovalStore(), Metadata: metadata, PolicyFingerprint: fingerprint, ArchiveProbe: archiveProbe, InitializationError: strings.TrimPrefix(initializationError, "; ")}, nil
}

func (s *AuditService) ScanDirectory(ctx context.Context, phase, root, packageBase string) (*Report, int, error) {
	return s.ScanDirectoryWithContext(ctx, phase, root, packageBase, YayContext{})
}

func (s *AuditService) ScanDirectoryWithContext(ctx context.Context, phase, root, packageBase string, yayContext YayContext) (*Report, int, error) {
	if err := yayContext.Validate(); err != nil {
		return nil, 20, err
	}
	activityTimedStage(ctx, StageDeterministicScan, s.Config.Limits.ScanTimeoutSeconds)
	inventory, err := s.Scanner.ScanDirectoryWithProgress(root, phase, func(progress ActivityScanProgress, force bool) {
		activityScan(ctx, progress, force)
	})
	if err != nil {
		recordScannerActivityFailure(ctx, err)
		return nil, 21, err
	}
	inventory.YayContext = yayContext
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
	report, status, err := s.evaluate(ctx, packageBase, phase, inventory)
	if err != nil {
		return nil, status, err
	}
	if err := writeMarker(root, phase, report); err != nil {
		return nil, 23, err
	}
	return report, status, nil
}
func (s *AuditService) ScanArtifacts(ctx context.Context, packages []string, packageBase string) (*Report, int, error) {
	activityTimedStage(ctx, StageArtifactInspection, s.Config.Limits.ScanTimeoutSeconds)
	inventory, err := s.Scanner.ScanArtifactsWithProgress(packages, func(progress ActivityScanProgress, force bool) {
		activityScan(ctx, progress, force)
	})
	if err != nil {
		recordScannerActivityFailure(ctx, err)
		return nil, 21, err
	}
	return s.evaluate(ctx, packageBase, "artifact", inventory)
}

func (s *AuditService) evaluate(ctx context.Context, packageBase, phase string, inv *Inventory) (*Report, int, error) {
	if err := ValidatePackageBase(packageBase); err != nil {
		return nil, 20, err
	}
	deterministic := AssessDeterministic(inv)
	hard := deterministic.HardBlock
	for index := range inv.Findings {
		inv.Findings[index].Source = "deterministic"
	}
	metadata := s.Metadata
	verdicts := []Verdict{}
	reviewError := s.InitializationError
	overridden := false
	unsafeBypass := false
	var authorizationSource *Report
	if s.Config.Overrides.AllowUnsafe {
		token, err := s.Approvals.Consume("unsafe", packageBase, phase, inv.ManifestHash, s.PolicyFingerprint)
		if err != nil {
			return nil, 23, err
		}
		if token != nil && inv.ManifestHash != "" {
			authorizationSource, err = s.authorizationSource(token, "unsafe")
			if err != nil {
				return nil, 23, err
			}
			overridden, unsafeBypass = true, true
		}
	}
	if !overridden && !deterministic.StructuralBlock {
		token, err := s.Approvals.Consume("approval", packageBase, phase, inv.ManifestHash, s.PolicyFingerprint)
		if err != nil {
			return nil, 23, err
		}
		if token != nil && inv.ManifestHash != "" {
			authorizationSource, err = s.authorizationSource(token, "approval")
			if err != nil {
				return nil, 23, err
			}
			overridden = true
		}
	}
	if authorizationSource != nil {
		verdicts = append(verdicts, authorizationSource.Reviewer.Verdicts...)
		reviewError = authorizationSource.Reviewer.Error
	}
	if s.Config.Review.Mode == ReviewModeAI && !hard && !overridden && reviewError == "" {
		activityStage(ctx, StageAIReview)
		reviewMetadata, reviewVerdicts, err := s.Reviewer.Review(ctx, packageBase, phase, inv)
		if err != nil {
			reviewError = err.Error()
			recordProviderActivityFailure(ctx, err, "AI provider review failed")
		} else if reviewMetadata != s.Metadata {
			reviewError = "provider metadata changed between compatibility probe and review"
			activityFailure(ctx, ActivityFailureProvider, "AI provider metadata changed during review")
		} else if len(reviewVerdicts) == 0 {
			reviewError = "provider review returned no verdict"
			activityFailure(ctx, ActivityFailureProvider, "AI provider returned no review verdict")
		} else {
			metadata = reviewMetadata
			verdicts = reviewVerdicts
		}
	}
	// Provider stderr is advisory evidence, not an unbounded report field. Keep
	// enough context for diagnosis while leaving room for the policy summary's
	// explanatory prefix and preserving a valid fail-closed report.
	reviewError = truncate(reviewError, 4*1024)
	modelFindings := []Finding{}
	modelBlocks := false
	for _, verdict := range verdicts {
		if verdict.Verdict != "allow" || !confidenceAtLeast(verdict.Confidence, s.Config.Review.MinimumConfidence) || verdict.PromptInjectionDetected || len(verdict.CoverageNotes) > 0 {
			modelBlocks = true
		}
		for _, finding := range verdict.Findings {
			if finding.Severity == "high" || finding.Severity == "critical" {
				modelBlocks = true
			}
			modelFindings = append(modelFindings, Finding{Source: "ai", Severity: finding.Severity, Category: finding.Category, File: finding.File, Line: finding.Line, Evidence: finding.Evidence, Rationale: finding.Rationale, RuleID: "ai-review", HardBlock: false})
		}
	}
	allowed := overridden || inv.Coverage.Complete && !hard
	if s.Config.Review.Mode == ReviewModeAI && !overridden {
		allowed = allowed && reviewError == "" && len(verdicts) > 0 && !modelBlocks
	} else if !overridden {
		allowed = deterministic.Decision == "allow"
	}
	decision := "block"
	disposition := "block"
	if allowed {
		decision = "allow"
		disposition = "allow"
		if !overridden && s.Config.Review.Mode == ReviewModeAI && lowestVerdictConfidence(verdicts) != "" && lowestVerdictConfidence(verdicts) != "high" {
			disposition = "auto_allow"
		}
		if overridden {
			disposition = "override"
		}
		if unsafeBypass {
			disposition = "unsafe_bypass"
		}
	}
	reportID, err := NewReportID(inv.ManifestHash)
	if err != nil {
		return nil, 23, err
	}
	transaction, err := TransactionIdentity()
	if err != nil {
		return nil, 23, err
	}
	manifest := make([]map[string]any, len(inv.Files))
	for i, item := range inv.Files {
		manifest[i] = item.ManifestValue()
	}
	findings := append(append([]Finding{}, inv.Findings...), modelFindings...)
	if unsafeBypass {
		findings = append(findings, Finding{Source: "deterministic", Severity: "critical", Category: "other", File: ".", Evidence: authorizationSource.ReportID, Rationale: "the user explicitly bypassed a blocking security decision; this is not evidence of safety", RuleID: "user-unsafe-bypass", HardBlock: true})
	}
	sortFindings(findings)
	approvalEligible := !allowed && inv.ManifestHash != "" && !deterministic.StructuralBlock && s.InitializationError == "" && !verdictsHavePromptInjection(verdicts)
	report := &Report{SchemaVersion: ReportSchemaVersion, ReportID: reportID, CreatedAt: UTCNow(), Transaction: transaction, PackageBase: packageBase, Phase: phase, Decision: decision, Disposition: disposition, Summary: policySummary(s.Config.Review.Mode, s.Config.Review.MinimumConfidence, inv, verdicts, reviewError, overridden, unsafeBypass), ContentHash: inv.ManifestHash, PolicyFingerprint: s.PolicyFingerprint, ScannerVersion: ScannerVersion, RulesVersion: RulesVersion, ApplicationVersion: ApplicationVersion, Reviewer: ReviewerReport{Mode: s.Config.Review.Mode, MinimumConfidence: aiMinimumConfidence(s.Config), Provider: metadata.Provider, Transport: metadata.Transport, RuntimeVersion: metadata.RuntimeVersion, Model: metadata.Model, Effort: metadata.Effort, AdapterPolicy: metadata.AdapterPolicy, Error: reviewError, Verdicts: verdicts}, Coverage: inv.Coverage, Exclusions: inv.Exclusions, Manifest: manifest, Findings: findings, Overridden: overridden, UnsafeBypass: unsafeBypass, ApprovalEligible: approvalEligible, UnsafeBypassEligible: !allowed && s.Config.Overrides.AllowUnsafe, NetworkEligible: allowed && !unsafeBypass && phase == "post" && inv.ManifestHash != "", ArchiveProbe: s.ArchiveProbe, YayContext: inv.YayContext, ManifestDiff: inv.ManifestDiff, Sources: inv.Sources, SourceVerification: inv.Verification}
	if err := s.Reports.Save(report); err != nil {
		return nil, 23, err
	}
	activityReport(ctx, report.ReportID)
	if allowed {
		return report, 0, nil
	}
	if reviewError != "" {
		return report, 22, nil
	}
	return report, 10, nil
}

func (s *AuditService) authorizationSource(token *ApprovalToken, kind string) (*Report, error) {
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
	if kind == "approval" && !report.ApprovalEligible || kind == "unsafe" && !report.UnsafeBypassEligible {
		return nil, errors.New("authorization source report is not eligible")
	}
	return report, nil
}

func recordScannerActivityFailure(ctx context.Context, err error) {
	if errors.Is(err, ErrScannerTimeout) {
		activityFailure(ctx, ActivityFailureScannerTimeout, "Deterministic scan exceeded its configured timeout")
		return
	}
	activityFailure(ctx, ActivityFailureScanner, "Deterministic scan failed before a report was produced")
}

func recordProviderActivityFailure(ctx context.Context, err error, fallback string) {
	if errors.Is(err, ErrProviderTimeout) || strings.Contains(strings.ToLower(err.Error()), "timed out") {
		activityFailure(ctx, ActivityFailureProviderTimeout, "AI provider request exceeded its configured timeout")
		return
	}
	activityFailure(ctx, ActivityFailureProvider, fallback)
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

func markerLocation(root, phase string) (string, string, error) {
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
	name := SHA256Bytes([]byte(canonical)) + "-" + phase + ".json"
	return canonical, filepath.Join(StateRoot(), "decision-markers", name), nil
}

func writeMarker(root, phase string, report *Report) error {
	if report == nil {
		return errors.New("cannot write marker for a nil report")
	}
	canonical, path, err := markerLocation(root, phase)
	if err != nil {
		return err
	}
	marker := Marker{SchemaVersion: MarkerSchemaVersion, Root: canonical, Phase: phase, PackageBase: report.PackageBase, ReportID: report.ReportID, ContentHash: report.ContentHash, PolicyFingerprint: report.PolicyFingerprint, Decision: report.Decision, Disposition: report.Disposition, Transaction: report.Transaction}
	return AtomicWriteJSON(path, marker)
}

func (s *AuditService) VerifyMarker(root, phase string) (*Report, error) {
	canonical, path, err := markerLocation(root, phase)
	if err != nil {
		return nil, err
	}
	if err := EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("validate audit marker directory: %w", err)
	}
	var marker Marker
	if err := ReadJSONFile(path, 64*1024, &marker); err != nil {
		return nil, fmt.Errorf("load %s audit marker: %w", phase, err)
	}
	if marker.SchemaVersion != MarkerSchemaVersion || marker.Root != canonical || marker.Phase != phase || marker.Decision != "allow" {
		return nil, errors.New("invalid, legacy, or non-allow audit marker")
	}
	report, err := s.Reports.Load(marker.ReportID)
	if err != nil {
		return nil, err
	}
	if marker.PackageBase != report.PackageBase || marker.ContentHash != report.ContentHash || marker.PolicyFingerprint != report.PolicyFingerprint || marker.Decision != report.Decision || marker.Disposition != report.Disposition {
		return nil, errors.New("audit marker does not match protected report")
	}
	if marker.PolicyFingerprint != s.PolicyFingerprint {
		return nil, errors.New("audit policy changed after approval")
	}
	if report.UnsafeBypass && !s.Config.Overrides.AllowUnsafe {
		return nil, errors.New("unsafe bypasses are disabled by current policy")
	}
	current, err := TransactionIdentity()
	if err != nil {
		return nil, err
	}
	if marker.Transaction != current || !IdentityIsLive(marker.Transaction) {
		return nil, errors.New("audit marker belongs to a stale or different yay transaction")
	}
	if report.UnscannedBypass {
		return report, nil
	}
	inventory, err := s.Scanner.bindDirectory(canonical, phase)
	if err != nil {
		return nil, err
	}
	expectedBinding, err := bindingHashManifest(report.Manifest)
	if err != nil {
		return nil, err
	}
	actualBinding, err := bindingHashFiles(inventory.Files)
	if err != nil {
		return nil, err
	}
	if actualBinding != expectedBinding {
		return nil, errors.New("package content changed after audit")
	}
	return report, nil
}

func (s *AuditService) CreateUnscannedBypass(root, phase, packageBase string, yayContext YayContext, cause error) (*Report, error) {
	if !s.Config.Overrides.AllowUnsafe {
		return nil, errors.New("unsafe bypasses are disabled")
	}
	if phase != "pre" && phase != "post" {
		return nil, errors.New("unscanned bypass supports directory phases only")
	}
	if err := ValidatePackageBase(packageBase); err != nil {
		return nil, err
	}
	if err := yayContext.Validate(); err != nil {
		return nil, err
	}
	transaction, err := TransactionIdentity()
	if err != nil {
		return nil, err
	}
	seed, err := CanonicalJSON(map[string]any{"package_base": packageBase, "phase": phase, "policy": s.PolicyFingerprint, "transaction": transaction, "created_at": UTCNow()})
	if err != nil {
		return nil, err
	}
	reportID, err := NewReportID(SHA256Bytes(seed))
	if err != nil {
		return nil, err
	}
	failure := "deterministic scanner failed before a complete content identity was available"
	evidence := "scanner failure"
	if cause != nil {
		evidence = TerminalText(cause.Error(), 320)
	}
	report := &Report{SchemaVersion: ReportSchemaVersion, ReportID: reportID, CreatedAt: UTCNow(), Transaction: transaction, PackageBase: packageBase, Phase: phase,
		Decision: "allow", Disposition: "unsafe_bypass", Summary: "UNSAFE BYPASS: continued without a complete deterministic scan or content hash.", PolicyFingerprint: s.PolicyFingerprint,
		ScannerVersion: ScannerVersion, RulesVersion: RulesVersion, ApplicationVersion: ApplicationVersion,
		Reviewer: ReviewerReport{Mode: s.Config.Review.Mode, MinimumConfidence: aiMinimumConfidence(s.Config), Provider: s.Metadata.Provider, Transport: s.Metadata.Transport, RuntimeVersion: s.Metadata.RuntimeVersion, Model: s.Metadata.Model, Effort: s.Metadata.Effort, AdapterPolicy: s.Metadata.AdapterPolicy, Verdicts: []Verdict{}},
		Coverage: Coverage{Complete: false, Notes: []string{failure}}, Exclusions: []string{}, Manifest: []map[string]any{},
		Findings:   []Finding{{Source: "deterministic", Severity: "critical", Category: "coverage", File: ".", Evidence: evidence, Rationale: failure, RuleID: "scanner-bypassed", HardBlock: true}},
		Overridden: true, UnsafeBypass: true, UnscannedBypass: true, ArchiveProbe: s.ArchiveProbe, YayContext: yayContext, ManifestDiff: []ManifestChange{}}
	if err := s.Reports.Save(report); err != nil {
		return nil, err
	}
	if err := writeMarker(root, phase, report); err != nil {
		return nil, err
	}
	return report, nil
}

func (s *AuditService) CreateArtifactBypass(packages []string, packageBase string, cause error) (*Report, error) {
	if !s.Config.Overrides.AllowUnsafe {
		return nil, errors.New("unsafe bypasses are disabled")
	}
	if err := ValidatePackageBase(packageBase); err != nil {
		return nil, err
	}
	files := make([]FileRecord, 0, len(packages))
	seen := map[string]bool{}
	for _, packagePath := range packages {
		absolute, err := filepath.Abs(packagePath)
		if err != nil {
			return nil, err
		}
		info, err := os.Lstat(absolute)
		if err != nil || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("bypassed artifact is not a readable regular file: %s", packagePath)
		}
		name := filepath.Base(absolute)
		if seen[name] {
			return nil, fmt.Errorf("duplicate bypassed artifact name: %s", name)
		}
		seen[name] = true
		hash, err := HashFileNoFollow(absolute)
		if err != nil {
			return nil, err
		}
		files = append(files, FileRecord{Path: name, PathB64: pathB64(name), Kind: "file", Mode: uint32(info.Mode().Perm()), Size: info.Size(), SHA256: hash, BinaryMetadata: map[string]any{}})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].PathB64 < files[j].PathB64 })
	manifest := make([]map[string]any, len(files))
	var bytesSeen int64
	for index, file := range files {
		manifest[index] = file.ManifestValue()
		bytesSeen += file.Size
	}
	raw, err := CanonicalJSON(manifest)
	if err != nil {
		return nil, err
	}
	contentHash := SHA256Bytes(raw)
	reportID, err := NewReportID(contentHash)
	if err != nil {
		return nil, err
	}
	transaction, err := TransactionIdentity()
	if err != nil {
		return nil, err
	}
	evidence := "artifact scanner failure or block"
	if cause != nil {
		evidence = TerminalText(cause.Error(), 320)
	}
	report := &Report{SchemaVersion: ReportSchemaVersion, ReportID: reportID, CreatedAt: UTCNow(), Transaction: transaction, PackageBase: packageBase, Phase: "artifact",
		Decision: "allow", Disposition: "unsafe_bypass", Summary: "UNSAFE BYPASS: package artifacts were handed off without a positive artifact review.", ContentHash: contentHash, PolicyFingerprint: s.PolicyFingerprint,
		ScannerVersion: ScannerVersion, RulesVersion: RulesVersion, ApplicationVersion: ApplicationVersion,
		Reviewer: ReviewerReport{Mode: s.Config.Review.Mode, MinimumConfidence: aiMinimumConfidence(s.Config), Provider: s.Metadata.Provider, Transport: s.Metadata.Transport, RuntimeVersion: s.Metadata.RuntimeVersion, Model: s.Metadata.Model, Effort: s.Metadata.Effort, AdapterPolicy: s.Metadata.AdapterPolicy, Verdicts: []Verdict{}},
		Coverage: Coverage{FilesSeen: len(files), BytesSeen: bytesSeen, Complete: false, Notes: []string{"artifact security inspection was explicitly bypassed"}}, Exclusions: []string{}, Manifest: manifest,
		Findings:   []Finding{{Source: "deterministic", Severity: "critical", Category: "coverage", File: ".", Evidence: evidence, Rationale: "artifact security inspection was explicitly bypassed", RuleID: "artifact-scan-bypassed", HardBlock: true}},
		Overridden: true, UnsafeBypass: true, ArchiveProbe: s.ArchiveProbe, YayContext: YayContext{}, ManifestDiff: []ManifestChange{}}
	if err := s.Reports.Save(report); err != nil {
		return nil, err
	}
	return report, nil
}

func ComputePolicyFingerprint(cfg Config, metadata ProviderMetadata, archiveProbe ToolIdentity) (string, error) {
	threatBundle, err := EmbeddedThreatBundleIdentity()
	if err != nil {
		return "", err
	}
	cleanRoot, err := activeCleanRootIdentity()
	if err != nil {
		return "", err
	}
	material := map[string]any{"application_version": ApplicationVersion, "report_schema_version": ReportSchemaVersion, "review_snapshot_version": ReviewSnapshotVersion, "scanner_version": ScannerVersion, "rules_version": RulesVersion, "review_mode": cfg.Review.Mode, "limits": cfg.Limits, "build": cfg.Build, "network": cfg.Network, "sandbox": cfg.Sandbox, "vendor": cfg.Vendor, "overrides": cfg.Overrides, "archive_probe": archiveProbe, "threat_bundle": threatBundle, "clean_root": cleanRoot}
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
		material["prompt_sha256"] = SHA256Bytes(prompt)
		material["schema_sha256"] = SHA256Bytes(schema)
	}
	raw, err := CanonicalJSON(material)
	if err != nil {
		return "", err
	}
	return SHA256Bytes(raw), nil
}

func structuralBlock(inv *Inventory) bool {
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
func policySummary(mode, minimumConfidence string, inv *Inventory, verdicts []Verdict, reviewError string, overridden, unsafeBypass bool) string {
	if unsafeBypass {
		return "UNSAFE BYPASS: continued without a positive Prolewatch security decision."
	}
	if overridden {
		return "Allowed by an exact, one-time user approval."
	}
	if reviewError != "" {
		return "Blocked because AI review failed: " + reviewError
	}
	hard := 0
	for _, finding := range inv.Findings {
		if finding.HardBlock {
			hard++
		}
	}
	if hard > 0 {
		return fmt.Sprintf("Blocked by %d deterministic hard-block finding(s).", hard)
	}
	if !inv.Coverage.Complete {
		return "Blocked because audit coverage is incomplete."
	}
	if mode == ReviewModeDeterministicOnly {
		severe := 0
		for _, finding := range inv.Findings {
			if finding.Severity == "critical" || finding.Severity == "high" {
				severe++
			}
		}
		if severe > 0 {
			return fmt.Sprintf("Blocked by %d deterministic high-severity finding(s).", severe)
		}
		return "All deterministic checks allowed this phase; medium and low findings remain visible as warnings."
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
			if finding.Severity == "critical" || finding.Severity == "high" {
				aiSevere++
			}
		}
	}
	if aiSevere > 0 {
		return fmt.Sprintf("Blocked by %d AI high-severity finding(s).", aiSevere)
	}
	if lowest := lowestVerdictConfidence(verdicts); lowest != "" && lowest != "high" {
		return fmt.Sprintf("Automatically allowed by the configured confidence policy: AI confidence %s meets minimum %s.", lowest, minimumConfidence)
	}
	return "All deterministic and AI checks allowed this phase."
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
