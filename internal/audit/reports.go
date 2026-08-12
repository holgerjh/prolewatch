package audit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type ReviewerReport struct {
	Mode              string    `json:"mode"`
	MinimumConfidence string    `json:"minimum_confidence,omitempty"`
	Provider          string    `json:"provider,omitempty"`
	Transport         string    `json:"transport,omitempty"`
	RuntimeVersion    string    `json:"runtime_version,omitempty"`
	Model             string    `json:"model,omitempty"`
	Effort            string    `json:"effort,omitempty"`
	AdapterPolicy     string    `json:"adapter_policy,omitempty"`
	Error             string    `json:"error,omitempty"`
	Verdicts          []Verdict `json:"verdicts"`
}

type SealedArtifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type Report struct {
	SchemaVersion        int                  `json:"schema_version"`
	ReportID             string               `json:"report_id"`
	CreatedAt            string               `json:"created_at"`
	Transaction          ProcessIdentity      `json:"transaction"`
	PackageBase          string               `json:"package_base"`
	Phase                string               `json:"phase"`
	Decision             string               `json:"decision"`
	Disposition          string               `json:"disposition"`
	Summary              string               `json:"summary"`
	ContentHash          string               `json:"content_hash"`
	PolicyFingerprint    string               `json:"policy_fingerprint"`
	ScannerVersion       int                  `json:"scanner_version"`
	RulesVersion         int                  `json:"rules_version"`
	ApplicationVersion   string               `json:"application_version"`
	Reviewer             ReviewerReport       `json:"reviewer"`
	Coverage             Coverage             `json:"coverage"`
	Exclusions           []string             `json:"exclusions"`
	Manifest             []map[string]any     `json:"manifest"`
	Findings             []Finding            `json:"findings"`
	Overridden           bool                 `json:"overridden"`
	UnsafeBypass         bool                 `json:"unsafe_bypass"`
	UnscannedBypass      bool                 `json:"unscanned_bypass"`
	ApprovalEligible     bool                 `json:"approval_eligible"`
	UnsafeBypassEligible bool                 `json:"unsafe_bypass_eligible"`
	NetworkEligible      bool                 `json:"network_eligible"`
	SealedArtifacts      []SealedArtifact     `json:"sealed_artifacts,omitempty"`
	ArchiveProbe         ToolIdentity         `json:"archive_probe"`
	SandboxRuns          []SandboxEnforcement `json:"sandbox_runs,omitempty"`
	YayContext           YayContext           `json:"yay_context"`
	ManifestDiff         []ManifestChange     `json:"manifest_diff"`
	Sources              []SourceProvenance   `json:"sources"`
	SourceVerification   SourceVerification   `json:"source_verification"`
}

type ReportStore struct{ Root string }

func NewReportStore() *ReportStore { return &ReportStore{Root: filepath.Join(StateRoot(), "reports")} }

func (r Report) Validate() error {
	if r.SchemaVersion != ReportSchemaVersion || !reportIDRE.MatchString(r.ReportID) {
		return errors.New("invalid or legacy report document")
	}
	if _, err := time.Parse(time.RFC3339Nano, r.CreatedAt); err != nil {
		return errors.New("invalid report creation time")
	}
	if err := ValidatePackageBase(r.PackageBase); err != nil {
		return err
	}
	if (r.Phase != "pre" && r.Phase != "post" && r.Phase != "artifact") || (r.Decision != "allow" && r.Decision != "block") ||
		(r.Disposition != "allow" && r.Disposition != "auto_allow" && r.Disposition != "block" && r.Disposition != "override" && r.Disposition != "unsafe_bypass") || r.Summary == "" || len(r.Summary) > 8192 {
		return errors.New("invalid report decision fields")
	}
	if !validHexDigest(r.PolicyFingerprint) || (!r.UnscannedBypass && (!validHexDigest(r.ContentHash) || !strings.Contains(r.ReportID, "-"+r.ContentHash[:12]+"-"))) {
		return errors.New("invalid report content or policy hash")
	}
	if r.UnscannedBypass && (r.ContentHash != "" || r.Disposition != "unsafe_bypass" || !r.UnsafeBypass) {
		return errors.New("invalid unscanned bypass report")
	}
	if r.ScannerVersion != ScannerVersion || r.RulesVersion != RulesVersion || r.ApplicationVersion != ApplicationVersion || r.Transaction.PID <= 0 || r.Transaction.StartTime == "" || r.Transaction.BootID == "" {
		return errors.New("invalid report provenance")
	}
	if r.Reviewer.Mode == ReviewModeAI {
		if !validConfidence(r.Reviewer.MinimumConfidence) {
			return errors.New("invalid report minimum confidence")
		}
		if r.Reviewer.Transport != "cli" || (r.Reviewer.Provider != "codex" && r.Reviewer.Provider != "anthropic") || r.Reviewer.RuntimeVersion == "" || r.Reviewer.Model == "" || !validEffort(r.Reviewer.Effort) || r.Reviewer.AdapterPolicy == "" || len(r.Reviewer.Error) > 8192 {
			return errors.New("invalid report reviewer metadata")
		}
	} else if r.Reviewer.Mode == ReviewModeDeterministicOnly {
		if r.Reviewer.MinimumConfidence != "" || r.Reviewer.Provider != "" || r.Reviewer.Transport != "" || r.Reviewer.RuntimeVersion != "" || r.Reviewer.Model != "" || r.Reviewer.Effort != "" || r.Reviewer.AdapterPolicy != "" || r.Reviewer.Error != "" || len(r.Reviewer.Verdicts) != 0 {
			return errors.New("deterministic-only report contains AI reviewer metadata")
		}
	} else {
		return errors.New("invalid report review mode")
	}
	for _, verdict := range r.Reviewer.Verdicts {
		if err := verdict.Validate(); err != nil {
			return err
		}
	}
	if err := validateCoverage(r.Coverage); err != nil {
		return err
	}
	if len(r.Manifest) > 200000 || len(r.Findings) > 100000 || len(r.Exclusions) > 100000 || len(r.SealedArtifacts) > 10000 || len(r.SandboxRuns) > 32 || len(r.Sources) > 10000 {
		return errors.New("report exceeds item limits")
	}
	for _, source := range r.Sources {
		if err := source.Validate(); err != nil {
			return err
		}
	}
	if err := r.SourceVerification.Validate(); err != nil {
		return err
	}
	if r.ArchiveProbe.Path != "/usr/bin/bsdtar" || r.ArchiveProbe.Version == "" || !validHexDigest(r.ArchiveProbe.SHA256) {
		return errors.New("invalid archive probe identity")
	}
	paths := make(map[string]bool, len(r.Manifest))
	for _, record := range r.Manifest {
		decoded, err := validateManifestRecord(record)
		if err != nil || paths[decoded.Path] {
			return errors.New("invalid report manifest")
		}
		paths[decoded.Path] = true
	}
	manifestRaw, err := CanonicalJSON(r.Manifest)
	if !r.UnscannedBypass && (err != nil || SHA256Bytes(manifestRaw) != r.ContentHash) {
		return errors.New("report manifest hash mismatch")
	}
	for _, finding := range r.Findings {
		if err := finding.Validate(); err != nil {
			return err
		}
	}
	for _, exclusion := range r.Exclusions {
		if exclusion == "" || len(exclusion) > 4096 {
			return errors.New("invalid report exclusion")
		}
	}
	for _, artifact := range r.SealedArtifacts {
		if artifact.Path == "" || len(artifact.Path) > 8192 || !filepath.IsAbs(artifact.Path) || !validHexDigest(artifact.SHA256) {
			return errors.New("invalid sealed artifact record")
		}
	}
	for _, run := range r.SandboxRuns {
		if run.CleanRoot == nil {
			return errors.New("sandbox run is missing clean-root provenance")
		}
		if err := run.Validate(); err != nil {
			return err
		}
	}
	if err := r.YayContext.Validate(); err != nil || len(r.ManifestDiff) > 400000 {
		return errors.New("invalid report advisory context")
	}
	for _, change := range r.ManifestDiff {
		if err := change.Validate(); err != nil {
			return err
		}
	}
	if r.ApprovalEligible && (r.ContentHash == "" || structuralBlock(&Inventory{Findings: r.Findings, Coverage: r.Coverage}) || reportHasPromptInjection(&r)) {
		return errors.New("report is incorrectly approval-eligible")
	}
	if r.ApprovalEligible && r.Decision != "block" {
		return errors.New("allowed report is incorrectly approval-eligible")
	}
	if r.UnsafeBypassEligible && (r.Decision != "block" || r.UnsafeBypass) {
		return errors.New("invalid unsafe bypass eligibility")
	}
	if r.UnsafeBypass != (r.Disposition == "unsafe_bypass") || r.Overridden != (r.Disposition == "override" || r.Disposition == "unsafe_bypass") {
		return errors.New("invalid report disposition")
	}
	if r.UnsafeBypass && !hasExplicitUnsafeBypassFinding(r.Findings) {
		return errors.New("unsafe bypass report lacks an explicit critical bypass finding")
	}
	if r.NetworkEligible != (r.Decision == "allow" && !r.UnsafeBypass && r.Phase == "post" && r.ContentHash != "") {
		return errors.New("invalid report network eligibility")
	}
	return nil
}

func hasExplicitUnsafeBypassFinding(findings []Finding) bool {
	for _, finding := range findings {
		if finding.Source == "deterministic" && finding.Severity == "critical" && finding.HardBlock && (finding.RuleID == "user-unsafe-bypass" || finding.RuleID == "scanner-bypassed" || finding.RuleID == "artifact-scan-bypassed") {
			return true
		}
	}
	return false
}

func (s *ReportStore) Save(report *Report) error {
	if report == nil {
		return errors.New("cannot save a nil report")
	}
	if err := report.Validate(); err != nil {
		return err
	}
	if err := EnsurePrivateDir(s.Root); err != nil {
		return err
	}
	target := filepath.Join(s.Root, report.ReportID+".json")
	if _, err := os.Lstat(target); err == nil {
		return fmt.Errorf("report already exists: %s", report.ReportID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return AtomicWriteJSON(target, report)
}
func (s *ReportStore) Replace(report *Report) error {
	if report == nil {
		return errors.New("cannot replace with a nil report")
	}
	if err := report.Validate(); err != nil {
		return err
	}
	current, err := s.Load(report.ReportID)
	if err != nil {
		return err
	}
	if current.ContentHash != report.ContentHash {
		return errors.New("refusing to replace report with different content hash")
	}
	return AtomicWriteJSON(filepath.Join(s.Root, report.ReportID+".json"), report)
}
func (s *ReportStore) Load(id string) (*Report, error) {
	if !reportIDRE.MatchString(id) {
		return nil, errors.New("invalid report id")
	}
	var report Report
	if err := ReadJSONFile(filepath.Join(s.Root, id+".json"), 32*1024*1024, &report); err != nil {
		return nil, err
	}
	if report.ReportID != id {
		return nil, errors.New("report filename does not match document")
	}
	if err := report.Validate(); err != nil {
		return nil, err
	}
	return &report, nil
}
func (s *ReportStore) Latest() (*Report, error) {
	ids, err := s.IDs(1)
	if err != nil {
		return nil, errors.New("no reports found")
	}
	if len(ids) == 0 {
		return nil, errors.New("no reports found")
	}
	return s.Load(ids[0])
}

func (s *ReportStore) IDs(limit int) ([]string, error) {
	entries, err := os.ReadDir(s.Root)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, entry := range entries {
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") && reportIDRE.MatchString(id) {
			ids = append(ids, id)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))
	if limit > 0 && len(ids) > limit {
		ids = ids[:limit]
	}
	return ids, nil
}

func (s *ReportStore) LatestFor(packageBase, phase string) (*Report, error) {
	if err := ValidatePackageBase(packageBase); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.Root)
	if err != nil {
		return nil, errors.New("no matching report found")
	}
	ids := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			ids = append(ids, strings.TrimSuffix(entry.Name(), ".json"))
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))
	for _, id := range ids {
		report, err := s.Load(id)
		if err == nil && report.PackageBase == packageBase && report.Phase == phase {
			return report, nil
		}
	}
	return nil, errors.New("no matching report found")
}

func RenderReport(report *Report) string {
	content := report.ContentHash
	if content == "" {
		content = "unavailable"
	}
	disposition := strings.ToUpper(strings.ReplaceAll(TerminalText(report.Disposition, 4096), "_", "-"))
	lines := []string{"Report: " + TerminalText(report.ReportID, 4096), "Package: " + TerminalText(report.PackageBase, 4096), "Phase: " + TerminalText(report.Phase, 4096), "Decision: " + disposition, "Content SHA-256: " + content, "Review mode: " + TerminalText(report.Reviewer.Mode, 100)}
	if report.Reviewer.Mode == ReviewModeAI {
		lines = append(lines, "Reviewer: "+TerminalText(report.Reviewer.Provider, 100)+" / "+TerminalText(report.Reviewer.Model, 256))
		lines = append(lines, "Minimum confidence: "+TerminalText(report.Reviewer.MinimumConfidence, 20))
		if lowest := lowestVerdictConfidence(report.Reviewer.Verdicts); lowest != "" {
			lines = append(lines, "AI confidence: "+lowest)
		}
	}
	lines = append(lines, "Summary: "+TerminalText(report.Summary, 4096))
	if sources := sourceSummary(report.Sources, report.SourceVerification); sources != "" {
		lines = append(lines, "Vendor sources: "+TerminalText(sources, 1000))
	}
	if verdictsHaveCoverageNotes(report.Reviewer.Verdicts) {
		lines = append(lines, "AI coverage gaps:")
		for batch, verdict := range report.Reviewer.Verdicts {
			for _, note := range verdict.CoverageNotes {
				lines = append(lines, fmt.Sprintf("  - Batch %d: %s", batch+1, terminalInline(note, 1000)))
			}
		}
	}
	if len(report.Findings) > 0 {
		lines = append(lines, "Findings (critical to info):")
		for _, item := range report.Findings {
			location := TerminalText(item.File, 4096)
			if item.Line != nil {
				location += fmt.Sprintf(":%d", *item.Line)
			}
			lines = append(lines, fmt.Sprintf("  - [%s] [%s] %s %s: %s; evidence=%s", strings.ToUpper(TerminalText(item.Severity, 40)), strings.ToUpper(TerminalText(item.Source, 20)), TerminalText(item.Category, 80), location, TerminalText(item.Rationale, 2000), TerminalText(item.Evidence, 320)))
		}
	}
	selection := fmt.Sprintf("%d files selected for AI review", report.Coverage.SelectedFiles)
	if report.Reviewer.Mode == ReviewModeDeterministicOnly {
		selection = "AI text selection disabled"
	}
	lines = append(lines, fmt.Sprintf("Coverage: %d files / %d bytes; %s", report.Coverage.FilesSeen, report.Coverage.BytesSeen, selection))
	if report.Decision == "block" && report.ApprovalEligible {
		lines = append(lines, "Override: prolewatch approve "+report.ReportID)
	}
	if report.Decision == "block" && report.UnsafeBypassEligible {
		lines = append(lines, "Unsafe bypass: available only through the interactive yay gate")
	}
	if report.NetworkEligible {
		lines = append(lines, "Network: prolewatch allow-network "+report.ReportID)
	}
	return strings.Join(lines, "\n")
}

func verdictsHaveCoverageNotes(verdicts []Verdict) bool {
	for _, verdict := range verdicts {
		if len(verdict.CoverageNotes) > 0 {
			return true
		}
	}
	return false
}
