package audit

import (
	"errors"
	"fmt"
	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/egress"
	"github.com/holgerjh/prolewatch/internal/safe"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type ReviewerReport struct {
	Mode              string `json:"mode"`
	MinimumConfidence string `json:"minimum_confidence,omitempty"`
	Provider          string `json:"provider,omitempty"`
	Transport         string `json:"transport,omitempty"`
	RuntimeVersion    string `json:"runtime_version,omitempty"`
	Model             string `json:"model,omitempty"`
	Effort            string `json:"effort,omitempty"`
	AdapterPolicy     string `json:"adapter_policy,omitempty"`
	Error             string `json:"error,omitempty"`
	// Trigger records why an otherwise optional recipe review ran.
	Trigger string `json:"trigger,omitempty"`
	// Skipped is why review did not run when nothing went wrong. Kept apart
	// from Error so a configuration choice is never rendered as a degradation.
	Skipped  string    `json:"skipped,omitempty"`
	Verdicts []Verdict `json:"verdicts"`
}

type ArtifactBinding struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// StrippedSurfaces is one package's gate outcome.
type StrippedSurfaces struct {
	Package string   `json:"package"`
	Members []string `json:"members"`
	SHA256  string   `json:"sha256"`
}

// CarriedFindingBinding records why one current deterministic finding did not
// ask the user the same question twice. FindingID binds the complete finding;
// ManifestEntryHash binds the complete current manifest entry rather than only
// its path or content digest.
type CarriedFindingBinding struct {
	FindingID         string `json:"finding_id"`
	Path              string `json:"path"`
	ManifestEntryHash string `json:"manifest_entry_hash"`
}

// CarriedDecision is transaction-local evidence that exact findings on exact
// files were already approved at an earlier phase. It is report metadata, not
// a reusable approval or a new marker authority.
type CarriedDecision struct {
	SourceReportID    string                  `json:"source_report_id"`
	SourcePhase       string                  `json:"source_phase"`
	SourceContentHash string                  `json:"source_content_hash"`
	Findings          []CarriedFindingBinding `json:"findings"`
}

type Report struct {
	// A report is evidence bound to exact content, policy, implementation, and
	// process identity. Decision fields protect honest-user workflow; root-side
	// operations never treat them as privileged authorization.
	SchemaVersion      int               `json:"schema_version"`
	ReportID           string            `json:"report_id"`
	CreatedAt          string            `json:"created_at"`
	Transaction        ProcessIdentity   `json:"transaction"`
	PackageBase        string            `json:"package_base"`
	Phase              string            `json:"phase"`
	Decision           string            `json:"decision"`
	Disposition        string            `json:"disposition"`
	Summary            string            `json:"summary"`
	ContentHash        string            `json:"content_hash"`
	PolicyFingerprint  string            `json:"policy_fingerprint"`
	ScannerVersion     int               `json:"scanner_version"`
	RulesVersion       int               `json:"rules_version"`
	ApplicationVersion string            `json:"application_version"`
	Reviewer           ReviewerReport    `json:"reviewer"`
	Coverage           brief.Coverage    `json:"coverage"`
	Exclusions         []string          `json:"exclusions"`
	Manifest           []map[string]any  `json:"manifest"`
	Findings           []brief.Finding   `json:"findings"`
	Overridden         bool              `json:"overridden"`
	ApprovalEligible   bool              `json:"approval_eligible"`
	NetworkEligible    bool              `json:"network_eligible"`
	CarriedDecision    *CarriedDecision  `json:"carried_decision,omitempty"`
	ArtifactBindings   []ArtifactBinding `json:"artifact_bindings,omitempty"`
	// AcquiredHosts is every host contacted while retrieving declared sources,
	// redirect hops included. It is reported, never prompted on: hop chains
	// drift benignly and often, so a question about them would fire routinely
	// and teach people to dismiss it. Visibility without a decision the user
	// has no basis to make.
	AcquiredHosts []string `json:"acquired_hosts,omitempty"`
	// StrippedSurfaces records what the privileged-integration gate removed and
	// the hash the transaction was re-bound to. Stripping is not free - removing
	// a surface a package genuinely needs produces a broken install - so what
	// was removed is recorded rather than left for the user to remember.
	StrippedSurfaces   []StrippedSurfaces       `json:"stripped_surfaces,omitempty"`
	ArchiveProbe       brief.ToolIdentity       `json:"archive_probe"`
	SandboxRuns        []SandboxEnforcement     `json:"sandbox_runs,omitempty"`
	YayContext         brief.YayContext         `json:"yay_context"`
	ManifestDiff       []brief.ManifestChange   `json:"manifest_diff"`
	Sources            []brief.SourceProvenance `json:"sources"`
	SourceVerification brief.SourceVerification `json:"source_verification"`
}

type ReportStore struct{ Root string }

func NewReportStore() *ReportStore { return &ReportStore{Root: filepath.Join(StateRoot(), "reports")} }

func (r Report) Validate() error {
	// Validate cross-field semantics, not only JSON shape. Reports are loaded
	// back from user-owned state and must not gain approval/network meaning by
	// mixing individually valid fields from different dispositions.
	if r.SchemaVersion != ReportSchemaVersion || !reportIDRE.MatchString(r.ReportID) {
		return errors.New("invalid or legacy report document")
	}
	if _, err := time.Parse(time.RFC3339Nano, r.CreatedAt); err != nil {
		return errors.New("invalid report creation time")
	}
	if err := brief.ValidatePackageBase(r.PackageBase); err != nil {
		return err
	}
	if (r.Phase != "pre" && r.Phase != "post" && r.Phase != "artifact") || (r.Decision != "allow" && r.Decision != "block") ||
		(r.Disposition != "allow" && r.Disposition != "block" && r.Disposition != "override") || r.Summary == "" || len(r.Summary) > 8192 {
		return errors.New("invalid report decision fields")
	}
	if !validHexDigest(r.PolicyFingerprint) || !validHexDigest(r.ContentHash) || !strings.Contains(r.ReportID, "-"+r.ContentHash[:12]+"-") {
		return errors.New("invalid report content or policy hash")
	}
	if r.ScannerVersion != ScannerVersion || r.RulesVersion != RulesVersion || r.ApplicationVersion != ApplicationVersion || r.Transaction.PID <= 0 || r.Transaction.StartTime == "" || r.Transaction.BootID == "" {
		return errors.New("invalid report provenance")
	}
	// AI and deterministic-only reports have disjoint provenance shapes. Empty
	// provider fields in deterministic-only mode are part of that assertion.
	if r.Reviewer.Mode == ReviewModeAI {
		if !validConfidence(r.Reviewer.MinimumConfidence) {
			return errors.New("invalid report minimum confidence")
		}
		if r.Reviewer.Transport != "cli" || (r.Reviewer.Provider != "codex" && r.Reviewer.Provider != "anthropic") || r.Reviewer.RuntimeVersion == "" || r.Reviewer.Model == "" || !validEffort(r.Reviewer.Effort) || r.Reviewer.AdapterPolicy == "" || len(r.Reviewer.Error) > 8192 {
			return errors.New("invalid report reviewer metadata")
		}
		if r.Reviewer.Trigger != "" && r.Reviewer.Trigger != reviewTriggerDecisionFindings {
			return errors.New("invalid report reviewer trigger")
		}
	} else if r.Reviewer.Mode == ReviewModeDeterministicOnly {
		if r.Reviewer.MinimumConfidence != "" || r.Reviewer.Provider != "" || r.Reviewer.Transport != "" || r.Reviewer.RuntimeVersion != "" || r.Reviewer.Model != "" || r.Reviewer.Effort != "" || r.Reviewer.AdapterPolicy != "" || r.Reviewer.Error != "" || r.Reviewer.Trigger != "" || len(r.Reviewer.Verdicts) != 0 {
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
	// These generous ceilings are deserialization/validation budgets for stored
	// evidence. Tighter scanner limits normally keep production reports far
	// below them, but a hand-edited file must still have a hard upper bound.
	for _, stripped := range r.StrippedSurfaces {
		if stripped.Package == "" || len(stripped.Members) == 0 || !safe.ValidHexDigest(stripped.SHA256) {
			return errors.New("invalid stripped-surface record")
		}
		for _, member := range stripped.Members {
			if _, ok := brief.ClassifySurface(member); !ok {
				// The gate may only ever remove privileged-integration
				// surfaces. A record naming an ordinary file means something
				// stripped payload, which is a defect, not a user decision.
				return errors.New("stripped-surface record names a member that is not a privileged surface")
			}
		}
	}
	if len(r.AcquiredHosts) > 1000 {
		return errors.New("report records an implausible number of acquisition hosts")
	}
	for _, host := range r.AcquiredHosts {
		if !egress.ValidRequestHost(host) {
			return errors.New("report records an invalid acquisition host")
		}
	}
	if len(r.Manifest) > 200000 || len(r.Findings) > 100000 || len(r.Exclusions) > 100000 || len(r.ArtifactBindings) > 10000 || len(r.SandboxRuns) > 32 || len(r.Sources) > 10000 || (r.CarriedDecision != nil && len(r.CarriedDecision.Findings) > 100000) {
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
	manifestEntryHashes := make(map[string]string, len(r.Manifest))
	for _, record := range r.Manifest {
		decoded, err := brief.ValidateManifestRecord(record)
		if err != nil || paths[decoded.Path] {
			return errors.New("invalid report manifest")
		}
		entryHash, err := manifestEntryHash(record)
		if err != nil {
			return errors.New("invalid report manifest binding")
		}
		paths[decoded.Path] = true
		manifestEntryHashes[decoded.Path] = entryHash
	}
	// Canonical JSON makes ContentHash a stable commitment to the entire ordered
	// manifest rather than to whichever serialization happened to be stored.
	manifestRaw, err := CanonicalJSON(r.Manifest)
	if err != nil || safe.SHA256Bytes(manifestRaw) != r.ContentHash {
		return errors.New("report manifest hash mismatch")
	}
	deterministicFindingIDs := map[string]bool{}
	deterministicFindings := map[string]brief.Finding{}
	for _, finding := range r.Findings {
		if err := finding.Validate(); err != nil {
			return err
		}
		if finding.Source == "deterministic" {
			id := findingGuidanceID(finding)
			deterministicFindingIDs[id] = true
			deterministicFindings[id] = finding
		}
	}
	if r.CarriedDecision != nil {
		carried := r.CarriedDecision
		if r.Phase != "post" || r.Overridden || carried.SourcePhase != "pre" || !reportIDRE.MatchString(carried.SourceReportID) ||
			!validHexDigest(carried.SourceContentHash) || !strings.Contains(carried.SourceReportID, "-"+carried.SourceContentHash[:12]+"-") || len(carried.Findings) == 0 {
			return errors.New("invalid carried decision provenance")
		}
		seen := map[string]bool{}
		for _, binding := range carried.Findings {
			finding, ok := deterministicFindings[binding.FindingID]
			if !ok || seen[binding.FindingID] || binding.Path != finding.File || finding.HardBlock || finding.Category == "coverage" ||
				!validHexDigest(binding.ManifestEntryHash) || manifestEntryHashes[binding.Path] != binding.ManifestEntryHash {
				return errors.New("invalid carried finding binding")
			}
			seen[binding.FindingID] = true
		}
	}
	for _, verdict := range r.Reviewer.Verdicts {
		for _, guidance := range verdict.Guidance {
			if !deterministicFindingIDs[guidance.FindingID] {
				return errors.New("report guidance is not bound to a deterministic finding")
			}
		}
	}
	for _, exclusion := range r.Exclusions {
		if exclusion == "" || len(exclusion) > 4096 {
			return errors.New("invalid report exclusion")
		}
	}
	for _, artifact := range r.ArtifactBindings {
		if artifact.Path == "" || len(artifact.Path) > 8192 || !filepath.IsAbs(artifact.Path) || !validHexDigest(artifact.SHA256) {
			return errors.New("invalid artifact binding")
		}
	}
	for _, run := range r.SandboxRuns {
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
	// Recompute the high-risk eligibility invariants from evidence. Persisted
	// booleans alone cannot make structural gaps or prompt injection overridable.
	if r.ApprovalEligible && (r.ContentHash == "" || structuralBlock(&brief.Inventory{Findings: r.Findings, Coverage: r.Coverage}) || reportHasPromptInjection(&r)) {
		return errors.New("report is incorrectly approval-eligible")
	}
	if r.ApprovalEligible && r.Decision != "block" {
		return errors.New("allowed report is incorrectly approval-eligible")
	}
	if r.Overridden != (r.Disposition == "override") {
		return errors.New("invalid report disposition")
	}
	if r.NetworkEligible != (r.Decision == "allow" && r.Phase == "post" && r.ContentHash != "") {
		return errors.New("invalid report network eligibility")
	}
	return nil
}

func manifestEntryHash(record map[string]any) (string, error) {
	raw, err := CanonicalJSON(record)
	if err != nil {
		return "", err
	}
	return safe.SHA256Bytes(raw), nil
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
	if err := AtomicWriteJSON(target, report); err != nil {
		return err
	}
	// Best effort, and deliberately after the write: a store that cannot be
	// tidied is not a reason to fail a scan.
	s.Prune()
	return nil
}

// reportRetention bounds how much history the store keeps.
//
// A report carries the complete manifest of everything it saw, so it is not a
// small file, and one transaction writes several. Keeping every one of them
// forever grew a directory nobody empties and made LatestFor - which reads
// newest-first until it finds a package and phase - slower every month for the
// packages built least often.
//
// The number is chosen so that the two things history is actually for still
// work: the manifest diff against the previous scan, and running
// `prolewatch approve` from another shell after reading a briefing.
const reportRetention = 200

// Prune deletes the oldest reports beyond reportRetention, keeping any that a
// pending approval still points at.
//
// Report IDs begin with a UTC timestamp, so ordering by name orders by age and
// this needs no reads at all - which is the point: a pass that had to open
// every report to decide what to delete would cost what it saves.
func (s *ReportStore) Prune() {
	// Consumed approvals are audit history, not live authority. Prune them in
	// the same maintenance pass and to the same window as their source reports.
	NewApprovalStore().PruneUsed()
	// Marker cleanup runs every time, not only when history is over its cap.
	// They are a separate unbounded directory, and a store below the cap - the
	// ordinary case - would otherwise never sweep an ended transaction's marker.
	protected := liveMarkerReports()
	for id := range pendingApprovalReports() {
		protected[id] = true
	}
	ids, err := s.IDs(0)
	if err != nil || len(ids) <= reportRetention {
		return
	}
	for _, id := range ids[reportRetention:] {
		if protected[id] {
			// An approval the user created but has not spent yet names this
			// report. Deleting it would answer their pending decision for them.
			continue
		}
		_ = os.Remove(filepath.Join(s.Root, id+".json"))
		// Contained build logs are diagnostic companions to reports, not a
		// second unbounded history. Remove the exact companion when its report
		// ages out; protected reports keep their logs as well.
		_ = os.Remove(filepath.Join(s.Root, id+containedBuildLogSuffix))
	}
}

// liveMarkerReports names the reports a decision marker from a running
// transaction still depends on, and deletes the markers of transactions that
// have ended.
//
// A marker is not history, it is the authorization the next build phase is
// about to be checked against: VerifyMarker loads its report and re-binds the
// directory against that manifest. Pruning to the newest N reports without
// asking meant a large enough transaction - pre and post hooks run for every
// package base before the early ones reach their wrapper phase - could delete
// the evidence for a package still waiting to build, and the transaction then
// failed closed on a report-load error.
//
// Protecting every marker instead would trade a bounded history for an
// unbounded one, because nothing removed markers either. So liveness decides
// both: a marker whose transaction is gone can never be verified again, and is
// removed here rather than pinning a report forever.
func liveMarkerReports() map[string]bool {
	live := map[string]bool{}
	root := filepath.Join(StateRoot(), "decision-markers")
	entries, err := os.ReadDir(root)
	if err != nil {
		return live
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(root, entry.Name())
		var marker Marker
		if err := ReadJSONFile(path, 64*1024, &marker); err != nil {
			// Unreadable is not authorization. It cannot protect a report, and
			// removing it costs nothing: VerifyMarker would reject it anyway.
			_ = os.Remove(path)
			continue
		}
		if marker.SchemaVersion != MarkerSchemaVersion || !IdentityIsLive(marker.Transaction) {
			_ = os.Remove(path)
			continue
		}
		if reportIDRE.MatchString(marker.ReportID) {
			live[marker.ReportID] = true
		}
	}
	return live
}

// pendingApprovalReports names the reports an unspent approval refers to.
func pendingApprovalReports() map[string]bool {
	protected := map[string]bool{}
	entries, err := os.ReadDir(filepath.Join(NewApprovalStore().Root, "pending"))
	if err != nil {
		return protected
	}
	for _, entry := range entries {
		name := strings.TrimSuffix(entry.Name(), ".json")
		if index := strings.Index(name, "-"); index >= 0 {
			if id := name[index+1:]; reportIDRE.MatchString(id) {
				protected[id] = true
			}
		}
	}
	return protected
}
func (s *ReportStore) Replace(report *Report) error {
	// Replacement appends lifecycle evidence such as final artifact identities.
	// It may never retarget an existing report ID to different content.
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
	if err := brief.ValidatePackageBase(packageBase); err != nil {
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

// reportOutcome states what happens next rather than passing a verdict on the
// package. Prolewatch describes, the user decides, and containment protects;
// the outcome therefore avoids claiming that a package is safe or malicious.
func reportOutcome(report *Report) string {
	switch {
	case report.Decision == "allow" && report.Overridden:
		return "APPROVED BY YOU"
	case report.Decision == "allow" && report.CarriedDecision != nil:
		return "NO NEW DECISION NEEDED"
	case report.Decision == "allow":
		return "NO BLOCKING FINDINGS"
	case !report.ApprovalEligible:
		return "STRUCTURAL FAILURE - NOT APPROVABLE"
	}
	return "NEEDS YOUR DECISION"
}

func renderReportText(report *Report, promptFollows bool) string {
	// Every interpolated value uses terminalInline, never TerminalText.
	// TerminalText keeps newlines so that multi-line evidence stays readable in
	// a log; on a report line a newline lets package content start its own line
	// and impersonate Prolewatch's output. Caught by
	// TestBriefingSanitizesEveryAttackerControlledField, which forged an
	// outcome stamp through a finding's evidence field.
	//
	// Same ordering as the coloured renderer, for the same reason: what this
	// package is, what is wrong with it, what protects you anyway, what to do,
	// and only then the identifiers. See terminalRenderer.report.
	lines := []string{
		"Package: " + terminalInline(report.PackageBase, 4096) + " / " + terminalInline(report.Phase, 100),
		"Outcome: " + reportOutcome(report),
		"Summary: " + terminalInline(report.Summary, 4096),
	}
	if transition := packageTransition(report, "->", ", "); transition != "" {
		lines = append(lines, "Change: "+transition)
	}
	if changed := changedMaterial(report, ": ", 4); changed != "" {
		lines = append(lines, "Changed: "+changed)
	}
	if summary := sourceBriefing(report); summary != "" {
		lines = append(lines, "Sources: "+terminalInline(summary, 2000))
	}
	if binding := brief.SourceSummary(report.Sources, report.SourceVerification); binding != "" {
		lines = append(lines, "Binding: "+terminalInline(binding, 2000))
	}
	if len(report.AcquiredHosts) > 0 {
		lines = append(lines, "Contacted: "+terminalInline(strings.Join(report.AcquiredHosts, ", "), 2000))
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
		carriedIDs := carriedFindingIDSet(report.CarriedDecision)
		for _, item := range report.Findings {
			location := terminalInline(item.File, 4096)
			if item.Line != nil {
				location += fmt.Sprintf(":%d", *item.Line)
			}
			origin, suffix := findingOrigin(item), ""
			if carriedIDs[findingGuidanceID(item)] {
				origin += "; approved at recipe gate"
				suffix = "; exact bytes unchanged"
			}
			entry := fmt.Sprintf("  - [%s] (%s): %s", strings.ToUpper(terminalInline(item.Severity, 40)), origin, terminalInline(item.Rationale, 2000))
			lines = append(lines, entry, fmt.Sprintf("      %s (%s)%s%s", location, terminalInline(item.Category, 80), evidenceSuffix(item.Evidence), suffix))
		}
	}
	if status, _ := aiReviewStatus(report, "; "); status != "" {
		lines = append(lines, "AI review: "+status)
		if note := aiReviewScopeNote(report); note != "" {
			lines = append(lines, "      "+note)
		}
	}
	lines = append(lines, "Sandbox: "+containmentSummary(report, "; "))
	for _, stripped := range report.StrippedSurfaces {
		lines = append(lines, "Stripped: "+terminalInline(strings.Join(stripped.Members, ", "), 2000)+" from "+terminalInline(stripped.Package, 512))
	}
	if report.Decision == "block" && report.ApprovalEligible && !promptFollows {
		lines = append(lines, "To approve this exact snapshot, once:", "    prolewatch approve "+terminalInline(report.ReportID, 4096))
	}
	// Printed regardless of promptFollows: no interactive prompt asks about a
	// structural failure, so there is nothing here to say twice.
	for _, class := range structuralRecovery(report) {
		lines = append(lines, class.title)
		for _, step := range class.steps {
			lines = append(lines, "    - "+step)
		}
	}
	selection := aiSelectionSummary(report)
	lines = append(lines, fmt.Sprintf("Coverage: %d files / %s / %s", report.Coverage.FilesSeen, humanBytes(report.Coverage.BytesSeen), selection))
	lines = append(lines, "Review mode: "+terminalInline(report.Reviewer.Mode, 100))
	if report.Reviewer.Mode == ReviewModeAI {
		lines = append(lines, "Reviewer: "+terminalInline(report.Reviewer.Provider, 100)+" / "+terminalInline(report.Reviewer.Model, 256))
		lines = append(lines, "Minimum confidence: "+terminalInline(report.Reviewer.MinimumConfidence, 20))
		if lowest := lowestVerdictConfidence(report.Reviewer.Verdicts); lowest != "" {
			lines = append(lines, "AI confidence: "+lowest)
		}
	}
	content := report.ContentHash
	if content == "" {
		content = "unavailable"
	}
	lines = append(lines, "Report: "+terminalInline(report.ReportID, 4096), "Content SHA-256: "+content)
	return strings.Join(lines, "\n") + "\n"
}

// aiSelectionSummary distinguishes review input prepared by the scanner from
// a review that actually ran. SelectedFiles is populated even when policy
// deliberately skips the recipe phase, so calling it "selected for AI review"
// in that case falsely describes work that never happened.
func aiSelectionSummary(report *Report) string {
	if report == nil || report.Reviewer.Mode == ReviewModeDeterministicOnly {
		return "AI selection off"
	}
	if len(report.Reviewer.Verdicts) == 0 {
		return "AI review not run"
	}
	return fmt.Sprintf("%d selected for AI review", report.Coverage.SelectedFiles)
}

func evidenceSuffix(evidence string) string {
	if evidence == "" {
		return ""
	}
	return "  " + terminalInline(evidence, 320)
}

func verdictsHaveCoverageNotes(verdicts []Verdict) bool {
	for _, verdict := range verdicts {
		if len(verdict.CoverageNotes) > 0 {
			return true
		}
	}
	return false
}
