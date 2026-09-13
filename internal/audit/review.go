package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/safe"
)

const DispatchProtocolVersion = 3

var ErrProviderTimeout = errors.New("provider request timed out")

type SelectedFile struct {
	File       string `json:"file"`
	ByteOffset int    `json:"byte_offset"`
	LineStart  int    `json:"line_start"`
	LineEnd    int    `json:"line_end"`
	Content    string `json:"content"`
}

type GuidanceContextLine struct {
	Line int    `json:"line"`
	Text string `json:"text"`
}

type GuidanceTarget struct {
	FindingID  string                `json:"finding_id"`
	Finding    brief.Finding         `json:"finding"`
	AnchorKind string                `json:"anchor_kind"`
	AnchorText string                `json:"anchor_text"`
	Context    []GuidanceContextLine `json:"context"`
}

type ReviewSnapshot struct {
	// ManifestHash binds the complete scan. ManifestViewHash separately binds the
	// possibly reduced provider view when post-phase vendor content is omitted by
	// an explicit scan-depth-zero policy.
	SnapshotSchemaVersion   int                      `json:"snapshot_schema_version"`
	PackageBase             string                   `json:"package_base"`
	Phase                   string                   `json:"phase"`
	ManifestHash            string                   `json:"manifest_hash"`
	ManifestViewHash        string                   `json:"manifest_view_hash,omitempty"`
	ManifestOmissions       []string                 `json:"manifest_omissions,omitempty"`
	Coverage                brief.Coverage           `json:"coverage"`
	DeterministicFindings   []brief.Finding          `json:"deterministic_findings"`
	GuidanceMinimumSeverity string                   `json:"guidance_minimum_severity"`
	GuidanceTargets         []GuidanceTarget         `json:"guidance_targets"`
	Manifest                []map[string]any         `json:"manifest"`
	BatchIndex              int                      `json:"batch_index"`
	BatchCount              int                      `json:"batch_count"`
	Files                   []SelectedFile           `json:"files"`
	YayContext              brief.YayContext         `json:"yay_context"`
	ManifestDiff            []brief.ManifestChange   `json:"manifest_diff"`
	Sources                 []brief.SourceProvenance `json:"sources"`
	SourceVerification      brief.SourceVerification `json:"source_verification"`
}

// ReviewOptions changes advisory guidance selection and records why an optional
// call ran without removing any deterministic finding or selected source
// material from the provider view.
type ReviewOptions struct {
	SkipGuidanceFindingIDs map[string]bool
	Trigger                string
}

func validHexDigest(value string) bool {
	return len(value) == 64 && strings.Trim(value, "0123456789abcdef") == ""
}

func validateCoverage(coverage brief.Coverage) error {
	values := []int64{
		int64(coverage.FilesSeen), coverage.BytesSeen, int64(coverage.TextFiles), coverage.TextBytes,
		int64(coverage.SelectedFiles), coverage.SelectedBytes, int64(coverage.ReviewEligibleFiles),
		coverage.ReviewEligibleBytes, int64(coverage.OmittedReviewFiles), coverage.OmittedReviewBytes,
		int64(coverage.BinaryFiles), coverage.BinaryBytes, int64(coverage.ArchivesSeen),
		int64(coverage.ArchiveEntries), coverage.ArchiveUnpackedBytes,
	}
	for _, value := range values {
		if value < 0 {
			return errors.New("coverage contains a negative counter")
		}
	}
	if coverage.SelectedFiles > coverage.ReviewEligibleFiles || coverage.SelectedBytes > coverage.ReviewEligibleBytes || coverage.OmittedReviewFiles > coverage.ReviewEligibleFiles || coverage.OmittedReviewBytes > coverage.ReviewEligibleBytes {
		return errors.New("coverage counters are inconsistent")
	}
	if len(coverage.Notes) > 1000 {
		return errors.New("coverage contains too many notes")
	}
	for _, note := range coverage.Notes {
		if len(note) > 2000 {
			return errors.New("coverage note exceeds hard limit")
		}
	}
	return nil
}

func (s ReviewSnapshot) Validate() error {
	// Keep the persisted/provider boundary strict even for locally assembled data.
	if s.SnapshotSchemaVersion != ReviewSnapshotVersion {
		return errors.New("unsupported review snapshot schema")
	}
	if err := brief.ValidatePackageBase(s.PackageBase); err != nil {
		return err
	}
	if s.Phase != "pre" && s.Phase != "post" && s.Phase != "artifact" {
		return errors.New("invalid review phase")
	}
	if !validHexDigest(s.ManifestHash) {
		return errors.New("invalid manifest hash")
	}
	if err := validateCoverage(s.Coverage); err != nil {
		return err
	}
	if !brief.ValidSeverity(s.GuidanceMinimumSeverity) {
		return errors.New("invalid guidance minimum severity")
	}
	if s.BatchCount < 1 || s.BatchIndex < 0 || s.BatchIndex >= s.BatchCount {
		return errors.New("invalid batch numbering")
	}
	if len(s.Manifest) > 200000 || len(s.ManifestOmissions) > 1 || len(s.DeterministicFindings) > 100000 || len(s.GuidanceTargets) > findingGuidanceLimit || len(s.Files) == 0 {
		return errors.New("review snapshot exceeds item limits")
	}
	omitsVendorTree := false
	for _, omission := range s.ManifestOmissions {
		if omission != "src/" || s.Phase != "post" || omitsVendorTree {
			return errors.New("invalid review manifest omission")
		}
		omitsVendorTree = true
	}
	if err := s.YayContext.Validate(); err != nil || len(s.ManifestDiff) > 400000 || len(s.Sources) > 10000 || s.SourceVerification.Validate() != nil {
		return errors.New("invalid advisory review context")
	}
	for _, source := range s.Sources {
		if err := source.Validate(); err != nil {
			return err
		}
	}
	for _, change := range s.ManifestDiff {
		if err := change.Validate(); err != nil {
			return err
		}
		if omitsVendorTree && strings.HasPrefix(change.Path, "src/") {
			return errors.New("omitted review path appears in manifest diff")
		}
	}
	paths := map[string]bool{"<none>": true}
	for _, record := range s.Manifest {
		decoded, err := brief.ValidateManifestRecord(record)
		if err != nil {
			return err
		}
		if paths[decoded.Path] {
			return errors.New("invalid or duplicate manifest path")
		}
		if omitsVendorTree && (decoded.Path == "src" || strings.HasPrefix(decoded.Path, "src/")) {
			return errors.New("omitted review path appears in manifest")
		}
		paths[decoded.Path] = true
	}
	manifestRaw, err := CanonicalJSON(s.Manifest)
	viewHash := safe.SHA256Bytes(manifestRaw)
	if err != nil || (s.ManifestViewHash != "" && s.ManifestViewHash != viewHash) ||
		(omitsVendorTree && (!validHexDigest(s.ManifestViewHash) || s.ManifestViewHash != viewHash)) ||
		(!omitsVendorTree && viewHash != s.ManifestHash) {
		return errors.New("review snapshot manifest hash mismatch")
	}
	for _, finding := range s.DeterministicFindings {
		if err := finding.Validate(); err != nil {
			return err
		}
	}
	findingIDs := map[string]bool{}
	for _, finding := range s.DeterministicFindings {
		findingIDs[findingGuidanceID(finding)] = true
	}
	seenTargets := map[string]bool{}
	for _, target := range s.GuidanceTargets {
		if !severityAtLeast(target.Finding.Severity, s.GuidanceMinimumSeverity) {
			return errors.New("guidance target is below the configured decision threshold")
		}
		if err := target.Finding.Validate(); err != nil {
			return err
		}
		if target.FindingID != findingGuidanceID(target.Finding) || !findingIDs[target.FindingID] {
			return errors.New("guidance target is not bound to a deterministic finding")
		}
		if seenTargets[target.FindingID] {
			return errors.New("duplicate guidance target")
		}
		if err := target.validateAnchor(); err != nil {
			return err
		}
		seenTargets[target.FindingID] = true
	}
	for _, file := range s.Files {
		if !paths[file.File] || file.ByteOffset < 0 || file.LineStart < 1 || file.LineEnd < file.LineStart {
			return errors.New("invalid selected file")
		}
		if len(file.Content) > 20*1024*1024 {
			return errors.New("selected content exceeds hard limit")
		}
		lineEnd := file.LineStart + strings.Count(file.Content, "\n")
		if strings.HasSuffix(file.Content, "\n") {
			lineEnd--
		}
		if lineEnd != file.LineEnd {
			return errors.New("selected file line range does not match its content")
		}
	}
	return nil
}

func (target GuidanceTarget) validateAnchor() error {
	if target.AnchorText == "" || len(target.AnchorText) > findingGuidanceTextLimit || terminalInline(target.AnchorText, 320) != target.AnchorText {
		return errors.New("invalid guidance target anchor")
	}
	switch target.AnchorKind {
	case "line":
		if target.Finding.Line == nil || len(target.Context) == 0 || len(target.Context) > findingPreviewRadius*2+1 {
			return errors.New("invalid line guidance target")
		}
		previous, anchorSeen := 0, false
		for _, current := range target.Context {
			if current.Line < 1 || (previous != 0 && current.Line != previous+1) ||
				current.Line < *target.Finding.Line-findingPreviewRadius || current.Line > *target.Finding.Line+findingPreviewRadius ||
				len(current.Text) > findingGuidanceTextLimit || terminalInline(current.Text, 320) != current.Text {
				return errors.New("invalid guidance target context")
			}
			if current.Line == *target.Finding.Line {
				if anchorSeen || current.Text != target.AnchorText {
					return errors.New("guidance target context does not match its anchor")
				}
				anchorSeen = true
			}
			previous = current.Line
		}
		if !anchorSeen {
			return errors.New("guidance target context omits its anchor")
		}
	case "evidence":
		if len(target.Context) != 0 || target.AnchorText != terminalInline(target.Finding.Evidence, 320) {
			return errors.New("guidance target evidence anchor mismatch")
		}
	default:
		return errors.New("invalid guidance target anchor kind")
	}
	return nil
}

type DispatchRequest struct {
	// probe returns fixed metadata, canary exercises provider isolation, review
	// carries an accepted verdict, and diagnose-review carries only an accepted
	// verdict or a redacted validation description.
	ProtocolVersion int             `json:"protocol_version"`
	Operation       string          `json:"operation"`
	Snapshot        *ReviewSnapshot `json:"snapshot,omitempty"`
}

func (r DispatchRequest) Validate() error {
	if r.ProtocolVersion != DispatchProtocolVersion {
		return errors.New("unsupported dispatcher protocol")
	}
	switch r.Operation {
	case "probe", "canary":
		if r.Snapshot != nil {
			return fmt.Errorf("%s must not include a snapshot", r.Operation)
		}
	case "review", "diagnose-review":
		if r.Snapshot == nil {
			return fmt.Errorf("%s requires a snapshot", r.Operation)
		}
		return r.Snapshot.Validate()
	default:
		return errors.New("unsupported dispatcher operation")
	}
	return nil
}

type ProviderMetadata struct {
	Provider       string `json:"provider"`
	Transport      string `json:"transport"`
	RuntimeVersion string `json:"runtime_version"`
	Model          string `json:"model"`
	ModelDigest    string `json:"model_digest,omitempty"`
	ContextTokens  int    `json:"context_tokens,omitempty"`
	Thinking       bool   `json:"thinking,omitempty"`
	Effort         string `json:"effort"`
	AdapterPolicy  string `json:"adapter_policy"`
	// CompatibilityWarning is set when the provider CLI is newer than the
	// version this adapter was checked against. It is advisory: it is part of
	// the attestation-bound metadata so the warning cannot be lost between the
	// worker and the caller, and empty in the ordinary supported case.
	CompatibilityWarning string `json:"compatibility_warning,omitempty"`
}

type DispatchResponse struct {
	ProtocolVersion int                          `json:"protocol_version"`
	Metadata        ProviderMetadata             `json:"metadata"`
	Verdict         *Verdict                     `json:"verdict"`
	OllamaMetrics   []OllamaRequestMetrics       `json:"ollama_metrics,omitempty"`
	Diagnostic      *LLMProviderReviewDiagnostic `json:"diagnostic,omitempty"`
}

func (r DispatchResponse) Validate(operation string) error {
	if r.ProtocolVersion != DispatchProtocolVersion {
		return errors.New("unsupported dispatcher response protocol")
	}
	cli := r.Metadata.Transport == "cli" && (r.Metadata.Provider == "codex" || r.Metadata.Provider == "anthropic") && r.Metadata.ModelDigest == "" && r.Metadata.ContextTokens == 0 && !r.Metadata.Thinking
	ollama := r.Metadata.Transport == "http-loopback" && r.Metadata.Provider == "ollama" && validHexDigest(r.Metadata.ModelDigest) && r.Metadata.ContextTokens >= 16_384
	validMetadataEffort := (cli && validEffort(r.Metadata.Effort)) || (ollama && validOllamaEffectiveReasoning(r.Metadata.Effort))
	if (!cli && !ollama) || r.Metadata.RuntimeVersion == "" || r.Metadata.Model == "" || r.Metadata.AdapterPolicy == "" || !validMetadataEffort {
		return errors.New("invalid provider metadata")
	}
	if operation == "review" {
		if r.Diagnostic != nil {
			return errors.New("review unexpectedly returned a diagnostic")
		}
		if r.Verdict == nil {
			return errors.New("dispatcher omitted verdict")
		}
		if r.Metadata.Provider == "ollama" {
			if len(r.OllamaMetrics) != 1 || r.OllamaMetrics[0].Validate() != nil {
				return errors.New("dispatcher omitted valid Ollama request metrics")
			}
		} else if len(r.OllamaMetrics) != 0 {
			return errors.New("CLI provider returned Ollama request metrics")
		}
		return r.Verdict.Validate()
	}
	if operation == "diagnose-review" {
		if !ollama || r.Diagnostic == nil {
			return errors.New("diagnostic review requires an Ollama diagnostic")
		}
		if err := validateProviderReviewDiagnostic(*r.Diagnostic, r.Verdict); err != nil {
			return err
		}
		if len(r.OllamaMetrics) != 1 || r.OllamaMetrics[0].Validate() != nil {
			return errors.New("diagnostic review omitted valid Ollama request metrics")
		}
		return nil
	}
	if r.Verdict != nil || len(r.OllamaMetrics) != 0 || r.Diagnostic != nil {
		return errors.New("probe unexpectedly returned a verdict")
	}
	return nil
}

type Reviewer struct {
	Config        Config
	Command       []string
	metricsMu     sync.Mutex
	ollamaMetrics []OllamaRequestMetrics
}

func (r *Reviewer) OllamaMetrics() []OllamaRequestMetrics {
	r.metricsMu.Lock()
	defer r.metricsMu.Unlock()
	return append([]OllamaRequestMetrics(nil), r.ollamaMetrics...)
}

func NewReviewer(cfg Config) *Reviewer {
	return &Reviewer{Config: cfg}
}

func (r *Reviewer) Probe(ctx context.Context) (ProviderMetadata, error) {
	response, err := r.dispatch(ctx, DispatchRequest{ProtocolVersion: DispatchProtocolVersion, Operation: "probe"})
	if err != nil {
		return ProviderMetadata{}, err
	}
	return response.Metadata, nil
}

// Canary runs the provider's real Bubblewrap boundary check: a host sentinel
// must be unreachable and the workspace must start empty. It executes inline as
// the invoking user - there is no service account, and has not been one since
// the single-administrator redesign.
func (r *Reviewer) Canary(ctx context.Context) (ProviderMetadata, error) {
	if r.Config.Provider == "ollama" {
		return ProviderMetadata{}, errors.New("host/workspace isolation is not observable for the http-loopback Ollama transport")
	}
	response, err := r.dispatch(ctx, DispatchRequest{ProtocolVersion: DispatchProtocolVersion, Operation: "canary"})
	if err != nil {
		return ProviderMetadata{}, err
	}
	return response.Metadata, nil
}

func (r *Reviewer) Review(ctx context.Context, packageBase, phase string, inventory *brief.Inventory, options ReviewOptions) (ProviderMetadata, []Verdict, error) {
	// Require identical provider metadata across all batches and reject findings
	// for paths absent from the full inventory. Batch boundaries cannot change
	// which provider implementation or file namespace made the decision.
	if options.Trigger != "" && options.Trigger != reviewTriggerOnDemand {
		return ProviderMetadata{}, nil, errors.New("unsupported review trigger")
	}
	var expectedMetadata ProviderMetadata
	reasoning := "off"
	if r.Config.Provider == "ollama" {
		probe, err := r.dispatch(ctx, DispatchRequest{ProtocolVersion: DispatchProtocolVersion, Operation: "probe"})
		if err != nil {
			return ProviderMetadata{}, nil, err
		}
		expectedMetadata = probe.Metadata
		reasoning = probe.Metadata.Effort
	}
	batches, err := r.batchesWithProviderOptions(packageBase, phase, inventory, options, reasoning)
	if err != nil {
		return ProviderMetadata{}, nil, err
	}
	metadata := expectedMetadata
	var verdicts []Verdict
	expectedGuidance := map[string]string{}
	for _, target := range batches[0].GuidanceTargets {
		expectedGuidance[target.FindingID] = target.AnchorText
	}
	reviewTrigger := options.Trigger
	for index, batch := range batches {
		progressAI(ctx, index+1, len(batches), r.Config.ProviderTimeoutSeconds(), reviewTrigger)
		response, err := r.dispatch(ctx, DispatchRequest{ProtocolVersion: DispatchProtocolVersion, Operation: "review", Snapshot: &batch})
		if err != nil {
			return ProviderMetadata{}, nil, err
		}
		if len(response.OllamaMetrics) != 0 {
			r.metricsMu.Lock()
			r.ollamaMetrics = append(r.ollamaMetrics, response.OllamaMetrics...)
			r.metricsMu.Unlock()
		}
		if metadata.Provider == "" {
			metadata = response.Metadata
		} else if metadata != response.Metadata {
			return ProviderMetadata{}, nil, errors.New("provider metadata changed between review batches")
		}
		allowed := map[string]bool{"<none>": true}
		for _, file := range inventory.Files {
			allowed[file.Path] = true
		}
		for _, finding := range response.Verdict.Findings {
			if !allowed[finding.File] {
				return ProviderMetadata{}, nil, fmt.Errorf("review verdict references unknown file %q", finding.File)
			}
		}
		batchGuidance := map[string]bool{}
		for _, guidance := range response.Verdict.Guidance {
			if _, ok := expectedGuidance[guidance.FindingID]; !ok {
				return ProviderMetadata{}, nil, errors.New("review guidance references an unknown deterministic finding")
			}
			batchGuidance[guidance.FindingID] = true
		}
		for findingID := range expectedGuidance {
			if !batchGuidance[findingID] {
				return ProviderMetadata{}, nil, errors.New("provider omitted guidance for a decision-requiring deterministic finding")
			}
		}
		// IDs and completeness are checked first. A provider that commented on the
		// wrong occurrence cannot attach that statement to the finding, but one bad
		// quote must not erase independent AI findings or correctly bound guidance.
		filtered := response.Verdict.Guidance[:0]
		for _, guidance := range response.Verdict.Guidance {
			if guidance.AnchorQuote == expectedGuidance[guidance.FindingID] {
				filtered = append(filtered, guidance)
			}
		}
		response.Verdict.Guidance = filtered
		verdicts = append(verdicts, *response.Verdict)
	}
	return metadata, verdicts, nil
}

func (r *Reviewer) dispatch(parent context.Context, request DispatchRequest) (DispatchResponse, error) {
	if err := request.Validate(); err != nil {
		return DispatchResponse{}, err
	}
	raw, err := CanonicalJSON(request)
	if err != nil {
		return DispatchResponse{}, err
	}
	if int64(len(raw)) > r.Config.Limits.MaxDispatchBytes {
		return DispatchResponse{}, errors.New("dispatcher payload exceeds hard input limit")
	}
	timeout := time.Duration(r.Config.ProviderTimeoutSeconds()+r.Config.Review.KillGraceSeconds) * time.Second
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	var response DispatchResponse
	if len(r.Command) != 0 {
		command := exec.CommandContext(ctx, r.Command[0], r.Command[1:]...)
		command.Stdin = bytes.NewReader(raw)
		stdout := newLimitedBuffer(r.Config.Limits.MaxDispatchBytes)
		stderr := newLimitedBuffer(1024 * 1024)
		command.Stdout = stdout
		command.Stderr = stderr
		err = command.Run()
		if ctx.Err() == context.DeadlineExceeded {
			return DispatchResponse{}, ErrProviderTimeout
		}
		if err != nil {
			return DispatchResponse{}, fmt.Errorf("provider worker failed: %w: %s", err, truncateTail(stderr.String(), 8*1024))
		}
		if err := DecodeStrict(stdout.Bytes(), &response); err != nil {
			return DispatchResponse{}, fmt.Errorf("provider worker returned invalid JSON: %w", err)
		}
	} else {
		// The provider worker runs in this process rather than behind a socket
		// service because the invoking administrator also owns its credentials;
		// a service account would not add a privilege boundary. The provider CLI
		// keeps its own Bubblewrap isolation and dedicated credential directory.
		var stdout, stderr bytes.Buffer
		if code := runProviderWorker(ctx, bytes.NewReader(raw), &stdout, &stderr); code != 0 {
			if ctx.Err() == context.DeadlineExceeded {
				return DispatchResponse{}, ErrProviderTimeout
			}
			return DispatchResponse{}, fmt.Errorf("provider worker failed (%d): %s", code, truncateTail(stderr.String(), 8*1024))
		}
		if err := DecodeStrict(stdout.Bytes(), &response); err != nil {
			return DispatchResponse{}, fmt.Errorf("provider worker returned invalid JSON: %w", err)
		}
	}
	if err := response.Validate(request.Operation); err != nil {
		return DispatchResponse{}, err
	}
	if response.Metadata.Provider != r.Config.Provider {
		return DispatchResponse{}, errors.New("dispatcher returned the wrong active provider")
	}
	configured := r.Config.ActiveProvider()
	if response.Metadata.Model != configured.Model {
		return DispatchResponse{}, errors.New("dispatcher returned unexpected model or effort metadata")
	}
	if r.Config.Provider == "ollama" {
		expected, err := ollamaReasoningLevel(configured.Effort, response.Metadata.Thinking)
		if err != nil || response.Metadata.Effort != expected {
			return DispatchResponse{}, errors.New("dispatcher returned unexpected Ollama reasoning metadata")
		}
	} else if response.Metadata.Effort != configured.Effort {
		return DispatchResponse{}, errors.New("dispatcher returned unexpected model or effort metadata")
	}
	return response, nil
}

func (r *Reviewer) batches(packageBase, phase string, inventory *brief.Inventory) ([]ReviewSnapshot, error) {
	return r.batchesWithOptions(packageBase, phase, inventory, ReviewOptions{})
}

func (r *Reviewer) batchesWithOptions(packageBase, phase string, inventory *brief.Inventory, options ReviewOptions) ([]ReviewSnapshot, error) {
	reasoning := "off"
	if r.Config.Provider == "ollama" {
		reasoning, _ = ollamaReasoningLevel(r.Config.Providers.Ollama.Reasoning, true)
	}
	return r.batchesWithProviderOptions(packageBase, phase, inventory, options, reasoning)
}

func (r *Reviewer) batchesWithProviderOptions(packageBase, phase string, inventory *brief.Inventory, options ReviewOptions, ollamaReasoning string) ([]ReviewSnapshot, error) {
	if err := brief.ValidatePackageBase(packageBase); err != nil {
		return nil, err
	}
	manifest := make([]map[string]any, 0, len(inventory.Files))
	omittedVendorTree := false
	for _, item := range inventory.Files {
		if r.reviewSnapshotIncludesPath(phase, item.Path) {
			manifest = append(manifest, item.ManifestValue())
		} else {
			omittedVendorTree = true
		}
	}
	manifestDiff := make([]brief.ManifestChange, 0, len(inventory.ManifestDiff))
	for _, change := range inventory.ManifestDiff {
		if r.reviewSnapshotIncludesPath(phase, change.Path) {
			manifestDiff = append(manifestDiff, change)
		} else {
			omittedVendorTree = true
		}
	}
	manifestRaw, err := CanonicalJSON(manifest)
	if err != nil {
		return nil, err
	}
	omissions := []string{}
	if omittedVendorTree {
		omissions = append(omissions, "src/")
	}
	guidanceTargets, err := reviewGuidanceTargets(inventory.Findings, inventory.Files, r.Config.Review.ManualReviewMinimumSeverity, options.SkipGuidanceFindingIDs)
	if err != nil {
		return nil, err
	}
	base := ReviewSnapshot{SnapshotSchemaVersion: ReviewSnapshotVersion, PackageBase: packageBase, Phase: phase, ManifestHash: inventory.ManifestHash, ManifestViewHash: safe.SHA256Bytes(manifestRaw), ManifestOmissions: omissions, Coverage: inventory.Coverage, DeterministicFindings: inventory.Findings, GuidanceMinimumSeverity: r.Config.Review.ManualReviewMinimumSeverity, GuidanceTargets: guidanceTargets, Manifest: manifest, YayContext: inventory.YayContext, ManifestDiff: manifestDiff, Sources: inventory.Sources, SourceVerification: inventory.Verification}
	var pieces []SelectedFile
	var total int64
	// Cap each content piece at half a batch to leave deterministic room for JSON
	// escaping and snapshot metadata. Ollama may reduce this further to fit the
	// configured context without truncation.
	chunkSize := max(1024, r.Config.Review.BatchBytes/2)
	ollamaCeiling := 0
	if r.Config.Provider == "ollama" {
		ollamaCeiling = ollamaInputByteCeiling(r.Config.Providers.Ollama.ContextTokens, ollamaReasoning)
		fixed := base
		fixed.BatchIndex, fixed.BatchCount = 999_999, 999_999
		fixed.Files = []SelectedFile{{File: "<none>", LineStart: 1, LineEnd: 1, Content: "No text selected."}}
		_, fixedRaw, _, err := buildOllamaChatRequest(r.Config, fixed, ollamaReasoning)
		if err != nil {
			return nil, err
		}
		if ollamaCeiling <= 0 || len(fixedRaw) > ollamaCeiling {
			return nil, fmt.Errorf("fixed Ollama review context is %d bytes, above the context-derived input ceiling of %d", len(fixedRaw), ollamaCeiling)
		}
		// JSON can expand one source byte to a six-byte escape. Keep additional
		// room for the selected-file path and object framing, then verify each
		// assembled request exactly below.
		available := ollamaCeiling - len(fixedRaw) - 4096
		if available <= 0 {
			return nil, errors.New("fixed Ollama review context leaves no selected-text budget")
		}
		chunkSize = min(chunkSize, max(1, available/6))
	}
	changed := map[string]bool{}
	for _, item := range inventory.ManifestDiff {
		changed[item.Path] = true
	}
	selected := append([]brief.FileRecord(nil), inventory.Files...)
	// Changed files are reviewed first so a later provider/budget failure cannot
	// leave the most decision-relevant delta until the final batch.
	sort.SliceStable(selected, func(i, j int) bool {
		if changed[selected[i].Path] != changed[selected[j].Path] {
			return changed[selected[i].Path]
		}
		return selected[i].PathB64 < selected[j].PathB64
	})
	for _, record := range selected {
		if record.SelectedText == "" {
			continue
		}
		encoded := []byte(record.SelectedText)
		total += int64(len(encoded))
		if total > r.Config.Limits.MaxSelectedTextBytes {
			return nil, errors.New("selected review text exceeds aggregate limit")
		}
		for offset := 0; offset < len(encoded); offset += chunkSize {
			end := min(len(encoded), offset+chunkSize)
			pieces = append(pieces, selectedFilePiece(record.Path, encoded, offset, end))
		}
	}
	if len(pieces) == 0 {
		pieces = []SelectedFile{{File: "<none>", LineStart: 1, LineEnd: 1, Content: "No text selected."}}
	}
	var batches []ReviewSnapshot
	var current []SelectedFile
	currentSize := 0
	ollamaFits := func(files []SelectedFile) (bool, error) {
		if r.Config.Provider != "ollama" {
			return true, nil
		}
		candidate := base
		candidate.BatchIndex, candidate.BatchCount = 999_999, 999_999
		candidate.Files = files
		_, raw, _, err := buildOllamaChatRequest(r.Config, candidate, ollamaReasoning)
		return err == nil && len(raw) <= ollamaCeiling, err
	}
	flush := func() {
		if len(current) == 0 {
			return
		}
		batch := base
		batch.BatchIndex = len(batches)
		batch.Files = append([]SelectedFile(nil), current...)
		batches = append(batches, batch)
		current = nil
		currentSize = 0
	}
	for _, piece := range pieces {
		raw, _ := json.Marshal(piece)
		fits, err := ollamaFits(append(append([]SelectedFile(nil), current...), piece))
		if err != nil {
			return nil, err
		}
		if len(current) > 0 && (currentSize+len(raw) > r.Config.Review.BatchBytes || !fits) {
			flush()
			fits, err = ollamaFits([]SelectedFile{piece})
			if err != nil {
				return nil, err
			}
		}
		if !fits {
			return nil, fmt.Errorf("selected file chunk %q cannot fit the context-derived Ollama input ceiling", piece.File)
		}
		current = append(current, piece)
		currentSize += len(raw)
	}
	flush()
	for index := range batches {
		batches[index].BatchCount = len(batches)
		if fits, err := ollamaFits(batches[index].Files); err != nil || !fits {
			if err != nil {
				return nil, err
			}
			return nil, errors.New("final Ollama batch exceeds context-derived input ceiling")
		}
	}
	return batches, nil
}

func selectedFilePiece(path string, content []byte, offset, end int) SelectedFile {
	lineStart := 1 + bytes.Count(content[:offset], []byte{'\n'})
	lineEnd := lineStart
	if end > offset {
		lineEnd += bytes.Count(content[offset:end-1], []byte{'\n'})
	}
	return SelectedFile{
		File: path, ByteOffset: offset, LineStart: lineStart, LineEnd: lineEnd,
		Content: safe.ValidUTF8OrReplacement(content[offset:end]),
	}
}

func reviewGuidanceTargets(findings []brief.Finding, files []brief.FileRecord, minimumSeverity string, excluded map[string]bool) ([]GuidanceTarget, error) {
	targets := make([]GuidanceTarget, 0, min(len(findings), findingGuidanceLimit))
	selected := make(map[string]string, len(files))
	for _, file := range files {
		if file.SelectedText != "" {
			selected[file.Path] = file.SelectedText
		}
	}
	sorted := append([]brief.Finding(nil), findings...)
	brief.SortFindings(sorted)
	for _, finding := range sorted {
		if !severityAtLeast(finding.Severity, minimumSeverity) || excluded[findingGuidanceID(finding)] {
			continue
		}
		target := GuidanceTarget{FindingID: findingGuidanceID(finding), Finding: finding, Context: []GuidanceContextLine{}}
		if finding.Line != nil {
			if raw, ok := selected[finding.File]; ok {
				context, contextErr := findingContextLines([]byte(raw), *finding.Line, findingPreviewRadius)
				if contextErr == nil {
					for _, current := range context {
						if current.Line == *finding.Line && current.Text != "" {
							target.AnchorKind, target.AnchorText, target.Context = "line", current.Text, context
							break
						}
					}
				}
			}
		}
		if target.AnchorKind == "" {
			target.AnchorKind = "evidence"
			target.AnchorText = terminalInline(finding.Evidence, 320)
		}
		if err := target.validateAnchor(); err != nil {
			return nil, fmt.Errorf("bind guidance target %s: %w", target.FindingID, err)
		}
		targets = append(targets, target)
		if len(targets) == findingGuidanceLimit {
			break
		}
	}
	return targets, nil
}

func (r *Reviewer) reviewSnapshotIncludesPath(phase, file string) bool {
	// The complete manifest hash still binds every vendor and Cargo-cache byte in
	// the report. At depth zero the AI is intentionally not reviewing vendor
	// content, so enumerating an arbitrarily large srcdir in every batch adds no
	// evidence and can exceed the provider dispatch boundary.
	return phase != "post" || r.Config.Vendor.ScanDepth > 0 || (file != "src" && !strings.HasPrefix(file, "src/"))
}
