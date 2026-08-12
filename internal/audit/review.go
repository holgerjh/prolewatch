package audit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

const DispatchProtocolVersion = 1

var ErrProviderTimeout = errors.New("provider request timed out")

type SelectedFile struct {
	File       string `json:"file"`
	ByteOffset int    `json:"byte_offset"`
	Content    string `json:"content"`
}

type ReviewSnapshot struct {
	SnapshotSchemaVersion int                `json:"snapshot_schema_version"`
	PackageBase           string             `json:"package_base"`
	Phase                 string             `json:"phase"`
	ManifestHash          string             `json:"manifest_hash"`
	ManifestViewHash      string             `json:"manifest_view_hash,omitempty"`
	ManifestOmissions     []string           `json:"manifest_omissions,omitempty"`
	Coverage              Coverage           `json:"coverage"`
	DeterministicFindings []Finding          `json:"deterministic_findings"`
	Manifest              []map[string]any   `json:"manifest"`
	BatchIndex            int                `json:"batch_index"`
	BatchCount            int                `json:"batch_count"`
	Files                 []SelectedFile     `json:"files"`
	YayContext            YayContext         `json:"yay_context"`
	ManifestDiff          []ManifestChange   `json:"manifest_diff"`
	Sources               []SourceProvenance `json:"sources"`
	SourceVerification    SourceVerification `json:"source_verification"`
}

var manifestKeys = map[string]bool{
	"path": true, "path_b64": true, "kind": true, "mode": true, "size": true,
	"sha256": true, "executable": true, "text": true, "link_target": true,
	"archive_entries": true, "archive_format": true, "extractable": true,
	"selected_reason": true, "binary_metadata": true,
}

func validHexDigest(value string) bool {
	return len(value) == 64 && strings.Trim(value, "0123456789abcdef") == ""
}

func validateCoverage(coverage Coverage) error {
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

func validateManifestRecord(record map[string]any) (FileRecord, error) {
	if len(record) != len(manifestKeys) {
		return FileRecord{}, errors.New("manifest record has missing or extra fields")
	}
	for key := range record {
		if !manifestKeys[key] {
			return FileRecord{}, fmt.Errorf("manifest record contains unknown field %q", key)
		}
	}
	raw, err := CanonicalJSON(record)
	if err != nil {
		return FileRecord{}, err
	}
	var decoded FileRecord
	if err := DecodeStrict(raw, &decoded); err != nil {
		return FileRecord{}, fmt.Errorf("invalid manifest record: %w", err)
	}
	validKinds := map[string]bool{"file": true, "archive-member": true, "symlink": true, "fifo": true, "char-device": true, "block-device": true, "socket": true, "special": true}
	validReasons := map[string]bool{"": true, "mandatory": true, "archive-member": true, "binary-metadata": true, "executable": true}
	if decoded.Path == "" || len(decoded.Path) > 4096 || len(decoded.PathB64) > 8192 || !validKinds[decoded.Kind] || decoded.Mode > 0o7777 || decoded.Size < 0 || decoded.ArchiveEntries < 0 || len(decoded.LinkTarget) > 4096 || !validReasons[decoded.SelectedReason] || decoded.BinaryMetadata == nil {
		return FileRecord{}, errors.New("manifest record violates value limits")
	}
	if _, err := base64.URLEncoding.DecodeString(decoded.PathB64); err != nil {
		return FileRecord{}, errors.New("manifest path_b64 is invalid")
	}
	if decoded.Kind == "file" || decoded.Kind == "archive-member" {
		if !validHexDigest(decoded.SHA256) {
			return FileRecord{}, errors.New("manifest file digest is invalid")
		}
	} else if decoded.SHA256 != "" {
		return FileRecord{}, errors.New("non-file manifest record has a digest")
	}
	return decoded, nil
}

func (s ReviewSnapshot) Validate() error {
	if s.SnapshotSchemaVersion != ReviewSnapshotVersion {
		return errors.New("unsupported review snapshot schema")
	}
	if err := ValidatePackageBase(s.PackageBase); err != nil {
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
	if s.BatchCount < 1 || s.BatchIndex < 0 || s.BatchIndex >= s.BatchCount {
		return errors.New("invalid batch numbering")
	}
	if len(s.Manifest) > 200000 || len(s.ManifestOmissions) > 1 || len(s.DeterministicFindings) > 100000 || len(s.Files) == 0 {
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
		decoded, err := validateManifestRecord(record)
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
	viewHash := SHA256Bytes(manifestRaw)
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
	for _, file := range s.Files {
		if !paths[file.File] || file.ByteOffset < 0 {
			return errors.New("invalid selected file")
		}
		if len(file.Content) > 20*1024*1024 {
			return errors.New("selected content exceeds hard limit")
		}
	}
	return nil
}

type DispatchRequest struct {
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
	case "review":
		if r.Snapshot == nil {
			return errors.New("review requires a snapshot")
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
	Effort         string `json:"effort"`
	AdapterPolicy  string `json:"adapter_policy"`
}

type DispatchResponse struct {
	ProtocolVersion int              `json:"protocol_version"`
	Metadata        ProviderMetadata `json:"metadata"`
	Verdict         *Verdict         `json:"verdict"`
}

func (r DispatchResponse) Validate(operation string) error {
	if r.ProtocolVersion != DispatchProtocolVersion {
		return errors.New("unsupported dispatcher response protocol")
	}
	if r.Metadata.Transport != "cli" || (r.Metadata.Provider != "codex" && r.Metadata.Provider != "anthropic") || r.Metadata.RuntimeVersion == "" || r.Metadata.Model == "" || r.Metadata.AdapterPolicy == "" {
		return errors.New("invalid provider metadata")
	}
	if operation == "review" {
		if r.Verdict == nil {
			return errors.New("dispatcher omitted verdict")
		}
		return r.Verdict.Validate()
	}
	if r.Verdict != nil {
		return errors.New("probe unexpectedly returned a verdict")
	}
	return nil
}

type Reviewer struct {
	Config  Config
	Command []string
}

func NewReviewer(cfg Config) *Reviewer {
	return &Reviewer{Config: cfg, Command: []string{"/usr/bin/sudo", "-n", "-u", "prolewatch", "/usr/libexec/prolewatch/provider-dispatch"}}
}

func (r *Reviewer) Probe(ctx context.Context) (ProviderMetadata, error) {
	response, err := r.dispatch(ctx, DispatchRequest{ProtocolVersion: DispatchProtocolVersion, Operation: "probe"})
	if err != nil {
		return ProviderMetadata{}, err
	}
	return response.Metadata, nil
}

// Canary asks the locked provider dispatcher to validate its real Bubblewrap
// boundary. The calling yay user intentionally cannot traverse the provider's
// private credential directory, so this check must execute as prolewatch.
func (r *Reviewer) Canary(ctx context.Context) (ProviderMetadata, error) {
	response, err := r.dispatch(ctx, DispatchRequest{ProtocolVersion: DispatchProtocolVersion, Operation: "canary"})
	if err != nil {
		return ProviderMetadata{}, err
	}
	return response.Metadata, nil
}

func (r *Reviewer) Review(ctx context.Context, packageBase, phase string, inventory *Inventory) (ProviderMetadata, []Verdict, error) {
	batches, err := r.batches(packageBase, phase, inventory)
	if err != nil {
		return ProviderMetadata{}, nil, err
	}
	var metadata ProviderMetadata
	var verdicts []Verdict
	for index, batch := range batches {
		activityAI(ctx, index+1, len(batches), r.Config.Review.TimeoutSeconds)
		response, err := r.dispatch(ctx, DispatchRequest{ProtocolVersion: DispatchProtocolVersion, Operation: "review", Snapshot: &batch})
		if err != nil {
			return ProviderMetadata{}, nil, err
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
	timeout := time.Duration(r.Config.Review.TimeoutSeconds+r.Config.Review.KillGraceSeconds) * time.Second
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
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
		return DispatchResponse{}, fmt.Errorf("provider dispatcher failed: %w: %s", err, truncateTail(stderr.String(), 8*1024))
	}
	var response DispatchResponse
	if err := DecodeStrict(stdout.Bytes(), &response); err != nil {
		return DispatchResponse{}, fmt.Errorf("provider dispatcher returned invalid JSON: %w", err)
	}
	if err := response.Validate(request.Operation); err != nil {
		return DispatchResponse{}, err
	}
	if response.Metadata.Provider != r.Config.Provider {
		return DispatchResponse{}, errors.New("dispatcher returned the wrong active provider")
	}
	configured := r.Config.ActiveProvider()
	if response.Metadata.Model != configured.Model || response.Metadata.Effort != configured.Effort {
		return DispatchResponse{}, errors.New("dispatcher returned unexpected model or effort metadata")
	}
	return response, nil
}

func (r *Reviewer) batches(packageBase, phase string, inventory *Inventory) ([]ReviewSnapshot, error) {
	if err := ValidatePackageBase(packageBase); err != nil {
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
	manifestDiff := make([]ManifestChange, 0, len(inventory.ManifestDiff))
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
	base := ReviewSnapshot{SnapshotSchemaVersion: ReviewSnapshotVersion, PackageBase: packageBase, Phase: phase, ManifestHash: inventory.ManifestHash, ManifestViewHash: SHA256Bytes(manifestRaw), ManifestOmissions: omissions, Coverage: inventory.Coverage, DeterministicFindings: inventory.Findings, Manifest: manifest, YayContext: inventory.YayContext, ManifestDiff: manifestDiff, Sources: inventory.Sources, SourceVerification: inventory.Verification}
	var pieces []SelectedFile
	var total int64
	chunkSize := max(1024, r.Config.Review.BatchBytes/2)
	changed := map[string]bool{}
	for _, item := range inventory.ManifestDiff {
		changed[item.Path] = true
	}
	selected := append([]FileRecord(nil), inventory.Files...)
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
			pieces = append(pieces, SelectedFile{File: record.Path, ByteOffset: offset, Content: validUTF8OrReplacement(encoded[offset:end])})
		}
	}
	if len(pieces) == 0 {
		pieces = []SelectedFile{{File: "<none>", Content: "No text selected."}}
	}
	var batches []ReviewSnapshot
	var current []SelectedFile
	currentSize := 0
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
		if len(current) > 0 && currentSize+len(raw) > r.Config.Review.BatchBytes {
			flush()
		}
		current = append(current, piece)
		currentSize += len(raw)
	}
	flush()
	for index := range batches {
		batches[index].BatchCount = len(batches)
	}
	return batches, nil
}

func (r *Reviewer) reviewSnapshotIncludesPath(phase, file string) bool {
	// The complete manifest hash still binds every vendor and Cargo-cache byte in
	// the report. At depth zero the AI is intentionally not reviewing vendor
	// content, so enumerating an arbitrarily large srcdir in every batch adds no
	// evidence and can exceed the provider dispatch boundary.
	return phase != "post" || r.Config.Vendor.ScanDepth > 0 || (file != "src" && !strings.HasPrefix(file, "src/"))
}

func StableMetadata(metadata []ProviderMetadata) []ProviderMetadata {
	result := append([]ProviderMetadata(nil), metadata...)
	sort.Slice(result, func(i, j int) bool { return result[i].Provider < result[j].Provider })
	return result
}
