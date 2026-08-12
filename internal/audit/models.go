package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
)

var severities = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
var findingSources = map[string]bool{"deterministic": true, "ai": true}
var categories = map[string]bool{
	"archive_escape": true, "build_hook": true, "coverage": true, "credential_access": true,
	"decode_execute": true, "filesystem": true, "integrity": true, "network": true,
	"obfuscation": true, "package_metadata": true, "persistence": true, "process_injection": true,
	"prompt_injection": true, "privilege_escalation": true, "remote_execution": true, "other": true,
}

type Finding struct {
	Source    string `json:"source"`
	Severity  string `json:"severity"`
	Category  string `json:"category"`
	File      string `json:"file"`
	Line      *int   `json:"line"`
	Evidence  string `json:"evidence"`
	Rationale string `json:"rationale"`
	RuleID    string `json:"rule_id"`
	HardBlock bool   `json:"hard_block"`
}

func (f Finding) Validate() error {
	if !findingSources[f.Source] || !severities[f.Severity] || !categories[f.Category] {
		return fmt.Errorf("invalid finding enum: %s/%s", f.Severity, f.Category)
	}
	if f.Line != nil && *f.Line < 1 {
		return errors.New("finding line must be positive")
	}
	if f.Rationale == "" {
		return errors.New("finding rationale is empty")
	}
	return nil
}

func sortFindings(findings []Finding) {
	severityRank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sourceRank := map[string]int{"deterministic": 0, "ai": 1}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] < severityRank[b.Severity]
		}
		if sourceRank[a.Source] != sourceRank[b.Source] {
			return sourceRank[a.Source] < sourceRank[b.Source]
		}
		if a.File != b.File {
			return a.File < b.File
		}
		lineA, lineB := 0, 0
		if a.Line != nil {
			lineA = *a.Line
		}
		if b.Line != nil {
			lineB = *b.Line
		}
		if lineA != lineB {
			return lineA < lineB
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		return a.RuleID < b.RuleID
	})
}

type FileRecord struct {
	Path           string         `json:"path"`
	PathB64        string         `json:"path_b64"`
	Kind           string         `json:"kind"`
	Mode           uint32         `json:"mode"`
	Size           int64          `json:"size"`
	SHA256         string         `json:"sha256"`
	Executable     bool           `json:"executable"`
	Text           bool           `json:"text"`
	LinkTarget     string         `json:"link_target"`
	ArchiveEntries int            `json:"archive_entries"`
	ArchiveFormat  string         `json:"archive_format"`
	Extractable    bool           `json:"extractable"`
	SelectedReason string         `json:"selected_reason"`
	BinaryMetadata map[string]any `json:"binary_metadata"`
	SelectedText   string         `json:"-"`
}

func (f FileRecord) ManifestValue() map[string]any {
	return map[string]any{
		"path": f.Path, "path_b64": f.PathB64, "kind": f.Kind, "mode": f.Mode,
		"size": f.Size, "sha256": f.SHA256, "executable": f.Executable, "text": f.Text,
		"link_target": f.LinkTarget, "archive_entries": f.ArchiveEntries,
		"archive_format": f.ArchiveFormat, "extractable": f.Extractable,
		"selected_reason": f.SelectedReason, "binary_metadata": f.BinaryMetadata,
	}
}

type Coverage struct {
	FilesSeen            int      `json:"files_seen"`
	BytesSeen            int64    `json:"bytes_seen"`
	TextFiles            int      `json:"text_files"`
	TextBytes            int64    `json:"text_bytes"`
	SelectedFiles        int      `json:"selected_files"`
	SelectedBytes        int64    `json:"selected_bytes"`
	ReviewEligibleFiles  int      `json:"review_eligible_files"`
	ReviewEligibleBytes  int64    `json:"review_eligible_bytes"`
	OmittedReviewFiles   int      `json:"omitted_review_files"`
	OmittedReviewBytes   int64    `json:"omitted_review_bytes"`
	BinaryFiles          int      `json:"binary_files"`
	BinaryBytes          int64    `json:"binary_bytes"`
	ArchivesSeen         int      `json:"archives_seen"`
	ArchiveEntries       int      `json:"archive_entries"`
	ArchiveUnpackedBytes int64    `json:"archive_unpacked_bytes"`
	Complete             bool     `json:"complete"`
	Notes                []string `json:"notes"`
}

type Inventory struct {
	Root         string
	Phase        string
	Files        []FileRecord
	Findings     []Finding
	Exclusions   []string
	ManifestHash string
	Coverage     Coverage
	YayContext   YayContext
	ManifestDiff []ManifestChange
	Sources      []SourceProvenance
	Verification SourceVerification
	started      time.Time
	active       map[string]bool
	vendorPaths  map[string]bool
}

type ReviewFinding struct {
	Severity  string `json:"severity"`
	Category  string `json:"category"`
	File      string `json:"file"`
	Line      *int   `json:"line"`
	Evidence  string `json:"evidence"`
	Rationale string `json:"rationale"`
}

type Verdict struct {
	SchemaVersion           int             `json:"schema_version"`
	Verdict                 string          `json:"verdict"`
	Confidence              string          `json:"confidence"`
	Summary                 string          `json:"summary"`
	PromptInjectionDetected bool            `json:"prompt_injection_detected"`
	Findings                []ReviewFinding `json:"findings"`
	CoverageNotes           []string        `json:"coverage_notes"`
}

func (v Verdict) Validate() error {
	if v.SchemaVersion != 1 || (v.Verdict != "allow" && v.Verdict != "block") {
		return errors.New("invalid verdict schema version or decision")
	}
	if v.Confidence != "low" && v.Confidence != "medium" && v.Confidence != "high" {
		return errors.New("invalid verdict confidence")
	}
	if v.Summary == "" || len(v.Summary) > 2000 || v.Findings == nil || v.CoverageNotes == nil || len(v.Findings) > 200 || len(v.CoverageNotes) > 100 {
		return errors.New("verdict exceeds schema limits")
	}
	for _, f := range v.Findings {
		if !severities[f.Severity] || !categories[f.Category] || f.Rationale == "" || len(f.File) > 4096 || len(f.Evidence) > 1000 || len(f.Rationale) > 2000 {
			return errors.New("invalid review finding")
		}
		if f.Line != nil && *f.Line < 1 {
			return errors.New("invalid review finding line")
		}
	}
	for _, note := range v.CoverageNotes {
		if len(note) > 1000 {
			return errors.New("coverage note exceeds schema limit")
		}
	}
	return nil
}

func DecodeStrict(data []byte, value any) error {
	dec := json.NewDecoder(bytesReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return fmt.Errorf("invalid trailing JSON: %w", err)
	}
	return nil
}
