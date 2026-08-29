package brief

import (
	"errors"
	"fmt"
	"github.com/holgerjh/prolewatch/internal/safe"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ValidSeverity and ValidCategory expose the finding vocabulary, so that
// anything validating a finding - including an AI verdict - checks against one
// list rather than a second copy that drifts.
func ValidSeverity(value string) bool { return severities[value] }
func ValidCategory(value string) bool { return categories[value] }

var severities = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
var findingSources = map[string]bool{"deterministic": true, "ai": true}
var categories = map[string]bool{
	"archive_escape": true, "build_hook": true, "coverage": true, "credential_access": true,
	"decode_execute": true, "filesystem": true, "integrity": true, "network": true,
	"obfuscation": true, "package_metadata": true, "persistence": true, "process_injection": true,
	"prompt_injection": true, "privilege_escalation": true, "remote_execution": true, "other": true,
}

type Finding struct {
	// HardBlock marks structural/trust failures that ordinary approval may not
	// overrule; severity alone controls ordering and policy thresholds.
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

// SortFindings orders findings deterministically. The order is part of the
// content-bound report, so it must not depend on filesystem iteration.
func SortFindings(findings []Finding) {
	// Deterministic findings win ties so fixed evidence is shown before heuristic
	// AI evidence at the same severity and source location.
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
	// SelectedText is the bounded review payload. It is intentionally excluded
	// from the manifest: the manifest binds full-file identity and metadata,
	// while provider batching carries only selected text.
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
	// Complete means all mandatory deterministic coverage succeeded. It does not
	// mean every byte was selected for AI or that the package is safe.
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
	// declared is the .SRCINFO text this scan treated as authoritative: the
	// contained freeze's output where one exists, the committed file otherwise.
	declared    []byte
	started     time.Time
	active      map[string]bool
	vendorPaths map[string]bool
}

type YayContext struct {
	// These fields explain yay's requested transaction to the briefing.
	Version      string              `json:"version"`
	LastModified int64               `json:"last_modified"`
	Installed    bool                `json:"installed"`
	Packages     []YayPackageContext `json:"packages"`
	Depends      []string            `json:"depends"`
	MakeDepends  []string            `json:"makedepends"`
	CheckDepends []string            `json:"checkdepends"`
}

type ManifestChange struct {
	Path           string `json:"path"`
	Status         string `json:"status"`
	PreviousSHA256 string `json:"previous_sha256,omitempty"`
	CurrentSHA256  string `json:"current_sha256,omitempty"`
}

type YayPackageContext struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	LocalVersion string `json:"local_version"`
	Reason       string `json:"reason"`
	Upgrade      bool   `json:"upgrade"`
	Devel        bool   `json:"devel"`
}

// Scan operations, reported upward as progress.
const (
	ScanOperationInventory          = "inventory"
	ScanOperationArchiveInspection  = "archive-inspection"
	ScanOperationSourceVerification = "source-verification"
	ScanOperationFinalizing         = "finalizing"
	ScanOperationComplete           = "complete"
)

var scanOperations = map[string]bool{
	"": true, ScanOperationInventory: true, ScanOperationArchiveInspection: true,
	ScanOperationSourceVerification: true, ScanOperationFinalizing: true, ScanOperationComplete: true,
}

func (c YayContext) Validate() error {
	if len(c.Version) > 256 || c.LastModified < 0 || len(c.Packages) > 128 ||
		len(c.Depends) > 4096 || len(c.MakeDepends) > 4096 || len(c.CheckDepends) > 4096 {
		return errors.New("yay context exceeds value limits")
	}
	reasons := map[string]bool{"explicit": true, "dependency": true, "make_dependency": true, "check_dependency": true, "unknown": true, "": true}
	seenPackages := map[string]bool{}
	for _, pkg := range c.Packages {
		if ValidatePackageBase(pkg.Name) != nil || seenPackages[pkg.Name] || len(pkg.Version) > 256 || len(pkg.LocalVersion) > 256 || !reasons[pkg.Reason] {
			return fmt.Errorf("invalid yay package context for %q", pkg.Name)
		}
		seenPackages[pkg.Name] = true
	}
	for _, values := range [][]string{c.Depends, c.MakeDepends, c.CheckDepends} {
		seen := map[string]bool{}
		for _, value := range values {
			if value == "" || len(value) > 512 || strings.ContainsAny(value, "\x00\r\n") || seen[value] {
				return errors.New("invalid or duplicate yay dependency context")
			}
			seen[value] = true
		}
	}
	return nil
}

// packageBaseRE bounds a package base name. The value comes from an AUR
// checkout and reaches paths and terminal output, so it is validated by shape
// rather than sanitised at each use.
var packageBaseRE = regexp.MustCompile(`^[A-Za-z0-9@._+][A-Za-z0-9@._+-]*$`)

// ValidatePackageBase rejects a package base that is not a plain package name.
func ValidatePackageBase(value string) error {
	if !packageBaseRE.MatchString(value) {
		return fmt.Errorf("invalid package base %q", value)
	}
	return nil
}

func (c ManifestChange) Validate() error {
	if c.Path == "" || len(c.Path) > 4096 || (c.Status != "added" && c.Status != "changed" && c.Status != "deleted") {
		return errors.New("invalid manifest change")
	}
	switch c.Status {
	case "added":
		if c.PreviousSHA256 != "" || !safe.ValidHexDigest(c.CurrentSHA256) {
			return errors.New("invalid added manifest change")
		}
	case "deleted":
		if !safe.ValidHexDigest(c.PreviousSHA256) || c.CurrentSHA256 != "" {
			return errors.New("invalid deleted manifest change")
		}
	case "changed":
		if !safe.ValidHexDigest(c.PreviousSHA256) || !safe.ValidHexDigest(c.CurrentSHA256) || c.PreviousSHA256 == c.CurrentSHA256 {
			return errors.New("invalid changed manifest change")
		}
	}
	return nil
}
