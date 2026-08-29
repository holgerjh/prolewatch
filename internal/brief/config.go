package brief

import "errors"

// Config is everything the inspection layer is allowed to see.
//
// It is deliberately not the umbrella configuration. The scanner parses hostile
// archives and attacker-authored text; there is no reason for that code to be
// able to reach provider credentials, review mode, build resource limits, or
// terminal styling, and the layering is what makes "it cannot" checkable rather
// than merely true today.
type Config struct {
	Limits LimitsConfig `json:"limits"`
	Vendor VendorConfig `json:"vendor"`

	// RetainTextForReview keeps selected file text in the inventory for an AI
	// reviewer to read. It is a boolean rather than a review mode because the
	// inspection layer has no business knowing that review modes exist - it
	// needs one bit: keep the text, or drop it.
	RetainTextForReview bool `json:"-"`
}

// LimitsConfig bounds every quantity an attacker-authored tree controls: file
// counts, archive nesting, decompressed sizes, captured text, and findings.
// These are the decompression-bomb and resource-exhaustion limits, so each one
// is a hard stop rather than a hint.
type LimitsConfig struct {
	MaxDispatchBytes        int64 `json:"max_dispatch_bytes"`
	MaxFiles                int   `json:"max_files"`
	MaxTotalInputBytes      int64 `json:"max_total_input_bytes"`
	MaxArchives             int   `json:"max_archives"`
	MaxArchiveEntries       int   `json:"max_archive_entries"`
	MaxArchiveUnpackedBytes int64 `json:"max_archive_unpacked_bytes"`
	MaxArchiveDepth         int   `json:"max_archive_depth"`
	MaxTextPerFile          int64 `json:"max_text_per_file"`
	MaxSelectedTextBytes    int64 `json:"max_selected_text_bytes"`
	BinaryStringsBytes      int64 `json:"binary_strings_bytes"`
	MaxFindings             int   `json:"max_findings"`
	ScanTimeoutSeconds      int   `json:"scan_timeout_seconds"`
}

// VendorConfig controls how deeply vendored dependency trees are inspected.
// Depth zero still binds every byte into the manifest hash; it only skips
// rule evaluation inside them.
type VendorConfig struct {
	ScanDepth int `json:"scan_depth"`
}

// ScanProgress is the running count the scanner reports to whatever is
// displaying progress. It travels upward as data; nothing here reaches for a
// terminal.
type ScanProgress struct {
	Operation            string `json:"operation,omitempty"`
	FilesSeen            int    `json:"files_seen,omitempty"`
	BytesSeen            int64  `json:"bytes_seen,omitempty"`
	ArchivesSeen         int    `json:"archives_seen,omitempty"`
	ArchiveEntries       int    `json:"archive_entries,omitempty"`
	ArchiveUnpackedBytes int64  `json:"archive_unpacked_bytes,omitempty"`
}

// These defaults are the hostile-input envelope. Naming them keeps the scanner
// and the shipped umbrella configuration from acquiring parallel numeric
// definitions of the same policy.
const (
	defaultMaxDispatchBytes        = 20 << 20
	defaultMaxFiles                = 200_000
	defaultMaxTotalInputBytes      = 16 << 30
	defaultMaxArchives             = 1_024
	defaultMaxArchiveEntries       = 100_000
	defaultMaxArchiveUnpackedBytes = 2 << 30
	defaultMaxArchiveDepth         = 4
	defaultMaxTextPerFile          = 4 << 20
	defaultMaxSelectedTextBytes    = 16 << 20
	defaultBinaryStringsBytes      = 128 << 10
	defaultMaxFindings             = 10_000
	defaultScanTimeoutSeconds      = 300
)

func (p ScanProgress) Validate() error {
	if !scanOperations[p.Operation] || p.FilesSeen < 0 || p.BytesSeen < 0 || p.ArchivesSeen < 0 || p.ArchiveEntries < 0 || p.ArchiveUnpackedBytes < 0 {
		return errors.New("invalid activity scan progress")
	}
	return nil
}

// DefaultConfig is the inspection layer's own defaults, used by tests and by
// any caller that has no umbrella configuration to narrow. The production path
// goes through audit.BriefConfig instead.
func DefaultConfig() Config {
	return Config{
		Limits: LimitsConfig{
			MaxDispatchBytes: defaultMaxDispatchBytes, MaxFiles: defaultMaxFiles,
			MaxTotalInputBytes: defaultMaxTotalInputBytes, MaxArchives: defaultMaxArchives,
			MaxArchiveEntries: defaultMaxArchiveEntries, MaxArchiveUnpackedBytes: defaultMaxArchiveUnpackedBytes,
			MaxArchiveDepth: defaultMaxArchiveDepth, MaxTextPerFile: defaultMaxTextPerFile,
			MaxSelectedTextBytes: defaultMaxSelectedTextBytes, BinaryStringsBytes: defaultBinaryStringsBytes,
			MaxFindings: defaultMaxFindings, ScanTimeoutSeconds: defaultScanTimeoutSeconds,
		},
		Vendor:              VendorConfig{ScanDepth: 0},
		RetainTextForReview: true,
	}
}
