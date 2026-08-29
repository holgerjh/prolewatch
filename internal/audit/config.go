package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/egress"
	"github.com/holgerjh/prolewatch/internal/safe"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	// Schema/behavior versions participate in stored evidence and policy
	// identity. Increment the relevant value when its interpretation changes.
	ApplicationVersion    = "0.11.0"
	ReportSchemaVersion   = 14
	MarkerSchemaVersion   = 8
	ApprovalSchemaVersion = 7
	ScannerVersion        = 8
	RulesVersion          = 13
	ReviewSnapshotVersion = 8
	MinYayVersion         = "13.0.1"
	// MaxYayVersion is the first yay release the makepkg wrapper has not been
	// checked against. It is a warning boundary, not a refusal: interception is
	// two `yay.opt` assignments and a closed classification of the makepkg
	// command lines yay produces. Yay rejects unknown options during full config
	// validation, and doctor separately verifies the effective wrapper paths; the
	// upper bound therefore warns about untested invocation shapes.
	MaxYayVersion   = "14.0.0"
	MinCodexVersion = "0.146.1"
	// MaxCodexVersion is the first Codex release the adapter has not been
	// checked against. Like MaxYayVersion it warns rather than refuses: the CLI
	// ships far faster than this adapter is re-verified, and every way a newer
	// Codex could actually break the adapter already fails closed. `codex
	// features list` must still parse, `--strict-config` rejects an option the
	// CLI no longer knows, the answer must satisfy the verdict schema, and
	// containment is Prolewatch's own bubblewrap sandbox rather than Codex's
	// `--sandbox` flag. Refusing to run the day Arch ships a new Codex would
	// cost more than the refusal buys.
	MaxCodexVersion  = "0.150.0"
	MinClaudeVersion = "2.1.205"
	MaxClaudeVersion = "3.0.0"
)

const (
	ReviewModeAI                = "ai"
	ReviewModeDeterministicOnly = "deterministic-only"
	TerminalStyleBrand          = "brand"
	TerminalStylePlain          = "plain"
)

const (
	systemConfigDefaultPath       = "/etc/prolewatch/config.json"
	maxConfigDocumentBytes        = 1 << 20
	maxProviderModelBytes         = 256
	maxNetworkDestinations        = 64
	maxNetworkConnections         = 256
	maxPromptTimeoutSeconds       = 3_600
	maxNetworkConnectSeconds      = 300
	maxNetworkIdleSeconds         = 3_600
	defaultReviewTimeoutSeconds   = 180
	defaultReviewKillGraceSeconds = 5
	defaultReviewBatchBytes       = 768_000
	defaultBuildMemoryBytes       = 8 << 30
	defaultBuildCPUCount          = 4
	defaultBuildTasks             = 512
	defaultBuildTimeoutSeconds    = 2 * 60 * 60
	defaultWorkspaceBytes         = 16 << 30
	defaultWorkspaceFiles         = 500_000
	defaultBuildOutputBytes       = 32 << 20
	defaultBuildDiskReserveBytes  = 2 << 30
)

var SystemConfigPath = systemConfigDefaultPath

type ProviderConfig struct {
	Model  string `json:"model"`
	Effort string `json:"effort"`
}

type ProvidersConfig struct {
	Codex     ProviderConfig `json:"codex"`
	Anthropic ProviderConfig `json:"anthropic"`
}

type ReviewConfig struct {
	Mode                        string `json:"mode"`
	MinimumConfidence           string `json:"minimum_confidence"`
	ManualReviewMinimumSeverity string `json:"manual_review_minimum_severity"`
	TimeoutSeconds              int    `json:"timeout_seconds"`
	KillGraceSeconds            int    `json:"kill_grace_seconds"`
	BatchBytes                  int    `json:"batch_bytes"`
	// IncludeRecipePhase adds the recipe phase to AI review. Off by default:
	// the recipe is two small, highly structured files, which is where the
	// deterministic rules are strongest and where the model has least to add,
	// while every phase costs a provider round trip per package. A ten-package
	// upgrade pays that three times over instead of twice.
	//
	// Deliberately a boolean that only ever adds a phase, rather than a list of
	// phases to run. A list would be more general and would also mean a typo
	// silently disables a gate while looking like it worked; this cannot be
	// misconfigured into weakening anything.
	IncludeRecipePhase bool `json:"include_recipe_phase"`
	// GuideDecisionFindings spends a recipe-phase provider call only when the
	// deterministic pass found evidence at the configured manual-review
	// threshold. It is guidance, not an AI override: the deterministic decision
	// and every finding remain intact.
	GuideDecisionFindings bool `json:"guide_decision_findings"`
}

type BuildConfig struct {
	MemoryBytes      int64 `json:"memory_bytes"`
	CPUCount         int   `json:"cpu_count"`
	TasksMax         int   `json:"tasks_max"`
	TimeoutSeconds   int   `json:"timeout_seconds"`
	WorkspaceBytes   int64 `json:"workspace_bytes"`
	WorkspaceFiles   int   `json:"workspace_files"`
	OutputBytes      int64 `json:"output_bytes"`
	DiskReserveBytes int64 `json:"disk_reserve_bytes"`
}

// TerminalConfig affects presentation only. It is deliberately excluded from
// the policy fingerprint so changing terminal decoration cannot invalidate a
// reviewed package snapshot.
type TerminalConfig struct {
	Style string `json:"style"`
}

type Config struct {
	Provider  string             `json:"provider"`
	Providers ProvidersConfig    `json:"providers"`
	Review    ReviewConfig       `json:"review"`
	Limits    brief.LimitsConfig `json:"limits"`
	Build     BuildConfig        `json:"build"`
	Network   egress.Config      `json:"network"`
	Vendor    brief.VendorConfig `json:"vendor"`
	Terminal  TerminalConfig     `json:"terminal"`
}

func DefaultConfig() Config {
	// Defaults balance an ordinary source build against bounded hostile input:
	// scan/archive ceilings constrain parsing, build ceilings constrain the
	// sandbox, and network ceilings apply independently to the prompt broker.
	briefDefaults := brief.DefaultConfig()
	return Config{
		Provider: "codex",
		Providers: ProvidersConfig{
			Codex:     ProviderConfig{Model: "gpt-5.6-sol", Effort: "high"},
			Anthropic: ProviderConfig{Model: "sonnet", Effort: "high"},
		},
		Review: ReviewConfig{Mode: ReviewModeDeterministicOnly, MinimumConfidence: "high", ManualReviewMinimumSeverity: "high", TimeoutSeconds: defaultReviewTimeoutSeconds, KillGraceSeconds: defaultReviewKillGraceSeconds, BatchBytes: defaultReviewBatchBytes, GuideDecisionFindings: true},
		Limits: briefDefaults.Limits,
		Build: BuildConfig{MemoryBytes: defaultBuildMemoryBytes, CPUCount: defaultBuildCPUCount, TasksMax: defaultBuildTasks,
			TimeoutSeconds: defaultBuildTimeoutSeconds, WorkspaceBytes: defaultWorkspaceBytes,
			WorkspaceFiles: defaultWorkspaceFiles, OutputBytes: defaultBuildOutputBytes, DiskReserveBytes: defaultBuildDiskReserveBytes},
		Network:  egress.DefaultConfig(),
		Vendor:   briefDefaults.Vendor,
		Terminal: TerminalConfig{Style: TerminalStyleBrand},
	}
}

func LoadConfig(path string) (Config, error) {
	if path == "" {
		path = SystemConfigPath
	}
	raw, err := readConfig(path)
	if err != nil {
		return Config{}, fmt.Errorf("read configuration %s: %w%s", path, err, missingConfigAdvice(path, err))
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse configuration %s: %w", path, err)
	}
	cfg.Network = normalizeNetworkConfig(cfg.Network)
	// A missing presentation-only style uses the safe default without requiring
	// a schema migration.
	if cfg.Terminal.Style == "" {
		cfg.Terminal.Style = TerminalStyleBrand
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, errors.New("configuration contains trailing JSON")
		}
		return Config{}, fmt.Errorf("parse trailing configuration data: %w", err)
	}
	return cfg, cfg.Validate()
}

// missingConfigAdvice gives protected commands a concrete repair for an absent
// system policy file.
func missingConfigAdvice(path string, cause error) string {
	if !errors.Is(cause, fs.ErrNotExist) || filepath.Clean(path) != systemConfigDefaultPath {
		return ""
	}
	shipped := filepath.Join(ShareRoot(), "default-config.json")
	if info, err := os.Stat(shipped); err != nil || !info.Mode().IsRegular() {
		return ""
	}
	return fmt.Sprintf("\n\nInstall the shipped default:\n    sudo install -Dm0644 %s %s", shipped, systemConfigDefaultPath)
}

func normalizeNetworkConfig(network egress.Config) egress.Config {
	defaults := DefaultConfig().Network
	if network.Mode == "" {
		network.Mode = defaults.Mode
	}
	if network.PromptTimeoutSeconds == 0 {
		network.PromptTimeoutSeconds = defaults.PromptTimeoutSeconds
	}
	if network.GrantScope == "" {
		network.GrantScope = defaults.GrantScope
	}
	if network.MaxDestinations == 0 {
		network.MaxDestinations = defaults.MaxDestinations
	}
	if network.MaxRequests == 0 {
		network.MaxRequests = defaults.MaxRequests
	}
	// These values bound trusted-side acquisition rather than the prompt. Missing
	// values receive finite defaults so every call site enforces aggregate limits.
	if network.MaxConnections == 0 {
		network.MaxConnections = defaults.MaxConnections
	}
	if network.ConnectTimeoutSeconds == 0 {
		network.ConnectTimeoutSeconds = defaults.ConnectTimeoutSeconds
	}
	if network.IdleTimeoutSeconds == 0 {
		network.IdleTimeoutSeconds = defaults.IdleTimeoutSeconds
	}
	if network.MaxTransferBytes == 0 {
		network.MaxTransferBytes = defaults.MaxTransferBytes
	}
	if network.DiskReserveBytes == 0 {
		network.DiskReserveBytes = defaults.DiskReserveBytes
	}
	return network
}

func readConfig(path string) ([]byte, error) {
	// One MiB is a hard document budget, not a configurable policy. Open with
	// O_NOFOLLOW and compare metadata before/after reading to reject symlink and
	// replacement races at the policy boundary.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var before, after unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return nil, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size < 0 || before.Size > maxConfigDocumentBytes || before.Mode&0o022 != 0 {
		return nil, errors.New("configuration is not a safe regular file")
	}
	if filepath.Clean(path) == systemConfigDefaultPath && before.Uid != 0 {
		return nil, errors.New("system configuration is not root-owned")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxConfigDocumentBytes+1))
	if err != nil || len(raw) > maxConfigDocumentBytes {
		return nil, errors.New("configuration exceeds its read limit")
	}
	if err := unix.Fstat(fd, &after); err != nil {
		return nil, err
	}
	if !safe.SameStat(before, after) || int64(len(raw)) != after.Size {
		return nil, errors.New("configuration changed while reading")
	}
	return raw, nil
}

func (c Config) ActiveProvider() ProviderConfig {
	if c.Provider == "anthropic" {
		return c.Providers.Anthropic
	}
	return c.Providers.Codex
}

func (c Config) Validate() error {
	// Validate relationships as well as positivity: inner operations must fit
	// inside aggregate budgets and unsupported broad-access options stay disabled.
	if c.Terminal.Style != TerminalStyleBrand && c.Terminal.Style != TerminalStylePlain {
		return fmt.Errorf("unsupported terminal style %q", c.Terminal.Style)
	}
	if c.Review.Mode != ReviewModeAI && c.Review.Mode != ReviewModeDeterministicOnly {
		return fmt.Errorf("unsupported review mode %q", c.Review.Mode)
	}
	if !validConfidence(c.Review.MinimumConfidence) {
		return fmt.Errorf("unsupported minimum review confidence %q", c.Review.MinimumConfidence)
	}
	if !brief.ValidSeverity(c.Review.ManualReviewMinimumSeverity) {
		return fmt.Errorf("unsupported manual review minimum severity %q", c.Review.ManualReviewMinimumSeverity)
	}
	if c.Provider != "codex" && c.Provider != "anthropic" {
		return fmt.Errorf("unsupported provider %q", c.Provider)
	}
	for name, p := range map[string]ProviderConfig{"codex": c.Providers.Codex, "anthropic": c.Providers.Anthropic} {
		if p.Model == "" || len(p.Model) > maxProviderModelBytes {
			return fmt.Errorf("providers.%s.model must be non-empty and at most %d bytes", name, maxProviderModelBytes)
		}
		if !validEffort(p.Effort) {
			return fmt.Errorf("providers.%s.effort is unsupported", name)
		}
	}
	if c.Review.TimeoutSeconds <= 0 || c.Review.KillGraceSeconds <= 0 || c.Review.BatchBytes <= 0 {
		return errors.New("all review limits must be positive")
	}
	limits := []int64{
		c.Limits.MaxDispatchBytes, int64(c.Limits.MaxFiles), c.Limits.MaxTotalInputBytes, int64(c.Limits.MaxArchives),
		int64(c.Limits.MaxArchiveEntries), c.Limits.MaxArchiveUnpackedBytes,
		int64(c.Limits.MaxArchiveDepth), c.Limits.MaxTextPerFile, c.Limits.MaxSelectedTextBytes,
		c.Limits.BinaryStringsBytes, int64(c.Limits.MaxFindings), int64(c.Limits.ScanTimeoutSeconds),
		c.Build.MemoryBytes, int64(c.Build.CPUCount), int64(c.Build.TasksMax), int64(c.Build.TimeoutSeconds),
		c.Build.WorkspaceBytes, int64(c.Build.WorkspaceFiles), c.Build.OutputBytes, c.Build.DiskReserveBytes,
		int64(c.Network.MaxConnections), int64(c.Network.ConnectTimeoutSeconds), int64(c.Network.IdleTimeoutSeconds),
		c.Network.MaxTransferBytes, int64(c.Network.PromptTimeoutSeconds), int64(c.Network.MaxDestinations),
		int64(c.Network.MaxRequests),
	}
	for _, value := range limits {
		if value <= 0 {
			return errors.New("all scan limits must be positive")
		}
	}
	if int64(c.Review.BatchBytes) > c.Limits.MaxSelectedTextBytes {
		return errors.New("review.batch_bytes exceeds limits.max_selected_text_bytes")
	}
	if c.Limits.BinaryStringsBytes > c.Limits.MaxTextPerFile {
		return errors.New("limits.binary_strings_bytes exceeds limits.max_text_per_file")
	}
	if c.Limits.MaxArchiveEntries > c.Limits.MaxFiles || c.Limits.MaxArchiveUnpackedBytes > c.Limits.MaxTotalInputBytes {
		return errors.New("archive limits exceed aggregate scanner limits")
	}
	if c.Vendor.ScanDepth < 0 || c.Vendor.ScanDepth > c.Limits.MaxArchiveDepth {
		return errors.New("vendor.scan_depth must be between zero and limits.max_archive_depth")
	}
	if c.Build.DiskReserveBytes >= c.Build.WorkspaceBytes {
		return errors.New("build.disk_reserve_bytes must be smaller than build.workspace_bytes")
	}
	if c.Network.Mode != "prompt" || c.Network.GrantScope != "transaction" || c.Network.MaxDestinations > maxNetworkDestinations || c.Network.MaxRequests > egress.MaximumMaxRequests ||
		c.Network.MaxConnections > maxNetworkConnections || c.Network.PromptTimeoutSeconds > maxPromptTimeoutSeconds ||
		c.Network.ConnectTimeoutSeconds > maxNetworkConnectSeconds || c.Network.IdleTimeoutSeconds > maxNetworkIdleSeconds {
		return errors.New("network policy must use phase-scoped interactive prompts")
	}
	return nil
}

func validConfidence(value string) bool {
	return value == "low" || value == "medium" || value == "high"
}

func severityAtLeast(actual, minimum string) bool {
	rank := map[string]int{"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
	return rank[actual] >= rank[minimum] && rank[minimum] != 0
}

func decisionSeverityLabel(minimum string) string {
	if minimum == "high" {
		return "HIGH/CRITICAL"
	}
	label := strings.ToUpper(minimum)
	if minimum != "critical" {
		label += "+"
	}
	return label
}

func validEffort(value string) bool {
	switch value {
	case "none", "low", "medium", "high", "xhigh", "max":
		return true
	default:
		return false
	}
}

func StateRoot() string {
	// User-owned reports and approvals follow XDG state placement;
	// this path is never used for root-service authority.
	if value := os.Getenv("XDG_STATE_HOME"); value != "" {
		return filepath.Join(value, "prolewatch")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".prolewatch-state")
	}
	return filepath.Join(home, ".local", "state", "prolewatch")
}

func ShareRoot() string {
	if info, err := os.Stat("/usr/share/prolewatch"); err == nil && info.IsDir() {
		return "/usr/share/prolewatch"
	}
	if value := os.Getenv("PROLEWATCH_SHARE"); value != "" {
		return value
	}
	return "/usr/share/prolewatch"
}

// briefConfig narrows the umbrella configuration to what the inspection layer
// is allowed to see. The scanner parses hostile archives; it has no business
// being able to reach provider credentials, build limits, or terminal styling,
// and passing the whole Config would have made that reachable by accident.
func BriefConfig(cfg Config) brief.Config {
	return brief.Config{
		Limits:              cfg.Limits,
		Vendor:              cfg.Vendor,
		RetainTextForReview: cfg.Review.Mode != ReviewModeDeterministicOnly,
	}
}
