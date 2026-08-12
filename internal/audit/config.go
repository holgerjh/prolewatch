package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const (
	ApplicationVersion    = "0.10.0"
	ReportSchemaVersion   = 8
	MarkerSchemaVersion   = 7
	ApprovalSchemaVersion = 6
	ScannerVersion        = 8
	RulesVersion          = 12
	ReviewSnapshotVersion = 6
	MinYayVersion         = "13.0.1"
	MinCodexVersion       = "0.146.1"
	MaxCodexVersion       = "0.147.0"
	MinClaudeVersion      = "2.1.205"
	MaxClaudeVersion      = "3.0.0"
)

const (
	ReviewModeAI                = "ai"
	ReviewModeDeterministicOnly = "deterministic-only"
	TerminalStyleBrand          = "brand"
	TerminalStylePlain          = "plain"
)

const systemConfigDefaultPath = "/etc/prolewatch/config.json"

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
	Mode              string `json:"mode"`
	MinimumConfidence string `json:"minimum_confidence"`
	TimeoutSeconds    int    `json:"timeout_seconds"`
	KillGraceSeconds  int    `json:"kill_grace_seconds"`
	BatchBytes        int    `json:"batch_bytes"`
}

type legacyReviewConfig struct {
	TimeoutSeconds   int `json:"timeout_seconds"`
	KillGraceSeconds int `json:"kill_grace_seconds"`
	BatchBytes       int `json:"batch_bytes"`
}

type legacyModeReviewConfig struct {
	Mode             string `json:"mode"`
	TimeoutSeconds   int    `json:"timeout_seconds"`
	KillGraceSeconds int    `json:"kill_grace_seconds"`
	BatchBytes       int    `json:"batch_bytes"`
}

type legacyPreModeReviewConfig struct {
	MinimumConfidence string `json:"minimum_confidence"`
	TimeoutSeconds    int    `json:"timeout_seconds"`
	KillGraceSeconds  int    `json:"kill_grace_seconds"`
	BatchBytes        int    `json:"batch_bytes"`
}

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

type BuildConfig struct {
	MemoryBytes                    int64 `json:"memory_bytes"`
	CPUCount                       int   `json:"cpu_count"`
	TasksMax                       int   `json:"tasks_max"`
	TimeoutSeconds                 int   `json:"timeout_seconds"`
	WorkspaceBytes                 int64 `json:"workspace_bytes"`
	WorkspaceFiles                 int   `json:"workspace_files"`
	OutputBytes                    int64 `json:"output_bytes"`
	DiskReserveBytes               int64 `json:"disk_reserve_bytes"`
	CleanRootPrepareTimeoutSeconds int   `json:"clean_root_prepare_timeout_seconds"`
	CleanRootBytes                 int64 `json:"clean_root_bytes"`
	CleanRootCacheBytes            int64 `json:"clean_root_cache_bytes"`
	CleanRootMaxPrepared           int   `json:"clean_root_max_prepared"`
}

type NetworkConfig struct {
	AutoEnableKnownTools  bool  `json:"auto_enable_known_tools"`
	MaxConnections        int   `json:"max_connections"`
	ConnectTimeoutSeconds int   `json:"connect_timeout_seconds"`
	IdleTimeoutSeconds    int   `json:"idle_timeout_seconds"`
	MaxTransferBytes      int64 `json:"max_transfer_bytes"`
}

type SandboxConfig struct {
	ReadOnlyPaths []string `json:"read_only_paths"`
}

type VendorConfig struct {
	ScanDepth int `json:"scan_depth"`
}

type OverridesConfig struct {
	AllowUnsafe bool `json:"allow_unsafe"`
}

// TerminalConfig affects presentation only. It is deliberately excluded from
// the policy fingerprint so changing terminal decoration cannot invalidate a
// reviewed package snapshot.
type TerminalConfig struct {
	Style string `json:"style"`
}

type Config struct {
	Provider  string          `json:"provider"`
	Providers ProvidersConfig `json:"providers"`
	Review    ReviewConfig    `json:"review"`
	Limits    LimitsConfig    `json:"limits"`
	Build     BuildConfig     `json:"build"`
	Network   NetworkConfig   `json:"network"`
	Sandbox   SandboxConfig   `json:"sandbox"`
	Vendor    VendorConfig    `json:"vendor"`
	Overrides OverridesConfig `json:"overrides"`
	Terminal  TerminalConfig  `json:"terminal"`
}

type legacyLimitsConfig struct {
	MaxDispatchBytes        int64 `json:"max_dispatch_bytes"`
	MaxArchiveEntries       int   `json:"max_archive_entries"`
	MaxArchiveUnpackedBytes int64 `json:"max_archive_unpacked_bytes"`
	MaxArchiveDepth         int   `json:"max_archive_depth"`
	MaxTextPerFile          int64 `json:"max_text_per_file"`
	MaxSelectedTextBytes    int64 `json:"max_selected_text_bytes"`
	BinaryStringsBytes      int64 `json:"binary_strings_bytes"`
}

type legacyConfigV3 struct {
	Provider  string             `json:"provider"`
	Providers ProvidersConfig    `json:"providers"`
	Review    legacyReviewConfig `json:"review"`
	Limits    legacyLimitsConfig `json:"limits"`
}

type legacyBuildConfigV4 struct {
	MemoryBytes      int64 `json:"memory_bytes"`
	CPUCount         int   `json:"cpu_count"`
	TasksMax         int   `json:"tasks_max"`
	TimeoutSeconds   int   `json:"timeout_seconds"`
	WorkspaceBytes   int64 `json:"workspace_bytes"`
	WorkspaceFiles   int   `json:"workspace_files"`
	OutputBytes      int64 `json:"output_bytes"`
	DiskReserveBytes int64 `json:"disk_reserve_bytes"`
}

type legacyConfigV4 struct {
	Provider  string              `json:"provider"`
	Providers ProvidersConfig     `json:"providers"`
	Review    legacyReviewConfig  `json:"review"`
	Limits    LimitsConfig        `json:"limits"`
	Build     legacyBuildConfigV4 `json:"build"`
	Network   NetworkConfig       `json:"network"`
	Sandbox   SandboxConfig       `json:"sandbox"`
}

type legacyConfigV5 struct {
	Provider  string             `json:"provider"`
	Providers ProvidersConfig    `json:"providers"`
	Review    legacyReviewConfig `json:"review"`
	Limits    LimitsConfig       `json:"limits"`
	Build     BuildConfig        `json:"build"`
	Network   NetworkConfig      `json:"network"`
	Sandbox   SandboxConfig      `json:"sandbox"`
}

// legacyConfigV6 is the complete configuration shipped immediately before
// minimum_confidence and the break-glass override policy were introduced.
type legacyConfigV6 struct {
	Provider  string                 `json:"provider"`
	Providers ProvidersConfig        `json:"providers"`
	Review    legacyModeReviewConfig `json:"review"`
	Limits    LimitsConfig           `json:"limits"`
	Build     BuildConfig            `json:"build"`
	Network   NetworkConfig          `json:"network"`
	Sandbox   SandboxConfig          `json:"sandbox"`
}

type legacyConfigWithoutOverrides struct {
	Provider  string          `json:"provider"`
	Providers ProvidersConfig `json:"providers"`
	Review    ReviewConfig    `json:"review"`
	Limits    LimitsConfig    `json:"limits"`
	Build     BuildConfig     `json:"build"`
	Network   NetworkConfig   `json:"network"`
	Sandbox   SandboxConfig   `json:"sandbox"`
}

type legacyConfigPreMode struct {
	Provider  string                    `json:"provider"`
	Providers ProvidersConfig           `json:"providers"`
	Review    legacyPreModeReviewConfig `json:"review"`
	Limits    LimitsConfig              `json:"limits"`
	Build     BuildConfig               `json:"build"`
	Network   NetworkConfig             `json:"network"`
	Sandbox   SandboxConfig             `json:"sandbox"`
	Vendor    VendorConfig              `json:"vendor"`
	Overrides OverridesConfig           `json:"overrides"`
	Terminal  TerminalConfig            `json:"terminal"`
}

func DefaultConfig() Config {
	return Config{
		Provider: "codex",
		Providers: ProvidersConfig{
			Codex:     ProviderConfig{Model: "gpt-5.6-sol", Effort: "high"},
			Anthropic: ProviderConfig{Model: "sonnet", Effort: "high"},
		},
		Review: ReviewConfig{Mode: ReviewModeAI, MinimumConfidence: "high", TimeoutSeconds: 180, KillGraceSeconds: 5, BatchBytes: 768000},
		Limits: LimitsConfig{
			MaxDispatchBytes: 20 * 1024 * 1024, MaxFiles: 200000, MaxTotalInputBytes: 16 * 1024 * 1024 * 1024,
			MaxArchives: 1024, MaxArchiveEntries: 100000,
			MaxArchiveUnpackedBytes: 2 * 1024 * 1024 * 1024, MaxArchiveDepth: 4,
			MaxTextPerFile: 4 * 1024 * 1024, MaxSelectedTextBytes: 16 * 1024 * 1024,
			BinaryStringsBytes: 128 * 1024, MaxFindings: 10000, ScanTimeoutSeconds: 300,
		},
		Build: BuildConfig{MemoryBytes: 8 * 1024 * 1024 * 1024, CPUCount: 4, TasksMax: 512,
			TimeoutSeconds: 2 * 60 * 60, WorkspaceBytes: 16 * 1024 * 1024 * 1024,
			WorkspaceFiles: 500000, OutputBytes: 32 * 1024 * 1024, DiskReserveBytes: 2 * 1024 * 1024 * 1024,
			CleanRootPrepareTimeoutSeconds: 15 * 60, CleanRootBytes: 32 * 1024 * 1024 * 1024,
			CleanRootCacheBytes: 16 * 1024 * 1024 * 1024, CleanRootMaxPrepared: 2},
		Network: NetworkConfig{AutoEnableKnownTools: true, MaxConnections: 32, ConnectTimeoutSeconds: 15, IdleTimeoutSeconds: 60,
			MaxTransferBytes: 8 * 1024 * 1024 * 1024},
		Sandbox:   SandboxConfig{ReadOnlyPaths: []string{}},
		Vendor:    VendorConfig{ScanDepth: 0},
		Overrides: OverridesConfig{AllowUnsafe: false},
		Terminal:  TerminalConfig{Style: TerminalStyleBrand},
	}
}

func LoadConfig(path string) (Config, error) {
	if path == "" {
		path = SystemConfigPath
	}
	raw, err := readConfig(path)
	if err != nil {
		return Config{}, fmt.Errorf("read configuration %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse configuration %s: %w", path, err)
	}
	// This setting was introduced with a default-on compatibility policy. A
	// missing key therefore means true, while an explicit false remains a
	// deliberate administrator choice.
	var presence struct {
		Network struct {
			AutoEnableKnownTools *bool `json:"auto_enable_known_tools"`
		} `json:"network"`
	}
	if err := json.Unmarshal(raw, &presence); err != nil {
		return Config{}, fmt.Errorf("parse network configuration presence: %w", err)
	}
	if presence.Network.AutoEnableKnownTools == nil {
		cfg.Network.AutoEnableKnownTools = true
	}
	// Configurations written before terminal styling existed remain current and
	// pick up the safe presentation default without entering a legacy migration.
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

func MigrateConfig(path string) (Config, error) {
	if cfg, err := LoadConfig(path); err == nil {
		return cfg, nil
	}
	raw, err := readConfig(path)
	if err != nil {
		return Config{}, err
	}
	var withoutOverrides legacyConfigWithoutOverrides
	if err := DecodeStrict(raw, &withoutOverrides); err == nil && withoutOverrides.Build.CleanRootBytes > 0 && withoutOverrides.Limits.MaxFiles > 0 && validConfidence(withoutOverrides.Review.MinimumConfidence) {
		cfg := DefaultConfig()
		cfg.Provider, cfg.Providers, cfg.Review, cfg.Limits, cfg.Build, cfg.Network, cfg.Sandbox = withoutOverrides.Provider, withoutOverrides.Providers, withoutOverrides.Review, withoutOverrides.Limits, withoutOverrides.Build, withoutOverrides.Network, withoutOverrides.Sandbox
		cfg.Network.AutoEnableKnownTools = true
		return cfg, cfg.Validate()
	}
	var v6 legacyConfigV6
	if err := DecodeStrict(raw, &v6); err == nil && v6.Build.CleanRootBytes > 0 && v6.Limits.MaxFiles > 0 {
		cfg := DefaultConfig()
		cfg.Provider, cfg.Providers, cfg.Limits, cfg.Build, cfg.Network, cfg.Sandbox = v6.Provider, v6.Providers, v6.Limits, v6.Build, v6.Network, v6.Sandbox
		cfg.Network.AutoEnableKnownTools = true
		cfg.Review = ReviewConfig{Mode: v6.Review.Mode, MinimumConfidence: "high", TimeoutSeconds: v6.Review.TimeoutSeconds, KillGraceSeconds: v6.Review.KillGraceSeconds, BatchBytes: v6.Review.BatchBytes}
		return cfg, cfg.Validate()
	}
	var preMode legacyConfigPreMode
	if err := DecodeStrict(raw, &preMode); err == nil && preMode.Build.CleanRootBytes > 0 && preMode.Limits.MaxFiles > 0 && validConfidence(preMode.Review.MinimumConfidence) {
		cfg := DefaultConfig()
		cfg.Provider, cfg.Providers, cfg.Limits, cfg.Build, cfg.Network, cfg.Sandbox, cfg.Vendor, cfg.Overrides = preMode.Provider, preMode.Providers, preMode.Limits, preMode.Build, preMode.Network, preMode.Sandbox, preMode.Vendor, preMode.Overrides
		cfg.Network.AutoEnableKnownTools = true
		if preMode.Terminal.Style != "" {
			cfg.Terminal = preMode.Terminal
		}
		cfg.Review = ReviewConfig{Mode: ReviewModeAI, MinimumConfidence: preMode.Review.MinimumConfidence, TimeoutSeconds: preMode.Review.TimeoutSeconds, KillGraceSeconds: preMode.Review.KillGraceSeconds, BatchBytes: preMode.Review.BatchBytes}
		return cfg, cfg.Validate()
	}
	var v5 legacyConfigV5
	if err := DecodeStrict(raw, &v5); err == nil && v5.Build.CleanRootBytes > 0 && v5.Limits.MaxFiles > 0 {
		cfg := DefaultConfig()
		cfg.Provider, cfg.Providers, cfg.Limits, cfg.Build, cfg.Network, cfg.Sandbox = v5.Provider, v5.Providers, v5.Limits, v5.Build, v5.Network, v5.Sandbox
		cfg.Network.AutoEnableKnownTools = true
		cfg.Review = migrateLegacyReview(v5.Review)
		return cfg, cfg.Validate()
	}
	var v4 legacyConfigV4
	if err := DecodeStrict(raw, &v4); err == nil && v4.Build.MemoryBytes > 0 && v4.Limits.MaxFiles > 0 {
		if len(v4.Sandbox.ReadOnlyPaths) > 0 {
			return Config{}, errors.New("sandbox.read_only_paths cannot be migrated because clean roots no longer expose host paths")
		}
		cfg := DefaultConfig()
		cfg.Provider, cfg.Providers, cfg.Limits, cfg.Network = v4.Provider, v4.Providers, v4.Limits, v4.Network
		cfg.Network.AutoEnableKnownTools = true
		cfg.Review = migrateLegacyReview(v4.Review)
		cfg.Build.MemoryBytes, cfg.Build.CPUCount, cfg.Build.TasksMax = v4.Build.MemoryBytes, v4.Build.CPUCount, v4.Build.TasksMax
		cfg.Build.TimeoutSeconds, cfg.Build.WorkspaceBytes, cfg.Build.WorkspaceFiles = v4.Build.TimeoutSeconds, v4.Build.WorkspaceBytes, v4.Build.WorkspaceFiles
		cfg.Build.OutputBytes, cfg.Build.DiskReserveBytes = v4.Build.OutputBytes, v4.Build.DiskReserveBytes
		return cfg, cfg.Validate()
	}
	var legacy legacyConfigV3
	if err := DecodeStrict(raw, &legacy); err != nil {
		return Config{}, fmt.Errorf("configuration is neither current nor a supported legacy schema: %w", err)
	}
	cfg := DefaultConfig()
	cfg.Provider, cfg.Providers = legacy.Provider, legacy.Providers
	cfg.Review = migrateLegacyReview(legacy.Review)
	cfg.Limits.MaxDispatchBytes = legacy.Limits.MaxDispatchBytes
	cfg.Limits.MaxArchiveEntries = legacy.Limits.MaxArchiveEntries
	cfg.Limits.MaxArchiveUnpackedBytes = legacy.Limits.MaxArchiveUnpackedBytes
	cfg.Limits.MaxArchiveDepth = legacy.Limits.MaxArchiveDepth
	cfg.Limits.MaxTextPerFile = legacy.Limits.MaxTextPerFile
	cfg.Limits.MaxSelectedTextBytes = legacy.Limits.MaxSelectedTextBytes
	cfg.Limits.BinaryStringsBytes = legacy.Limits.BinaryStringsBytes
	return cfg, cfg.Validate()
}

func migrateLegacyReview(review legacyReviewConfig) ReviewConfig {
	return ReviewConfig{Mode: ReviewModeAI, MinimumConfidence: "high", TimeoutSeconds: review.TimeoutSeconds, KillGraceSeconds: review.KillGraceSeconds, BatchBytes: review.BatchBytes}
}

func readConfig(path string) ([]byte, error) {
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
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size < 0 || before.Size > 1024*1024 || before.Mode&0o022 != 0 {
		return nil, errors.New("configuration is not a safe regular file")
	}
	if filepath.Clean(path) == systemConfigDefaultPath && before.Uid != 0 {
		return nil, errors.New("system configuration is not root-owned")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 1024*1024+1))
	if err != nil || len(raw) > 1024*1024 {
		return nil, errors.New("configuration exceeds its read limit")
	}
	if err := unix.Fstat(fd, &after); err != nil {
		return nil, err
	}
	if !sameStat(before, after) || int64(len(raw)) != after.Size {
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
	if c.Terminal.Style != TerminalStyleBrand && c.Terminal.Style != TerminalStylePlain {
		return fmt.Errorf("unsupported terminal style %q", c.Terminal.Style)
	}
	if c.Review.Mode != ReviewModeAI && c.Review.Mode != ReviewModeDeterministicOnly {
		return fmt.Errorf("unsupported review mode %q", c.Review.Mode)
	}
	if !validConfidence(c.Review.MinimumConfidence) {
		return fmt.Errorf("unsupported minimum review confidence %q", c.Review.MinimumConfidence)
	}
	if c.Provider != "codex" && c.Provider != "anthropic" {
		return fmt.Errorf("unsupported provider %q", c.Provider)
	}
	for name, p := range map[string]ProviderConfig{"codex": c.Providers.Codex, "anthropic": c.Providers.Anthropic} {
		if p.Model == "" || len(p.Model) > 256 {
			return fmt.Errorf("providers.%s.model must be non-empty and at most 256 bytes", name)
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
		int64(c.Build.CleanRootPrepareTimeoutSeconds), c.Build.CleanRootBytes, c.Build.CleanRootCacheBytes, int64(c.Build.CleanRootMaxPrepared),
		int64(c.Network.MaxConnections), int64(c.Network.ConnectTimeoutSeconds), int64(c.Network.IdleTimeoutSeconds),
		c.Network.MaxTransferBytes,
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
	if len(c.Sandbox.ReadOnlyPaths) != 0 {
		return errors.New("sandbox.read_only_paths is unsupported with mandatory clean roots")
	}
	if c.Build.CleanRootCacheBytes >= c.Build.CleanRootBytes || c.Build.CleanRootMaxPrepared > 32 {
		return errors.New("clean-root limits are inconsistent")
	}
	return nil
}

func validConfidence(value string) bool {
	return value == "low" || value == "medium" || value == "high"
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
