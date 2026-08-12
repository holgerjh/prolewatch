package audit

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDefaultConfigAndStrictLoading(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.Provider != "codex" || cfg.ActiveProvider().Model == "" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if cfg.Review.MinimumConfidence != "high" || cfg.Vendor.ScanDepth != 0 || !cfg.Network.AutoEnableKnownTools || cfg.Overrides.AllowUnsafe || cfg.Terminal.Style != TerminalStyleBrand {
		t.Fatalf("unexpected policy defaults: %+v", cfg)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"provider":"codex","providers":{"codex":{"model":"gpt","effort":"high"},"anthropic":{"model":"sonnet","effort":"high"}},"review":{"timeout_seconds":1,"kill_grace_seconds":1,"batch_bytes":1024},"limits":{"max_dispatch_bytes":2048,"max_archive_entries":1,"max_archive_unpacked_bytes":2048,"max_archive_depth":1,"max_text_per_file":1024,"max_selected_text_bytes":1024,"binary_strings_bytes":128},"extra":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("unknown key was accepted")
	}
}

func TestShippedConfigMatchesCompiledDefaults(t *testing.T) {
	path, err := filepath.Abs(filepath.Join("..", "..", "share", "default-config.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := DecodeStrict(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg, DefaultConfig()) {
		t.Fatalf("shipped defaults drifted from compiled policy: %#v", cfg)
	}
}

func TestConfigValidatesActiveProviderAndLimits(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Review.Mode = "automatic"
	if err := cfg.Validate(); err == nil {
		t.Fatal("unknown review mode accepted")
	}
	cfg = DefaultConfig()
	cfg.Review.MinimumConfidence = "certain"
	if err := cfg.Validate(); err == nil {
		t.Fatal("unknown confidence accepted")
	}
	cfg = DefaultConfig()
	cfg.Provider = "router"
	if err := cfg.Validate(); err == nil {
		t.Fatal("unknown provider accepted")
	}
	cfg = DefaultConfig()
	cfg.Terminal.Style = "sparkles"
	if err := cfg.Validate(); err == nil {
		t.Fatal("unknown terminal style accepted")
	}
	cfg = DefaultConfig()
	cfg.Review.BatchBytes = int(cfg.Limits.MaxSelectedTextBytes + 1)
	if err := cfg.Validate(); err == nil {
		t.Fatal("inconsistent batch limit accepted")
	}
	cfg = DefaultConfig()
	cfg.Vendor.ScanDepth = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("negative vendor scan depth accepted")
	}
	cfg = DefaultConfig()
	cfg.Vendor.ScanDepth = cfg.Limits.MaxArchiveDepth + 1
	if err := cfg.Validate(); err == nil {
		t.Fatal("vendor scan depth beyond the archive limit accepted")
	}
}

func TestConfigWithoutTerminalStyleLoadsAsBrand(t *testing.T) {
	cfg := DefaultConfig()
	raw, err := CanonicalJSON(cfg)
	if err != nil {
		t.Fatal(err)
	}
	withoutTerminal := strings.Replace(string(raw), `,"terminal":{"style":"brand"}`, "", 1)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(withoutTerminal), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(path)
	if err != nil || loaded.Terminal.Style != TerminalStyleBrand {
		t.Fatalf("old current config did not adopt brand style: %+v err=%v", loaded.Terminal, err)
	}
}

func TestConfigWithoutAutomaticKnownToolNetworkUsesNewDefault(t *testing.T) {
	cfg := DefaultConfig()
	raw, err := CanonicalJSON(cfg)
	if err != nil {
		t.Fatal(err)
	}
	withoutSetting := strings.Replace(string(raw), `"auto_enable_known_tools":true,`, "", 1)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(withoutSetting), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(path)
	if err != nil || !loaded.Network.AutoEnableKnownTools {
		t.Fatalf("old current config did not adopt known-tool network default: %+v err=%v", loaded.Network, err)
	}

	cfg.Network.AutoEnableKnownTools = false
	raw, err = CanonicalJSON(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err = LoadConfig(path)
	if err != nil || loaded.Network.AutoEnableKnownTools {
		t.Fatalf("explicitly disabled known-tool network was not preserved: %+v err=%v", loaded.Network, err)
	}
}

func TestTerminalStyleConfigCLISelectorsAndMigration(t *testing.T) {
	raw, err := CanonicalJSON(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if status := runConfigCheck([]string{"--path", path, "--terminal-style-only"}); status != 0 {
		t.Fatalf("terminal style selector status=%d", status)
	}
	for _, selector := range []string{"--review-mode-only", "--minimum-confidence-only", "--unsafe-overrides-only"} {
		if status := runConfigCheck([]string{"--path", path, selector}); status != 0 {
			t.Fatalf("config selector %s status=%d", selector, status)
		}
	}
	if status := runConfigCheck([]string{"--path", path}); status != 0 {
		t.Fatalf("human config check status=%d", status)
	}
	if status := runConfigCheck([]string{"--path", path, "--terminal-style-only", "--provider-only"}); status != 20 {
		t.Fatalf("mutually exclusive selectors status=%d", status)
	}
	if status := runConfigMigrate([]string{"--path", path, "--terminal-style", TerminalStylePlain}); status != 0 {
		t.Fatalf("terminal style migration status=%d", status)
	}
	if status := runConfigMigrate([]string{"--path", path, "--terminal-style", "sparkles"}); status != 20 {
		t.Fatalf("invalid terminal style migration status=%d", status)
	}
}

func TestCurrentPreModeConfigMigratesToAI(t *testing.T) {
	cfg := DefaultConfig()
	raw, err := CanonicalJSON(cfg)
	if err != nil {
		t.Fatal(err)
	}
	withoutMode := strings.Replace(string(raw), `"mode":"ai",`, "", 1)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(withoutMode), 0o600); err != nil {
		t.Fatal(err)
	}
	migrated, err := MigrateConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if migrated.Review.Mode != ReviewModeAI {
		t.Fatalf("pre-mode config migrated to %q", migrated.Review.Mode)
	}
}

func TestPreviousCompleteConfigMigratesToSafePolicyDefaults(t *testing.T) {
	current := DefaultConfig()
	legacy := legacyConfigV6{Provider: current.Provider, Providers: current.Providers,
		Review: legacyModeReviewConfig{Mode: ReviewModeAI, TimeoutSeconds: current.Review.TimeoutSeconds, KillGraceSeconds: current.Review.KillGraceSeconds, BatchBytes: current.Review.BatchBytes},
		Limits: current.Limits, Build: current.Build, Network: current.Network, Sandbox: current.Sandbox}
	raw, err := CanonicalJSON(legacy)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	migrated, err := MigrateConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if migrated.Review.Mode != ReviewModeAI || migrated.Review.MinimumConfidence != "high" || !migrated.Network.AutoEnableKnownTools || migrated.Overrides.AllowUnsafe {
		t.Fatalf("unsafe previous-config migration: %+v", migrated)
	}
}

func TestConfigWithoutOverridesMigratesWithUnsafeDisabled(t *testing.T) {
	current := DefaultConfig()
	legacy := legacyConfigWithoutOverrides{Provider: current.Provider, Providers: current.Providers, Review: current.Review,
		Limits: current.Limits, Build: current.Build, Network: current.Network, Sandbox: current.Sandbox}
	raw, err := CanonicalJSON(legacy)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	migrated, err := MigrateConfig(path)
	if err != nil || migrated.Overrides.AllowUnsafe || migrated.Review.MinimumConfidence != current.Review.MinimumConfidence {
		t.Fatalf("config migration changed policy unexpectedly: %+v err=%v", migrated, err)
	}
}

func TestConfigRejectsEverySecurityBudgetClass(t *testing.T) {
	mutations := []func(*Config){
		func(c *Config) { c.Providers.Codex.Model = "" },
		func(c *Config) { c.Providers.Anthropic.Effort = "impossible" },
		func(c *Config) { c.Review.TimeoutSeconds = 0 },
		func(c *Config) { c.Limits.MaxFiles = 0 },
		func(c *Config) { c.Review.BatchBytes = int(c.Limits.MaxSelectedTextBytes + 1) },
		func(c *Config) { c.Limits.BinaryStringsBytes = c.Limits.MaxTextPerFile + 1 },
		func(c *Config) { c.Limits.MaxArchiveEntries = c.Limits.MaxFiles + 1 },
		func(c *Config) { c.Limits.MaxArchiveUnpackedBytes = c.Limits.MaxTotalInputBytes + 1 },
		func(c *Config) { c.Build.DiskReserveBytes = c.Build.WorkspaceBytes },
		func(c *Config) { c.Sandbox.ReadOnlyPaths = make([]string, 33) },
		func(c *Config) { c.Sandbox.ReadOnlyPaths = []string{"relative"} },
		func(c *Config) { c.Sandbox.ReadOnlyPaths = []string{"/usr/share", "/usr/share"} },
	}
	for index, mutate := range mutations {
		cfg := DefaultConfig()
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("config mutation %d accepted", index)
		}
	}
	if DefaultConfig().ActiveProvider().Model == "" {
		t.Fatal("default active provider missing")
	}
	cfg := DefaultConfig()
	cfg.Provider = "anthropic"
	if cfg.ActiveProvider() != cfg.Providers.Anthropic {
		t.Fatal("anthropic provider selection failed")
	}
}

func TestConfigRejectsTrailingJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	raw := []byte(`{"provider":"codex"} {"provider":"anthropic"}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("trailing JSON was accepted")
	}
}

func TestConfigRejectsWritableOrLinkedFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("group/world-writable configuration was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(link); err == nil {
		t.Fatal("symlinked configuration was accepted")
	}
}
