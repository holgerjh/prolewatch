package audit

import (
	"encoding/json"
	"github.com/holgerjh/prolewatch/internal/safe"
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
	if cfg.Review.MinimumConfidence != "high" || cfg.Review.ManualReviewMinimumSeverity != "high" || !cfg.Review.GuideDecisionFindings || cfg.Vendor.ScanDepth != 0 || cfg.Network.Mode != "prompt" ||
		cfg.Network.GrantScope != "transaction" || cfg.Terminal.Style != TerminalStyleBrand {
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
	if err := safe.DecodeJSON(raw, &cfg); err != nil {
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
	cfg.Review.ManualReviewMinimumSeverity = "severe"
	if err := cfg.Validate(); err == nil {
		t.Fatal("unknown manual review severity accepted")
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
	raw, err := safe.CanonicalJSON(cfg)
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

// TestRetiredPolicyFieldsAreRejected holds the line on configuration surfaces
// that described capabilities the product does not have.
//
// `network.auto_enable_known_tools` was decoded and then forced to false, and
// `sandbox.read_only_paths` could only ever be empty because validation
// rejected every non-empty value. Both told an administrator there was
// something to tune. Neither is accepted now: strict decoding refuses the key
// outright, which is a clearer answer than silently normalising it away.
func TestRetiredPolicyFieldsAreRejected(t *testing.T) {
	raw, err := safe.CanonicalJSON(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, retired := range []string{"auto_enable_known_tools", "read_only_paths", "sandbox", "guide_high_recipe_findings"} {
		if strings.Contains(string(raw), retired) {
			t.Errorf("the compiled default still carries the retired field %q", retired)
		}
	}
	// A file still carrying either key fails to load rather than loading with
	// the value ignored.
	for _, document := range []string{
		`{"network":{"auto_enable_known_tools":true}}`,
		`{"sandbox":{"read_only_paths":["/usr/share"]}}`,
		`{"review":{"guide_high_recipe_findings":true}}`,
	} {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil {
			t.Errorf("a configuration carrying a retired field was accepted: %s", document)
		}
	}
}

func TestTerminalStyleConfigCLISelectors(t *testing.T) {
	raw, err := safe.CanonicalJSON(DefaultConfig())
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
	for _, selector := range []string{"--review-mode-only", "--minimum-confidence-only"} {
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

// Configuration cannot enable a global break-glass. Release invariant 4 limits
// hard blocks to structurally decidable properties and permits no switch that
// crosses one.
func TestGlobalUnsafeOverrideCannotBeReintroducedByConfiguration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	raw, err := json.Marshal(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	document["overrides"] = map[string]any{"allow_unsafe": true}
	edited, _ := json.Marshal(document)
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	// Strict decoding rejects the unknown field rather than ignoring it. A
	// lenient decoder would let a user believe the switch is still in effect.
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("a configuration setting allow_unsafe was accepted")
	}
}

// There is exactly one bypass mechanism, and it is content-bound.
func TestOnlyApprovalTokensExist(t *testing.T) {
	store := &ApprovalStore{Root: t.TempDir()}
	report := approvalFixture()
	for _, kind := range []string{"unsafe", "bypass", "force", ""} {
		if _, err := store.Create(report, kind, "a reason long enough"); err == nil {
			t.Fatalf("approval kind %q was accepted", kind)
		}
	}
	if _, err := store.Create(report, "approval", "a reason long enough"); err != nil {
		t.Fatalf("the one legitimate approval kind was rejected: %v", err)
	}
}

// TestReviewerDefaultsAreDeliberate binds the provider defaults so that changing
// a model or an effort level is a decision someone made rather than a drift.
//
// It also records the property the documentation has to keep stating: the
// Anthropic default is a moving alias, so the model recorded in a report is the
// alias and not the model that answered. Two reports can carry the same policy
// fingerprint and the same "sonnet" while different models produced them. The
// Codex default is a pinned identifier and does not have that property.
func TestReviewerDefaultsAreDeliberate(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Provider != "codex" {
		t.Fatalf("default provider changed to %q", cfg.Provider)
	}
	if cfg.Providers.Codex.Model != "gpt-5.6-sol" || cfg.Providers.Codex.Effort != "high" {
		t.Fatalf("codex defaults changed: %+v", cfg.Providers.Codex)
	}
	if cfg.Providers.Anthropic.Model != "sonnet" || cfg.Providers.Anthropic.Effort != "high" {
		t.Fatalf("anthropic defaults changed: %+v", cfg.Providers.Anthropic)
	}
	// The whole reason the defaults above are tolerable: nothing contacts a
	// provider unless the user turns review on.
	if cfg.Review.Mode != ReviewModeDeterministicOnly {
		t.Fatalf("AI review is no longer off by default: %q", cfg.Review.Mode)
	}
}

// TestDocumentedReviewerDefaultsMatchTheCode keeps the README honest about what
// it tells users they are about to spend time and money on. A default changed
// in code and not in prose is how documentation starts lying.
func TestDocumentedReviewerDefaultsMatchTheCode(t *testing.T) {
	path, err := filepath.Abs(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	readme := string(raw)
	cfg := DefaultConfig()
	for _, value := range []string{
		cfg.Providers.Codex.Model,
		cfg.Providers.Anthropic.Model,
		cfg.Providers.Codex.Effort,
	} {
		if !strings.Contains(readme, value) {
			t.Fatalf("README does not document the default %q", value)
		}
	}
	if !strings.Contains(readme, "moving alias") {
		t.Fatal("README no longer explains that a default model is a moving alias")
	}
}

// TestReadmeOffersTheNarrowEscapeBeforeTheWideOne binds a product decision that
// is easy to undo by accident while editing prose.
//
// A user who cannot build the one package they came for will find some way
// around the boundary. The cheapest to reach must be the one that costs a
// single package - building it without yay - rather than uninstall-hook, which
// costs containment on every future build until the hook is restored. If the
// wide escape is the only one documented, it becomes the one people use.
func TestReadmeOffersTheNarrowEscapeBeforeTheWideOne(t *testing.T) {
	path, err := filepath.Abs(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	readme := string(raw)

	narrow := strings.Index(readme, "Building one package without Prolewatch")
	wide := strings.Index(readme, "Deliberately remove the yay hook")
	if narrow < 0 {
		t.Fatal("the per-package escape route is no longer documented")
	}
	if wide < 0 {
		t.Fatal("the uninstall-hook escape hatch is no longer documented")
	}
	if narrow > wide {
		t.Fatal("removing the hook is offered before building a single package without yay")
	}
	// Offering the route without its cost would be worse than not offering it.
	// Matched against whitespace-collapsed, unemphasised text so that reflowing
	// a paragraph or bolding a phrase does not silently drop the warning.
	flat := strings.Join(strings.Fields(strings.ReplaceAll(readme, "*", "")), " ")
	for _, want := range []string{
		"no containment, inspection, network prompt, or integration gate",
		"aur.archlinux.org",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("the manual-build route omitted %q", want)
		}
	}
	// The absence of a global switch is the reason the narrow route exists.
	if !strings.Contains(readme, "no global override") {
		t.Error("README no longer states that there is no global override")
	}
}

// TestDocumentedCodexVersionRangeMatchesTheCode binds the supported Codex range
// to the constants that enforce it.
//
// The README names an exact range, and the range moves every time Codex ships a
// version worth supporting. Prose that repeats a constant goes stale silently:
// the code would reject a version the documentation had just told the user to
// install, and the failure would surface as "unsupported version" on a machine
// set up exactly as instructed.
func TestDocumentedCodexVersionRangeMatchesTheCode(t *testing.T) {
	path, err := filepath.Abs(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	readme := string(raw)
	for _, version := range []string{MinCodexVersion, MaxCodexVersion} {
		if !strings.Contains(readme, version) {
			t.Errorf("README does not document the supported Codex version %q", version)
		}
	}
	// The binary is hard-coded, never resolved through PATH, so a Codex
	// installed elsewhere silently is not the one that runs.
	if !strings.Contains(readme, codexHostBinary) {
		t.Errorf("README does not name the required binary path %q", codexHostBinary)
	}
	if !strings.Contains(readme, "not searched for on `PATH`") {
		t.Error("README no longer warns that the Codex path is not resolved through PATH")
	}
}
