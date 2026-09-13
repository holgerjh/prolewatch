package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigYAMLHardCutRejectsJSONPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("provider: codex\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), ".yaml") {
		t.Fatalf("legacy JSON path was accepted: %v", err)
	}
	if SystemConfigPath != systemConfigDefaultPath || systemConfigDefaultPath != "/etc/prolewatch/config.yaml" {
		t.Fatalf("default configuration path is not YAML: %q", SystemConfigPath)
	}
}

func TestConfigYAMLIgnoresOldJSONFile(t *testing.T) {
	directory := t.TempDir()
	legacy := filepath.Join(directory, "config.json")
	if err := os.WriteFile(legacy, []byte("not a policy"), 0o600); err != nil {
		t.Fatal(err)
	}
	shipped, err := os.ReadFile(filepath.Join("..", "..", "share", "default-config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(directory, "config.yaml")
	if err := os.WriteFile(current, shipped, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(current); err != nil {
		t.Fatalf("old JSON file affected YAML loading: %v", err)
	}
}

func TestConfigYAMLRejectsAmbiguousOrExtendedSyntax(t *testing.T) {
	cases := map[string]string{
		"duplicate root key":   "provider: codex\nprovider: ollama\n",
		"duplicate nested key": "providers:\n  codex:\n    model: one\n    model: two\n",
		"mixed-case key":       "provider: codex\nProvider: ollama\n",
		"unknown key":          "unrecognised_option: true\n",
		"anchor":               "provider: &chosen codex\n",
		"alias":                "provider: &chosen codex\nterminal:\n  style: *chosen\n",
		"merge":                "terminal:\n  <<: {style: brand}\n",
		"multiple documents":   "provider: codex\n---\nprovider: ollama\n",
		"non-string key":       "1: value\n",
		"float":                "review:\n  timeout_seconds: 1.5\n",
		"nondecimal integer":   "review:\n  timeout_seconds: 0x10\n",
		"explicit custom tag":  "provider: !custom codex\n",
		"non-mapping document": "- provider\n- codex\n",
		"empty document":       "# comments only\n",
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeConfigYAML([]byte(document)); err == nil {
				t.Fatal("unsafe or invalid YAML configuration was accepted")
			}
		})
	}
}
