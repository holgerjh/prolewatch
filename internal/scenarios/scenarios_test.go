package scenarios

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecurityScenarioCorpus(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "security-scenarios"))
	if err != nil {
		t.Fatal(err)
	}
	results, err := Run(root, "")
	if err != nil {
		t.Fatal(err)
	}
	required := map[string]bool{
		"aur-2018-remote-pipeline": false, "aur-2025-remote-source": false,
		"aur-2026-install-ecosystem": false, "aur-2026-atomic-arch": false,
		"aur-2026-native-binary": false, "aur-2026-native-sudo": false,
		"baseline-safe": false, "network-warning": false, "structural-escapes": false,
	}
	for _, result := range results {
		if _, ok := required[result.Manifest.ID]; ok {
			required[result.Manifest.ID] = true
		}
		if !result.Passed() {
			t.Errorf("scenario %s failed: %v", result.Manifest.ID, result.Problems)
		}
	}
	for id, found := range required {
		if !found {
			t.Errorf("required scenario %s is missing", id)
		}
	}
}

func TestSecurityScenarioFilter(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "security-scenarios"))
	if err != nil {
		t.Fatal(err)
	}
	results, err := Run(root, "aur-2026-native-binary")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Manifest.ID != "aur-2026-native-binary" || !results[0].Passed() {
		t.Fatalf("unexpected filtered result: %+v", results)
	}
	if _, err := Run(root, "missing-scenario"); err == nil {
		t.Fatal("unknown scenario filter was accepted")
	}
}

func TestSecurityScenarioCLI(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "testdata", "security-scenarios"))
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if status := RunCLI([]string{"--root", root, "--scenario", "baseline-safe"}, &stdout, &stderr); status != 0 {
		t.Fatalf("scenario CLI failed with %d: %s", status, stderr.String())
	}
	if !strings.Contains(stdout.String(), "PASS baseline-safe") || !strings.Contains(stdout.String(), "1 scenario(s), 0 failure(s)") {
		t.Fatalf("unexpected scenario CLI output: %s", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	if status := RunCLI([]string{"unexpected"}, &stdout, &stderr); status != 2 || !strings.Contains(stderr.String(), "accepts flags only") {
		t.Fatalf("positional argument status=%d stderr=%q", status, stderr.String())
	}
}

func TestManifestValidationRejectsUnsafeDefinitions(t *testing.T) {
	trueValue, falseValue := true, false
	valid := Manifest{
		SchemaVersion: 1, ID: "safe-case", Title: "Safe", Incident: "Control", Reference: "docs/security-scenarios.md#scenario-map", Claim: "control", Phase: "pre",
		Expected:       Expected{Decision: "allow", ApprovalEligible: &falseValue, CoverageComplete: &trueValue, ExactRuleIDs: true, RequiredFindings: []ExpectedFinding{}},
		GeneratedFiles: []GeneratedFile{},
	}
	if err := valid.validate("safe-case"); err != nil {
		t.Fatal(err)
	}
	invalidID := valid
	invalidID.ID = "../escape"
	if err := invalidID.validate("safe-case"); err == nil {
		t.Fatal("escaping id was accepted")
	}
	missingExpectation := valid
	missingExpectation.Expected.CoverageComplete = nil
	if err := missingExpectation.validate("safe-case"); err == nil {
		t.Fatal("missing explicit coverage expectation was accepted")
	}
	unsafeGenerated := valid
	unsafeGenerated.GeneratedFiles = []GeneratedFile{{Path: "../escape", Kind: "minimal-elf"}}
	if err := unsafeGenerated.validate("safe-case"); err == nil {
		t.Fatal("escaping generated path was accepted")
	}
}

func TestFixtureSafetyRejectsRealURLsAndExecutables(t *testing.T) {
	if err := validateFixtureURLs("PKGBUILD", []byte("curl https://payload.example.invalid/file\n")); err != nil {
		t.Fatal(err)
	}
	if err := validateFixtureURLs("PKGBUILD", []byte("curl https://example.com/file\n")); err == nil {
		t.Fatal("non-reserved network target was accepted")
	}
	source := t.TempDir()
	destination := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "script.sh"), []byte("harmless\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := copyFixtureTree(source, destination); err == nil || !strings.Contains(err.Error(), "non-executable") {
		t.Fatalf("executable fixture was not rejected: %v", err)
	}
}

func TestStrictManifestRejectsUnknownFields(t *testing.T) {
	root := t.TempDir()
	scenarioRoot := filepath.Join(root, "safe-case")
	if err := os.MkdirAll(filepath.Join(scenarioRoot, packageDirectory), 0o700); err != nil {
		t.Fatal(err)
	}
	raw := `{
  "schema_version": 1,
  "id": "safe-case",
  "title": "Safe",
  "incident": "Control",
  "reference": "docs/security-scenarios.md#scenario-map",
  "claim": "control",
  "phase": "pre",
  "expected": {"decision":"allow","approval_eligible":false,"coverage_complete":true,"exact_rule_ids":true,"required_findings":[]},
  "generated_files": [],
  "unexpected": true
}`
	if err := os.WriteFile(filepath.Join(scenarioRoot, manifestName), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadManifest(scenarioRoot, "safe-case"); err == nil {
		t.Fatal("unknown manifest field was accepted")
	}
}
