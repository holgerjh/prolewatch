package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/safe"
	"io"
	"os"
	"strings"
	"testing"
)

func TestDispatcherHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_DISPATCH_HELPER") != "1" {
		return
	}
	raw, _ := io.ReadAll(os.Stdin)
	var request DispatchRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		os.Exit(2)
	}
	metadata := ProviderMetadata{Provider: "codex", Transport: "cli", RuntimeVersion: "codex-cli 9.0.0", Model: "gpt-5.6-sol", Effort: "high", AdapterPolicy: "test-v1"}
	response := DispatchResponse{ProtocolVersion: 1, Metadata: metadata}
	if request.Operation == "review" {
		guidance := []FindingGuidance{}
		if os.Getenv("GO_OMIT_FINDING_GUIDANCE") != "1" {
			for index, target := range request.Snapshot.GuidanceTargets {
				findingID := target.FindingID
				quote := target.AnchorText
				if index == 0 && os.Getenv("GO_MISMATCH_FINDING_GUIDANCE") == "1" {
					quote += " (wrong occurrence)"
				}
				if index == 0 && os.Getenv("GO_UNKNOWN_FINDING_GUIDANCE") == "1" {
					findingID = strings.Repeat("f", 64)
				}
				guidance = append(guidance, FindingGuidance{FindingID: findingID, Assessment: "unclear", Comment: "review the bound deterministic finding", AnchorQuote: quote})
			}
			if len(guidance) > 0 && os.Getenv("GO_DUPLICATE_FINDING_GUIDANCE") == "1" {
				guidance = append(guidance, guidance[0])
			}
		}
		findings := []ReviewFinding{}
		if os.Getenv("GO_RETURN_AI_FINDING") == "1" {
			findings = append(findings, ReviewFinding{Severity: "high", Category: "other", File: "PKGBUILD", Line: nil, Evidence: "independent", Rationale: "independent AI finding"})
		}
		response.Verdict = &Verdict{SchemaVersion: VerdictSchemaVersion, Verdict: "allow", Confidence: "high", Summary: "safe", Findings: findings, Guidance: guidance, CoverageNotes: []string{}}
	}
	_ = json.NewEncoder(os.Stdout).Encode(response)
	os.Exit(0)
}

func TestReviewerDropsOnlyGuidanceWithTheWrongAnchorQuote(t *testing.T) {
	t.Setenv("GO_WANT_DISPATCH_HELPER", "1")
	t.Setenv("GO_MISMATCH_FINDING_GUIDANCE", "1")
	t.Setenv("GO_RETURN_AI_FINDING", "1")
	record := brief.FileRecord{Path: "PKGBUILD", PathB64: brief.PathB64("PKGBUILD"), Kind: "file", SHA256: strings.Repeat("b", 64), Text: true, SelectedText: "eval first\neval second\n", BinaryMetadata: map[string]any{}}
	manifestRaw, _ := safe.CanonicalJSON([]map[string]any{record.ManifestValue()})
	line1, line2 := 1, 2
	findings := []brief.Finding{
		{Source: "deterministic", Severity: "high", Category: "obfuscation", File: "PKGBUILD", Line: &line1, Evidence: "eval", Rationale: "first review", RuleID: "first"},
		{Source: "deterministic", Severity: "high", Category: "obfuscation", File: "PKGBUILD", Line: &line2, Evidence: "eval", Rationale: "second review", RuleID: "second"},
	}
	inv := &brief.Inventory{Phase: "pre", ManifestHash: safe.SHA256Bytes(manifestRaw), Coverage: brief.Coverage{Complete: true, Notes: []string{}}, Files: []brief.FileRecord{record}, Findings: findings}
	reviewer := NewReviewer(DefaultConfig())
	reviewer.Command = []string{os.Args[0], "-test.run=TestDispatcherHelperProcess"}
	_, verdicts, err := reviewer.Review(context.Background(), "demo", "pre", inv, ReviewOptions{})
	if err != nil || len(verdicts) != 1 || len(verdicts[0].Guidance) != 1 || len(verdicts[0].Findings) != 1 {
		t.Fatalf("wrong quote did not discard only its guidance: verdicts=%+v err=%v", verdicts, err)
	}
	if verdicts[0].Guidance[0].FindingID != findingGuidanceID(findings[1]) || verdicts[0].Findings[0].Rationale != "independent AI finding" {
		t.Fatalf("valid provider output was lost with mismatched guidance: %+v", verdicts[0])
	}
	report := &Report{Findings: findings, Reviewer: ReviewerReport{Mode: ReviewModeAI, Provider: "codex", Model: "gpt-test", Verdicts: verdicts}}
	if advisory := strings.Join(findingAdvisoryLines(report, findings[0]), "\n"); !strings.Contains(advisory, "NOT PRODUCED FOR THIS REPORT") {
		t.Fatalf("inspection presented mismatched guidance: %q", advisory)
	}
	if advisory := strings.Join(findingAdvisoryLines(report, findings[1]), "\n"); !strings.Contains(advisory, "review the bound deterministic finding") {
		t.Fatalf("inspection lost correctly anchored guidance: %q", advisory)
	}
}

func TestReviewerRequiresContentBoundGuidanceForEveryHighFinding(t *testing.T) {
	record := brief.FileRecord{Path: "PKGBUILD", PathB64: brief.PathB64("PKGBUILD"), Kind: "file", SHA256: strings.Repeat("b", 64), Text: true, SelectedText: "eval command", BinaryMetadata: map[string]any{}}
	manifestRaw, _ := safe.CanonicalJSON([]map[string]any{record.ManifestValue()})
	line := 1
	finding := brief.Finding{Source: "deterministic", Severity: "high", Category: "obfuscation", File: "PKGBUILD", Line: &line, Evidence: "eval", Rationale: "indirect command execution requires review", RuleID: "indirect-execution"}
	inv := &brief.Inventory{Phase: "pre", ManifestHash: safe.SHA256Bytes(manifestRaw), Coverage: brief.Coverage{Complete: true, Notes: []string{}}, Files: []brief.FileRecord{record}, Findings: []brief.Finding{finding}}

	t.Run("bound guidance accepted", func(t *testing.T) {
		t.Setenv("GO_WANT_DISPATCH_HELPER", "1")
		reviewer := NewReviewer(DefaultConfig())
		reviewer.Command = []string{os.Args[0], "-test.run=TestDispatcherHelperProcess"}
		_, verdicts, err := reviewer.Review(context.Background(), "demo", "pre", inv, ReviewOptions{})
		if err != nil || len(verdicts) != 1 || len(verdicts[0].Guidance) != 1 || verdicts[0].Guidance[0].FindingID != findingGuidanceID(finding) {
			t.Fatalf("bound guidance was not preserved: verdicts=%+v err=%v", verdicts, err)
		}
	})

	t.Run("omitted guidance rejected", func(t *testing.T) {
		t.Setenv("GO_WANT_DISPATCH_HELPER", "1")
		t.Setenv("GO_OMIT_FINDING_GUIDANCE", "1")
		reviewer := NewReviewer(DefaultConfig())
		reviewer.Command = []string{os.Args[0], "-test.run=TestDispatcherHelperProcess"}
		if _, _, err := reviewer.Review(context.Background(), "demo", "pre", inv, ReviewOptions{}); err == nil || !strings.Contains(err.Error(), "omitted guidance") {
			t.Fatalf("provider omission was accepted: %v", err)
		}
	})

	t.Run("unknown guidance rejected", func(t *testing.T) {
		t.Setenv("GO_WANT_DISPATCH_HELPER", "1")
		t.Setenv("GO_UNKNOWN_FINDING_GUIDANCE", "1")
		reviewer := NewReviewer(DefaultConfig())
		reviewer.Command = []string{os.Args[0], "-test.run=TestDispatcherHelperProcess"}
		if _, _, err := reviewer.Review(context.Background(), "demo", "pre", inv, ReviewOptions{}); err == nil || !strings.Contains(err.Error(), "unknown deterministic finding") {
			t.Fatalf("unknown guidance was accepted: %v", err)
		}
	})

	t.Run("duplicate guidance rejected", func(t *testing.T) {
		t.Setenv("GO_WANT_DISPATCH_HELPER", "1")
		t.Setenv("GO_DUPLICATE_FINDING_GUIDANCE", "1")
		reviewer := NewReviewer(DefaultConfig())
		reviewer.Command = []string{os.Args[0], "-test.run=TestDispatcherHelperProcess"}
		if _, _, err := reviewer.Review(context.Background(), "demo", "pre", inv, ReviewOptions{}); err == nil || !strings.Contains(err.Error(), "invalid deterministic finding guidance") {
			t.Fatalf("duplicate guidance was accepted: %v", err)
		}
	})
}

func TestReviewSnapshotRejectsGuidanceTargetMutationAndDuplication(t *testing.T) {
	record := brief.FileRecord{Path: "PKGBUILD", PathB64: brief.PathB64("PKGBUILD"), Kind: "file", SHA256: strings.Repeat("b", 64), Text: true, SelectedText: "eval command", BinaryMetadata: map[string]any{}}
	manifestRaw, _ := safe.CanonicalJSON([]map[string]any{record.ManifestValue()})
	finding := brief.Finding{Source: "deterministic", Severity: "high", Category: "obfuscation", File: "PKGBUILD", Evidence: "eval", Rationale: "review", RuleID: "indirect-execution"}
	inv := &brief.Inventory{Phase: "pre", ManifestHash: safe.SHA256Bytes(manifestRaw), Coverage: brief.Coverage{Complete: true, Notes: []string{}}, Files: []brief.FileRecord{record}, Findings: []brief.Finding{finding}}
	batches, err := NewReviewer(DefaultConfig()).batches("demo", "pre", inv)
	if err != nil || len(batches) != 1 || batches[0].Validate() != nil {
		t.Fatalf("valid guidance snapshot rejected: batches=%+v err=%v", batches, err)
	}
	mutated := batches[0]
	mutated.GuidanceTargets = append([]GuidanceTarget(nil), batches[0].GuidanceTargets...)
	mutated.GuidanceTargets[0].FindingID = strings.Repeat("f", 64)
	if mutated.Validate() == nil {
		t.Fatal("mutated guidance binding accepted")
	}
	duplicated := batches[0]
	duplicated.GuidanceTargets = append(append([]GuidanceTarget(nil), batches[0].GuidanceTargets...), batches[0].GuidanceTargets[0])
	if duplicated.Validate() == nil {
		t.Fatal("duplicate guidance target accepted")
	}
	wrongAnchor := batches[0]
	wrongAnchor.GuidanceTargets = append([]GuidanceTarget(nil), batches[0].GuidanceTargets...)
	wrongAnchor.GuidanceTargets[0].AnchorText = "another occurrence"
	if wrongAnchor.Validate() == nil {
		t.Fatal("guidance target with context/anchor mismatch accepted")
	}
}

func TestGuidanceTargetsCarryExactBoundContextForRepeatedTokens(t *testing.T) {
	raw := "header\ncc_set_libc=...\neval \"$cc_set_libc\"\nmiddle\ncc_set_abi=...\neval \"$cc_set_abi\"\nfooter\n"
	record := brief.FileRecord{Path: "config.patch", PathB64: brief.PathB64("config.patch"), Kind: "file", SHA256: safe.SHA256Bytes([]byte(raw)), Text: true, SelectedText: raw, BinaryMetadata: map[string]any{}}
	line3, line6 := 3, 6
	findings := []brief.Finding{
		{Source: "deterministic", Severity: "high", Category: "obfuscation", File: "config.patch", Line: &line3, Evidence: "eval", Rationale: "review", RuleID: "indirect-execution"},
		{Source: "deterministic", Severity: "high", Category: "obfuscation", File: "config.patch", Line: &line6, Evidence: "eval", Rationale: "review", RuleID: "indirect-execution"},
	}
	targets, err := reviewGuidanceTargets(findings, []brief.FileRecord{record}, "high", nil)
	if err != nil || len(targets) != 2 {
		t.Fatalf("guidance targets=%+v err=%v", targets, err)
	}
	wants := []string{`eval "$cc_set_libc"`, `eval "$cc_set_abi"`}
	for index, target := range targets {
		context, contextErr := findingContextLines([]byte(raw), *target.Finding.Line, findingPreviewRadius)
		if contextErr != nil || target.AnchorKind != "line" || target.AnchorText != wants[index] || !equalGuidanceContext(target.Context, context) {
			t.Fatalf("target %d was not bound to the rendered occurrence: %+v context=%+v err=%v", index, target, context, contextErr)
		}
	}
}

func TestReviewOptionsKeepCarriedFindingsButOmitTheirGuidanceTargets(t *testing.T) {
	raw := "eval first\neval second\n"
	record := brief.FileRecord{Path: "PKGBUILD", PathB64: brief.PathB64("PKGBUILD"), Kind: "file", SHA256: safe.SHA256Bytes([]byte(raw)), Text: true, SelectedText: raw, SelectedReason: "mandatory", BinaryMetadata: map[string]any{}}
	manifestRaw, _ := safe.CanonicalJSON([]map[string]any{record.ManifestValue()})
	line1, line2 := 1, 2
	findings := []brief.Finding{
		{Source: "deterministic", Severity: "high", Category: "obfuscation", File: "PKGBUILD", Line: &line1, Evidence: "eval", Rationale: "first review", RuleID: "first"},
		{Source: "deterministic", Severity: "high", Category: "obfuscation", File: "PKGBUILD", Line: &line2, Evidence: "eval", Rationale: "second review", RuleID: "second"},
	}
	inv := &brief.Inventory{Phase: "post", ManifestHash: safe.SHA256Bytes(manifestRaw), Coverage: brief.Coverage{Complete: true, Notes: []string{}}, Files: []brief.FileRecord{record}, Findings: findings}
	carriedID := findingGuidanceID(findings[0])
	batches, err := NewReviewer(DefaultConfig()).batchesWithOptions("demo", "post", inv, ReviewOptions{SkipGuidanceFindingIDs: map[string]bool{carriedID: true}})
	if err != nil || len(batches) != 1 || len(batches[0].DeterministicFindings) != 2 || len(batches[0].GuidanceTargets) != 1 {
		t.Fatalf("carry option changed the scan instead of only guidance: batches=%+v err=%v", batches, err)
	}
	if batches[0].GuidanceTargets[0].FindingID != findingGuidanceID(findings[1]) {
		t.Fatalf("wrong guidance target survived carry exclusion: %+v", batches[0].GuidanceTargets)
	}
	if err := batches[0].Validate(); err != nil {
		t.Fatalf("snapshot with carried finding evidence is invalid: %v", err)
	}
}

func TestGuidanceTargetFallsBackToBoundFindingEvidence(t *testing.T) {
	finding := brief.Finding{Source: "deterministic", Severity: "high", Category: "coverage", File: ".SRCINFO", Evidence: "missing or unreadable", Rationale: "required metadata is unavailable", RuleID: "srcinfo-missing"}
	targets, err := reviewGuidanceTargets([]brief.Finding{finding}, nil, "high", nil)
	if err != nil || len(targets) != 1 || targets[0].AnchorKind != "evidence" || targets[0].AnchorText != finding.Evidence || len(targets[0].Context) != 0 {
		t.Fatalf("evidence fallback was not exact: targets=%+v err=%v", targets, err)
	}
}

func equalGuidanceContext(left, right []GuidanceContextLine) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func TestReviewerBatchesAndNormalizes(t *testing.T) {
	t.Setenv("GO_WANT_DISPATCH_HELPER", "1")
	cfg := DefaultConfig()
	reviewer := NewReviewer(cfg)
	reviewer.Command = []string{os.Args[0], "-test.run=TestDispatcherHelperProcess"}
	record := brief.FileRecord{Path: "PKGBUILD", PathB64: "UEtHQlVJTEQ=", Kind: "file", SHA256: strings.Repeat("b", 64), Text: true, SelectedText: "pkgname=demo", BinaryMetadata: map[string]any{}}
	manifestRaw, _ := safe.CanonicalJSON([]map[string]any{record.ManifestValue()})
	inv := &brief.Inventory{Phase: "pre", ManifestHash: safe.SHA256Bytes(manifestRaw), Coverage: brief.Coverage{Complete: true, Notes: []string{}}, Files: []brief.FileRecord{record}}
	metadata, verdicts, err := reviewer.Review(context.Background(), "demo", "pre", inv, ReviewOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Provider != "codex" || len(verdicts) != 1 || verdicts[0].Verdict != "allow" {
		t.Fatalf("unexpected result: %+v %+v", metadata, verdicts)
	}
	canaryMetadata, err := reviewer.Canary(context.Background())
	if err != nil || canaryMetadata != metadata {
		t.Fatalf("dispatcher canary failed: %+v %v", canaryMetadata, err)
	}
}

func TestReviewerOmitsUninspectedVendorTreeFromSnapshotManifest(t *testing.T) {
	cfg := DefaultConfig()
	reviewer := NewReviewer(cfg)
	control := brief.FileRecord{Path: "PKGBUILD", PathB64: "UEtHQlVJTEQ=", Kind: "file", SHA256: strings.Repeat("a", 64), Text: true, SelectedText: "pkgname=demo", BinaryMetadata: map[string]any{}}
	vendorPath := "src/.prolewatch-cargo-home/registry/cache/dependency.crate"
	vendor := brief.FileRecord{Path: vendorPath, PathB64: brief.PathB64(vendorPath), Kind: "file", SHA256: strings.Repeat("b", 64), BinaryMetadata: map[string]any{}}
	fullManifest := []map[string]any{control.ManifestValue(), vendor.ManifestValue()}
	fullManifestRaw, _ := safe.CanonicalJSON(fullManifest)
	inv := &brief.Inventory{
		Phase: "post", ManifestHash: safe.SHA256Bytes(fullManifestRaw), Coverage: brief.Coverage{Complete: true, Notes: []string{}},
		Files: []brief.FileRecord{control, vendor}, ManifestDiff: []brief.ManifestChange{
			{Path: control.Path, Status: "changed", PreviousSHA256: strings.Repeat("c", 64), CurrentSHA256: control.SHA256},
			{Path: vendor.Path, Status: "added", CurrentSHA256: vendor.SHA256},
		},
	}
	batches, err := reviewer.batches("demo", "post", inv)
	if err != nil || len(batches) != 1 || len(batches[0].Manifest) != 1 || len(batches[0].ManifestDiff) != 1 ||
		len(batches[0].ManifestOmissions) != 1 || batches[0].ManifestOmissions[0] != "src/" || batches[0].Validate() != nil {
		t.Fatalf("depth-zero review snapshot=%+v err=%v", batches, err)
	}
	cfg.Vendor.ScanDepth = 1
	reviewer = NewReviewer(cfg)
	batches, err = reviewer.batches("demo", "post", inv)
	if err != nil || len(batches) != 1 || len(batches[0].Manifest) != 2 || len(batches[0].ManifestDiff) != 2 ||
		len(batches[0].ManifestOmissions) != 0 || batches[0].Validate() != nil {
		t.Fatalf("depth-one review snapshot=%+v err=%v", batches, err)
	}
}

func TestSnapshotRejectsUnknownSelectedFile(t *testing.T) {
	snapshot := ReviewSnapshot{SnapshotSchemaVersion: ReviewSnapshotVersion, PackageBase: "demo", Phase: "pre", ManifestHash: strings.Repeat("0", 64), Coverage: brief.Coverage{Complete: true, Notes: []string{}}, GuidanceMinimumSeverity: "high", BatchCount: 1, Files: []SelectedFile{{File: "missing", Content: "x"}}}
	if err := snapshot.Validate(); err == nil {
		t.Fatal("unknown selected file accepted")
	}
}

func TestSnapshotRejectsLooseManifestShape(t *testing.T) {
	record := brief.FileRecord{Path: "PKGBUILD", PathB64: "UEtHQlVJTEQ=", Kind: "file", SHA256: strings.Repeat("a", 64), Text: true, BinaryMetadata: map[string]any{}}
	manifest := record.ManifestValue()
	manifest["unexpected"] = true
	snapshot := ReviewSnapshot{SnapshotSchemaVersion: ReviewSnapshotVersion, PackageBase: "demo", Phase: "pre", ManifestHash: strings.Repeat("0", 64), Coverage: brief.Coverage{Complete: true, Notes: []string{}}, GuidanceMinimumSeverity: "high", Manifest: []map[string]any{manifest}, BatchCount: 1, Files: []SelectedFile{{File: "PKGBUILD", Content: "pkgname=demo"}}}
	if err := snapshot.Validate(); err == nil {
		t.Fatal("extra manifest field was accepted")
	}
	delete(manifest, "unexpected")
	delete(manifest, "sha256")
	if err := snapshot.Validate(); err == nil {
		t.Fatal("missing manifest field was accepted")
	}
}

func TestVersionComparisonUsesMinimums(t *testing.T) {
	if compareVersions(mustVersion("2.1.205"), mustVersion(MinClaudeVersion)) != 0 {
		t.Fatal("minimum mismatch")
	}
	if compareVersions(mustVersion("2.2.0"), mustVersion(MinClaudeVersion)) <= 0 {
		t.Fatal("newer version rejected")
	}
	if got := fmt.Sprint(mustVersion("0.146.1")); got != "[0 146 1]" {
		t.Fatal(got)
	}
	if compareVersions(mustVersion("0.150.0"), mustVersion(MaxCodexVersion)) != 0 || compareVersions(mustVersion("3.0.0"), mustVersion(MaxClaudeVersion)) != 0 {
		t.Fatal("provider maximum mismatch")
	}
}
