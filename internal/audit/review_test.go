package audit

import (
	"context"
	"encoding/json"
	"fmt"
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
		response.Verdict = &Verdict{SchemaVersion: 1, Verdict: "allow", Confidence: "high", Summary: "safe", Findings: []ReviewFinding{}, CoverageNotes: []string{}}
	}
	_ = json.NewEncoder(os.Stdout).Encode(response)
	os.Exit(0)
}

func TestReviewerBatchesAndNormalizes(t *testing.T) {
	t.Setenv("GO_WANT_DISPATCH_HELPER", "1")
	cfg := DefaultConfig()
	reviewer := NewReviewer(cfg)
	reviewer.Command = []string{os.Args[0], "-test.run=TestDispatcherHelperProcess"}
	record := FileRecord{Path: "PKGBUILD", PathB64: "UEtHQlVJTEQ=", Kind: "file", SHA256: strings.Repeat("b", 64), Text: true, SelectedText: "pkgname=demo", BinaryMetadata: map[string]any{}}
	manifestRaw, _ := CanonicalJSON([]map[string]any{record.ManifestValue()})
	inv := &Inventory{Phase: "pre", ManifestHash: SHA256Bytes(manifestRaw), Coverage: Coverage{Complete: true, Notes: []string{}}, Files: []FileRecord{record}}
	metadata, verdicts, err := reviewer.Review(context.Background(), "demo", "pre", inv)
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
	control := FileRecord{Path: "PKGBUILD", PathB64: "UEtHQlVJTEQ=", Kind: "file", SHA256: strings.Repeat("a", 64), Text: true, SelectedText: "pkgname=demo", BinaryMetadata: map[string]any{}}
	vendorPath := "src/.prolewatch-cargo-home/registry/cache/dependency.crate"
	vendor := FileRecord{Path: vendorPath, PathB64: pathB64(vendorPath), Kind: "file", SHA256: strings.Repeat("b", 64), BinaryMetadata: map[string]any{}}
	fullManifest := []map[string]any{control.ManifestValue(), vendor.ManifestValue()}
	fullManifestRaw, _ := CanonicalJSON(fullManifest)
	inv := &Inventory{
		Phase: "post", ManifestHash: SHA256Bytes(fullManifestRaw), Coverage: Coverage{Complete: true, Notes: []string{}},
		Files: []FileRecord{control, vendor}, ManifestDiff: []ManifestChange{
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
	snapshot := ReviewSnapshot{SnapshotSchemaVersion: ReviewSnapshotVersion, PackageBase: "demo", Phase: "pre", ManifestHash: strings.Repeat("0", 64), Coverage: Coverage{Complete: true, Notes: []string{}}, BatchCount: 1, Files: []SelectedFile{{File: "missing", Content: "x"}}}
	if err := snapshot.Validate(); err == nil {
		t.Fatal("unknown selected file accepted")
	}
}

func TestSnapshotRejectsLooseManifestShape(t *testing.T) {
	record := FileRecord{Path: "PKGBUILD", PathB64: "UEtHQlVJTEQ=", Kind: "file", SHA256: strings.Repeat("a", 64), Text: true, BinaryMetadata: map[string]any{}}
	manifest := record.ManifestValue()
	manifest["unexpected"] = true
	snapshot := ReviewSnapshot{SnapshotSchemaVersion: ReviewSnapshotVersion, PackageBase: "demo", Phase: "pre", ManifestHash: strings.Repeat("0", 64), Coverage: Coverage{Complete: true, Notes: []string{}}, Manifest: []map[string]any{manifest}, BatchCount: 1, Files: []SelectedFile{{File: "PKGBUILD", Content: "pkgname=demo"}}}
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
	if compareVersions(mustVersion("0.147.0"), mustVersion(MaxCodexVersion)) != 0 || compareVersions(mustVersion("3.0.0"), mustVersion(MaxClaudeVersion)) != 0 {
		t.Fatal("provider maximum mismatch")
	}
}
