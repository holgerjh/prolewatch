package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/safe"
)

func findingPreviewFixture(t *testing.T, root, name string, raw []byte, line int) *Report {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	record := brief.FileRecord{Path: name, PathB64: brief.PathB64(name), Kind: "file", Mode: 0o600,
		Size: int64(len(raw)), SHA256: safe.SHA256Bytes(raw), Text: true, SelectedReason: "mandatory", BinaryMetadata: map[string]any{}}
	finding := brief.Finding{Source: "deterministic", Severity: "high", Category: "obfuscation", File: name, Line: &line,
		Evidence: "eval", Rationale: "indirect command execution requires review", RuleID: "indirect-execution"}
	return &Report{Phase: "pre", Manifest: []map[string]any{record.ManifestValue()}, Findings: []brief.Finding{finding},
		Reviewer: ReviewerReport{Mode: ReviewModeAI, Provider: "codex", Model: "gpt-test", Verdicts: []Verdict{{
			Guidance: []FindingGuidance{{FindingID: findingGuidanceID(finding), Assessment: "likely-benign", Comment: "This is a generated portability probe.", AnchorQuote: `eval "$cmd" # \u001b[2JFORGED`}},
		}}}}
}

func TestFindingPreviewIsReadOnlyManifestBoundAndTerminalSafe(t *testing.T) {
	root := t.TempDir()
	raw := []byte("before\ncontext\neval \"$cmd\" # \x1b[2JFORGED\nafter\nend\n")
	report := findingPreviewFixture(t, root, "config.patch", raw, 3)
	renderer := terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{Interactive: true, Unicode: true})

	rendered := renderFindingPreview(report, root, "high", renderer)
	for _, want := range []string{"READ-ONLY FINDING INSPECTION", "HIGH (deterministic) · indirect command execution requires review", "config.patch:3 · obfuscation", "SHA-256 verified", "Local file (untrusted) · " + filepath.Join(root, "config.patch") + ":3", `\u001b[2JFORGED`, ">      3", "AI GUIDANCE · codex/gpt-test", "likely benign · This is a generated portability probe.", "external tool leaves this verified read-only view"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("preview omitted %q:\n%s", want, rendered)
		}
	}
	lowLine := 1
	report.Findings = append(report.Findings, brief.Finding{Source: "deterministic", Severity: "low", Category: "integrity", File: "config.patch", Line: &lowLine, Rationale: "must not be inspected"})
	if rendered = renderFindingPreview(report, root, "high", renderer); strings.Contains(rendered, "must not be inspected") {
		t.Fatalf("LOW finding appeared in blocking-finding inspection: %q", rendered)
	}
	mediumLine := 2
	report.Findings = append(report.Findings, brief.Finding{Source: "deterministic", Severity: "medium", Category: "other", File: "config.patch", Line: &mediumLine, Rationale: "medium policy finding"})
	if rendered = renderFindingPreview(report, root, "medium", renderer); !strings.Contains(rendered, "medium policy finding") || strings.Contains(rendered, "must not be inspected") {
		t.Fatalf("MEDIUM threshold inspection did not follow policy: %q", rendered)
	}
	if strings.Contains(rendered, "\x1b[2JFORGED") {
		t.Fatalf("package text injected terminal controls: %q", rendered)
	}
	if strings.Contains(rendered, "ADVISORY, NOT SOURCE CODE") || !strings.Contains(rendered, "This is a generated portability probe.\n│") {
		t.Fatalf("AI guidance label or spacing is noisy: %q", rendered)
	}

	changed := bytes.Replace(raw, []byte("$cmd"), []byte("$bad"), 1)
	if err := os.WriteFile(filepath.Join(root, "config.patch"), changed, 0o600); err != nil {
		t.Fatal(err)
	}
	rendered = renderFindingPreview(report, root, "high", renderer)
	if !strings.Contains(rendered, "no longer matches this report") || strings.Contains(rendered, "$bad") {
		t.Fatalf("changed content was displayed as reviewed context: %q", rendered)
	}
}

func TestFindingPreviewCannotEscapeTheScannedRoot(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	raw := []byte("host-only\n")
	if err := os.WriteFile(outside, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	line := 1
	record := brief.FileRecord{Path: "claimed", PathB64: brief.PathB64("../outside"), Kind: "file", Mode: 0o600,
		Size: int64(len(raw)), SHA256: safe.SHA256Bytes(raw), Text: true, SelectedReason: "mandatory", BinaryMetadata: map[string]any{}}
	report := &Report{Phase: "pre", Manifest: []map[string]any{record.ManifestValue()},
		Findings: []brief.Finding{{Source: "deterministic", Severity: "high", Category: "other", File: "claimed", Line: &line, Rationale: "review"}}}
	rendered := renderFindingPreview(report, root, "high", terminalRenderer{})
	if !strings.Contains(rendered, "no longer matches this report") || strings.Contains(rendered, "host-only") {
		t.Fatalf("escaping manifest path exposed outside content: %q", rendered)
	}
}

func TestFindingPreviewUsesTheMostCautiousBoundGuidance(t *testing.T) {
	root := t.TempDir()
	report := findingPreviewFixture(t, root, "PKGBUILD", []byte("eval command\n"), 1)
	findingID := findingGuidanceID(report.Findings[0])
	report.Reviewer.Verdicts = []Verdict{
		{Guidance: []FindingGuidance{{FindingID: findingID, Assessment: "likely-benign", Comment: "ordinary generated code", AnchorQuote: "eval command"}}},
		{Guidance: []FindingGuidance{{FindingID: findingID, Assessment: "concerning", Comment: "the command is assembled from mutable input", AnchorQuote: "eval command"}}},
	}
	rendered := renderFindingPreview(report, root, "high", terminalRenderer{})
	if !strings.Contains(rendered, "concerning · the command is assembled from mutable input") || strings.Contains(rendered, "ordinary generated code") {
		t.Fatalf("inspection did not select the most cautious guidance: %q", rendered)
	}
}

func TestFindingPreviewShowsPendingBeforeCarriedContext(t *testing.T) {
	root := t.TempDir()
	raw := []byte("new decision line\npreviously approved line\n")
	path := filepath.Join(root, "PKGBUILD")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	record := brief.FileRecord{Path: "PKGBUILD", PathB64: brief.PathB64("PKGBUILD"), Kind: "file", Mode: 0o600,
		Size: int64(len(raw)), SHA256: safe.SHA256Bytes(raw), Text: true, SelectedReason: "mandatory", BinaryMetadata: map[string]any{}}
	pendingLine, carriedLine := 1, 2
	pending := brief.Finding{Source: "deterministic", Severity: "high", Category: "other", File: "PKGBUILD", Line: &pendingLine, Evidence: "new", Rationale: "new decision", RuleID: "new"}
	carried := brief.Finding{Source: "deterministic", Severity: "critical", Category: "other", File: "PKGBUILD", Line: &carriedLine, Evidence: "old", Rationale: "old decision", RuleID: "old"}
	report := &Report{
		Phase: "post", Manifest: []map[string]any{record.ManifestValue()}, Findings: []brief.Finding{carried, pending},
		Reviewer:        ReviewerReport{Mode: ReviewModeAI, Provider: "codex", Model: "gpt-test", Verdicts: []Verdict{{Guidance: []FindingGuidance{{FindingID: findingGuidanceID(pending), Assessment: "unclear", Comment: "review this new occurrence", AnchorQuote: "new decision line"}}}}},
		CarriedDecision: &CarriedDecision{Findings: []CarriedFindingBinding{{FindingID: findingGuidanceID(carried), Path: "PKGBUILD", ManifestEntryHash: strings.Repeat("a", 64)}}},
	}
	renderer := terminalRendererWithCapabilities(&bytes.Buffer{}, terminalCapabilities{Interactive: true, Unicode: true, Color: terminalColorTrue})
	rendered := renderFindingPreview(report, root, "high", renderer)
	pendingAt := strings.Index(rendered, "HIGH (deterministic) · new decision")
	carriedGroupAt := strings.Index(rendered, "Previously approved finding context · exact bytes unchanged")
	carriedAt := strings.Index(rendered, "CRITICAL (deterministic · approved at recipe gate) · old decision")
	if pendingAt < 0 || carriedGroupAt < 0 || carriedAt < 0 || !(pendingAt < carriedGroupAt && carriedGroupAt < carriedAt) {
		t.Fatalf("inspection did not group unresolved context before carried context:\n%s", rendered)
	}
	if strings.Count(rendered, "AI GUIDANCE") != 1 || !strings.Contains(rendered, "review this new occurrence") {
		t.Fatalf("inspection requested or invented fresh guidance for carried context:\n%s", rendered)
	}
	if !strings.Contains(rendered, "previously approved line") || !strings.Contains(rendered, "exact bytes unchanged") {
		t.Fatalf("inspection hid the carried context:\n%s", rendered)
	}
}
