package audit

import (
	"strings"
	"testing"
)

func TestParseSourceProvenanceBindings(t *testing.T) {
	commit := strings.Repeat("a", 40)
	raw := []byte("pkgbase = demo\n" +
		"source = archive::https://vendor.example/release.tar.xz\n" +
		"source = https://vendor.example/release.tar.xz.sig\n" +
		"source = git+https://vendor.example/repository.git#commit=" + commit + "\n" +
		"source = git+https://vendor.example/mutable.git#branch=main\n" +
		"sha256sums = " + strings.Repeat("b", 64) + "\n" +
		"sha256sums = SKIP\n" +
		"sha256sums = SKIP\n" +
		"sha256sums = SKIP\n")
	sources := parseSourceProvenance(raw, 0)
	if len(sources) != 4 {
		t.Fatalf("sources=%#v", sources)
	}
	byName := map[string]SourceProvenance{}
	for _, source := range sources {
		byName[source.Name] = source
	}
	if source := byName["archive"]; source.Kind != SourceKindArchive || source.Binding != "fixed-digest" || source.DeclaredAlgorithm != "sha256" || source.ContentInspected {
		t.Fatalf("fixed archive provenance=%#v", source)
	}
	if source := byName["release.tar.xz.sig"]; source.Kind != SourceKindSignature || source.Binding != "signature-companion" {
		t.Fatalf("signature provenance=%#v", source)
	}
	if source := byName["repository"]; source.Kind != SourceKindVCS || source.Binding != "vcs-commit" || source.DeclaredDigest != commit {
		t.Fatalf("fixed VCS provenance=%#v", source)
	}
	if source := byName["mutable"]; source.Kind != SourceKindVCS || source.Binding != "mutable-vcs" {
		t.Fatalf("mutable VCS provenance=%#v", source)
	}
	findings := sourceProvenanceFindings(sources)
	if len(findings) != 1 || findings[0].RuleID != "vendor-provenance-weak" || findings[0].HardBlock || findings[0].Severity != "medium" {
		t.Fatalf("weak provenance policy=%#v", findings)
	}
}

func TestSourceSummaryMakesTrustPolicyExplicit(t *testing.T) {
	sources := []SourceProvenance{{Name: "source.tar", Kind: SourceKindArchive, URL: "https://vendor.example/source.tar", Transport: "https", Binding: "fixed-digest", ScanDepth: 0}}
	got := sourceSummary(sources, SourceVerification{Checksums: "passed", PGP: "not-applicable"})
	if !strings.Contains(got, "accepted uninspected") || !strings.Contains(got, "checksums passed") {
		t.Fatalf("source summary hides policy: %q", got)
	}
}
