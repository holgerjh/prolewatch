package brief

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
	sources := ParseSourceProvenance(raw, 0)
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
	got := SourceSummary(sources, SourceVerification{Checksums: "passed", PGP: "not-applicable"})
	if !strings.Contains(got, "accepted uninspected") || !strings.Contains(got, "checksums passed") {
		t.Fatalf("source summary hides policy: %q", got)
	}
}

// TestUnsupportedTransportIsReportedBeforeTheBuild covers the compatibility
// boundary the code enforced without ever stating.
//
// The classifier recognises git+, svn+, hg+, bzr+ and fossil+ as VCS
// conversations, but acquisition fetches http(s) only and the broker permits
// only ports 80 and 443. A git:// or git+ssh:// source is therefore recognised
// and unfetchable, and the user found out when acquisition failed - after the
// briefing they had already read and agreed to.
func TestUnsupportedTransportIsReportedBeforeTheBuild(t *testing.T) {
	for _, url := range []string{"https://example.com/x.tar.gz", "git+https://example.com/x.git", "local.patch"} {
		if ok, _ := SupportedSourceTransport(url); !ok {
			t.Errorf("%q is fetchable and was reported as unsupported", url)
		}
	}
	for url, scheme := range map[string]string{
		"git://example.com/x.git":     "git",
		"git+ssh://git@example.com/x": "ssh",
		"ftp://example.com/x.tar.gz":  "ftp",
	} {
		ok, reported := SupportedSourceTransport(url)
		if ok {
			t.Errorf("%q cannot be fetched by this release and was accepted", url)
			continue
		}
		if reported != scheme {
			t.Errorf("%q reported scheme %q, want %q", url, reported, scheme)
		}
	}
	findings := unsupportedTransportFindings([]SourceProvenance{
		{Name: "x.git", URL: "git+ssh://git@example.com/x"},
		{Name: "ok.tar.gz", URL: "https://example.com/ok.tar.gz"},
	})
	if len(findings) != 1 || findings[0].RuleID != "source-transport-unsupported" || findings[0].HardBlock {
		t.Fatalf("unsupported transport finding is wrong: %#v", findings)
	}
}
