package brief

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestAdditionalSecurityBoundaryUtilities(t *testing.T) {
	root := t.TempDir()
	writePackageFixture(t, root)
	sourceInfo, err := os.ReadFile(filepath.Join(root, ".SRCINFO"))
	if err != nil {
		t.Fatal(err)
	}
	extractable := ParseExtractableSources(sourceInfo, 1024*1024)
	if !extractable["local.patch"] {
		t.Fatalf("extractable source was not parsed: %#v", extractable)
	}
	if got := makepkgSourceName("https://example.invalid/payload.tar?download=1#fragment"); got != "payload.tar" {
		t.Fatalf("makepkg source filename mismatch: %q", got)
	}
	for input, expected := range map[string]string{
		"alias::https://example.invalid/value":        "alias",
		"git+https://example.invalid/repo.git#tag=v1": "repo",
		"fossil+https://example.invalid/repo":         "repo.fossil",
		"svn+https://example.invalid/project/":        "project",
	} {
		if got := makepkgSourceName(input); got != expected {
			t.Errorf("makepkgSourceName(%q)=%q, want %q", input, got, expected)
		}
	}
	raw := tarBytes(t, map[string][]byte{"usr/bin/blob": append([]byte{0x7f, 'E', 'L', 'F', 2, 1}, bytes.Repeat([]byte{0}, 40)...)})
	result := ScanArchive(bytes.NewReader(raw), "binary.pkg.tar", DefaultConfig(), RuleEngine{}, 0)
	if !result.Supported || len(result.Selected) == 0 {
		t.Fatalf("bounded binary archive inspection failed: %+v", result)
	}
	for kind, expected := range map[uint32]string{syscall.S_IFIFO: "fifo", syscall.S_IFCHR: "char-device", syscall.S_IFBLK: "block-device", syscall.S_IFSOCK: "socket", 0: "special"} {
		if FileKind(kind) != expected {
			t.Errorf("file kind %#o=%q, want %q", kind, FileKind(kind), expected)
		}
	}
}

func tarBytes(t *testing.T, members map[string][]byte) []byte {
	t.Helper()
	var raw bytes.Buffer
	writer := tar.NewWriter(&raw)
	for name, body := range members {
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return raw.Bytes()
}

func TestArchiveMetadataAndBinaryFormatBranches(t *testing.T) {
	if !findingIDs(artifactMetadataFindings(".PKGINFO", "pkgname = x\n", "pkg!/.PKGINFO"))["pkginfo-missing"] {
		t.Fatal("incomplete PKGINFO was not reported")
	}
	if !findingIDs(artifactMetadataFindings(".BUILDINFO", "format = 2\n", "pkg!/.BUILDINFO"))["buildinfo-incomplete"] {
		t.Fatal("incomplete BUILDINFO was not reported")
	}
	if !findingIDs(artifactMetadataFindings(".MTREE", "./x mode=4755\n", "pkg!/.MTREE"))["mtree-privileged"] {
		t.Fatal("privileged MTREE was not reported")
	}
	result := ArchiveScan{}
	archiveModeFindings("usr/bin/demo", 0o4755, map[string]string{"SCHILY.xattr.security.capability": "x"}, "pkg!/usr/bin/demo", &result)
	ids := findingIDs(result.Findings)
	if !ids["artifact-setid"] || !ids["artifact-capability"] {
		t.Fatalf("archive modes were not reported: %#v", result.Findings)
	}
	pe := make([]byte, 128)
	copy(pe, "MZ")
	pe[0x3c] = 64
	copy(pe[64:], []byte{'P', 'E', 0, 0, 0x64, 0x86, 2, 0})
	metadata, finding := binaryMetadata("demo.exe", pe, 128)
	if finding != nil || metadata["format"] != "PE" {
		t.Fatalf("PE metadata failed: %#v %#v", metadata, finding)
	}
	mach := make([]byte, 32)
	copy(mach, []byte{0xfe, 0xed, 0xfa, 0xcf})
	metadata, finding = binaryMetadata("demo", mach, 32)
	if finding != nil || metadata["format"] != "Mach-O" {
		t.Fatalf("Mach-O metadata failed: %#v %#v", metadata, finding)
	}
	if _, finding := binaryMetadata("bad.exe", []byte("MZ"), 2); finding == nil {
		t.Fatal("truncated PE was accepted")
	}
	for name, head := range map[string][]byte{"bzip2": []byte("BZh"), "xz": {0xfd, '7', 'z', 'X', 'Z'}, "zstd": {0x28, 0xb5, 0x2f, 0xfd}} {
		if format := ArchiveFormat(head); format != name {
			t.Errorf("archive format=%q, want %q", format, name)
		}
	}
	for _, value := range []string{"", "/absolute", "../escape", "a/../../escape", "nul\x00name"} {
		if !unsafeArchiveMember(value) {
			t.Errorf("unsafe archive member accepted: %q", value)
		}
	}
	if !archiveLinkEscapes("a/link", "/etc/passwd") || !archiveLinkEscapes("a/link", "../../escape") {
		t.Fatal("archive link escape accepted")
	}
	cfg := DefaultConfig()
	for index, setup := range []func(*ArchiveScan, *Config) int64{
		func(*ArchiveScan, *Config) int64 { return -1 },
		func(r *ArchiveScan, c *Config) int64 { c.Limits.MaxArchiveEntries = 0; return 0 },
		func(r *ArchiveScan, c *Config) int64 { c.Limits.MaxArchiveUnpackedBytes = 0; return 1 },
	} {
		candidate, candidateCfg := ArchiveScan{Complete: true}, cfg
		size := setup(&candidate, &candidateCfg)
		if checkArchiveLimits(&candidate, size, candidateCfg, "member") || candidate.Complete {
			t.Errorf("archive limit mutation %d accepted: %+v", index, candidate)
		}
	}
}

func TestStructuredPacmanMetadataDoesNotRunCodeSignatures(t *testing.T) {
	buildInfo := []byte("format = 2\nbuilddate = 1787691600\nbuildenv = eval\ninstalled = curl-8.0-1\n")
	metadata := ScanArchive(bytes.NewReader(tarBytes(t, map[string][]byte{".BUILDINFO": buildInfo})), "demo.pkg.tar", DefaultConfig(), RuleEngine{}, 0)
	ids := findingIDs(metadata.Findings)
	if ids["dynamic-execution"] || ids["unexpected-network-client"] || ids["buildinfo-incomplete"] {
		t.Fatalf("structured BUILDINFO was treated as executable code: %#v", metadata.Findings)
	}

	scriptlet := ScanArchive(bytes.NewReader(tarBytes(t, map[string][]byte{".INSTALL": []byte("eval \"$hook\"\ncurl https://example.invalid\n")})), "demo.pkg.tar", DefaultConfig(), RuleEngine{}, 0)
	ids = findingIDs(scriptlet.Findings)
	if !ids["dynamic-execution"] || !ids["unexpected-network-client"] {
		t.Fatalf("executable package scriptlet escaped code signatures: %#v", scriptlet.Findings)
	}
}

// Every aggregate scanner budget must fail closed at this package boundary.
func TestEveryAggregateScannerBudgetFailsClosed(t *testing.T) {
	cfg := DefaultConfig()
	scanner := NewScanner(cfg)
	cases := []*Inventory{
		{started: time.Now().Add(-time.Duration(cfg.Limits.ScanTimeoutSeconds+1) * time.Second)},
		{Findings: make([]Finding, cfg.Limits.MaxFindings+1)},
		{Coverage: Coverage{ArchivesSeen: cfg.Limits.MaxArchives + 1}},
		{Coverage: Coverage{ArchiveEntries: cfg.Limits.MaxArchiveEntries + 1}},
		{Coverage: Coverage{ArchiveUnpackedBytes: cfg.Limits.MaxArchiveUnpackedBytes + 1}},
	}
	for index, inventory := range cases {
		if err := scanner.checkBudget(inventory); err == nil {
			t.Errorf("scanner budget mutation %d accepted", index)
		}
	}
	for reason, expected := range map[string]int{"mandatory": 0, "archive-member": 1, "binary-metadata": 2, "executable": 3, "other": 4} {
		if got := selectionPriority(reason); got != expected {
			t.Errorf("selection priority %q=%d, want %d", reason, got, expected)
		}
	}
	if got := displayPath(string([]byte{'a', 0xff})); got != `a\xff` {
		t.Fatalf("invalid path display=%q", got)
	}
}
