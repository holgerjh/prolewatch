package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validTestCleanRootManifest() *CleanRootManifest {
	manifest := &CleanRootManifest{SchemaVersion: cleanRootManifestSchemaVersion, Generation: "1001-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		BaseManifestHash: strings.Repeat("b", 64), PolicyFingerprint: strings.Repeat("c", 64),
		StagingBackend: cleanRootStagingBackend, HookPolicy: cleanRootHookPolicy, ArtifactTrust: cleanRootArtifactTrust,
		Packages: []string{"base-devel=1"}, ArtifactHashes: []string{}, PacmanConfigHash: strings.Repeat("d", 64),
		PacmanVersion: "pacman test", MkarchrootVersion: "mkarchroot test"}
	copy := *manifest
	raw, _ := CanonicalJSON(copy)
	manifest.ManifestSHA256 = SHA256Bytes(raw)
	return manifest
}

func TestDecodeYayContextStrictAndBounded(t *testing.T) {
	raw := `{"version":"1:2-3","last_modified":1700000000,"installed":true,"packages":[{"name":"demo","version":"1:2-3","local_version":"1:2-2","reason":"explicit","upgrade":true,"devel":false}],"depends":["glibc"],"makedepends":["go"],"checkdepends":[]}`
	context, err := DecodeYayContext(raw)
	if err != nil {
		t.Fatal(err)
	}
	if context.Version != "1:2-3" || len(context.Packages) != 1 || context.Packages[0].Name != "demo" {
		t.Fatalf("unexpected context: %#v", context)
	}
	for _, invalid := range []string{
		`{"version":"x","last_modified":0,"installed":false,"packages":[],"depends":[],"makedepends":[],"checkdepends":[],"extra":true}`,
		`{"version":"x","last_modified":-1,"installed":false,"packages":[],"depends":[],"makedepends":[],"checkdepends":[]}`,
		strings.Repeat("x", maxYayContextBytes+1),
	} {
		if _, err := DecodeYayContext(invalid); err == nil {
			t.Fatalf("accepted invalid context: %.80q", invalid)
		}
	}
}

func TestCompareManifests(t *testing.T) {
	record := func(name, hash string) map[string]any {
		return FileRecord{Path: name, PathB64: pathB64(name), Kind: "file", SHA256: hash, Text: true, BinaryMetadata: map[string]any{}}.ManifestValue()
	}
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)
	changes := CompareManifests(
		[]map[string]any{record("changed", a), record("deleted", a)},
		[]map[string]any{record("added", b), record("changed", b)},
	)
	if len(changes) != 3 || changes[0].Status != "added" || changes[1].Status != "changed" || changes[2].Status != "deleted" {
		t.Fatalf("unexpected changes: %#v", changes)
	}
	for _, change := range changes {
		if err := change.Validate(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestManifestHistoryCannotBypassCurrentScan(t *testing.T) {
	scanner := NewScanner(DefaultConfig())
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "PKGBUILD"), []byte("pkgname=demo\npkgver=1\npkgrel=1\npackage() { sudo install payload \"$pkgdir/usr/bin/payload\"; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".SRCINFO"), []byte("pkgbase = demo\npkgver = 1\npkgrel = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	inv, err := scanner.ScanDirectory(root, "pre")
	if err != nil {
		t.Fatal(err)
	}
	if !structuralBlock(inv) || findingByRule(inv.Findings, "shell-privilege-command") == nil {
		t.Fatalf("current malicious content was not independently blocked: %#v", inv.Findings)
	}
}
