package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/safe"
)

// writeExternalSourceFixture is the layout production actually produces: the
// recipe in the checkout, and the acquired archive only in the transaction
// source store. Every existing source test writes the archive into the checkout,
// which is the layout that stopped being true when acquisition moved SRCDEST out
// of the build directory.
func writeExternalSourceFixture(t *testing.T, checkout string, archive []byte) string {
	t.Helper()
	digest := safe.SHA256Bytes(archive)
	pkgbuild := "pkgbase=demo\npkgver=1\npkgrel=1\nsource=('https://vendor.example/source.tar')\nsha256sums=('" + digest + "')\n"
	srcinfo := "pkgbase = demo\npkgver = 1\npkgrel = 1\nsource = https://vendor.example/source.tar\nsha256sums = " + digest + "\n"
	for name, body := range map[string][]byte{"PKGBUILD": []byte(pkgbuild), ".SRCINFO": []byte(srcinfo)} {
		if err := os.WriteFile(filepath.Join(checkout, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	store, err := transactionSourceDir(checkout)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, "source.tar"), archive, 0o600); err != nil {
		t.Fatal(err)
	}
	return store
}

// TestPostScanFindsSourcesInTheTransactionStore is the regression for a defect
// that made the product unusable on ordinary packages.
//
// Trusted acquisition writes declared remote sources to the transaction source
// store and binds it as SRCDEST. `makepkg --verifysource` exits before
// extraction, and extraction is what would have linked those files back into the
// checkout - so at AURPostDownload the checkout does not contain them. The post
// scan looked only at the checkout, found every declared extractable source
// absent, and raised `extractable-source-missing`, which is a hard block no
// approval can cross. That is every AUR package with a remote source.
func TestPostScanFindsSourcesInTheTransactionStore(t *testing.T) {
	withStateAndShare(t)
	checkout := t.TempDir()
	archive := vendorTarBytes(t, map[string][]byte{"safe.txt": []byte("safe\n")})
	writeExternalSourceFixture(t, checkout, archive)

	service, err := NewAuditService(context.Background(), aiConfig(), &fakeReviewer{})
	if err != nil {
		t.Fatal(err)
	}
	post, status, err := service.ScanDirectory(context.Background(), "post", checkout, "demo")
	if err != nil {
		t.Fatalf("post scan failed: %v", err)
	}
	for _, finding := range post.Findings {
		if finding.RuleID == "extractable-source-missing" {
			t.Fatalf("an acquired source in the transaction store was reported absent: %+v", finding)
		}
	}
	if status != 0 {
		t.Fatalf("an ordinary package with one remote source was blocked: status=%d summary=%q", status, post.Summary)
	}
	// The arrived bytes are the point of the post phase: their digest has to
	// reach the report, or the decision is about material nobody hashed.
	if len(post.Sources) != 1 || post.Sources[0].ObservedSHA256 != safe.SHA256Bytes(archive) {
		t.Fatalf("the acquired archive was not bound to the report: %#v", post.Sources)
	}
	inStore := false
	for _, raw := range post.Manifest {
		record, err := brief.ValidateManifestRecord(raw)
		if err != nil {
			t.Fatal(err)
		}
		if record.Path == "source.tar" {
			inStore = true
		}
	}
	if !inStore {
		t.Fatal("the acquired archive is missing from the content-bound manifest")
	}
}

// A marker is verified by re-binding what the scan bound. If the bind skipped
// the source store, the same untouched material would hash differently and every
// build phase would fail closed on a change that did not happen.
func TestMarkerRebindsTheTransactionStore(t *testing.T) {
	withStateAndShare(t)
	checkout := t.TempDir()
	archive := vendorTarBytes(t, map[string][]byte{"safe.txt": []byte("safe\n")})
	writeExternalSourceFixture(t, checkout, archive)

	service, err := NewAuditService(context.Background(), aiConfig(), &fakeReviewer{})
	if err != nil {
		t.Fatal(err)
	}
	post, status, err := service.ScanDirectory(context.Background(), "post", checkout, "demo")
	if err != nil || status != 0 {
		t.Fatalf("post scan: status=%d err=%v", status, err)
	}
	if _, err := service.VerifyMarker(checkout, "post"); err != nil {
		t.Fatalf("the marker written by that scan does not verify: %v", err)
	}
	// And a source that changed after the decision must still be caught.
	store := ExistingTransactionSourceDir(checkout)
	if store == "" {
		t.Fatal("the transaction source store was not found")
	}
	if err := os.WriteFile(filepath.Join(store, "source.tar"), append(archive, 'x'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.VerifyMarker(checkout, "post"); err == nil {
		t.Fatal("a source replaced after the decision still verified")
	}
	_ = post
}

// The store and the checkout share one namespace, so a package shipping a file
// named exactly like the source it downloads would otherwise shadow the arrived
// bytes with its own.
func TestCheckoutCannotShadowAnAcquiredSource(t *testing.T) {
	withStateAndShare(t)
	checkout := t.TempDir()
	archive := vendorTarBytes(t, map[string][]byte{"safe.txt": []byte("safe\n")})
	writeExternalSourceFixture(t, checkout, archive)
	if err := os.WriteFile(filepath.Join(checkout, "source.tar"), []byte("decoy"), 0o600); err != nil {
		t.Fatal(err)
	}
	service, err := NewAuditService(context.Background(), aiConfig(), &fakeReviewer{})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = service.ScanDirectory(context.Background(), "post", checkout, "demo")
	if err == nil || !strings.Contains(err.Error(), "source.tar") {
		t.Fatalf("a checkout file shadowing an acquired source was accepted: %v", err)
	}
}

// TestPostBriefingUsesTheFrozenPlanNotTheCommittedFile is the second half of
// the same defect.
//
// The scanner built the user's source list from the committed .SRCINFO, while
// acquisition planned the fetch from a contained `makepkg --printsrcinfo`. Both
// files are attacker-controlled and the static comparison deliberately does not
// check remote declarations, so a package could show one host in the briefing
// and fetch from another. The architecture said the committed copy is never
// read; it was, and it was the copy the user saw.
func TestPostBriefingUsesTheFrozenPlanNotTheCommittedFile(t *testing.T) {
	withStateAndShare(t)
	checkout := t.TempDir()
	archive := vendorTarBytes(t, map[string][]byte{"safe.txt": []byte("safe\n")})
	digest := safe.SHA256Bytes(archive)

	// The committed file names a reassuring host. The recipe, as the contained
	// freeze regenerates it, names another - and that is the one fetched.
	committed := "pkgbase = demo\npkgver = 1\npkgrel = 1\nsource = https://trusted.example/source.tar\nsha256sums = " + digest + "\n"
	frozen := "pkgbase = demo\npkgver = 1\npkgrel = 1\nsource = https://elsewhere.example/source.tar\nsha256sums = " + digest + "\n"
	for name, body := range map[string]string{
		"PKGBUILD": "pkgbase=demo\npkgver=1\npkgrel=1\nsource=('https://elsewhere.example/source.tar')\nsha256sums=('" + digest + "')\n",
		".SRCINFO": committed,
	} {
		if err := os.WriteFile(filepath.Join(checkout, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	store, err := transactionSourceDir(checkout)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, "source.tar"), archive, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := saveTransactionSourcePlan(checkout, []byte(frozen)); err != nil {
		t.Fatal(err)
	}

	service, err := NewAuditService(context.Background(), aiConfig(), &fakeReviewer{})
	if err != nil {
		t.Fatal(err)
	}
	post, status, err := service.ScanDirectory(context.Background(), "post", checkout, "demo")
	if err != nil || status != 0 {
		t.Fatalf("post scan: status=%d err=%v", status, err)
	}
	if len(post.Sources) != 1 {
		t.Fatalf("expected one source, got %#v", post.Sources)
	}
	if !strings.Contains(post.Sources[0].URL, "elsewhere.example") {
		t.Fatalf("the briefing shows the committed .SRCINFO instead of the frozen plan: %q", post.Sources[0].URL)
	}
	// The plan is what decides which files must have arrived, too.
	rendered := RenderReport(post)
	if strings.Contains(rendered, "trusted.example") {
		t.Fatalf("the committed host reached the briefing:\n%s", rendered)
	}
}
