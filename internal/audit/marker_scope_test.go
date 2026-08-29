package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestConcurrentTransactionsKeepSeparateMarkers is the concurrency regression.
//
// yay builds in a persistent directory, so two live yay processes working on the
// same package base resolve to the same checkout. With a checkout-scoped marker
// name they wrote the same file: the second scan replaced the first, and when
// the first transaction reached its wrapper phase VerifyMarker correctly
// rejected the identity mismatch and that transaction died. Two valid scans,
// unchanged content, and one fails because state described as transaction-local
// lived in a shared slot.
func TestConcurrentTransactionsKeepSeparateMarkers(t *testing.T) {
	withStateAndShare(t)
	checkout := t.TempDir()
	first, err := TransactionIdentity()
	if err != nil {
		t.Fatal(err)
	}
	second := first
	second.PID++

	_, firstPath, err := markerLocation(checkout, "post", first)
	if err != nil {
		t.Fatal(err)
	}
	_, secondPath, err := markerLocation(checkout, "post", second)
	if err != nil {
		t.Fatal(err)
	}
	if firstPath == secondPath {
		t.Fatal("two live transactions on one checkout share a marker file")
	}
	// Phase still separates, and the same transaction still replaces its own
	// marker rather than accumulating one per scan.
	_, prePath, err := markerLocation(checkout, "pre", first)
	if err != nil {
		t.Fatal(err)
	}
	if prePath == firstPath {
		t.Fatal("pre and post markers collide")
	}
	_, again, err := markerLocation(checkout, "post", first)
	if err != nil {
		t.Fatal(err)
	}
	if again != firstPath {
		t.Fatal("a rescan in the same transaction wrote a second marker instead of replacing its own")
	}
	// Markers live outside the checkout, where package code cannot reach them.
	if strings.HasPrefix(firstPath, checkout+string(os.PathSeparator)) {
		t.Fatalf("marker was stored inside the checkout: %q", firstPath)
	}
}

// An incomplete identity must not silently produce a shared filename: that is
// the state the transaction scoping exists to prevent.
func TestMarkerLocationRequiresACompleteIdentity(t *testing.T) {
	withStateAndShare(t)
	checkout := t.TempDir()
	complete, err := TransactionIdentity()
	if err != nil {
		t.Fatal(err)
	}
	for name, identity := range map[string]ProcessIdentity{
		"no pid":     {StartTime: complete.StartTime, BootID: complete.BootID},
		"no start":   {PID: complete.PID, BootID: complete.BootID},
		"no boot id": {PID: complete.PID, StartTime: complete.StartTime},
	} {
		if _, _, err := markerLocation(checkout, "post", identity); err == nil {
			t.Errorf("an identity with %s produced a marker location", name)
		}
	}
}

// Retention already deletes markers whose transaction has ended. With one
// marker per transaction that must not take a live sibling with it.
func TestPruningOneTransactionKeepsTheOther(t *testing.T) {
	withStateAndShare(t)
	checkout := t.TempDir()
	live, err := TransactionIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ended := live
	ended.StartTime += "0"

	markers := filepath.Join(StateRoot(), "decision-markers")
	if err := EnsurePrivateDir(markers); err != nil {
		t.Fatal(err)
	}
	write := func(identity ProcessIdentity, reportID string) string {
		_, path, err := markerLocation(checkout, "post", identity)
		if err != nil {
			t.Fatal(err)
		}
		marker := Marker{SchemaVersion: MarkerSchemaVersion, Root: checkout, Phase: "post", PackageBase: "demo",
			ReportID: reportID, ContentHash: strings.Repeat("a", 64), PolicyFingerprint: strings.Repeat("b", 64),
			Decision: "allow", Disposition: "allow", Transaction: identity}
		if err := AtomicWriteJSON(path, marker); err != nil {
			t.Fatal(err)
		}
		return path
	}
	livePath := write(live, "20260101T000001Z-aaaaaaaaaaaa-bbbbbbbb")
	endedPath := write(ended, "20260101T000002Z-aaaaaaaaaaaa-bbbbbbbb")

	NewReportStore().Prune()

	if _, err := os.Lstat(livePath); err != nil {
		t.Errorf("a live transaction's marker was pruned: %v", err)
	}
	if _, err := os.Lstat(endedPath); err == nil {
		t.Error("a marker whose transaction has ended was kept, which is an unbounded leak")
	}
}
