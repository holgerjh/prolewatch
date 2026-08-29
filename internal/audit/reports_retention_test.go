package audit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReportHistoryIsBounded holds the line on a directory nobody empties.
//
// Every phase of every transaction writes a report carrying a complete
// manifest, and nothing ever removed one. A long-lived installation therefore
// accumulated state forever while getting very little back from it: the CLI can
// show a report by id or the single newest one, and the diff only ever looks at
// the previous scan.
func TestReportHistoryIsBounded(t *testing.T) {
	withStateAndShare(t)
	store := NewReportStore()
	if err := EnsurePrivateDir(store.Root); err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, reportRetention+5)
	for index := 0; index < reportRetention+5; index++ {
		// Strictly increasing ids: report ids begin with a timestamp, so
		// lexical order is age order and the test must not depend on anything else.
		id := fmt.Sprintf("20260101T%06dZ-aaaaaaaaaaaa-bbbbbbbb", index)
		if !reportIDRE.MatchString(id) {
			t.Fatalf("test built an id the store would ignore: %q", id)
		}
		if err := os.WriteFile(filepath.Join(store.Root, id+".json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(store.Root, id+containedBuildLogSuffix), []byte("build output\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	// The oldest by id is the first to go - unless an approval the user created
	// and has not spent yet still names it, in which case pruning it would
	// answer their pending decision for them.
	oldest, err := store.IDs(0)
	if err != nil {
		t.Fatal(err)
	}
	protected := oldest[len(oldest)-1]
	pending := filepath.Join(NewApprovalStore().Root, "pending")
	if err := EnsurePrivateDir(pending); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pending, "approval-"+protected+".json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	store.Prune()

	remaining, err := store.IDs(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) > reportRetention+1 {
		t.Fatalf("pruning left %d reports, which is not a bound", len(remaining))
	}
	if _, err := os.Lstat(filepath.Join(store.Root, protected+".json")); err != nil {
		t.Fatalf("a report with an unspent approval was deleted: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(store.Root, protected+containedBuildLogSuffix)); err != nil {
		t.Fatalf("a protected report's build log was deleted: %v", err)
	}
	pruned := ids[1]
	if _, err := os.Lstat(filepath.Join(store.Root, pruned+containedBuildLogSuffix)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a pruned report's build log was retained: %v", err)
	}
	// Newest survive: the diff against the previous scan still works.
	if _, err := os.Lstat(filepath.Join(store.Root, ids[len(ids)-1]+".json")); err != nil {
		t.Fatalf("the newest report was pruned: %v", err)
	}
}

// TestLiveMarkersSurviveRetentionAndStaleOnesDoNot covers the state that is not
// history: a decision the current transaction has not spent yet.
//
// VerifyMarker loads the marker's report and re-binds the directory against its
// manifest, so deleting that report ends the transaction with a load error. Pre
// and post hooks run for every package base before the earliest one reaches its
// wrapper phase, so a large enough `yay -Syu` could push a still-needed report
// past the cap. The opposite mistake is just as bad: protecting every marker
// would make an unbounded marker directory into an unbounded report store.
func TestLiveMarkersSurviveRetentionAndStaleOnesDoNot(t *testing.T) {
	withStateAndShare(t)
	store := NewReportStore()
	if err := EnsurePrivateDir(store.Root); err != nil {
		t.Fatal(err)
	}
	markers := filepath.Join(StateRoot(), "decision-markers")
	if err := EnsurePrivateDir(markers); err != nil {
		t.Fatal(err)
	}
	oldest := "20260101T000000Z-aaaaaaaaaaaa-bbbbbbbb"
	for index := 0; index < reportRetention+5; index++ {
		id := fmt.Sprintf("20260101T%06dZ-aaaaaaaaaaaa-bbbbbbbb", index)
		if err := os.WriteFile(filepath.Join(store.Root, id+".json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	live, err := TransactionIdentity()
	if err != nil {
		t.Fatal(err)
	}
	stale := live
	stale.StartTime += "0"
	write := func(name, reportID string, identity ProcessIdentity) {
		marker := Marker{SchemaVersion: MarkerSchemaVersion, Root: "/x", Phase: "pre", PackageBase: "demo",
			ReportID: reportID, ContentHash: strings.Repeat("a", 64), PolicyFingerprint: strings.Repeat("b", 64),
			Decision: "allow", Disposition: "allow", Transaction: identity}
		if err := AtomicWriteJSON(filepath.Join(markers, name+".json"), marker); err != nil {
			t.Fatal(err)
		}
	}
	write("live", oldest, live)
	write("stale", "20260101T000001Z-aaaaaaaaaaaa-bbbbbbbb", stale)

	store.Prune()

	if _, err := os.Lstat(filepath.Join(store.Root, oldest+".json")); err != nil {
		t.Fatalf("a report a live marker still needs was pruned: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(markers, "live.json")); err != nil {
		t.Fatalf("a live marker was removed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(markers, "stale.json")); err == nil {
		t.Fatal("a marker whose transaction has ended was kept, which is an unbounded leak")
	}
	remaining, err := store.IDs(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) > reportRetention+2 {
		t.Fatalf("protecting markers unbounded the history: %d reports", len(remaining))
	}
}
