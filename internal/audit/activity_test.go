package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testActivity(t *testing.T, id string) Activity {
	t.Helper()
	identity, err := IdentityForPID(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	now := UTCNow()
	return Activity{SchemaVersion: ActivitySchemaVersion, ActivityID: id, Transaction: identity, Worker: identity,
		PackageBase: "demo", Kind: "scan", Phase: "pre", Stage: StageDeterministicScan,
		Status: ActivityRunning, StartedAt: now, UpdatedAt: now, StageStartedAt: now, LastProgressAt: now,
		ReportIDs: []string{}, ScanProgress: ActivityScanProgress{Operation: ScanOperationInventory}, Containment: defaultActivityContainment()}
}

func TestActivityStoreValidationAndDeadWorkerInference(t *testing.T) {
	store := &ActivityStore{Root: filepath.Join(t.TempDir(), "activities")}
	activity := testActivity(t, "20260812T010203Z-aaaaaaaaaaaaaaaa")
	if err := store.Save(&activity); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(activity.ActivityID)
	if err != nil || loaded.Status != ActivityRunning {
		t.Fatalf("activity load failed: %+v %v", loaded, err)
	}
	activity.Worker.PID = 999999999
	activity.UpdatedAt = UTCNow()
	if err := store.Save(&activity); err != nil {
		t.Fatal(err)
	}
	listed, err := store.List(10)
	if err != nil || len(listed) != 1 || listed[0].Status != ActivityInterrupted || listed[0].FinishedAt == "" || listed[0].FailureReason != ActivityFailureWorkerExited {
		t.Fatalf("dead worker was not inferred as interrupted: %#v %v", listed, err)
	}

	mutations := []func(*Activity){
		func(value *Activity) { value.SchemaVersion++ },
		func(value *Activity) { value.ActivityID = "../escape" },
		func(value *Activity) { value.Stage = "unknown" },
		func(value *Activity) { value.Status = "secure" },
		func(value *Activity) { value.Message = strings.Repeat("x", 2001) },
		func(value *Activity) { value.DeadlineAt = "not-a-time" },
		func(value *Activity) { value.FailureReason = "mysterious" },
		func(value *Activity) { value.ScanProgress.FilesSeen = -1 },
		func(value *Activity) {
			value.Status, value.Stage = ActivityFailed, StageComplete
			value.FinishedAt = value.StartedAt
			value.UpdatedAt = time.Now().UTC().Add(time.Second).Format(time.RFC3339Nano)
		},
		func(value *Activity) { value.Containment.NetworkPolicy = "host" },
		func(value *Activity) { value.Containment.CleanRootGeneration = "../../root" },
	}
	for index, mutate := range mutations {
		copy := testActivity(t, "20260812T010203Z-bbbbbbbbbbbbbbbb")
		mutate(&copy)
		if err := copy.Validate(); err == nil {
			t.Errorf("invalid activity mutation %d accepted", index)
		}
	}
}

func TestActivityStoreRejectsUnsafeRootAndPrunesTerminalRecords(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "activities")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	activity := testActivity(t, "20260812T010203Z-cccccccccccccccc")
	if err := (&ActivityStore{Root: link}).Save(&activity); err == nil {
		t.Fatal("symlinked activity root accepted")
	}

	store := &ActivityStore{Root: filepath.Join(t.TempDir(), "activities")}
	old := time.Now().Add(-8 * 24 * time.Hour).UTC()
	activity = testActivity(t, "20260812T010203Z-dddddddddddddddd")
	activity.Status, activity.Stage = ActivityAllowed, StageComplete
	activity.StartedAt = old.Add(-time.Minute).Format(time.RFC3339Nano)
	activity.UpdatedAt = old.Format(time.RFC3339Nano)
	activity.StageStartedAt = activity.StartedAt
	activity.LastProgressAt = activity.UpdatedAt
	activity.FinishedAt = activity.UpdatedAt
	if err := store.Save(&activity); err != nil {
		t.Fatal(err)
	}
	if err := store.Prune(time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(store.Root, activity.ActivityID+".json")); !os.IsNotExist(err) {
		t.Fatal("expired activity was not pruned")
	}
}

func TestActivityContextTracksBatchesReportsAndContainment(t *testing.T) {
	withStateAndShare(t)
	recorder, err := NewActivityRecorder("demo", "scan", "pre")
	if err != nil {
		t.Fatal(err)
	}
	base, err := time.Parse(time.RFC3339Nano, recorder.activity.UpdatedAt)
	if err != nil {
		t.Fatal(err)
	}
	current := base.Add(time.Second)
	recorder.now = func() time.Time { return current }
	ctx := withActivity(context.Background(), recorder)
	activityStage(ctx, StageAIReview)
	activityAI(ctx, 2, 3, 180)
	current = current.Add(time.Second)
	activityScan(ctx, ActivityScanProgress{Operation: ScanOperationArchiveInspection, FilesSeen: 4, BytesSeen: 4096, ArchivesSeen: 1, ArchiveEntries: 3}, true)
	id := "20260812T010203Z-aaaaaaaaaaaa-bbbbbbbb"
	activityReport(ctx, id)
	activityReport(ctx, id)
	activityContainment(ctx, func(value *ActivityContainment) {
		value.CleanRootState = "prepared"
		value.SandboxState = "running"
		value.Supervisor = "systemd-user"
		value.NetworkPolicy = "isolated"
	})
	recorder.Finish(ActivityAllowed, "done")
	stored, err := recorder.store.Load(recorder.activity.ActivityID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != ActivityAllowed || stored.AIBatch != 2 || stored.AIBatchCount != 3 || stored.DeadlineAt == "" ||
		stored.ScanProgress.ArchiveEntries != 3 || len(stored.ReportIDs) != 1 || stored.Containment.SandboxState != "running" {
		t.Fatalf("activity progress was not preserved: %#v", stored)
	}

	recorder.store.Root = filepath.Join(t.TempDir(), "blocked", "activity.json")
	if err := os.WriteFile(filepath.Dir(recorder.store.Root), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A status failure is observable but cannot alter the already-computed result.
	recorder.update(func(value *Activity) { value.Message = "ignored write failure" })
}

func TestActivityStoreReadsRetainedV1Records(t *testing.T) {
	store := &ActivityStore{Root: filepath.Join(t.TempDir(), "activities")}
	if err := EnsurePrivateDir(store.Root); err != nil {
		t.Fatal(err)
	}
	activity := testActivity(t, "20260812T010203Z-eeeeeeeeeeeeeeee")
	activity.SchemaVersion = 1
	activity.StageStartedAt, activity.LastProgressAt = "", ""
	activity.ScanProgress = ActivityScanProgress{}
	if err := AtomicWriteJSON(filepath.Join(store.Root, activity.ActivityID+".json"), &activity); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(activity.ActivityID)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.SchemaVersion != ActivitySchemaVersion || loaded.StageStartedAt != activity.UpdatedAt || loaded.LastProgressAt != activity.UpdatedAt {
		t.Fatalf("v1 activity was not migrated in memory: %#v", loaded)
	}
}

func TestActivityScanProgressPersistenceIsThrottledAndForceable(t *testing.T) {
	withStateAndShare(t)
	recorder, err := NewActivityRecorder("demo", "scan", "pre")
	if err != nil {
		t.Fatal(err)
	}
	base, err := time.Parse(time.RFC3339Nano, recorder.activity.UpdatedAt)
	if err != nil {
		t.Fatal(err)
	}
	current := base.Add(100 * time.Millisecond)
	recorder.now = func() time.Time { return current }
	recorder.recordScanProgress(ActivityScanProgress{Operation: ScanOperationInventory, FilesSeen: 1}, false)
	stored, err := recorder.store.Load(recorder.activity.ActivityID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ScanProgress.FilesSeen != 0 {
		t.Fatalf("progress was persisted before the throttle interval: %#v", stored.ScanProgress)
	}

	current = base.Add(1100 * time.Millisecond)
	recorder.recordScanProgress(ActivityScanProgress{Operation: ScanOperationInventory, FilesSeen: 2}, false)
	stored, err = recorder.store.Load(recorder.activity.ActivityID)
	if err != nil || stored.ScanProgress.FilesSeen != 2 {
		t.Fatalf("progress was not persisted after the throttle interval: %#v %v", stored, err)
	}

	current = base.Add(1200 * time.Millisecond)
	recorder.recordScanProgress(ActivityScanProgress{Operation: ScanOperationComplete, FilesSeen: 3}, true)
	stored, err = recorder.store.Load(recorder.activity.ActivityID)
	if err != nil || stored.ScanProgress.FilesSeen != 3 || stored.ScanProgress.Operation != ScanOperationComplete {
		t.Fatalf("forced progress was not persisted: %#v %v", stored, err)
	}
}
