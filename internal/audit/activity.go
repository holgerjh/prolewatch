package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const ActivitySchemaVersion = 2

const (
	ActivityRunning     = "running"
	ActivityAllowed     = "allowed"
	ActivityBlocked     = "blocked"
	ActivityFailed      = "failed"
	ActivityInterrupted = "interrupted"
)

const (
	StageInitializing       = "initializing"
	StageAIProviderCheck    = "ai-provider-check"
	StageDeterministicScan  = "deterministic-scan"
	StageAIReview           = "ai-review"
	StageCleanRootPrepare   = "clean-root-preparation"
	StageBubblewrapLaunch   = "bubblewrap-launch"
	StageSandboxExecution   = "sandbox-execution"
	StageCleanRootCleanup   = "clean-root-cleanup"
	StagePostDownloadRescan = "post-download-rescan"
	StageArtifactInspection = "artifact-inspection"
	StageArtifactImport     = "artifact-import"
	StageArtifactSealing    = "artifact-sealing"
	StageComplete           = "complete"
)

var activityIDRE = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}$`)

var activityStages = map[string]bool{
	StageInitializing: true, StageAIProviderCheck: true, StageDeterministicScan: true, StageAIReview: true,
	StageCleanRootPrepare: true, StageBubblewrapLaunch: true, StageSandboxExecution: true,
	StageCleanRootCleanup: true, StagePostDownloadRescan: true, StageArtifactInspection: true,
	StageArtifactImport: true, StageArtifactSealing: true, StageComplete: true,
}

const (
	ActivityFailureProviderTimeout = "provider-timeout"
	ActivityFailureProvider        = "provider-error"
	ActivityFailureScannerTimeout  = "scanner-timeout"
	ActivityFailureScanner         = "scanner-error"
	ActivityFailureOperational     = "operational-error"
	ActivityFailureWorkerExited    = "worker-exited"
)

var activityFailureReasons = map[string]bool{
	"": true, ActivityFailureProviderTimeout: true, ActivityFailureProvider: true,
	ActivityFailureScannerTimeout: true, ActivityFailureScanner: true,
	ActivityFailureOperational: true, ActivityFailureWorkerExited: true,
}

const (
	ScanOperationInventory          = "inventory"
	ScanOperationArchiveInspection  = "archive-inspection"
	ScanOperationSourceVerification = "source-verification"
	ScanOperationFinalizing         = "finalizing"
	ScanOperationComplete           = "complete"
)

var scanOperations = map[string]bool{
	"": true, ScanOperationInventory: true, ScanOperationArchiveInspection: true,
	ScanOperationSourceVerification: true, ScanOperationFinalizing: true, ScanOperationComplete: true,
}

var activityPhases = map[string]bool{
	"pre": true, "post": true, "artifact": true, "verify": true, "prepare": true,
	"build": true, "packagelist": true, "skip": true,
}

type ActivityContainment struct {
	CleanRootState      string `json:"clean_root_state"`
	CleanRootGeneration string `json:"clean_root_generation,omitempty"`
	CleanRootManifest   string `json:"clean_root_manifest,omitempty"`
	PackageCount        int    `json:"package_count,omitempty"`
	ArtifactCount       int    `json:"artifact_count,omitempty"`
	SandboxState        string `json:"sandbox_state"`
	Supervisor          string `json:"supervisor,omitempty"`
	NetworkPolicy       string `json:"network_policy,omitempty"`
}

type ActivityScanProgress struct {
	Operation      string `json:"operation,omitempty"`
	FilesSeen      int    `json:"files_seen,omitempty"`
	BytesSeen      int64  `json:"bytes_seen,omitempty"`
	ArchivesSeen   int    `json:"archives_seen,omitempty"`
	ArchiveEntries int    `json:"archive_entries,omitempty"`
}

func (p ActivityScanProgress) Validate() error {
	if !scanOperations[p.Operation] || p.FilesSeen < 0 || p.BytesSeen < 0 || p.ArchivesSeen < 0 || p.ArchiveEntries < 0 {
		return errors.New("invalid activity scan progress")
	}
	return nil
}

func defaultActivityContainment() ActivityContainment {
	return ActivityContainment{CleanRootState: "not-required", SandboxState: "not-started"}
}

func (c ActivityContainment) Validate() error {
	cleanRootStates := map[string]bool{"not-required": true, "preparing": true, "prepared": true, "cleaning": true, "cleaned": true, "failed": true}
	sandboxStates := map[string]bool{"not-started": true, "launching": true, "running": true, "completed": true, "failed": true}
	if !cleanRootStates[c.CleanRootState] || !sandboxStates[c.SandboxState] {
		return errors.New("invalid activity containment state")
	}
	if c.Supervisor != "" && c.Supervisor != "systemd-user" {
		return errors.New("invalid activity supervisor")
	}
	if c.NetworkPolicy != "" && c.NetworkPolicy != "isolated" && c.NetworkPolicy != "public-web-broker" {
		return errors.New("invalid activity network policy")
	}
	if c.PackageCount < 0 || c.ArtifactCount < 0 {
		return errors.New("invalid activity containment counts")
	}
	if c.CleanRootGeneration != "" && !cleanRootTokenRE.MatchString(c.CleanRootGeneration) {
		return errors.New("invalid activity clean-root generation")
	}
	if c.CleanRootManifest != "" && !validHexDigest(c.CleanRootManifest) {
		return errors.New("invalid activity clean-root manifest")
	}
	return nil
}

type Activity struct {
	SchemaVersion  int                  `json:"schema_version"`
	ActivityID     string               `json:"activity_id"`
	Transaction    ProcessIdentity      `json:"transaction"`
	Worker         ProcessIdentity      `json:"worker"`
	PackageBase    string               `json:"package_base,omitempty"`
	Kind           string               `json:"kind"`
	Phase          string               `json:"phase"`
	Stage          string               `json:"stage"`
	Status         string               `json:"status"`
	StartedAt      string               `json:"started_at"`
	UpdatedAt      string               `json:"updated_at"`
	FinishedAt     string               `json:"finished_at,omitempty"`
	StageStartedAt string               `json:"stage_started_at"`
	LastProgressAt string               `json:"last_progress_at"`
	DeadlineAt     string               `json:"deadline_at,omitempty"`
	AIBatch        int                  `json:"ai_batch,omitempty"`
	AIBatchCount   int                  `json:"ai_batch_count,omitempty"`
	ReportIDs      []string             `json:"report_ids"`
	Message        string               `json:"message,omitempty"`
	FailureReason  string               `json:"failure_reason,omitempty"`
	ScanProgress   ActivityScanProgress `json:"scan_progress"`
	Containment    ActivityContainment  `json:"containment"`
}

func validActivityIdentity(identity ProcessIdentity) bool {
	return identity.PID > 0 && identity.StartTime != "" && identity.BootID != ""
}

func (a Activity) Validate() error {
	if a.SchemaVersion != ActivitySchemaVersion || !activityIDRE.MatchString(a.ActivityID) {
		return errors.New("invalid activity document")
	}
	if !validActivityIdentity(a.Transaction) || !validActivityIdentity(a.Worker) {
		return errors.New("invalid activity process identity")
	}
	if a.PackageBase != "" {
		if err := ValidatePackageBase(a.PackageBase); err != nil {
			return err
		}
	}
	if (a.Kind != "scan" && a.Kind != "makepkg") || !activityPhases[a.Phase] || !activityStages[a.Stage] {
		return errors.New("invalid activity kind, phase, or stage")
	}
	statuses := map[string]bool{ActivityRunning: true, ActivityAllowed: true, ActivityBlocked: true, ActivityFailed: true, ActivityInterrupted: true}
	if !statuses[a.Status] {
		return errors.New("invalid activity status")
	}
	started, err := time.Parse(time.RFC3339Nano, a.StartedAt)
	if err != nil {
		return errors.New("invalid activity start time")
	}
	updated, err := time.Parse(time.RFC3339Nano, a.UpdatedAt)
	if err != nil || updated.Before(started) {
		return errors.New("invalid activity update time")
	}
	stageStarted, err := time.Parse(time.RFC3339Nano, a.StageStartedAt)
	if err != nil || stageStarted.Before(started) || stageStarted.After(updated) {
		return errors.New("invalid activity stage start time")
	}
	lastProgress, err := time.Parse(time.RFC3339Nano, a.LastProgressAt)
	if err != nil || lastProgress.Before(stageStarted) || lastProgress.After(updated) {
		return errors.New("invalid activity progress time")
	}
	if a.DeadlineAt != "" {
		deadline, err := time.Parse(time.RFC3339Nano, a.DeadlineAt)
		if err != nil || deadline.Before(stageStarted) {
			return errors.New("invalid activity deadline")
		}
	}
	if a.Status == ActivityRunning {
		if a.FinishedAt != "" {
			return errors.New("running activity has a finish time")
		}
	} else {
		finished, err := time.Parse(time.RFC3339Nano, a.FinishedAt)
		if err != nil || finished.Before(updated) {
			return errors.New("terminal activity lacks a valid finish time")
		}
	}
	if a.AIBatch < 0 || a.AIBatchCount < 0 || a.AIBatch > a.AIBatchCount || (a.AIBatchCount == 0 && a.AIBatch != 0) {
		return errors.New("invalid activity AI batch progress")
	}
	if len(a.ReportIDs) > 16 || len(a.Message) > 2000 {
		return errors.New("activity exceeds field limits")
	}
	if !activityFailureReasons[a.FailureReason] {
		return errors.New("invalid activity failure reason")
	}
	seen := map[string]bool{}
	for _, id := range a.ReportIDs {
		if !reportIDRE.MatchString(id) || seen[id] {
			return errors.New("invalid activity report ID")
		}
		seen[id] = true
	}
	if err := a.ScanProgress.Validate(); err != nil {
		return err
	}
	return a.Containment.Validate()
}

type ActivityStore struct{ Root string }

func NewActivityStore() *ActivityStore {
	return &ActivityStore{Root: filepath.Join(StateRoot(), "activities")}
}

func (s *ActivityStore) ensureRoot(create bool) error {
	info, err := os.Lstat(s.Root)
	if errors.Is(err, os.ErrNotExist) && create {
		return EnsurePrivateDir(s.Root)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("unsafe activity state directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		return errors.New("activity state directory is not owned by the current user")
	}
	return nil
}

func (s *ActivityStore) Save(activity *Activity) error {
	if activity == nil {
		return errors.New("cannot save a nil activity")
	}
	if err := activity.Validate(); err != nil {
		return err
	}
	if err := s.ensureRoot(true); err != nil {
		return err
	}
	return AtomicWriteJSON(filepath.Join(s.Root, activity.ActivityID+".json"), activity)
}

func (s *ActivityStore) Load(id string) (*Activity, error) {
	if !activityIDRE.MatchString(id) {
		return nil, errors.New("invalid activity id")
	}
	var activity Activity
	if err := ReadJSONFile(filepath.Join(s.Root, id+".json"), 64*1024, &activity); err != nil {
		return nil, err
	}
	if activity.ActivityID != id {
		return nil, errors.New("activity filename does not match document")
	}
	if activity.SchemaVersion == 1 {
		activity.SchemaVersion = ActivitySchemaVersion
		activity.StageStartedAt = activity.UpdatedAt
		activity.LastProgressAt = activity.UpdatedAt
	}
	if err := activity.Validate(); err != nil {
		return nil, err
	}
	return &activity, nil
}

func (s *ActivityStore) List(limit int) ([]Activity, error) {
	if err := s.ensureRoot(false); errors.Is(err, os.ErrNotExist) {
		return []Activity{}, nil
	} else if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.Root)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, entry := range entries {
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") && activityIDRE.MatchString(id) {
			ids = append(ids, id)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))
	if limit > 0 && len(ids) > limit {
		ids = ids[:limit]
	}
	result := make([]Activity, 0, len(ids))
	for _, id := range ids {
		activity, err := s.Load(id)
		if err != nil {
			continue
		}
		if activity.Status == ActivityRunning && !IdentityIsLive(activity.Worker) {
			activity.Status = ActivityInterrupted
			activity.Stage = StageComplete
			activity.FinishedAt = activity.UpdatedAt
			activity.FailureReason = ActivityFailureWorkerExited
			activity.Message = valueOr(activity.Message, "worker process is no longer running")
		}
		result = append(result, *activity)
	}
	return result, nil
}

func (s *ActivityStore) Prune(now time.Time) error {
	activities, err := s.List(0)
	if err != nil {
		return err
	}
	terminal := 0
	for _, activity := range activities {
		if activity.Status == ActivityRunning {
			continue
		}
		terminal++
		finished, err := time.Parse(time.RFC3339Nano, activity.FinishedAt)
		if err != nil || now.Sub(finished) > 7*24*time.Hour || terminal > 200 {
			if err := os.Remove(filepath.Join(s.Root, activity.ActivityID+".json")); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

type ActivityRecorder struct {
	mu               sync.Mutex
	store            *ActivityStore
	activity         Activity
	warned           bool
	lastProgressSave time.Time
	now              func() time.Time
}

func NewActivityRecorder(packageBase, kind, phase string) (*ActivityRecorder, error) {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	transaction, err := TransactionIdentity()
	if err != nil {
		return nil, err
	}
	worker, err := IdentityForPID(os.Getpid())
	if err != nil {
		return nil, err
	}
	clock := time.Now
	nowTime := clock().UTC()
	now := nowTime.Format(time.RFC3339Nano)
	recorder := &ActivityRecorder{store: NewActivityStore(), activity: Activity{
		SchemaVersion: ActivitySchemaVersion, ActivityID: time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(random),
		Transaction: transaction, Worker: worker, PackageBase: packageBase, Kind: kind, Phase: phase,
		Stage: StageInitializing, Status: ActivityRunning, StartedAt: now, UpdatedAt: now,
		StageStartedAt: now, LastProgressAt: now, ReportIDs: []string{},
		ScanProgress: ActivityScanProgress{}, Containment: defaultActivityContainment(),
	}, lastProgressSave: nowTime, now: clock}
	if err := recorder.store.Save(&recorder.activity); err != nil {
		return nil, err
	}
	_ = recorder.store.Prune(time.Now())
	return recorder, nil
}

func (r *ActivityRecorder) warn(err error) {
	if err != nil && !r.warned {
		r.warned = true
		fmt.Fprintln(os.Stderr, "prolewatch: activity update failed:", err)
	}
}

func (r *ActivityRecorder) update(change func(*Activity)) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.activity.Status != ActivityRunning {
		return
	}
	change(&r.activity)
	r.activity.UpdatedAt = r.now().UTC().Format(time.RFC3339Nano)
	r.warn(r.store.Save(&r.activity))
}

func (r *ActivityRecorder) beginStage(stage string, timeoutSeconds int, force bool) {
	if r == nil {
		return
	}
	r.update(func(a *Activity) {
		if !force && a.Stage == stage {
			return
		}
		now := r.now().UTC()
		stamp := now.Format(time.RFC3339Nano)
		a.Stage, a.StageStartedAt, a.LastProgressAt = stage, stamp, stamp
		a.DeadlineAt = ""
		if timeoutSeconds > 0 {
			a.DeadlineAt = now.Add(time.Duration(timeoutSeconds) * time.Second).Format(time.RFC3339Nano)
		}
		if stage == StageDeterministicScan || stage == StageArtifactInspection {
			a.ScanProgress = ActivityScanProgress{Operation: ScanOperationInventory}
		}
		if stage != StageAIReview {
			a.AIBatch, a.AIBatchCount = 0, 0
		}
	})
}

func (r *ActivityRecorder) recordScanProgress(progress ActivityScanProgress, force bool) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.activity.Status != ActivityRunning {
		return
	}
	now := r.now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	r.activity.ScanProgress = progress
	r.activity.LastProgressAt, r.activity.UpdatedAt = stamp, stamp
	if !force && now.Sub(r.lastProgressSave) < time.Second {
		return
	}
	r.lastProgressSave = now
	r.warn(r.store.Save(&r.activity))
}

func (r *ActivityRecorder) markFailure(reason, message string) {
	r.update(func(a *Activity) {
		a.FailureReason = reason
		a.Message = truncate(message, 2000)
	})
}

func (r *ActivityRecorder) Finish(status, message string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.activity.Status != ActivityRunning {
		return
	}
	now := r.now().UTC().Format(time.RFC3339Nano)
	r.activity.Status, r.activity.Stage = status, StageComplete
	r.activity.UpdatedAt, r.activity.FinishedAt = now, now
	if message != "" {
		r.activity.Message = truncate(message, 2000)
	}
	if status == ActivityFailed && r.activity.FailureReason == "" {
		r.activity.FailureReason = ActivityFailureOperational
	}
	if status == ActivityAllowed || status == ActivityBlocked {
		r.activity.FailureReason = ""
		if message == "" {
			r.activity.Message = ""
		}
	}
	r.warn(r.store.Save(&r.activity))
	r.warn(r.store.Prune(time.Now()))
}

func (r *ActivityRecorder) SetPackage(packageBase string) {
	r.update(func(a *Activity) { a.PackageBase = packageBase })
}

func (r *ActivityRecorder) LinkReport(id string) {
	r.update(func(a *Activity) {
		for _, existing := range a.ReportIDs {
			if existing == id {
				return
			}
		}
		a.ReportIDs = append(a.ReportIDs, id)
	})
}

type activityContextKey struct{}

func withActivity(ctx context.Context, recorder *ActivityRecorder) context.Context {
	return context.WithValue(ctx, activityContextKey{}, recorder)
}

func activityRecorder(ctx context.Context) *ActivityRecorder {
	if ctx == nil {
		return nil
	}
	recorder, _ := ctx.Value(activityContextKey{}).(*ActivityRecorder)
	return recorder
}

func activityStage(ctx context.Context, stage string) {
	if recorder := activityRecorder(ctx); recorder != nil {
		recorder.beginStage(stage, 0, false)
	}
	if progress := terminalProgressFrom(ctx); progress != nil {
		progress.Stage(stage, 0)
	}
}

func activityTimedStage(ctx context.Context, stage string, timeoutSeconds int) {
	if recorder := activityRecorder(ctx); recorder != nil {
		recorder.beginStage(stage, timeoutSeconds, true)
	}
	if progress := terminalProgressFrom(ctx); progress != nil {
		progress.Stage(stage, timeoutSeconds)
	}
}

func activityAI(ctx context.Context, batch, count, timeoutSeconds int) {
	if recorder := activityRecorder(ctx); recorder != nil {
		recorder.beginStage(StageAIReview, timeoutSeconds, true)
		recorder.update(func(a *Activity) { a.AIBatch, a.AIBatchCount = batch, count })
	}
	if progress := terminalProgressFrom(ctx); progress != nil {
		progress.AI(batch, count, timeoutSeconds)
	}
}

func activityScan(ctx context.Context, progress ActivityScanProgress, force bool) {
	if recorder := activityRecorder(ctx); recorder != nil {
		recorder.recordScanProgress(progress, force)
	}
	if terminal := terminalProgressFrom(ctx); terminal != nil {
		terminal.Scan(progress)
	}
}

func activityFailure(ctx context.Context, reason, message string) {
	if recorder := activityRecorder(ctx); recorder != nil {
		recorder.markFailure(reason, message)
	}
}

func activityReport(ctx context.Context, id string) {
	if recorder := activityRecorder(ctx); recorder != nil {
		recorder.LinkReport(id)
	}
}

func activityContainment(ctx context.Context, change func(*ActivityContainment)) {
	if recorder := activityRecorder(ctx); recorder != nil {
		recorder.update(func(a *Activity) { change(&a.Containment) })
	}
}

func activityResult(exitCode int) string {
	if exitCode == 0 {
		return ActivityAllowed
	}
	if exitCode == 10 {
		return ActivityBlocked
	}
	return ActivityFailed
}
