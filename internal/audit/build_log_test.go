package audit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestContainedBuildLogIsPrivateBoundedOutputMadeTerminalSafe(t *testing.T) {
	withStateAndShare(t)
	store := NewReportStore()
	report := &Report{
		ReportID:    "20260827T190003Z-c82f23606669-a86dad6e",
		PackageBase: "stu-git",
	}
	stdout := []byte("building\n\x1b[2Jforged screen\n")
	stderr := []byte("mkdir: /usr/local: read-only\rfailed\n")

	path, err := saveContainedBuildLog(store, report, Invocation{Profile: "build"}, stdout, stderr, errors.New("exit status 4"))
	if err != nil {
		t.Fatal(err)
	}
	wantPath := filepath.Join(store.Root, report.ReportID+containedBuildLogSuffix)
	if path != wantPath {
		t.Fatalf("build log path=%q, want %q", path, wantPath)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("build log mode=%v, want a private regular file", info.Mode())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	log := string(raw)
	for _, want := range []string{"Result: failure: exit status 4", "--- stdout ---", "building", `\u001b[2Jforged screen`, "--- stderr ---", `read-only\u000dfailed`} {
		if !strings.Contains(log, want) {
			t.Errorf("build log does not contain %q:\n%s", want, log)
		}
	}
	if strings.ContainsRune(log, '\x1b') || strings.ContainsRune(log, '\r') {
		t.Fatalf("build log retained raw terminal controls: %q", log)
	}
}
