package audit

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func captureStderr(t *testing.T, run func()) string {
	t.Helper()
	previous := os.Stderr
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = write
	done := make(chan string, 1)
	go func() {
		var buffer bytes.Buffer
		_, _ = buffer.ReadFrom(read)
		done <- buffer.String()
	}()
	run()
	write.Close()
	os.Stderr = previous
	return <-done
}

// TestQuarantineTellsTheUserWhereTheArchiveWent covers the half of failing
// closed that is about the person afterwards.
//
// There were two quarantine implementations. The policy-block path reported
// each failed move and printed the destination; the artifact-validation path
// discarded the directory-creation result and every move result and printed
// only the cause. Two failures with the same outcome gave materially different
// explanations, and one of them silently moved the package out of the directory
// the user was looking in.
func TestQuarantineTellsTheUserWhereTheArchiveWent(t *testing.T) {
	withStateAndShare(t)
	workdir := t.TempDir()
	archive := filepath.Join(workdir, "demo-1-1-any.pkg.tar.zst")
	if err := os.WriteFile(archive, []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	report := &Report{ReportID: "20260101T000000Z-aaaaaaaaaaaa-bbbbbbbb"}

	output := captureStderr(t, func() {
		if !quarantinePackages(context.Background(), []string{archive}, report, "Blocked package archives") {
			t.Error("quarantining an ordinary archive reported failure")
		}
	})
	destination := filepath.Join(StateRoot(), "quarantine", report.ReportID, filepath.Base(archive))
	if _, err := os.Lstat(destination); err != nil {
		t.Fatalf("the archive was not moved into quarantine: %v", err)
	}
	if _, err := os.Lstat(archive); err == nil {
		t.Error("the archive was left in the build directory as well")
	}
	// The user has to be able to find it, and to know nothing will clean it up.
	if !strings.Contains(output, filepath.Dir(destination)) {
		t.Errorf("the quarantine directory was not named:\n%s", output)
	}
	if !strings.Contains(output, "delete that directory") {
		t.Errorf("the output does not say the files stay until removed by hand:\n%s", output)
	}
}

// A failure to move must be reported rather than swallowed: the archive is then
// still in the build directory, which is the opposite of what the other message
// would have implied.
func TestQuarantineReportsWhatItCouldNotMove(t *testing.T) {
	withStateAndShare(t)
	workdir := t.TempDir()
	present := filepath.Join(workdir, "demo-1-1-any.pkg.tar.zst")
	if err := os.WriteFile(present, []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A directory where a package file is expected cannot be moved by
	// moveVerified, which refuses anything that is not a regular file.
	directory := filepath.Join(workdir, "demo-2-1-any.pkg.tar.zst")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	report := &Report{ReportID: "20260101T000001Z-aaaaaaaaaaaa-bbbbbbbb"}

	complete := true
	output := captureStderr(t, func() {
		complete = quarantinePackages(context.Background(), []string{present, directory}, report, "Blocked package archives")
	})
	if !complete {
		// A non-regular entry is skipped rather than failed: nothing to move.
		t.Log("reported incomplete, which is acceptable if it names the file")
	}
	if !strings.Contains(output, "moved to") {
		t.Errorf("the successful move was not reported:\n%s", output)
	}
	if _, err := os.Lstat(filepath.Join(StateRoot(), "quarantine", report.ReportID, filepath.Base(present))); err != nil {
		t.Errorf("the movable archive was not quarantined: %v", err)
	}
}

// An unwritable state root is a real failure and must leave the archives where
// the user can still see them, with the reason said out loud.
func TestQuarantineFailureLeavesTheArchiveAndSaysSo(t *testing.T) {
	withStateAndShare(t)
	workdir := t.TempDir()
	archive := filepath.Join(workdir, "demo-1-1-any.pkg.tar.zst")
	if err := os.WriteFile(archive, []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	report := &Report{ReportID: "20260101T000002Z-aaaaaaaaaaaa-bbbbbbbb"}
	// Put a regular file where the quarantine directory needs to be.
	blocked := filepath.Join(StateRoot(), "quarantine")
	if err := EnsurePrivateDir(StateRoot()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blocked, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	complete := true
	output := captureStderr(t, func() {
		complete = quarantinePackages(context.Background(), []string{archive}, report, "Blocked package archives")
	})
	if complete {
		t.Error("an unusable quarantine directory reported success")
	}
	if _, err := os.Lstat(archive); err != nil {
		t.Errorf("the archive was lost when quarantine failed: %v", err)
	}
	if !strings.Contains(output, "still in the build directory") {
		t.Errorf("the output does not say where the archive actually is:\n%s", output)
	}
}
