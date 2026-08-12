package main

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/holgerjh/prolewatch/internal/audit"
)

func stubInstalledSuite(t *testing.T) {
	t.Helper()
	oldUID := effectiveUID
	oldValidate := validateInstalledBinary
	oldOutput := installedOutput
	oldRun := installedRun
	t.Cleanup(func() {
		effectiveUID = oldUID
		validateInstalledBinary = oldValidate
		installedOutput = oldOutput
		installedRun = oldRun
	})
	effectiveUID = func() int { return 1000 }
	validateInstalledBinary = func(string) error { return nil }
	installedOutput = func(string, ...string) ([]byte, error) {
		return []byte("prolewatch " + audit.ApplicationVersion + "\n"), nil
	}
}

func TestInstalledScenarioSuiteHappyPath(t *testing.T) {
	stubInstalledSuite(t)
	root := t.TempDir()
	var calls [][]string
	installedRun = func(_ io.Writer, _ io.Writer, name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		return nil
	}
	var stdout, stderr bytes.Buffer
	status := run([]string{"--installed", "--root", root, "--scenario", "baseline-safe"}, &stdout, &stderr)
	if status != 0 {
		t.Fatalf("installed suite status=%d stderr=%q", status, stderr.String())
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{installedProlewatch, "doctor", "--no-probe"},
		{installedProlewatch, "security-scenarios", "--root", absoluteRoot, "--scenario", "baseline-safe"},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("installed command calls=%v, want %v", calls, want)
	}
	if !strings.Contains(stdout.String(), "version matches checkout") {
		t.Fatalf("missing version preflight output: %s", stdout.String())
	}
}

func TestInstalledScenarioSuiteRejectsRootAndVersionMismatch(t *testing.T) {
	stubInstalledSuite(t)
	effectiveUID = func() int { return 0 }
	var stdout, stderr bytes.Buffer
	if status := run([]string{"--installed"}, &stdout, &stderr); status != 1 || !strings.Contains(stderr.String(), "not root") {
		t.Fatalf("root status=%d stderr=%q", status, stderr.String())
	}

	effectiveUID = func() int { return 1000 }
	installedOutput = func(string, ...string) ([]byte, error) { return []byte("prolewatch 0.0.0\n"), nil }
	stdout.Reset()
	stderr.Reset()
	if status := run([]string{"--installed"}, &stdout, &stderr); status != 1 || !strings.Contains(stderr.String(), "update the installation first") {
		t.Fatalf("mismatch status=%d stderr=%q", status, stderr.String())
	}
}

func TestInstalledScenarioSuitePropagatesPreflightFailures(t *testing.T) {
	stubInstalledSuite(t)
	var calls int
	installedRun = func(_ io.Writer, _ io.Writer, _ string, _ ...string) error {
		calls++
		return errors.New("doctor failed")
	}
	var stdout, stderr bytes.Buffer
	if status := run([]string{"--installed"}, &stdout, &stderr); status != 1 || calls != 1 || !strings.Contains(stderr.String(), "doctor --no-probe failed") {
		t.Fatalf("doctor failure status=%d calls=%d stderr=%q", status, calls, stderr.String())
	}

	stubInstalledSuite(t)
	calls = 0
	installedRun = func(_ io.Writer, _ io.Writer, _ string, args ...string) error {
		calls++
		if args[0] == "security-scenarios" {
			return errors.New("scenario failed")
		}
		return nil
	}
	stdout.Reset()
	stderr.Reset()
	if status := run([]string{"--installed"}, &stdout, &stderr); status != 1 || calls != 2 || !strings.Contains(stderr.String(), "security scenarios failed") {
		t.Fatalf("scenario failure status=%d calls=%d stderr=%q", status, calls, stderr.String())
	}
}

func TestCheckInstalledBinaryRejectsMissingPath(t *testing.T) {
	if err := checkInstalledBinary(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing installed binary was accepted")
	}
}
