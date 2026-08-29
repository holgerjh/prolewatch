package contain

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func validLimits() Limits {
	return Limits{MemoryBytes: 1 << 30, CPUCount: 2, TasksMax: 128,
		TimeoutSeconds: 60, FileSizeBytes: 1 << 26, OutputBytes: 1 << 20}
}

// A non-positive limit is not a permissive limit - systemd reads MemoryMax=0 as
// "no memory at all" and TasksMax=0 as "no tasks" - but it means the envelope
// was never configured, and guessing which reading was intended is worse than
// refusing.
func TestNonPositiveLimitsAreRefused(t *testing.T) {
	if err := validLimits().Validate(); err != nil {
		t.Fatalf("a complete envelope was rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Limits){
		"memory":  func(l *Limits) { l.MemoryBytes = 0 },
		"cpu":     func(l *Limits) { l.CPUCount = 0 },
		"tasks":   func(l *Limits) { l.TasksMax = 0 },
		"timeout": func(l *Limits) { l.TimeoutSeconds = 0 },
		"fsize":   func(l *Limits) { l.FileSizeBytes = -1 },
		"output":  func(l *Limits) { l.OutputBytes = 0 },
	} {
		limits := validLimits()
		mutate(&limits)
		if err := limits.Validate(); err == nil {
			t.Errorf("an envelope with no %s limit was accepted", name)
		}
	}
}

// Assert the complete envelope rather than sampling it, because omitting any
// one systemd property silently weakens containment for every caller.
func TestEveryResourceControlReachesSystemd(t *testing.T) {
	args := ScopeArgs("prolewatch-test.service", validLimits())
	rendered := strings.Join(args, " ")
	for _, property := range []string{
		"MemoryMax=1073741824",
		"MemorySwapMax=0",
		"TasksMax=128",
		"CPUQuota=200%",
		"RuntimeMaxSec=60",
		"LimitFSIZE=67108864",
		// Without control-group kill semantics a process that forks away from
		// the one systemd started survives the stop, and the envelope holds
		// only against programs that were not trying to escape it.
		"KillMode=control-group",
		"SendSIGKILL=yes",
		"TimeoutStopSec=5s",
	} {
		if !strings.Contains(rendered, property) {
			t.Errorf("%s is not applied to the transient unit", property)
		}
	}
	for _, flag := range []string{"--user", "--wait", "--collect", "--pipe", "--unit prolewatch-test.service"} {
		if !strings.Contains(rendered, flag) {
			t.Errorf("systemd-run is missing %s", flag)
		}
	}
}

func TestScopeUnitNamesAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		unit, err := ScopeUnit()
		if err != nil {
			t.Fatal(err)
		}
		if seen[unit] {
			t.Fatalf("duplicate transient unit name: %s", unit)
		}
		seen[unit] = true
		if !strings.HasSuffix(unit, ".service") {
			t.Fatalf("unit name is not a service unit: %s", unit)
		}
	}
}

// The namespace path reaches a shell. It must arrive as a positional argument,
// never interpolated into the script, or a path containing shell metacharacters
// is a command injection into the trusted side.
func TestNamespacePathIsNotInterpolatedIntoTheScript(t *testing.T) {
	hostile := "/proc/1/fd/3\"; touch /tmp/pwned; #"
	executable, args, err := NamespaceJoiningCommand(
		[]string{NamespaceRunnerMarker, hostile, "--userns", "3", "--", "/bin/true"})
	if err != nil {
		t.Fatal(err)
	}
	if executable != "/bin/sh" || args[0] != "-c" {
		t.Fatalf("unexpected launcher: %s %v", executable, args)
	}
	if strings.Contains(args[1], "touch") || strings.Contains(args[1], hostile) {
		t.Fatalf("the namespace path was interpolated into the script: %q", args[1])
	}
	found := false
	for _, arg := range args[2:] {
		if arg == hostile {
			found = true
		}
	}
	if !found {
		t.Fatalf("the namespace path did not arrive as an argument: %v", args)
	}
}

// Anything that is not a /proc path is refused rather than passed through.
func TestNamespaceLauncherRejectsPathsItDidNotProduce(t *testing.T) {
	for _, args := range [][]string{
		{NamespaceRunnerMarker},
		{NamespaceRunnerMarker, "/proc/1/fd/3"},
		{NamespaceRunnerMarker, "/etc/passwd", "--userns", "3"},
		{NamespaceRunnerMarker, "../proc/1/fd/3", "--userns", "3"},
	} {
		if _, _, err := NamespaceJoiningCommand(args); err == nil {
			t.Errorf("%v was accepted", args)
		}
	}
	// Without the marker the arguments go to bwrap unchanged.
	executable, passed, err := NamespaceJoiningCommand([]string{"--unshare-all", "/bin/true"})
	if err != nil || executable != "/usr/bin/bwrap" || len(passed) != 2 {
		t.Fatalf("plain bwrap invocation was rewritten: %s %v (%v)", executable, passed, err)
	}
}

// RunLimited must refuse rather than silently fall back to an unconstrained
// run: an envelope that is skipped when it is inconvenient is not an envelope.
func TestRunLimitedRefusesWithoutANamespaceOrLimits(t *testing.T) {
	if _, _, err := RunLimited(t.Context(), nil, Spec{}, validLimits()); err == nil {
		t.Fatal("RunLimited ran without a namespace")
	}
}

// The resource envelope exists to stop package code that will not stop by
// itself, so nothing on its teardown path may block without a ceiling. Both
// halves of that are measured against seams that never return, because the
// failure they guard against - a wedged user manager or D-Bus - cannot be
// produced on demand and does not show up in a passing suite.
func TestScopeTeardownIsBoundedWhenTheUserManagerNeverAnswers(t *testing.T) {
	previousBudget, previousBinary := ScopeStopBudget, systemctlBinary
	ScopeStopBudget = 100 * time.Millisecond
	blocking := filepath.Join(t.TempDir(), "systemctl")
	if err := os.WriteFile(blocking, []byte("#!/bin/sh\nsleep 600\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	systemctlBinary = blocking
	defer func() { ScopeStopBudget, systemctlBinary = previousBudget, previousBinary }()

	start := time.Now()
	KillScope("prolewatch-does-not-exist.service")
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("KillScope waited %v on an unresponsive user manager", elapsed)
	}

	// A systemd-run client that is never told its unit is gone. AwaitScopeExit
	// must kill it and return rather than wait for a report that is not coming.
	client := exec.Command("/bin/sh", "-c", "sleep 600")
	if err := client.Start(); err != nil {
		t.Skipf("cannot start a blocking client: %v", err)
	}
	done := make(chan error, 1) // deliberately never written
	start = time.Now()
	err := AwaitScopeExit(client, done)
	elapsed := time.Since(start)
	if !errors.Is(err, ErrScopeCleanup) {
		t.Fatalf("an unconfirmed cleanup must be reported as one: %v", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("AwaitScopeExit waited %v for a client that never returns", elapsed)
	}
	if err := client.Wait(); err == nil {
		t.Fatal("the blocking client was left running after the cleanup budget expired")
	}

	// The ordinary path still returns the moment the client reports.
	reported := make(chan error, 1)
	reported <- nil
	if err := AwaitScopeExit(exec.Command("/bin/true"), reported); err != nil {
		t.Fatalf("a client that reported promptly was treated as a failed cleanup: %v", err)
	}
}
