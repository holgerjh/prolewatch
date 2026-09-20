package audit

import (
	"context"
	"errors"
	"testing"

	"github.com/holgerjh/prolewatch/internal/contain"
	"github.com/holgerjh/prolewatch/internal/egress"
)

func fakeSourceFreezeMonitor() *workspaceMonitor {
	finished := make(chan struct{})
	close(finished)
	return &workspaceMonitor{
		fd:       -1,
		errors:   make(chan error, 1),
		done:     make(chan struct{}),
		finished: finished,
	}
}

func withSourceFreezeSeams(t *testing.T) {
	t.Helper()
	previousRunner := sourceFreezeRunner
	previousMonitorStart := sourceFreezeMonitorStart
	t.Cleanup(func() {
		sourceFreezeRunner = previousRunner
		sourceFreezeMonitorStart = previousMonitorStart
	})
}

func TestSourceFreezeMonitorStartFailurePreventsEvaluation(t *testing.T) {
	withSourceFreezeSeams(t)
	sentinel := errors.New("workspace accounting unavailable")
	called := false
	sourceFreezeMonitorStart = func(string, BuildConfig) (*workspaceMonitor, error) {
		return nil, sentinel
	}
	sourceFreezeRunner = func(context.Context, *contain.Namespace, string, contain.Limits) (*egress.Allowance, error) {
		called = true
		return nil, nil
	}

	_, err := freezeDeclaredSourcesWithWorkspaceMonitor(context.Background(), nil, t.TempDir(), DefaultConfig().Build)
	if !errors.Is(err, sentinel) {
		t.Fatalf("start failure = %v, want %v", err, sentinel)
	}
	if called {
		t.Fatal("PKGBUILD evaluation ran after workspace monitor setup failed")
	}
}

func TestSourceFreezeMonitorFailureCancelsEvaluation(t *testing.T) {
	withSourceFreezeSeams(t)
	monitor := fakeSourceFreezeMonitor()
	sentinel := errors.New("workspace file limit exceeded")
	sourceFreezeMonitorStart = func(string, BuildConfig) (*workspaceMonitor, error) {
		return monitor, nil
	}
	var observedCause error
	sourceFreezeRunner = func(ctx context.Context, _ *contain.Namespace, _ string, _ contain.Limits) (*egress.Allowance, error) {
		monitor.errors <- sentinel
		<-ctx.Done()
		observedCause = context.Cause(ctx)
		return nil, ctx.Err()
	}

	_, err := freezeDeclaredSourcesWithWorkspaceMonitor(context.Background(), nil, t.TempDir(), DefaultConfig().Build)
	if !errors.Is(err, sentinel) || !errors.Is(observedCause, sentinel) {
		t.Fatalf("monitor failure did not cancel evaluation: err=%v cause=%v", err, observedCause)
	}
	select {
	case <-monitor.done:
	default:
		t.Fatal("workspace monitor was not stopped")
	}
}

func TestSourceFreezeSuccessStopsMonitorAndForwarder(t *testing.T) {
	withSourceFreezeSeams(t)
	monitor := fakeSourceFreezeMonitor()
	sourceFreezeMonitorStart = func(string, BuildConfig) (*workspaceMonitor, error) {
		return monitor, nil
	}
	sourceFreezeRunner = func(ctx context.Context, _ *contain.Namespace, _ string, _ contain.Limits) (*egress.Allowance, error) {
		if err := context.Cause(ctx); err != nil {
			t.Fatalf("clean freeze began with cancellation: %v", err)
		}
		return nil, nil
	}

	if _, err := freezeDeclaredSourcesWithWorkspaceMonitor(context.Background(), nil, t.TempDir(), DefaultConfig().Build); err != nil {
		t.Fatal(err)
	}
	select {
	case <-monitor.done:
	default:
		t.Fatal("successful freeze left its workspace monitor running")
	}
}

func TestSourceFreezeQueuedMonitorFailureWinsOverSuccessfulProcess(t *testing.T) {
	withSourceFreezeSeams(t)
	monitor := fakeSourceFreezeMonitor()
	sentinel := errors.New("workspace byte limit exceeded")
	monitor.errors <- sentinel
	sourceFreezeMonitorStart = func(string, BuildConfig) (*workspaceMonitor, error) {
		return monitor, nil
	}
	sourceFreezeRunner = func(context.Context, *contain.Namespace, string, contain.Limits) (*egress.Allowance, error) {
		return nil, nil
	}

	_, err := freezeDeclaredSourcesWithWorkspaceMonitor(context.Background(), nil, t.TempDir(), DefaultConfig().Build)
	if !errors.Is(err, sentinel) {
		t.Fatalf("successful process hid queued monitor failure: %v", err)
	}
}

func TestSourceFreezeShutdownMonitorFailureWinsOverSuccessfulProcess(t *testing.T) {
	withSourceFreezeSeams(t)
	monitor := fakeSourceFreezeMonitor()
	monitor.finished = make(chan struct{})
	sentinel := errors.New("workspace filesystem reserve violated")
	go func() {
		<-monitor.done
		monitor.errors <- sentinel
		close(monitor.finished)
	}()
	sourceFreezeMonitorStart = func(string, BuildConfig) (*workspaceMonitor, error) {
		return monitor, nil
	}
	sourceFreezeRunner = func(context.Context, *contain.Namespace, string, contain.Limits) (*egress.Allowance, error) {
		return nil, nil
	}

	_, err := freezeDeclaredSourcesWithWorkspaceMonitor(context.Background(), nil, t.TempDir(), DefaultConfig().Build)
	if !errors.Is(err, sentinel) {
		t.Fatalf("successful process hid monitor shutdown failure: %v", err)
	}
}
