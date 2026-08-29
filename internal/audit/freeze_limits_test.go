package audit

import (
	"testing"

	"github.com/holgerjh/prolewatch/internal/contain"
)

// PKGBUILD evaluation is arbitrary shell and therefore needs the same kinds of
// cgroup, task, and timeout controls as the build. Otherwise top-level code can
// exhaust the host before any build phase begins.
//
// The envelope for evaluation must always be valid, whatever the configuration
// says, because an invalid envelope means the evaluation is refused for a
// reason the user cannot act on.
func TestFreezeEnvelopeIsAlwaysValid(t *testing.T) {
	for name, cfg := range map[string]BuildConfig{
		"defaults": DefaultConfig().Build,
		"zeroed":   {},
		"negative": {MemoryBytes: -1, CPUCount: -1, TasksMax: -1, TimeoutSeconds: -1,
			WorkspaceBytes: -1, WorkspaceFiles: -1, OutputBytes: -1},
		"enormous": {MemoryBytes: 1 << 62, CPUCount: 4096, TasksMax: 1 << 20,
			TimeoutSeconds: 86400, WorkspaceBytes: 1 << 62, WorkspaceFiles: 1 << 30, OutputBytes: 1 << 40},
	} {
		limits := freezeLimits(cfg)
		if err := limits.Validate(); err != nil {
			t.Errorf("%s: freeze envelope is unusable: %v (%+v)", name, err, limits)
		}
	}
}

// Evaluation is supposed to print a few dozen lines and exit; a build is
// supposed to compile for minutes. Handing evaluation the build's envelope
// means a top-level `while :; do :; done` hangs for the full build timeout
// before the user sees anything - most of the attack, none of the work.
func TestFreezeEnvelopeIsNeverLooserThanTheBuild(t *testing.T) {
	for name, cfg := range map[string]BuildConfig{
		"defaults": DefaultConfig().Build,
		"enormous": {MemoryBytes: 1 << 62, CPUCount: 4096, TasksMax: 1 << 20,
			TimeoutSeconds: 86400, WorkspaceBytes: 1 << 62, WorkspaceFiles: 1 << 30, OutputBytes: 1 << 40},
		"tiny": {MemoryBytes: 64 << 20, CPUCount: 1, TasksMax: 8, TimeoutSeconds: 5,
			WorkspaceBytes: 1 << 20, WorkspaceFiles: 16, OutputBytes: 4096},
	} {
		build := effectiveBuildLimits(cfg).limits()
		freeze := freezeLimits(cfg)
		if build.MemoryBytes > 0 && freeze.MemoryBytes > build.MemoryBytes {
			t.Errorf("%s: evaluation may use more memory than the build", name)
		}
		if build.TimeoutSeconds > 0 && freeze.TimeoutSeconds > build.TimeoutSeconds {
			t.Errorf("%s: evaluation may run longer than the build", name)
		}
		if build.TasksMax > 0 && freeze.TasksMax > build.TasksMax {
			t.Errorf("%s: evaluation may spawn more tasks than the build", name)
		}
		if build.CPUCount > 0 && freeze.CPUCount > build.CPUCount {
			t.Errorf("%s: evaluation may use more CPU than the build", name)
		}
		if build.OutputBytes > 0 && freeze.OutputBytes > build.OutputBytes {
			t.Errorf("%s: evaluation may emit more output than the build", name)
		}
	}
	// And it must be meaningfully shorter than a default build, not merely
	// not-longer: the point is that a hang is noticed in a minute, not an hour.
	if freezeLimits(DefaultConfig().Build).TimeoutSeconds > 60 {
		t.Error("evaluation may hang for longer than a minute under default configuration")
	}
}

// The build path and the containment primitive must use the same resource
// values so the reported and enforced envelopes cannot diverge.
func TestBuildEnforcementSurvivesTheSharedPrimitive(t *testing.T) {
	effective := effectiveBuildLimits(DefaultConfig().Build)
	limits := effective.limits()
	if limits.MemoryBytes != effective.MemoryBytes || limits.CPUCount != effective.CPUCount ||
		limits.TasksMax != effective.TasksMax || limits.TimeoutSeconds != effective.TimeoutSeconds ||
		limits.OutputBytes != effective.OutputBytes {
		t.Fatalf("the reported envelope and the enforced one disagree:\n%+v\n%+v", effective, limits)
	}
	// LimitFSIZE enforces the build's per-file workspace byte budget.
	if limits.FileSizeBytes != effective.WorkspaceBytes {
		t.Fatalf("LimitFSIZE = %d, want the workspace budget %d", limits.FileSizeBytes, effective.WorkspaceBytes)
	}
	var _ contain.Limits = limits
}
