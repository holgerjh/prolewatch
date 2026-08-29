package audit

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// yay -B asks its configured makepkg binary for fresh .SRCINFO before source
// verification and before the AURPreInstall event that creates the pre marker.
// The query still sources the PKGBUILD, so the wrapper must run it inside the
// resource-bounded sandbox while keeping stdout as unframed protocol data for
// yay. No audit service may be consulted in this bootstrap ordering.
func TestPrintsrcinfoRunsContainedBeforeThePreMarkerExists(t *testing.T) {
	withStateAndShare(t)
	checkout := t.TempDir()
	writePackageFixture(t, checkout)

	cfg := DefaultConfig()
	previousConfigPath := SystemConfigPath
	SystemConfigPath = writeCurrentConfig(t, cfg)
	t.Cleanup(func() { SystemConfigPath = previousConfigPath })
	previousFactory, previousRunner, previousManager := auditServiceFactory, makepkgSandboxRunner, userManagerAvailable
	t.Cleanup(func() {
		auditServiceFactory = previousFactory
		makepkgSandboxRunner = previousRunner
		userManagerAvailable = previousManager
	})
	serviceCalled := false
	auditServiceFactory = func(context.Context, Config, ReviewClient) (*AuditService, error) {
		serviceCalled = true
		return nil, errors.New("printsrcinfo must precede audit service use")
	}
	userManagerAvailable = func() bool { return true }

	want := "pkgbase = demo\n\tpkgver = 1\n\tpkgrel = 1\npkgname = demo\n"
	var captured Invocation
	var network bool
	var sandboxConfig Config
	makepkgSandboxRunner = func(_ context.Context, invocation Invocation, _ string, enabled bool, cfg Config) ([]byte, []byte, SandboxEnforcement, error) {
		captured, network = invocation, enabled
		sandboxConfig = cfg
		return []byte(want), []byte("diagnostic \x1b[2Kforged\n"), effectiveBuildLimits(cfg.Build), nil
	}

	t.Chdir(checkout)
	var stdout string
	stderr := captureStderr(t, func() {
		stdout = captureStdout(t, func() {
			if status := RunMakepkg(context.Background(), []string{"--printsrcinfo"}); status != ExitOK {
				t.Fatalf("printsrcinfo status=%d", status)
			}
		})
	})
	if stdout != want {
		t.Fatalf("stdout was not exact .SRCINFO protocol data:\ngot  %q\nwant %q", stdout, want)
	}
	if captured.Profile != "printsrcinfo" || captured.SourceDest != "" || network {
		t.Fatalf("printsrcinfo widened its profile: invocation=%+v network=%t", captured, network)
	}
	if serviceCalled {
		t.Fatal("printsrcinfo tried to load an audit marker before yay created it")
	}
	wantLimits := freezeLimits(cfg.Build)
	if sandboxConfig.Build.MemoryBytes != wantLimits.MemoryBytes || sandboxConfig.Build.CPUCount != wantLimits.CPUCount ||
		sandboxConfig.Build.TasksMax != wantLimits.TasksMax || sandboxConfig.Build.TimeoutSeconds != wantLimits.TimeoutSeconds ||
		sandboxConfig.Build.OutputBytes != wantLimits.OutputBytes {
		t.Fatalf("printsrcinfo did not receive evaluation limits: %+v, want %+v", sandboxConfig.Build, wantLimits)
	}
	if sandboxConfig.Build.WorkspaceBytes != cfg.Build.WorkspaceBytes || sandboxConfig.Build.WorkspaceFiles != cfg.Build.WorkspaceFiles ||
		sandboxConfig.Build.DiskReserveBytes != cfg.Build.DiskReserveBytes {
		t.Fatalf("printsrcinfo changed whole-checkout accounting limits: %+v", sandboxConfig.Build)
	}
	if strings.Contains(stderr, "\x1b[2K") || !strings.Contains(stderr, `\u001b[2Kforged`) {
		t.Fatalf("diagnostic stderr was not neutralised: %q", stderr)
	}
}

func TestPrintsrcinfoFailureNeverForwardsPartialProtocolOutput(t *testing.T) {
	previousRunner := makepkgSandboxRunner
	t.Cleanup(func() { makepkgSandboxRunner = previousRunner })
	cfg := DefaultConfig()

	for _, test := range []struct {
		name        string
		enforcement SandboxEnforcement
		err         error
	}{
		{
			name: "contained command failed",
			enforcement: func() SandboxEnforcement {
				value := effectiveBuildLimits(cfg.Build)
				value.Termination = "process-exit"
				return value
			}(),
			err: errors.New("makepkg rejected the recipe"),
		},
		{
			name: "unexpected network evidence",
			enforcement: func() SandboxEnforcement {
				value := effectiveBuildLimits(cfg.Build)
				value.NetworkPolicy = "public-web-broker"
				return value
			}(),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			makepkgSandboxRunner = func(context.Context, Invocation, string, bool, Config) ([]byte, []byte, SandboxEnforcement, error) {
				return []byte("pkgbase = forged\n"), []byte("diagnostic \x1b[2Kforged\n"), test.enforcement, test.err
			}
			var stdout string
			stderr := captureStderr(t, func() {
				stdout = captureStdout(t, func() {
					status := runPrintsrcinfoBootstrap(context.Background(), Invocation{Profile: "printsrcinfo", Args: []string{"--printsrcinfo"}}, t.TempDir(), cfg, terminalRenderer{}, newOutputTranscript(4096))
					if status != ExitExecutionFailure {
						t.Fatalf("failure status=%d", status)
					}
				})
			})
			if stdout != "" {
				t.Fatalf("failed metadata evaluation leaked protocol stdout: %q", stdout)
			}
			if !strings.Contains(stderr, "pkgbase = forged") || strings.Contains(stderr, "\x1b[2K") || !strings.Contains(stderr, `\u001b[2Kforged`) {
				t.Fatalf("failed metadata diagnostics were not safely replayed: %q", stderr)
			}
		})
	}
}

func TestPrintsrcinfoSetupFailureWithoutOutputDoesNotRenderAnEmptyOutputFrame(t *testing.T) {
	previousRunner := makepkgSandboxRunner
	t.Cleanup(func() { makepkgSandboxRunner = previousRunner })
	cfg := DefaultConfig()
	makepkgSandboxRunner = func(context.Context, Invocation, string, bool, Config) ([]byte, []byte, SandboxEnforcement, error) {
		enforcement := effectiveBuildLimits(cfg.Build)
		enforcement.Termination = "workspace-accounting"
		return nil, nil, enforcement, errors.New("workspace reserve unavailable")
	}
	stderr := captureStderr(t, func() {
		if status := runPrintsrcinfoBootstrap(context.Background(), Invocation{Profile: "printsrcinfo", Args: []string{"--printsrcinfo"}}, t.TempDir(), cfg, terminalRenderer{}, newOutputTranscript(4096)); status != ExitExecutionFailure {
			t.Fatalf("setup failure status=%d", status)
		}
	})
	if strings.Contains(stderr, "contained makepkg output") || !strings.Contains(stderr, "workspace reserve unavailable") {
		t.Fatalf("empty setup failure rendered the wrong diagnostics: %q", stderr)
	}
}
