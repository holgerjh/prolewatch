package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestSetupAndInstallHookRefuseWithoutAConfiguration is the regression test for
// a successful-looking installation that could not do anything.
//
// The hook makes every yay transaction call `prolewatch scan`, and scan reads
// /etc/prolewatch/config.yaml before it does any work. Writing the hook while
// that file is unreadable does not leave the user unprotected - it leaves their
// package manager unable to install anything, immediately after a branded line
// saying setup succeeded. Neither command may write the hook in that state.
func TestSetupAndInstallHookRefuseWithoutAConfiguration(t *testing.T) {
	yayConfig := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", yayConfig)
	previous := SystemConfigPath
	SystemConfigPath = filepath.Join(t.TempDir(), "absent.yaml")
	defer func() { SystemConfigPath = previous }()

	for _, command := range [][]string{{"setup"}, {"install-hook"}} {
		if status := RunCLI(context.Background(), command); status == 0 {
			t.Errorf("%v succeeded with no configuration to run against", command)
		}
	}
	for _, name := range []string{"prolewatch.lua", "init.lua"} {
		if _, err := os.Lstat(filepath.Join(yayConfig, "yay", name)); err == nil {
			t.Errorf("%s was written despite the configuration being unreadable", name)
		}
	}
}

func TestSetupPreflightsBeforeWritingTheHook(t *testing.T) {
	withStateAndShare(t)
	yayConfig := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", yayConfig)
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	raw, err := CanonicalJSON(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	previousPath, previousOwner := SystemConfigPath, installedFileOwnerUID
	SystemConfigPath, installedFileOwnerUID = configPath, ^uint32(0)
	defer func() { SystemConfigPath, installedFileOwnerUID = previousPath, previousOwner }()

	if status := RunCLI(context.Background(), []string{"setup"}); status != 22 {
		t.Fatalf("setup with a failing installation preflight returned %d", status)
	}
	for _, name := range []string{"prolewatch.lua", "init.lua"} {
		if _, err := os.Lstat(filepath.Join(yayConfig, "yay", name)); err == nil {
			t.Errorf("%s was written before the health preflight passed", name)
		}
	}
}

// TestSetupUndoesTheHookWhenVerificationFails is the rollback regression.
//
// Between the preflight and the post-install checks, setup writes a hook that
// makes every yay invocation call Prolewatch. If the verification that follows
// fails - the case that matters is a yay which rejects the module's option keys
// and therefore refuses to run at all - leaving that hook installed hands the
// user a broken package manager and a note telling them to repair it.
func TestSetupUndoesTheHookWhenVerificationFails(t *testing.T) {
	withStateAndShare(t)
	yayConfig := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", yayConfig)
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	raw, err := CanonicalJSON(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// An unrelated line in init.lua stands in for the user's own configuration:
	// rollback must remove Prolewatch's block and nothing else.
	initPath := filepath.Join(yayConfig, "yay", "init.lua")
	if err := os.MkdirAll(filepath.Dir(initPath), 0o700); err != nil {
		t.Fatal(err)
	}
	const userLine = "-- the user's own configuration\n"
	if err := os.WriteFile(initPath, []byte(userLine), 0o600); err != nil {
		t.Fatal(err)
	}

	previousPath, previousOwner := SystemConfigPath, installedFileOwnerUID
	SystemConfigPath = configPath
	// Every installed-payload check passes so that setup gets past its preflight
	// and actually writes the hook; the post-install verification then fails
	// because this machine's yay does not report the wrapper paths.
	installedFileOwnerUID = ^uint32(0)
	defer func() { SystemConfigPath, installedFileOwnerUID = previousPath, previousOwner }()

	previousDoctor := doctorChecks
	doctorChecks = func(context.Context, Config, bool) []Check {
		return []Check{{Name: "installation", OK: true, Required: true, Detail: "stubbed"}}
	}
	previousEffective := yayEffectiveCheck
	yayEffectiveCheck = func(context.Context) Check {
		return Check{Name: yayEffectiveCheckName, OK: false, Required: true, Detail: "yay rejected the configuration"}
	}
	defer func() { doctorChecks, yayEffectiveCheck = previousDoctor, previousEffective }()

	if status := RunCLI(context.Background(), []string{"setup"}); status != 22 {
		t.Fatalf("setup with a failing post-install check returned %d", status)
	}
	if _, err := os.Lstat(filepath.Join(yayConfig, "yay", "prolewatch.lua")); err == nil {
		t.Error("the hook module survived a failed verification")
	}
	current, err := os.ReadFile(initPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != userLine {
		t.Errorf("init.lua was not restored to the user's own content: %q", string(current))
	}
}
