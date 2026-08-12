package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClassifyInvocation(t *testing.T) {
	cases := map[string][]string{
		"verify":      {"--verifysource", "--skippgpcheck", "-f", "-Cc"},
		"prepare":     {"--nobuild", "-f", "-C", "--ignorearch"},
		"packagelist": {"--packagelist", "--ignorearch"},
		"build":       {"-f", "-c", "--noconfirm", "--noextract", "--noprepare", "--holdver"},
		"skip":        {"-c", "--nobuild", "--noextract", "--ignorearch"},
	}
	for expected, args := range cases {
		inv, err := ClassifyInvocation(args)
		if err != nil || inv.Profile != expected {
			t.Errorf("%s: %+v %v", expected, inv, err)
		}
	}
	if _, err := ClassifyInvocation([]string{"--skipchecksums", "--verifysource"}); err == nil {
		t.Fatal("integrity bypass accepted")
	}
	if _, err := ClassifyInvocation([]string{"--nobuild", "--unknown"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
}

func TestSourceVerificationReceiptAdvancesAfterPrepare(t *testing.T) {
	sources := []SourceProvenance{{Name: "release.tar.xz.sig", Kind: SourceKindSignature}}
	pending, updated := sourceVerificationAfterInvocation(Invocation{Profile: "verify", Args: []string{"--verifysource", "--skippgpcheck"}}, sources)
	if !updated || pending.Checksums != "passed" || pending.PGP != "pending" {
		t.Fatalf("preliminary receipt=%+v updated=%t", pending, updated)
	}
	verified, updated := sourceVerificationAfterInvocation(Invocation{Profile: "prepare", Args: []string{"--nobuild"}}, sources)
	if !updated || verified.Checksums != "passed" || verified.PGP != "verified" {
		t.Fatalf("prepare receipt=%+v updated=%t", verified, updated)
	}
	unsigned, updated := sourceVerificationAfterInvocation(Invocation{Profile: "verify", Args: []string{"--verifysource", "--skippgpcheck"}}, nil)
	if !updated || unsigned.PGP != "not-applicable" {
		t.Fatalf("unsigned receipt=%+v updated=%t", unsigned, updated)
	}
}
func TestGPGArguments(t *testing.T) {
	action, keys, err := ValidateGPGArguments([]string{"--recv-keys", "0123456789abcdef"})
	if err != nil || action != "--recv-keys" || keys[0] != "0123456789ABCDEF" {
		t.Fatalf("unexpected: %s %#v %v", action, keys, err)
	}
	if _, _, err := ValidateGPGArguments([]string{"--decrypt", "0123456789abcdef"}); err == nil {
		t.Fatal("unsafe action accepted")
	}
	if _, _, err := ValidateGPGArguments([]string{"--list-keys", "bad"}); err == nil {
		t.Fatal("invalid fingerprint accepted")
	}
	if _, _, err := ValidateGPGArguments([]string{"--list-keys", strings.Repeat("A", 16), strings.Repeat("B", 16)}); err == nil {
		t.Fatal("multiple list fingerprints accepted")
	}
	manyKeys := append([]string{"--recv-keys"}, make([]string, 65)...)
	for index := 1; index < len(manyKeys); index++ {
		manyKeys[index] = strings.Repeat("A", 16)
	}
	if _, _, err := ValidateGPGArguments(manyKeys); err == nil {
		t.Fatal("excessive fingerprint set accepted")
	}
}
func TestHookInstallIsIdempotent(t *testing.T) {
	config := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", config)
	share, err := filepath.Abs(filepath.Join("..", "..", "share"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROLEWATCH_SHARE", share)
	module, _, err := InstallHook()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := InstallHook(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(config, "yay", "init.lua"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(raw), hookBegin) != 1 {
		t.Fatal("hook duplicated")
	}
	if err := UninstallHook(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(module); !os.IsNotExist(err) {
		t.Fatal("module was not removed")
	}
}

func TestHookInstallMigratesLegacyNamespace(t *testing.T) {
	configRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configRoot)
	share, err := filepath.Abs(filepath.Join("..", "..", "share"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROLEWATCH_SHARE", share)
	yayConfig := filepath.Join(configRoot, "yay")
	if err := os.MkdirAll(yayConfig, 0o700); err != nil {
		t.Fatal(err)
	}
	legacyBlock := legacyHookBegin + "\nrequire(\"yay-ai-audit\")\n" + legacyHookEnd + "\n"
	initPath := filepath.Join(yayConfig, "init.lua")
	if err := os.WriteFile(initPath, []byte("local keep = true\n"+legacyBlock), 0o600); err != nil {
		t.Fatal(err)
	}
	legacyModule := filepath.Join(yayConfig, "yay-ai-audit.lua")
	if err := os.WriteFile(legacyModule, []byte("legacy module\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	module, backup, err := InstallHook()
	if err != nil {
		t.Fatal(err)
	}
	if module != filepath.Join(yayConfig, "prolewatch.lua") || backup == "" {
		t.Fatalf("unexpected migration result: module=%q backup=%q", module, backup)
	}
	updated, err := os.ReadFile(initPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(updated), legacyHookBegin) || strings.Count(string(updated), hookBegin) != 1 || !strings.Contains(string(updated), "local keep = true") {
		t.Fatalf("legacy hook was not safely replaced: %s", updated)
	}
	if _, err := os.Stat(legacyModule); !os.IsNotExist(err) {
		t.Fatal("legacy hook module was not retired")
	}
	legacyBackups, err := filepath.Glob(legacyModule + ".backup-*")
	if err != nil || len(legacyBackups) != 1 {
		t.Fatalf("legacy module backup missing: %v %v", legacyBackups, err)
	}
}

func TestYayHookAnnouncesOneTransactionWithoutExternalState(t *testing.T) {
	path, err := filepath.Abs(filepath.Join("..", "..", "share", "prolewatch.lua"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	if strings.Count(source, `table.insert(command_parts, "--announce-transaction")`) != 1 ||
		!strings.Contains(source, "local transaction_announced = false") ||
		!strings.Contains(source, `phase == "pre" and not transaction_announced`) {
		t.Fatalf("yay hook does not scope the activation marker to one pre-scan: %s", source)
	}
	for _, forbidden := range []string{"/tmp/prolewatch-announced", "PROLEWATCH_ANNOUNCED", "os.getenv"} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("yay activation state uses externally spoofable state %q", forbidden)
		}
	}
}
