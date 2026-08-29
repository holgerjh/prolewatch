package audit

import (
	"bytes"
	"context"
	"errors"
	"github.com/holgerjh/prolewatch/internal/brief"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestClassifyInvocation(t *testing.T) {
	cases := map[string][]string{
		"printsrcinfo": {"--printsrcinfo"},
		"verify":       {"--verifysource", "--skippgpcheck", "-f", "-Cc"},
		"prepare":      {"--nobuild", "-f", "-C", "--ignorearch"},
		"packagelist":  {"--packagelist", "--ignorearch"},
		"build":        {"-f", "-c", "--noconfirm", "--noextract", "--noprepare", "--holdver"},
		"skip":         {"-c", "--nobuild", "--noextract", "--ignorearch"},
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
	for _, args := range [][]string{
		{"--printsrcinfo", "--verifysource"},
		{"--printsrcinfo", "--packagelist"},
	} {
		if _, err := ClassifyInvocation(args); err == nil {
			t.Fatalf("mixed lifecycle invocation accepted: %v", args)
		}
	}
}

func TestMakepkgCompatibilityFailuresStaySeparateFromSecurityStops(t *testing.T) {
	compatibilityCases := [][]string{
		nil,
		{"--config"},
		{"--unknown-class"},
		{"--nobuild", "--unknown-flag"},
	}
	for _, args := range compatibilityCases {
		_, err := ClassifyInvocation(args)
		if !errors.Is(err, errMakepkgCompatibility) {
			t.Errorf("command shape %q was not classified as a compatibility failure: %v", args, err)
		}
	}

	securityCases := [][]string{
		{"--printsrcinfo", "--skipchecksums"},
		{"--verifysource", "--skipchecksums"},
		{"--verifysource", "--skipinteg"},
		{"--nobuild", "--skippgpcheck"},
	}
	for _, args := range securityCases {
		_, err := ClassifyInvocation(args)
		if err == nil || errors.Is(err, errMakepkgCompatibility) {
			t.Errorf("security stop %q was presented as recoverable compatibility: %v", args, err)
		}
	}
}

func TestMakepkgCompatibilityFailureExplainsRecoveryAndProtectionLoss(t *testing.T) {
	_, compatibility := ClassifyInvocation([]string{"--nobuild", "--future-yay-flag"})
	var output bytes.Buffer
	renderMakepkgInvocationFailure(newTerminalRenderer(DefaultConfig(), &output), &output, compatibility)
	rendered := output.String()
	for _, want := range []string{
		"MAKEPKG COMPATIBILITY STOP",
		"before makepkg evaluated package code",
		"prolewatch doctor",
		"prolewatch uninstall-hook",
		"without Prolewatch containment or review",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("compatibility diagnostic omitted %q: %s", want, rendered)
		}
	}

	_, forbidden := ClassifyInvocation([]string{"--verifysource", "--skipchecksums"})
	output.Reset()
	renderMakepkgInvocationFailure(newTerminalRenderer(DefaultConfig(), &output), &output, forbidden)
	if strings.Contains(output.String(), "uninstall-hook") || strings.Contains(output.String(), "compatibility") {
		t.Fatalf("integrity bypass received compatibility recovery advice: %s", output.String())
	}
}

func TestSandboxFailureDetailsDistinguishKilledTimeoutAndNormalExit(t *testing.T) {
	enforcement := SandboxEnforcement{
		MemoryBytes: 8 << 30, CPUCount: 4, TasksMax: 512, TimeoutSeconds: 2 * 60 * 60,
		WorkspaceBytes: 16 << 30, WorkspaceFiles: 500_000, OutputBytes: 32 << 20,
		NetworkPolicy: "isolated", Termination: "process-exit",
	}
	killed := exec.Command("/bin/sh", "-c", "kill -9 $$").Run()
	if killed == nil {
		t.Fatal("SIGKILL fixture unexpectedly succeeded")
	}
	detail := strings.Join(sandboxFailureDetails(enforcement, killed), "\n")
	for _, want := range []string{"SIGKILL", "may indicate", "memory 8.0 GiB", "swap disabled", "tasks 512", "CPUs 4", "timeout 2h0m0s", "build.memory_bytes", systemConfigDefaultPath} {
		if !strings.Contains(detail, want) {
			t.Errorf("SIGKILL diagnostic omitted %q: %s", want, detail)
		}
	}

	if detail := sandboxFailureDetails(enforcement, errors.New("exit status 8")); len(detail) != 0 {
		t.Fatalf("ordinary package failure received speculative resource advice: %q", detail)
	}

	enforcement.Termination = "timeout"
	detail = strings.Join(sandboxFailureDetails(enforcement, errors.New("build sandbox timed out")), "\n")
	for _, want := range []string{"2h0m0s", "build.timeout_seconds", systemConfigDefaultPath} {
		if !strings.Contains(detail, want) {
			t.Errorf("timeout diagnostic omitted %q: %s", want, detail)
		}
	}
}

func TestReadOnlyUsrFailureExplainsThePackagingFix(t *testing.T) {
	detail := strings.Join(sandboxOutputFailureDetails(
		Invocation{Profile: "build", PackageBase: "stu-git"},
		nil,
		[]byte("mkdir: cannot create directory '/usr/local/man/man1': Read-only file system\n"),
	), "\n")
	// The plain-language cause, the technical defect for whoever fixes it, and
	// both recovery paths. Reporting upstream comes first: it is the one that
	// fixes the package for everyone rather than only for this user.
	for _, want := range []string{
		"usually means", "the write to /usr was refused",
		"$pkgdir", "DESTDIR",
		"Preferred fix", "AUR maintainer of stu-git",
		"yay -S stu-git --editmenu",
	} {
		if !strings.Contains(detail, want) {
			t.Errorf("read-only /usr diagnostic omitted %q: %s", want, detail)
		}
	}
	// The diagnosis is inferred from package-authored output, which can print
	// these strings without having attempted the write. It must not harden into
	// a categorical claim, and must not promise that nothing changed: the
	// checkout, sources, and caches are writable inside the sandbox.
	for _, forbidden := range []string{"nothing on your system was changed", "The recipe tried to"} {
		if strings.Contains(detail, forbidden) {
			t.Errorf("diagnosis overclaimed with %q: %s", forbidden, detail)
		}
	}
	if !strings.Contains(detail, "may have changed") {
		t.Errorf("diagnostic did not say what the build may still have altered: %s", detail)
	}
	// The variable to set is upstream-specific, so it points at where to look
	// rather than naming one and being wrong.
	if !strings.Contains(detail, "does not guess") {
		t.Errorf("diagnostic did not say the staging variable is not guessed: %s", detail)
	}
	// /usr/local means the installer got no prefix at all; bare /usr means it
	// got one but not the staging directory. They are different defects.
	if !strings.Contains(detail, "/usr/local") {
		t.Errorf("the no-prefix case was not distinguished: %s", detail)
	}
	bare := strings.Join(sandboxOutputFailureDetails(
		Invocation{Profile: "build", PackageBase: "stu-git"},
		nil,
		[]byte("install: cannot create regular file '/usr/lib/thing': Read-only file system\n"),
	), "\n")
	if !strings.Contains(bare, "a prefix did reach the installer") {
		t.Errorf("the prefix-honoured case was not distinguished: %s", bare)
	}
	if strings.Index(detail, "Preferred fix") > strings.Index(detail, "--editmenu") {
		t.Errorf("the editable-recipe path was offered before reporting upstream: %s", detail)
	}
	// Editing a PKGBUILD means opening attacker-authored text. Offering it
	// without saying so would make it look like an ordinary repair step.
	for _, want := range []string{"package-authored text", "Containment stays on"} {
		if !strings.Contains(detail, want) {
			t.Errorf("editable-recipe path omitted its warning %q: %s", want, detail)
		}
	}
	// A name the recipe validator would reject never reaches a command line the
	// user is invited to run.
	hostile := strings.Join(sandboxOutputFailureDetails(
		Invocation{Profile: "build", PackageBase: "evil; rm -rf ~"},
		nil,
		[]byte("mkdir: cannot create directory '/usr/lib/x': Read-only file system\n"),
	), "\n")
	if strings.Contains(hostile, "--editmenu") || strings.Contains(hostile, "rm -rf") {
		t.Fatalf("an unvalidated package name reached a suggested command: %s", hostile)
	}
	if !strings.Contains(hostile, "Preferred fix") {
		t.Fatalf("the upstream-report path was dropped along with the command: %s", hostile)
	}
	if detail := sandboxOutputFailureDetails(Invocation{Profile: "prepare"}, nil, []byte("/usr/local: Read-only file system")); len(detail) != 0 {
		t.Fatalf("non-build phase received package staging advice: %q", detail)
	}
	if detail := sandboxOutputFailureDetails(Invocation{Profile: "build"}, nil, []byte("/tmp: Read-only file system")); len(detail) != 0 {
		t.Fatalf("unrelated read-only path received /usr staging advice: %q", detail)
	}
}

func TestContainedMakepkgSkipsOnlyRedundantHostDependencyProbe(t *testing.T) {
	for _, profile := range []string{"prepare", "build", "skip"} {
		original := []string{"--marker"}
		got := containedMakepkgArgs(Invocation{Profile: profile, Args: original})
		if strings.Join(got, " ") != "--marker --nodeps" {
			t.Fatalf("%s args=%q", profile, got)
		}
		if len(original) != 1 {
			t.Fatalf("%s mutated the classified yay arguments: %q", profile, original)
		}
	}
	for _, profile := range []string{"printsrcinfo", "verify", "packagelist", "info"} {
		if got := containedMakepkgArgs(Invocation{Profile: profile, Args: []string{"--marker"}}); strings.Join(got, " ") != "--marker" {
			t.Fatalf("%s unexpectedly disabled dependency checks: %q", profile, got)
		}
	}
}

func TestPrintsrcinfoProtocolOutputIsExactAndRejectsTerminalControls(t *testing.T) {
	valid := []byte("pkgbase = demo\n\tpkgver = 1\n\tpkgrel = 1\npkgname = demo\n")
	var output bytes.Buffer
	if err := writeMakepkgProtocolOutput(&output, valid); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), valid) {
		t.Fatalf("protocol output changed: %q", output.Bytes())
	}
	for name, value := range map[string][]byte{
		"empty":         nil,
		"escape":        []byte("pkgbase = demo\x1b[2K\n"),
		"carriage":      []byte("pkgbase = demo\rforged\n"),
		"invalid UTF-8": {0xff, '\n'},
	} {
		output.Reset()
		if err := writeMakepkgProtocolOutput(&output, value); err == nil {
			t.Errorf("%s protocol output was accepted", name)
		}
		if output.Len() != 0 {
			t.Errorf("%s protocol output wrote bytes before rejection: %q", name, output.Bytes())
		}
	}
}

func TestSourceVerificationReceiptAdvancesAfterPrepare(t *testing.T) {
	sources := []brief.SourceProvenance{{Name: "release.tar.xz.sig", Kind: brief.SourceKindSignature}}
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

// The failure narrative used to read backwards. stdout and stderr are captured
// into separate buffers, and replaying them one block after the other put
// "A failure occurred in package()" above "Starting build()". The transcript
// records observation order instead.
func TestOutputTranscriptPreservesObservedOrder(t *testing.T) {
	transcript := newOutputTranscript(1 << 20)
	transcript.Observe(commandStdout, []byte("==> Starting build()...\n"))
	transcript.Observe(commandStderr, []byte("warning: something\n"))
	transcript.Observe(commandStdout, []byte("==> Entering fakeroot environment...\n"))
	transcript.Observe(commandStderr, []byte("==> ERROR: A failure occurred in package().\n"))

	merged, dropped := transcript.Bytes()
	if dropped {
		t.Fatal("a short transcript reported dropped output")
	}
	got := string(merged)
	want := "==> Starting build()...\nwarning: something\n==> Entering fakeroot environment...\n==> ERROR: A failure occurred in package().\n"
	if got != want {
		t.Fatalf("streams were not interleaved:\n got %q\nwant %q", got, want)
	}
	if strings.Index(got, "A failure occurred") < strings.Index(got, "Starting build()") {
		t.Fatal("the failure still renders before the build that produced it")
	}
}

// The tail is the part worth keeping: a build that failed says why at the end,
// so overflowing must not discard the error to preserve the opening banner.
func TestOutputTranscriptKeepsTheFailureTail(t *testing.T) {
	transcript := newOutputTranscript(32)
	transcript.Observe(commandStdout, []byte(strings.Repeat("banner\n", 40)))
	transcript.Observe(commandStderr, []byte("==> ERROR: the part that matters\n"))

	merged, dropped := transcript.Bytes()
	if !dropped {
		t.Fatal("overflowing the window was not reported")
	}
	if len(merged) > 32 {
		t.Fatalf("transcript kept %d bytes, past its %d limit", len(merged), 32)
	}
	if !strings.Contains(string(merged), "the part that matters") {
		t.Fatalf("the failure tail was discarded: %q", merged)
	}
	// A single write larger than the window keeps its own tail.
	single := newOutputTranscript(8)
	single.Observe(commandStderr, []byte("0123456789abcdef"))
	if merged, _ := single.Bytes(); string(merged) != "9abcdef" && string(merged) != "89abcdef" {
		t.Fatalf("an oversized write did not keep its tail: %q", merged)
	}
	// A zero limit records nothing and must not panic.
	empty := newOutputTranscript(0)
	empty.Observe(commandStdout, []byte("x"))
	if merged, _ := empty.Bytes(); len(merged) != 0 {
		t.Fatalf("a zero-limit transcript recorded %q", merged)
	}
}

// The transcript is fed by the real capture wiring: os/exec drains stdout and
// stderr with independent goroutines, so both notifyingBuffers call the shared
// observer concurrently. Exercising that path is the only way to show the
// locking holds and that no write is lost or duplicated; run under -race.
func TestOutputTranscriptSurvivesConcurrentDualStreamCapture(t *testing.T) {
	transcript := newOutputTranscript(1 << 20)
	overflow := make(chan error, 2)
	out := &notifyingBuffer{buffer: newLimitedBuffer(1 << 20), errors: overflow, stream: commandStdout, observer: transcript.Observe}
	errStream := &notifyingBuffer{buffer: newLimitedBuffer(1 << 20), errors: overflow, stream: commandStderr, observer: transcript.Observe}

	const writes = 200
	var wg sync.WaitGroup
	wg.Add(2)
	for _, target := range []struct {
		writer *notifyingBuffer
		line   string
	}{{out, "O\n"}, {errStream, "E\n"}} {
		go func(w *notifyingBuffer, line string) {
			defer wg.Done()
			for i := 0; i < writes; i++ {
				if _, err := w.Write([]byte(line)); err != nil {
					t.Errorf("capture write failed: %v", err)
					return
				}
			}
		}(target.writer, target.line)
	}
	wg.Wait()

	merged, dropped := transcript.Bytes()
	if dropped {
		t.Fatal("a transcript inside its limit reported dropped output")
	}
	// Interleaving across two pipes is not deterministic, so the property under
	// test is that every observed byte is recorded exactly once.
	if got := strings.Count(string(merged), "O"); got != writes {
		t.Fatalf("stdout writes recorded %d times, want %d", got, writes)
	}
	if got := strings.Count(string(merged), "E"); got != writes {
		t.Fatalf("stderr writes recorded %d times, want %d", got, writes)
	}
	if len(merged) != 2*writes*2 {
		t.Fatalf("transcript length %d, want %d", len(merged), 2*writes*2)
	}
}

// Every Termination the runner can produce needs a decided label. A resource
// ceiling means containment worked; only a genuine setup or accounting failure
// is an error about Prolewatch.
func TestSandboxFailureStampCoversEveryTermination(t *testing.T) {
	tests := []struct {
		termination string
		cause       error
		wantLabel   string
		wantRole    string
	}{
		{"process-exit", errors.New("exit status 4"), "BUILD FAILED", "amber"},
		{"process-exit", errors.New("signal: killed"), "BUILD STOPPED", "amber"},
		{"process-exit", errors.New("exit status 125"), "SANDBOX ERROR", "red"},
		{"process-exit", errors.New("exit status 126"), "SANDBOX ERROR", "red"},
		{"process-exit", errors.New("exit status 127"), "SANDBOX ERROR", "red"},
		{"timeout", errors.New("build sandbox timed out"), "BUILD STOPPED", "amber"},
		{"output-limit", errors.New("subprocess output exceeds hard limit"), "BUILD STOPPED", "amber"},
		{"workspace-limit", errors.New("workspace byte limit exceeded"), "BUILD STOPPED", "amber"},
		{"cancelled", context.Canceled, "BUILD STOPPED", "amber"},
		{"sandbox-setup", errors.New("bwrap missing"), "SANDBOX ERROR", "red"},
		{"systemd-start", errors.New("systemd-run failed"), "SANDBOX ERROR", "red"},
		{"workspace-accounting", errors.New("monitor failed"), "SANDBOX ERROR", "red"},
		{"", errors.New("unset"), "SANDBOX ERROR", "red"},
	}
	seen := map[string]bool{}
	for _, test := range tests {
		t.Run(test.termination+"/"+test.cause.Error(), func(t *testing.T) {
			seen[test.termination] = true
			label, role := sandboxFailureStamp(SandboxEnforcement{Termination: test.termination}, test.cause)
			if label != test.wantLabel || role != test.wantRole {
				t.Fatalf("stamp = %q/%q, want %q/%q", label, role, test.wantLabel, test.wantRole)
			}
			if label == "BLOCK" {
				t.Fatal("a build failure was stamped as a policy block")
			}
		})
	}
	// Guard against a Termination being added to the runner without a decided
	// label here. These are every value runConstrainedCommand can assign.
	for _, termination := range []string{
		"process-exit", "timeout", "output-limit", "workspace-limit",
		"cancelled", "sandbox-setup", "systemd-start", "workspace-accounting",
	} {
		if !seen[termination] {
			t.Errorf("termination %q has no test deciding its label", termination)
		}
	}
}

// A containment startup failure is reported as process-exit like any other
// non-zero result, so the message must not attribute it to the package.
func TestSandboxFailureMessageDoesNotBlameThePackageWithoutEvidence(t *testing.T) {
	ordinary := sandboxFailureMessage(SandboxEnforcement{Termination: "process-exit"}, errors.New("exit status 4"))
	if strings.Contains(ordinary, "package's own build") {
		t.Fatalf("an unattributable exit was blamed on the package: %q", ordinary)
	}
	if !strings.Contains(ordinary, "exited non-zero") {
		t.Fatalf("ordinary exit lost its explanation: %q", ordinary)
	}
	startup := sandboxFailureMessage(SandboxEnforcement{Termination: "process-exit"}, errors.New("exit status 125"))
	if !strings.Contains(startup, "could not start") {
		t.Fatalf("a bubblewrap startup failure read as a build failure: %q", startup)
	}
}

// The plain renderer must carry the same distinction; a log without colour is
// where the word is doing all of the work.
func TestStampedLineCarriesTheLabelWithoutColour(t *testing.T) {
	plain := terminalRenderer{}
	got := plain.stampedLine("BUILD FAILED", "amber", "stu-git / build: exit status 4")
	if !strings.Contains(got, "BUILD FAILED") || strings.Contains(got, "BLOCK") {
		t.Fatalf("plain failure line lost its label: %q", got)
	}
}
