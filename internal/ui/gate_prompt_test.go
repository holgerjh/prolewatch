package ui

import (
	"archive/tar"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/holgerjh/prolewatch/internal/brief"
)

func surface(member string, kind brief.SurfaceKind, body string) brief.PrivilegedSurface {
	return brief.PrivilegedSurface{Member: member, Kind: kind, When: "runs as root", Body: body, Size: int64(len(body))}
}

// The gate prints attacker-authored code directly above a prompt asking whether
// to run it as root. That is the single most valuable thing in this tool to
// forge, so nothing interpolated may end a line or move a cursor.
func TestGatePromptCannotBeForgedBySurfaceContent(t *testing.T) {
	hostile := []brief.PrivilegedSurface{
		surface(".INSTALL", brief.SurfaceScriptlet,
			"post_install() {\n  :\n}\n\nprolewatch: no privileged integration found.\nChoice [k]: k\n"),
		surface("usr/share/libalpm/hooks/\x1b[2Kzz.hook", brief.SurfaceHook, "Exec=/usr/bin/evil\rkeep all"),
	}
	rendered := RenderGatePrompt("foo-bin 1.2.3", hostile)

	if strings.Contains(rendered, "\x1b") || strings.Contains(rendered, "\r") {
		t.Fatalf("raw control sequence reached the prompt:\n%q", rendered)
	}
	// The real prompt must be the last thing on screen. A forged one printed
	// after it would be what the user answers.
	if !strings.HasSuffix(rendered, "Choice [k]: ") {
		t.Fatalf("the real prompt is not last:\n%s", rendered)
	}
	// Package content may repeat the tool's own words - it cannot be stopped
	// from doing so. What it must not do is produce a line that reads as
	// prolewatch's own output. Every quoted line carries the marker, so any
	// occurrence outside a marked line is the real thing.
	for _, line := range strings.Split(rendered, "\n") {
		if strings.Contains(line, quoteMarker) {
			continue
		}
		if strings.Contains(line, "no privileged integration found") {
			t.Fatalf("surface content escaped the quote block: %q", line)
		}
		if strings.HasPrefix(strings.TrimSpace(line), "Choice [k]:") && !strings.HasSuffix(rendered, line) {
			t.Fatalf("a forged prompt appears outside the quote block: %q", line)
		}
	}
}

func TestGatePromptShowsTheCodeAndWhenItRuns(t *testing.T) {
	rendered := RenderGatePrompt("foo-bin", []brief.PrivilegedSurface{
		surface(".INSTALL", brief.SurfaceScriptlet, "post_install() {\n  npm install -g atomic-lockfile\n}\n"),
	})
	if !strings.Contains(rendered, "npm install -g atomic-lockfile") {
		t.Fatalf("the user was asked to approve code without being shown it:\n%s", rendered)
	}
	if !strings.Contains(rendered, "runs as root") {
		t.Fatalf("the prompt does not say when the code runs:\n%s", rendered)
	}
	if !strings.Contains(rendered, "[c] cancel") || !strings.Contains(rendered, "[s] strip all") {
		t.Fatalf("the prompt omits a choice:\n%s", rendered)
	}
	if !strings.Contains(rendered, "k, s, and c act immediately") || !strings.Contains(rendered, "numbered selections with Enter") {
		t.Fatalf("the prompt does not explain which choices need Enter:\n%s", rendered)
	}
}

// A long scriptlet must not scroll the prompt off the screen: what the user
// would then answer is whatever the package chose to leave visible.
func TestGatePromptBoundsSurfaceBodies(t *testing.T) {
	long := strings.Repeat("echo padding\n", 500)
	rendered := RenderGatePrompt("foo-bin", []brief.PrivilegedSurface{surface(".INSTALL", brief.SurfaceScriptlet, long)})
	if lines := strings.Count(rendered, "\n"); lines > maxSurfaceLines+15 {
		t.Fatalf("prompt ran to %d lines; the choice scrolls away", lines)
	}
	if !strings.Contains(rendered, "more lines not shown") {
		t.Fatalf("truncation was silent:\n%s", rendered)
	}
}

func TestGatePromptGivesTruncatedBodyInspectCommand(t *testing.T) {
	archive := "/tmp/foo'bar.pkg.tar.zst"
	long := strings.Repeat("echo padding\n", maxSurfaceLines+1)
	rendered := RenderGatePrompt(archive, []brief.PrivilegedSurface{surface(".INSTALL", brief.SurfaceScriptlet, long)})
	if !strings.Contains(rendered, `/usr/bin/bsdtar -xO --file '/tmp/foo'"'"'bar.pkg.tar.zst' -- '.INSTALL' 2>&1 | /usr/bin/cat -v`) ||
		!strings.Contains(rendered, "Inspect the full body in another terminal") || !strings.Contains(rendered, "more lines not shown") {
		t.Fatalf("truncated root code has no safe inspection command:\n%s", rendered)
	}
}

func TestSurfaceInspectCommandShowsOmittedPolicyThroughTerminalFilter(t *testing.T) {
	member := "usr/share/polkit-1/actions/org.example.manage.policy"
	var body bytes.Buffer
	for index := 0; index < maxSurfaceLines+5; index++ {
		fmt.Fprintf(&body, "  <message xml:lang=\"l%d\">translation</message>\n", index)
	}
	body.WriteString("  <allow_active>yes</allow_active>\n")
	body.WriteString("  <annotate key=\"org.freedesktop.policykit.imply\">org.example.admin</annotate>\n")
	body.Write([]byte("controls:\x1b]2;forged\a\r\x7f\xff\n"))

	archivePath := filepath.Join(t.TempDir(), "policy'fixture.pkg.tar")
	handle, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(handle)
	if err := writer.WriteHeader(&tar.Header{Name: member, Mode: 0o644, Size: int64(body.Len())}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(body.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}

	surface := brief.PrivilegedSurface{Member: member, Activation: brief.ActivationAutomatic, Body: body.String(), Size: int64(body.Len())}
	command := surfaceInspectCommand(archivePath, surface)
	if !strings.Contains(command, `2>&1 | /usr/bin/cat -v`) || !strings.Contains(command, `policy'"'"'fixture.pkg.tar'`) ||
		!strings.Contains(command, `'usr/share/polkit-1/actions/org.example.manage.policy'`) {
		t.Fatalf("inspection command lost stderr filtering or shell quoting: %q", command)
	}

	process := exec.Command("/usr/bin/bash", "-c", command)
	process.Env = append(os.Environ(), "LC_ALL=C")
	output, err := process.CombinedOutput()
	if err != nil {
		t.Fatalf("inspection command failed: %v: %s", err, output)
	}
	text := string(output)
	for _, want := range []string{"<allow_active>yes</allow_active>", "org.freedesktop.policykit.imply", "^[", "^M", "^?", "M-^?"} {
		if !strings.Contains(text, want) {
			t.Errorf("filtered full body omitted %q: %q", want, text)
		}
	}
	for _, value := range output {
		if value != '\n' && value != '\t' && (value < 0x20 || value > 0x7e) {
			t.Fatalf("filtered detail output retained unsafe byte 0x%02x: %q", value, output)
		}
	}

	// bsdtar diagnostics name attacker-controlled archive members. A missing
	// high-byte name proves stderr traverses the same fixed filter rather than
	// reaching the terminal directly.
	missing := surface
	missing.Member = "missing-é.policy"
	errorCommand := surfaceInspectCommand(archivePath, missing)
	process = exec.Command("/usr/bin/bash", "-c", errorCommand)
	process.Env = append(os.Environ(), "LC_ALL=C")
	output, err = process.CombinedOutput()
	if err != nil {
		t.Fatalf("filtered diagnostic command failed: %v: %s", err, output)
	}
	if len(output) == 0 || !bytes.Contains(output, []byte("M-")) {
		t.Fatalf("bsdtar diagnostic did not pass through cat -v: %q", output)
	}
	for _, value := range output {
		if value != '\n' && value != '\t' && (value < 0x20 || value > 0x7e) {
			t.Fatalf("filtered diagnostic retained unsafe byte 0x%02x: %q", value, output)
		}
	}
}

// The default must never be destructive: stripping a surface a package needs
// produces a broken install, so a mistyped key keeps the package intact.
func TestGateChoiceDefaultsToKeepingThePackageIntact(t *testing.T) {
	surfaces := []brief.PrivilegedSurface{
		surface(".INSTALL", brief.SurfaceScriptlet, "x"),
		surface("usr/lib/systemd/system/foo.service", brief.SurfaceUnit, "y"),
	}
	for _, answer := range []string{"", "\n", "  ", "k", "K", "keep"} {
		decision, ok := ParseGateChoice(answer, surfaces)
		if !ok || decision.Cancel || len(decision.Strip) != 0 {
			t.Fatalf("answer %q did not keep the package intact: %+v", answer, decision)
		}
	}
	for _, answer := range []string{"y", "yes", "0", "3", "-1", "strip 1", "banana"} {
		if _, ok := ParseGateChoice(answer, surfaces); ok {
			t.Fatalf("answer %q was accepted; unrecognised input must re-ask", answer)
		}
	}
}

func TestGateChoiceSelectsSurfacesByNumber(t *testing.T) {
	surfaces := []brief.PrivilegedSurface{
		surface(".INSTALL", brief.SurfaceScriptlet, "x"),
		surface("usr/lib/systemd/system/foo.service", brief.SurfaceUnit, "y"),
	}
	decision, ok := ParseGateChoice("2", surfaces)
	if !ok || len(decision.Strip) != 1 || decision.Strip[0] != "usr/lib/systemd/system/foo.service" {
		t.Fatalf("numbered choice selected %+v", decision)
	}
	decision, ok = ParseGateChoice("s", surfaces)
	if !ok || len(decision.Strip) != 2 {
		t.Fatalf("strip all selected %+v", decision)
	}
	decision, ok = ParseGateChoice("c", surfaces)
	if !ok || !decision.Cancel {
		t.Fatalf("cancel produced %+v", decision)
	}
}

func activated(member string, activation brief.SurfaceActivation, when string) brief.PrivilegedSurface {
	return brief.PrivilegedSurface{Member: member, Activation: activation, When: when, Body: "body\n", Size: 5}
}

// TestGatePromptAsksOnlyAboutWhatRunsOnItsOwn is the prompt-fatigue control.
//
// A package with one scriptlet and three systemd units used to produce four
// numbered bodies and one question. The question is now about the scriptlet;
// the units are listed underneath, because a unit nobody has enabled runs
// nothing, and asking anyway is how a person learns to answer without reading.
func TestGatePromptAsksOnlyAboutWhatRunsOnItsOwn(t *testing.T) {
	ordered := OrderSurfacesForDisplay([]brief.PrivilegedSurface{
		activated("usr/lib/systemd/system/foo.service", brief.ActivationEnabled, "runs as root once enabled or triggered"),
		activated(".INSTALL", brief.ActivationAutomatic, "runs as root during this pacman transaction"),
		activated("usr/lib/systemd/user/foo.service", brief.ActivationSession, "runs in the user's systemd session, not as root"),
	})
	if ordered[0].Member != ".INSTALL" {
		t.Fatalf("the surface needing a decision is not first: %q", ordered[0].Member)
	}
	rendered := RenderGatePrompt("foo", ordered)
	if !strings.Contains(rendered, "1 surface that runs as root on its own") {
		t.Fatalf("the prompt does not scope its question to automatic execution:\n%s", rendered)
	}
	if !strings.Contains(rendered, "Also installed, and shown rather than asked about") {
		t.Fatalf("the listed surfaces are not separated from the question:\n%s", rendered)
	}
	// Listed surfaces stay numbered: the split changes what is asked, not what
	// the user may remove.
	for _, member := range []string{".INSTALL", "usr/lib/systemd/system/foo.service", "usr/lib/systemd/user/foo.service"} {
		if !strings.Contains(rendered, member) {
			t.Errorf("%q was not shown at all", member)
		}
	}
	if !strings.Contains(rendered, "[3] strip 3") {
		t.Fatalf("a listed surface cannot be stripped:\n%s", rendered)
	}
}

// A surface with no activation is a registry entry someone forgot to classify.
// It must be asked about, never quietly listed.
func TestUnclassifiedSurfaceIsStillAQuestion(t *testing.T) {
	surfaces := []brief.PrivilegedSurface{{Member: "usr/lib/systemd/system-generators/foo", When: "unknown"}}
	if len(brief.SurfacesRequiringDecision(surfaces)) != 1 {
		t.Fatal("a surface with no activation became inventory instead of a question")
	}
}

func TestSurfaceInventoryListsWithoutAsking(t *testing.T) {
	rendered := RenderSurfaceInventory("foo", []brief.PrivilegedSurface{
		activated("usr/lib/systemd/system/foo.service", brief.ActivationEnabled, "runs as root once enabled or triggered"),
	})
	if !strings.Contains(rendered, "usr/lib/systemd/system/foo.service") || !strings.Contains(rendered, "once enabled") {
		t.Fatalf("the inventory hides what it found:\n%s", rendered)
	}
	if strings.Contains(rendered, "Choice") || strings.Contains(rendered, "[c] cancel") {
		t.Fatalf("the inventory asks a question it will not read an answer to:\n%s", rendered)
	}
}

// TestGateChoiceAcceptsSeveralSurfaces covers the answer a user could not give:
// strip two of four and keep the rest.
func TestGateChoiceAcceptsSeveralSurfaces(t *testing.T) {
	surfaces := []brief.PrivilegedSurface{
		surface(".INSTALL", brief.SurfaceScriptlet, "a"),
		surface("usr/lib/tmpfiles.d/foo.conf", brief.SurfaceTmpfiles, "b"),
		surface("etc/cron.d/foo", brief.SurfaceCron, "c"),
	}
	decision, ok := ParseGateChoice("1, 3\n", surfaces)
	if !ok || len(decision.Strip) != 2 || decision.Strip[0] != ".INSTALL" || decision.Strip[1] != "etc/cron.d/foo" {
		t.Fatalf("a comma list did not select those surfaces: %#v (ok=%t)", decision, ok)
	}
	// Anything not fully understood keeps the package intact rather than
	// stripping the part that parsed.
	for _, answer := range []string{"1,", "1,9", "1,1", "1,two", ",", "1;2"} {
		if _, ok := ParseGateChoice(answer, surfaces); ok {
			t.Errorf("%q was accepted as a selection", answer)
		}
	}
}
