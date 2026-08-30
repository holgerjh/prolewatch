package ui

import (
	"bytes"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/safe"
	"golang.org/x/sys/unix"
)

func gateSurfaces() []brief.PrivilegedSurface {
	return []brief.PrivilegedSurface{
		{Member: ".INSTALL", Kind: brief.SurfaceScriptlet, When: "runs as root", Body: "post_install() { :; }"},
		{Member: "usr/lib/systemd/system/foo.service", Kind: brief.SurfaceUnit, When: "runs as root", Body: "[Unit]"},
	}
}

func openGatePTY(t *testing.T) (controller, follower *os.File) {
	t.Helper()
	controller, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no /dev/ptmx: %v", err)
	}
	if err := unix.IoctlSetPointerInt(int(controller.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		controller.Close()
		t.Skipf("cannot unlock pty: %v", err)
	}
	number, err := unix.IoctlGetInt(int(controller.Fd()), unix.TIOCGPTN)
	if err != nil {
		controller.Close()
		t.Skipf("cannot get pty number: %v", err)
	}
	follower, err = os.OpenFile("/dev/pts/"+strconv.Itoa(number), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		controller.Close()
		t.Skipf("cannot open pty follower: %v", err)
	}
	t.Cleanup(func() { follower.Close(); controller.Close() })
	return controller, follower
}

func TestGateKeepChoiceDoesNotWaitForEnter(t *testing.T) {
	controller, follower := openGatePTY(t)
	type result struct {
		decision GateDecision
		err      error
	}
	done := make(chan result, 1)
	go func() {
		decision, err := promptGateTerminal(&safe.PromptTerminal{File: follower}, "demo", gateSurfaces())
		done <- result{decision: decision, err: err}
	}()
	time.Sleep(20 * time.Millisecond)
	if _, err := controller.WriteString("k"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err != nil || got.decision.Cancel || len(got.decision.Strip) != 0 {
			t.Fatalf("single k produced %+v (%v)", got.decision, got.err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("root gate still waited for Enter after k")
	}
}

// An unrecognised answer must be re-asked, not resolved. Guessing here would
// either strip a surface the package needs - breaking the install - or keep one
// the user meant to remove.
func TestGatePromptReAsksRatherThanGuessing(t *testing.T) {
	var out bytes.Buffer
	decision, err := promptGateFrom(strings.NewReader("maybe\nwhat?\n2\n"), &out, "demo", gateSurfaces())
	if err != nil {
		t.Fatal(err)
	}
	if len(decision.Strip) != 1 || decision.Strip[0] != "usr/lib/systemd/system/foo.service" {
		t.Fatalf("the eventual answer was not honoured: %+v", decision)
	}
	if strings.Count(out.String(), "Not a choice.") != 2 {
		t.Fatalf("the prompt did not re-ask for each bad answer:\n%s", out.String())
	}
}

// Nobody answering is not an answer.
//
// Keeping every automatic surface must come from a displayed question and a
// real answer; redirected input or silence cannot choose it implicitly.
func TestGatePromptRefusesToInventADecision(t *testing.T) {
	for name, input := range map[string]string{
		"no input":          "",
		"only bad answers":  "a\nb\nd\ne\nf\ng\n",
		"end after garbage": "zzz",
	} {
		var out bytes.Buffer
		decision, err := promptGateFrom(strings.NewReader(input), &out, "demo", gateSurfaces())
		if !errors.Is(err, ErrNoGateDecision) {
			t.Fatalf("%s: silence produced %+v (%v)", name, decision, err)
		}
	}
	// A deliberate Enter is an answer: it selects the displayed default, and
	// keeping the surfaces stays the ordinary outcome of the gate.
	var out bytes.Buffer
	decision, err := promptGateFrom(strings.NewReader("\n"), &out, "demo", gateSurfaces())
	if err != nil {
		t.Fatalf("a deliberate Enter was not accepted as the default answer: %v", err)
	}
	if decision.Cancel || len(decision.Strip) != 0 {
		t.Fatalf("the default answer produced %+v", decision)
	}
}

func TestGatePromptHonoursCancelAndStripAll(t *testing.T) {
	var out bytes.Buffer
	if decision, _ := promptGateFrom(strings.NewReader("c\n"), &out, "demo", gateSurfaces()); !decision.Cancel {
		t.Fatalf("cancel was not honoured: %+v", decision)
	}
	if decision, _ := promptGateFrom(strings.NewReader("s\n"), &out, "demo", gateSurfaces()); len(decision.Strip) != 2 {
		t.Fatalf("strip all was not honoured: %+v", decision)
	}
}

// A package with no privileged integration must not produce a prompt at all.
func TestGatePromptIsSkippedWhenThereIsNothingToDecide(t *testing.T) {
	decision, err := PromptGate("demo", nil)
	if err != nil || decision.Cancel || len(decision.Strip) != 0 {
		t.Fatalf("an empty surface list produced a decision: %+v %v", decision, err)
	}
}

// Anything that is not an explicit yes denies. A blank line, an end of input,
// or a typo must never open a destination.
func TestNetworkAnswerDeniesUnlessExplicitlyAllowed(t *testing.T) {
	for _, allowed := range []string{"y\n", "Y\n", "yes\n", "YES\n", "allow\n", " y \n"} {
		if !readNetworkAnswer(strings.NewReader(allowed)) {
			t.Fatalf("an explicit yes was denied: %q", allowed)
		}
	}
	for _, denied := range []string{"", "\n", "n\n", "no\n", "yeah\n", "ok\n", "sure\n", "1\n", "Y E S\n"} {
		if readNetworkAnswer(strings.NewReader(denied)) {
			t.Fatalf("a destination was opened by %q", denied)
		}
	}
}

// The answer is bounded so a package cannot make the prompt read forever.
func TestNetworkAnswerIsBounded(t *testing.T) {
	if readNetworkAnswer(strings.NewReader(strings.Repeat("y", 5000))) {
		t.Fatal("an unbounded answer was accepted as a yes")
	}
}

// The gate blocked forever before this existed: an unattended yay transaction
// that reached a package with an install scriptlet wedged with no later timer
// to release it. The network prompt already polled and denied on expiry.
func TestGatePromptTimesOutInsteadOfBlockingForever(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()

	var out bytes.Buffer
	start := time.Now()
	decision, err := promptGateFrom(gateInput{file: reader, timeout: 60 * time.Millisecond}, &out, "demo", gateSurfaces())
	if !errors.Is(err, ErrGatePromptTimeout) {
		t.Fatalf("a silent terminal produced %+v (%v)", decision, err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the prompt waited %s past its budget", elapsed)
	}
	// The timeout must not resolve into the permissive answer by another route.
	if decision.Cancel || len(decision.Strip) != 0 {
		t.Fatalf("a timeout produced a decision: %+v", decision)
	}
	if !strings.Contains(out.String(), "timed out") {
		t.Fatalf("the user was not told why the install stopped:\n%s", out.String())
	}
}

// A timeout and an absent terminal both fail closed, but they are different
// situations and the caller prints different advice for each.
func TestGateTimeoutIsDistinctFromNoDecision(t *testing.T) {
	if errors.Is(ErrGatePromptTimeout, ErrNoGateDecision) || errors.Is(ErrNoGateDecision, ErrGatePromptTimeout) {
		t.Fatal("the two gate failures are not distinguishable")
	}
}

// The budget bounds silence, not typing. An answer that arrives inside the
// window is read normally.
func TestGatePromptAcceptsAnAnswerInsideTheBudget(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	go func() {
		time.Sleep(20 * time.Millisecond)
		_, _ = writer.WriteString("s\n")
		_ = writer.Close()
	}()
	var out bytes.Buffer
	decision, err := promptGateFrom(gateInput{file: reader, timeout: 10 * time.Second}, &out, "demo", gateSurfaces())
	if err != nil {
		t.Fatalf("an answer inside the budget was rejected: %v", err)
	}
	if len(decision.Strip) != 2 {
		t.Fatalf("the answer was not honoured: %+v", decision)
	}
}
