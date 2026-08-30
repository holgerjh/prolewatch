package safe

import (
	"bufio"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// openPTY returns a connected controller/follower pair. The follower behaves
// like a real terminal, which is what this test needs: the typeahead problem
// only exists because a terminal buffers input, and a pipe does not.
func openPTY(t *testing.T) (controller *os.File, follower *os.File) {
	t.Helper()
	primary, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no /dev/ptmx: %v", err)
	}
	if err := unix.IoctlSetPointerInt(int(primary.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		primary.Close()
		t.Skipf("cannot unlock pty: %v", err)
	}
	number, err := unix.IoctlGetInt(int(primary.Fd()), unix.TIOCGPTN)
	if err != nil {
		primary.Close()
		t.Skipf("cannot get pty number: %v", err)
	}
	secondary, err := os.OpenFile("/dev/pts/"+itoa(number), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		primary.Close()
		t.Skipf("cannot open pty follower: %v", err)
	}
	t.Cleanup(func() { secondary.Close(); primary.Close() })
	return primary, secondary
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// The attack this closes: a package prints a convincing fake prompt as ordinary
// build output, the user answers it while real work is still running, and the
// keystroke waits in the terminal queue until the next genuine prompt reads it.
// The answer then belongs to a question the attacker wrote.
//
// Reading from /dev/tty does not help, because the buffered keystroke is on
// /dev/tty.
func TestQueuedInputCannotAnswerAPromptThatHasNotBeenAskedYet(t *testing.T) {
	controller, follower := openPTY(t)

	// The user answers the package's fake prompt, well before Prolewatch asks.
	if _, err := controller.WriteString("y\n"); err != nil {
		t.Fatalf("write to pty: %v", err)
	}
	// Give the terminal time to deliver it to the input queue.
	time.Sleep(50 * time.Millisecond)

	terminal := &PromptTerminal{File: follower}
	terminal.Discard()

	// Now the real prompt reads. There must be nothing waiting for it.
	//
	// A blocking read is the point: if the discard worked there is nothing to
	// deliver and the read hangs, which is why it runs with a timeout rather
	// than a deadline - os.File deadlines do not apply to a pty opened this way.
	if answer, ok := readWithTimeout(follower, 300*time.Millisecond); ok {
		t.Fatalf("a keystroke typed before the prompt was delivered to it: %q", answer)
	}
}

// readWithTimeout reports whether a line arrived within the window.
func readWithTimeout(file *os.File, wait time.Duration) (string, bool) {
	result := make(chan string, 1)
	go func() {
		answer, err := bufio.NewReader(file).ReadString('\n')
		if err == nil {
			result <- answer
		}
	}()
	select {
	case answer := <-result:
		return strings.TrimSpace(answer), true
	case <-time.After(wait):
		return "", false
	}
}

// The discard must not eat an answer given after the prompt was drawn, or the
// prompt becomes unanswerable.
func TestInputTypedAfterThePromptStillArrives(t *testing.T) {
	controller, follower := openPTY(t)

	terminal := &PromptTerminal{File: follower}
	terminal.Discard()

	if _, err := controller.WriteString("y\n"); err != nil {
		t.Fatalf("write to pty: %v", err)
	}
	answer, ok := readWithTimeout(follower, 2*time.Second)
	if !ok || answer != "y" {
		t.Fatalf("a legitimate answer was lost: %q (delivered=%t)", answer, ok)
	}
}

func TestYesNoPromptAcceptsAKeyWithoutEnterAndRestoresTheTerminal(t *testing.T) {
	controller, follower := openPTY(t)
	before, err := unix.IoctlGetTermios(int(follower.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	terminal := &PromptTerminal{File: follower}
	type result struct {
		allowed bool
		err     error
	}
	done := make(chan result, 1)
	go func() {
		allowed, err := terminal.ReadYesNo(2 * time.Second)
		done <- result{allowed: allowed, err: err}
	}()
	time.Sleep(20 * time.Millisecond)
	if _, err := controller.WriteString("y"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err != nil || !got.allowed {
			t.Fatalf("single y key returned allowed=%t err=%v", got.allowed, got.err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("single y key still waited for Enter")
	}
	after, err := unix.IoctlGetTermios(int(follower.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	const restored = unix.ICANON | unix.ECHO | unix.ISIG
	if before.Lflag&restored != after.Lflag&restored {
		t.Fatalf("prompt did not restore terminal flags: before=%#x after=%#x", before.Lflag, after.Lflag)
	}
}

func TestYesNoPromptIgnoresWrongKeysAndEnterDefaultsToNo(t *testing.T) {
	controller, follower := openPTY(t)
	terminal := &PromptTerminal{File: follower}
	type result struct {
		allowed bool
		err     error
	}
	done := make(chan result, 1)
	go func() {
		allowed, err := terminal.ReadYesNo(2 * time.Second)
		done <- result{allowed: allowed, err: err}
	}()
	time.Sleep(20 * time.Millisecond)
	if _, err := controller.WriteString("x"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		t.Fatalf("unrelated key invented a decision: %+v", got)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := controller.WriteString("\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err != nil || got.allowed {
			t.Fatalf("Enter did not select no: allowed=%t err=%v", got.allowed, got.err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Enter did not finish the prompt")
	}
}

func TestYesNoPromptAcceptsNWithoutEnter(t *testing.T) {
	controller, follower := openPTY(t)
	terminal := &PromptTerminal{File: follower}
	done := make(chan error, 1)
	go func() {
		allowed, err := terminal.ReadYesNo(2 * time.Second)
		if err == nil && allowed {
			err = errors.New("n was accepted as yes")
		}
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if _, err := controller.WriteString("n"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("single n key still waited for Enter")
	}
}

func TestPromptChoiceCanReturnANonAuthorizingViewAction(t *testing.T) {
	controller, follower := openPTY(t)
	terminal := &PromptTerminal{File: follower}
	type result struct {
		choice byte
		err    error
	}
	done := make(chan result, 1)
	go func() {
		choice, err := terminal.ReadChoice(2*time.Second, "ynv", 'n')
		done <- result{choice: choice, err: err}
	}()
	time.Sleep(20 * time.Millisecond)
	if _, err := controller.WriteString("V"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err != nil || got.choice != 'v' {
			t.Fatalf("view key returned choice=%q err=%v", got.choice, got.err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("single V key still waited for Enter")
	}
}

func TestChoiceOrLineAcceptsImmediateActionWithoutEnter(t *testing.T) {
	controller, follower := openPTY(t)
	terminal := &PromptTerminal{File: follower}
	type result struct {
		answer string
		err    error
	}
	done := make(chan result, 1)
	go func() {
		answer, err := terminal.ReadChoiceOrLine(2*time.Second, "ksc", 'k', "0123456789, ", 4096)
		done <- result{answer: answer, err: err}
	}()
	time.Sleep(20 * time.Millisecond)
	if _, err := controller.WriteString("k"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err != nil || got.answer != "k" {
			t.Fatalf("single k key returned answer=%q err=%v", got.answer, got.err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("single k key still waited for Enter")
	}
}

func TestChoiceOrLineRetainsCommaSeparatedSelections(t *testing.T) {
	controller, follower := openPTY(t)
	terminal := &PromptTerminal{File: follower}
	type result struct {
		answer string
		err    error
	}
	done := make(chan result, 1)
	go func() {
		answer, err := terminal.ReadChoiceOrLine(2*time.Second, "ksc", 'k', "0123456789, ", 4096)
		done <- result{answer: answer, err: err}
	}()
	time.Sleep(20 * time.Millisecond)
	if _, err := controller.WriteString("1,2"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		t.Fatalf("numeric prefix completed before Enter: %+v", got)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := controller.WriteString("\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err != nil || got.answer != "1,2" {
			t.Fatalf("number list returned answer=%q err=%v", got.answer, got.err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("number list did not finish on Enter")
	}
}

func TestYesNoPromptKeepsItsOverallTimeout(t *testing.T) {
	_, follower := openPTY(t)
	terminal := &PromptTerminal{File: follower}
	start := time.Now()
	allowed, err := terminal.ReadYesNo(60 * time.Millisecond)
	if allowed || !errors.Is(err, ErrYesNoPromptTimeout) {
		t.Fatalf("silent prompt returned allowed=%t err=%v", allowed, err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("prompt exceeded its timeout: %s", elapsed)
	}
}

// Discard must be safe on a nil or closed terminal: prompts call it on a path
// where the terminal may not have opened.
func TestDiscardIsSafeWithoutATerminal(t *testing.T) {
	var absent *PromptTerminal
	absent.Discard()
	(&PromptTerminal{}).Discard()
}
