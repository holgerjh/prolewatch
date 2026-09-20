package ui

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/safe"
)

// GateDecision is what the user chose to do about a package's
// privileged-integration surfaces.
type GateDecision struct {
	// Strip names the archive members to remove. Empty means install intact.
	Strip []string
	// Cancel abandons the install entirely.
	Cancel bool
}

// quoteMarker prefixes every line of package-authored content.
//
// Indentation alone is not enough. A scriptlet containing the tool's own prompt
// text renders as a plausible prolewatch line that happens to be indented, and
// a user scanning quickly can answer the wrong one. The marker makes quoted
// content structurally distinguishable from the tool's own output, so a forged
// line is visibly inside the quote block rather than beside it.
const quoteMarker = "│"

// maxSurfaceLines bounds how much of a surface body is printed. A scriptlet
// worth reading is short; a long one is itself worth noticing, and scrolling a
// hostile file past the user is not review.
const maxSurfaceLines = 40

// OrderSurfacesForDisplay puts the surfaces that need an answer first.
//
// Display order and choice numbering come from the same slice, so the caller
// must pass the result of this function to both RenderGatePrompt and
// ParseGateChoice. Numbering the original order and displaying another would
// let "[2] strip 2" remove a different file than the one printed as 2.
func OrderSurfacesForDisplay(surfaces []brief.PrivilegedSurface) []brief.PrivilegedSurface {
	ordered := make([]brief.PrivilegedSurface, 0, len(surfaces))
	for _, surface := range surfaces {
		if surface.Activation.RequiresDecision() {
			ordered = append(ordered, surface)
		}
	}
	for _, surface := range surfaces {
		if !surface.Activation.RequiresDecision() {
			ordered = append(ordered, surface)
		}
	}
	return ordered
}

// RenderGatePrompt describes the privileged-integration surfaces a package
// carries and the choices available.
//
// This is an action, not a warning. It addresses package integration installed
// with pacman's privileges, outside the build sandbox.
//
// The prompt separates what it asks about from what it merely reports. Only
// surfaces that run as root, or grant privilege, with no further step by anyone
// are the question; a unit nobody has enabled, a user-session unit, a policy
// declaration and a module file nothing references are listed beneath it. Both
// halves are numbered, so anything shown can still be stripped - the split
// changes what the user is asked, not what they are allowed to do.
//
// The scoped claim is that a package cannot hide *that* it carries privileged
// integration - every surface is a file in the archive, and the archive is
// enumerated. It can still obfuscate what the code does; that stays a human
// review problem. Bodies for automatic surfaces are quoted and bounded;
// deferred or passive surfaces are listed without pretending their semantics
// were proved.
//
// surfaces must come from OrderSurfacesForDisplay.
func RenderGatePrompt(packagePath string, surfaces []brief.PrivilegedSurface) string {
	var out strings.Builder
	packageName := filepath.Base(packagePath)
	archivePath := ""
	if filepath.IsAbs(packagePath) {
		archivePath = packagePath
	}
	decide := brief.SurfacesRequiringDecision(surfaces)
	fmt.Fprintf(&out, "\nprolewatch: %s carries %s.\n\n",
		safe.Inline(packageName, 256), pluralSurfaces(len(decide)))
	for index, surface := range surfaces {
		if index == len(decide) {
			out.WriteString("Also installed, and shown rather than asked about:\n\n")
		}
		fmt.Fprintf(&out, "  [%d] %s — %s\n", index+1,
			safe.Inline(surface.Member, 512), safe.Inline(surface.When, 256))
		if surface.LinkTarget != "" {
			fmt.Fprintf(&out, "      links to %s\n", safe.Inline(surface.LinkTarget, 512))
		}
		if index < len(decide) {
			for _, line := range bodyLines(surface) {
				fmt.Fprintf(&out, "      %s %s\n", quoteMarker, line)
			}
			if command := surfaceInspectCommand(archivePath, surface); command != "" {
				fmt.Fprintf(&out, "      Inspect the full body in another terminal:\n        %s\n", command)
			}
		}
		out.WriteString("\n")
	}
	out.WriteString("  [k] keep all")
	for index := range surfaces {
		fmt.Fprintf(&out, "   [%d] strip %d", index+1, index+1)
	}
	out.WriteString("   [s] strip all   [c] cancel\n")
	out.WriteString("k, s, and c act immediately. Finish numbered selections with Enter; commas select several.\n")
	out.WriteString("Removing a surface a package genuinely needs produces a broken install.\n")
	out.WriteString("Choice [k]: ")
	return out.String()
}

// RenderSurfaceInventory describes surfaces that are worth seeing and are not
// worth stopping for: nothing here runs until something enables it, references
// it, or the user's own session starts it.
//
// It is printed and the install continues. That is the honest position: the
// alternative asked the same unanswerable question on every package carrying an
// ordinary systemd service, and a question whose answer is always "keep" is a
// habit, not a control.
func RenderSurfaceInventory(packageName string, surfaces []brief.PrivilegedSurface) string {
	if len(surfaces) == 0 {
		return ""
	}
	var out strings.Builder
	fmt.Fprintf(&out, "\nprolewatch: %s installs %s. None of it runs until something starts it:\n",
		safe.Inline(packageName, 256), pluralIntegration(len(surfaces)))
	for _, surface := range surfaces {
		fmt.Fprintf(&out, "      %s — %s\n",
			safe.Inline(surface.Member, 512), safe.Inline(surface.When, 256))
		if surface.LinkTarget != "" {
			fmt.Fprintf(&out, "          links to %s\n", safe.Inline(surface.LinkTarget, 512))
		}
	}
	return out.String()
}

func pluralSurfaces(count int) string {
	if count == 1 {
		return "1 surface that runs as root on its own"
	}
	return fmt.Sprintf("%d surfaces that run as root on their own", count)
}

func pluralIntegration(count int) string {
	if count == 1 {
		return "1 system-integration file"
	}
	return fmt.Sprintf("%d system-integration files", count)
}

// bodyLines renders a surface body for display. Every line goes through
// safe.Inline: the content is attacker-authored and is being printed directly
// above a prompt, which is the single most valuable thing in this tool to
// forge. Release invariant 7.
func bodyLines(surface brief.PrivilegedSurface) []string {
	if strings.TrimSpace(surface.Body) == "" {
		return []string{fmt.Sprintf("(%d bytes, not shown)", surface.Size)}
	}
	raw := strings.Split(strings.TrimRight(surface.Body, "\n"), "\n")
	lines := make([]string, 0, len(raw)+1)
	for index, line := range raw {
		if index >= maxSurfaceLines {
			lines = append(lines, fmt.Sprintf("… %d more lines not shown", len(raw)-maxSurfaceLines))
			break
		}
		lines = append(lines, safe.Inline(line, 1000))
	}
	if surface.Truncated {
		lines = append(lines, "… file truncated for display")
	}
	return lines
}

func surfaceInspectCommand(archivePath string, surface brief.PrivilegedSurface) string {
	rawLines := strings.Count(strings.TrimRight(surface.Body, "\n"), "\n") + 1
	omitted := surface.Truncated || rawLines > maxSurfaceLines || (strings.TrimSpace(surface.Body) == "" && surface.Size > 0)
	archive, archiveOK := shellQuotedInline(archivePath)
	member, memberOK := shellQuotedInline(surface.Member)
	if !omitted || !archiveOK || !memberOK {
		return ""
	}
	return "/usr/bin/bsdtar -xO --file " + archive + " -- " + member + " 2>&1 | /usr/bin/cat -v"
}

func shellQuotedInline(value string) (string, bool) {
	if value == "" || safe.Inline(value, 8192) != value {
		return "", false
	}
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'", true
}

// ParseGateChoice interprets one answer. Anything unrecognised keeps the
// package intact, because the default must never be the destructive option:
// stripping a surface a package needs produces a broken installation, and a
// mistyped key should not do that.
//
// For a package that is actually hostile the right answer is not to install it
// at all. The strip path is for the ambiguous middle.
func ParseGateChoice(answer string, surfaces []brief.PrivilegedSurface) (GateDecision, bool) {
	answer = strings.ToLower(strings.TrimSpace(answer))
	switch answer {
	case "", "k", "keep":
		return GateDecision{}, true
	case "c", "cancel", "q":
		return GateDecision{Cancel: true}, true
	case "s", "strip", "strip all":
		members := make([]string, 0, len(surfaces))
		for _, surface := range surfaces {
			members = append(members, surface.Member)
		}
		return GateDecision{Strip: members}, true
	}
	// A comma list, because a package can carry several surfaces and the user
	// may want two of the four gone. One number per re-prompt was not a
	// smaller interface, it was a missing one: there was no answer that
	// expressed "strip these two and keep the rest", so the only reachable
	// choices were one, all, or none.
	var members []string
	seen := map[int]bool{}
	for _, field := range strings.Split(answer, ",") {
		index, err := strconv.Atoi(strings.TrimSpace(field))
		if err != nil || index < 1 || index > len(surfaces) || seen[index] {
			return GateDecision{}, false
		}
		seen[index] = true
		members = append(members, surfaces[index-1].Member)
	}
	if len(members) == 0 {
		return GateDecision{}, false
	}
	return GateDecision{Strip: members}, true
}

// PromptGate asks the user about a package's privileged-integration surfaces.
//
// It reads and writes /dev/tty directly, so package output on stdout cannot
// answer on the user's behalf, and re-asks on an unrecognised answer rather
// than silently choosing.
func PromptGate(packageName string, surfaces []brief.PrivilegedSurface) (GateDecision, error) {
	if len(surfaces) == 0 {
		return GateDecision{}, nil
	}
	// One ordering for what is printed and what a number means.
	surfaces = OrderSurfacesForDisplay(surfaces)
	tty, err := openTTY()
	if err != nil {
		// No terminal means nobody can be shown the code that will run as root,
		// and nobody can answer. That is a failure, not a decision: the caller
		// stops the install rather than handing over a package whose root
		// surfaces were never displayed.
		return GateDecision{}, err
	}
	defer tty.Close()

	return promptGateTerminal(tty, packageName, surfaces)
}

// GatePromptTimeout bounds how long the gate waits for a keystroke.
//
// Without one this prompt blocked forever, so an unattended `yay -Syu` that
// reached a package with an install scriptlet wedged mid-transaction with no
// later timer to release it. The network prompt already polls and denies on
// expiry; this is the same shape for the same reason.
//
// It is deliberately generous rather than tuned. The prompt itself tells the
// user to inspect a long scriptlet in another terminal, so a few minutes is a
// realistic reading time and cutting that short would be its own defect. This
// is a release valve for an absent user, not a pace for a present one - which
// is also why it is a constant instead of new configuration surface.
//
// It is a var only so tests can shrink it; nothing in the product writes it.
var GatePromptTimeout = 15 * time.Minute

// ErrGatePromptTimeout reports that nobody answered within the budget.
//
// It is distinct from ErrNoGateDecision because the causes differ and so does
// the useful advice: no decision means there was no terminal or no input at
// all, while this means a terminal was there and unattended.
var ErrGatePromptTimeout = errors.New("the privileged-integration gate timed out waiting for an answer")

// gateInput fails a read that no keystroke arrives for.
//
// The poll is per read rather than per prompt, so a user typing an answer keeps
// resetting it and only genuine silence expires.
type gateInput struct {
	file    *os.File
	timeout time.Duration
}

func (g gateInput) Read(buffer []byte) (int, error) {
	deadline := time.Now().Add(g.timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, ErrGatePromptTimeout
		}
		ready, err := unix.Poll([]unix.PollFd{{Fd: int32(g.file.Fd()), Events: unix.POLLIN}}, int(remaining.Milliseconds()))
		if errors.Is(err, unix.EINTR) {
			// The Go runtime signals its own threads often enough that an
			// interrupted wait is ordinary. Treating it as a timeout would
			// cancel an install for no reason, so the remaining budget is
			// re-polled rather than surrendered.
			continue
		}
		if err != nil {
			return 0, err
		}
		if ready < 1 {
			return 0, ErrGatePromptTimeout
		}
		return g.file.Read(buffer)
	}
}

// ErrNoGateDecision reports that no answer was obtained.
//
// Keeping every automatic surface is the most consequential choice, so it must
// come from a displayed question and a real answer rather than silence.
var ErrNoGateDecision = errors.New("no privileged-integration decision was given")

// promptGateTerminal gives the letter actions the same immediate-key behavior
// as the package-review prompt while retaining Enter-terminated numeric lists.
// The latter cannot be single-key choices because "1" and "1,2" must remain
// distinguishable.
func promptGateTerminal(terminal *safe.PromptTerminal, packageName string, surfaces []brief.PrivilegedSurface) (GateDecision, error) {
	fmt.Fprint(terminal, RenderGatePrompt(packageName, surfaces))
	for attempt := 0; attempt < 5; attempt++ {
		answer, err := terminal.ReadChoiceOrLine(GatePromptTimeout, "ksc", 'k', "0123456789, ", 4096)
		if errors.Is(err, safe.ErrYesNoPromptTimeout) {
			fmt.Fprintln(terminal, "\nInstall stopped: the privileged-integration gate timed out waiting for an answer.")
			return GateDecision{}, ErrGatePromptTimeout
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return GateDecision{}, ErrNoGateDecision
			}
			return GateDecision{}, err
		}
		decision, ok := ParseGateChoice(answer, surfaces)
		if ok {
			return decision, nil
		}
		fmt.Fprint(terminal, "Not a choice. [k] keep all, numbers such as 1,3 to strip those, [s] strip all, [c] cancel: ")
	}
	return GateDecision{}, ErrNoGateDecision
}

// promptGateFrom is the loop, separated from the terminal so it can be tested.
// Re-asking rather than guessing is the property under test: an unrecognised
// answer must not be resolved into a decision the user did not make.
func promptGateFrom(input io.Reader, output io.Writer, packageName string, surfaces []brief.PrivilegedSurface) (GateDecision, error) {
	fmt.Fprint(output, RenderGatePrompt(packageName, surfaces))
	reader := bufio.NewReader(io.LimitReader(input, 4096))
	for attempt := 0; attempt < 5; attempt++ {
		answer, err := reader.ReadString('\n')
		if errors.Is(err, ErrGatePromptTimeout) {
			// Checked before the partial-answer case: a half-typed line that
			// then went silent is still an unattended terminal.
			fmt.Fprintln(output, "\nInstall stopped: the privileged-integration gate timed out waiting for an answer.")
			return GateDecision{}, ErrGatePromptTimeout
		}
		if err != nil && answer == "" {
			// End of input with nothing typed: nobody is answering.
			return GateDecision{}, ErrNoGateDecision
		}
		decision, ok := ParseGateChoice(answer, surfaces)
		if ok {
			return decision, nil
		}
		fmt.Fprint(output, "Not a choice. [k] keep all, numbers such as 1,3 to strip those, [s] strip all, [c] cancel: ")
	}
	// Five unrecognised answers is not a decision either.
	return GateDecision{}, ErrNoGateDecision
}
