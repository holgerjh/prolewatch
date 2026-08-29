// Package ui owns everything the human sees and answers: terminal rendering,
// prompts, reports.
//
// It is the top layer. Nothing imports it, which is what lets the layers below
// be reasoned about without reading presentation code.
package ui

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/holgerjh/prolewatch/internal/egress"
	"github.com/holgerjh/prolewatch/internal/safe"
)

// PromptNetworkDestination asks the user about one blocked destination.
//
// It lives in ui rather than in egress for a reason that is structural, not
// stylistic: this is the only component that holds the TTY, and it must not be
// the component that holds the network. The broker runs inside a sandbox with
// network access and no terminal; this runs outside it with a terminal and no
// listening socket of its own, and they speak over a private unix socket. The
// broker therefore cannot forge an approval - it can only ask for one.
//
// Every piece of package-controlled text reaching the terminal here goes
// through safe.Text first. The host is attacker-chosen, and without that a
// hostname carrying ANSI or OSC sequences could redraw this prompt, overwrite
// the line above it, or hide the destination being approved. That is release
// invariant 7.
func PromptNetworkDestination(request egress.AuthorizationRequest, cfg egress.Config) bool {
	tty, err := openTTY()
	if err != nil {
		return false
	}
	defer tty.Close()
	decoration := networkPromptTTYDecorationFor(os.Getenv, os.LookupEnv)
	fmt.Fprint(tty, renderNetworkPrompt(request, cfg, decoration))
	if cfg.PromptTimeoutSeconds <= 0 {
		return false
	}
	allowed, err := tty.ReadYesNo(time.Duration(cfg.PromptTimeoutSeconds) * time.Second)
	if errors.Is(err, safe.ErrYesNoPromptTimeout) {
		fmt.Fprintln(tty, "\nNetwork request denied: approval timed out.")
		return false
	}
	if err != nil {
		fmt.Fprintln(tty, "\nNetwork request denied: terminal input failed.")
		return false
	}
	return allowed
}

// readNetworkAnswer parses one answer. Anything that is not an explicit yes
// denies: a blank line, an end of input, or a typo must not open a destination.
func readNetworkAnswer(input io.Reader) bool {
	answer, err := bufio.NewReader(io.LimitReader(input, 64)).ReadString('\n')
	if err != nil && len(answer) == 0 {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes", "allow":
		return true
	}
	return false
}

// RenderNetworkPrompt builds the prompt text. It is separated from the TTY so
// that what the user is shown can be tested against hostile input, which is
// the only part of this that is security-relevant.
//
// Every interpolated value uses safe.Inline, not safe.Text. That distinction
// is the whole control: safe.Text preserves newlines for multi-line evidence,
// and a host is attacker-chosen, so safe.Text here lets a host string end the
// line and write its own - producing a convincing "previously approved" notice
// and a second prompt with the default flipped to yes. Prompt text is exactly
// the place where the multi-line variant is wrong.
func RenderNetworkPrompt(request egress.AuthorizationRequest, cfg egress.Config) string {
	return renderNetworkPrompt(request, cfg, networkPromptDecoration{header: "◆ PROLEWATCH · NETWORK INTERVENTION"})
}

type networkPromptDecoration struct {
	header, blueStart, boldStart, reset string
}

func renderNetworkPrompt(request egress.AuthorizationRequest, cfg egress.Config, decoration networkPromptDecoration) string {
	var out strings.Builder
	blue := func(value string) string {
		if decoration.blueStart == "" {
			return value
		}
		return decoration.blueStart + value + decoration.reset
	}
	fmt.Fprintf(&out, "\n%s\n", decoration.header)
	fmt.Fprintf(&out, "%s Connection paused before DNS or contact; your decision is required.\n", blue("├─"))
	// Describe the connection as paused because the decision has not been made
	// and the build is waiting for this answer.
	//
	// Name the package and the phase. During a multi-package upgrade "the
	// build" is several builds, and a request arriving while foo is being
	// prepared reads very differently from the same request during bar's
	// package() step.
	subject := "build request"
	if name := safe.Inline(cfg.PromptPackage, 256); name != "" {
		subject = name
		if phase := safe.Inline(cfg.PromptPhase, 64); phase != "" {
			subject += " / " + phase
		}
	}
	type promptFact struct{ label, value string }
	sources := promptSourcesForHost(request.Host, cfg.PromptSources)
	operation := promptOperation(sources, cfg.PromptContext)
	facts := []promptFact{{"operation", operation}}
	for index, source := range sources {
		if index >= 2 {
			facts = append(facts, promptFact{"declared source", fmt.Sprintf("+%d more source(s) on this host", len(sources)-index)})
			break
		}
		sourceValue := safe.Inline(promptSourceURL(source.URL), 1000)
		if decoration.boldStart != "" {
			sourceValue = decoration.boldStart + sourceValue + decoration.reset
		}
		facts = append(facts, promptFact{"declared source", sourceValue})
		if binding := promptSourceBinding(source); binding != "" {
			facts = append(facts, promptFact{"binding", binding})
		}
	}
	// A generic, otherwise unexplained request benefits from saying whether its
	// host occurs in the recipe. Recognized Cargo/Go operations explain
	// themselves; showing "not a recipe source" for a package registry would be
	// technically true but needlessly alarming.
	if len(sources) == 0 && safe.Inline(cfg.PromptContext, 512) == "" {
		if declaration := declaredHostDetail(request.Host, cfg); declaration != "" {
			facts = append(facts, promptFact{"source status", declaration})
		}
	}
	protocol := "public-web request"
	if request.Port == egress.HTTPSPort {
		protocol = "HTTPS tunnel"
	} else if request.Port == egress.HTTPPort {
		protocol = "HTTP request"
	}
	facts = append(facts,
		promptFact{"destination", fmt.Sprintf("%s:%d · %s", safe.Inline(request.Host, egress.MaxHostnameBytes), request.Port, protocol)},
		promptFact{"grant scope", "this destination · this phase only · no credentials forwarded"},
	)

	fmt.Fprintf(&out, "%s\n%s   %s\n", blue("│"), blue("│"), subject)
	for index, fact := range facts {
		branch := "├─"
		if index == len(facts)-1 {
			branch = "└─"
		}
		fmt.Fprintf(&out, "%s   %s %-15s %s\n", blue("│"), branch, fact.label, fact.value)
	}
	fmt.Fprintf(&out, "%s\n%s Allow and continue this build? [y/N]: ", blue("│"), blue("└─"))
	return out.String()
}

func promptSourcesForHost(host string, sources []egress.PromptSource) []egress.PromptSource {
	wanted := strings.ToLower(strings.TrimSpace(host))
	var matched []egress.PromptSource
	for _, source := range sources {
		if strings.ToLower(strings.TrimSpace(source.Host)) == wanted {
			matched = append(matched, source)
		}
	}
	return matched
}

func promptOperation(sources []egress.PromptSource, context string) string {
	for _, source := range sources {
		if source.Kind != "vcs" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(source.Transport), "git") {
			return "expected Git/VCS source checkout"
		}
		return "expected VCS source checkout"
	}
	switch safe.Inline(context, 512) {
	case "cargo fetch --locked":
		return "Cargo dependency prefetch"
	case "go mod download":
		return "Go module prefetch"
	case "":
		return "contained build network request"
	default:
		return "declared build network step"
	}
}

func promptSourceURL(raw string) string {
	prefix, target := "", raw
	for _, candidate := range []string{"git+", "hg+", "svn+", "bzr+", "fossil+"} {
		if strings.HasPrefix(strings.ToLower(target), candidate) {
			prefix, target = target[:len(candidate)], target[len(candidate):]
			break
		}
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.Host == "" {
		return raw
	}
	parsed.User = nil
	return prefix + parsed.String()
}

func promptSourceBinding(source egress.PromptSource) string {
	switch source.Binding {
	case "vcs-commit":
		return "commit pinned by full hash"
	case "mutable-vcs":
		return "mutable VCS reference"
	}
	fragment := ""
	if index := strings.IndexByte(source.URL, '#'); index >= 0 {
		fragment = source.URL[index+1:]
	}
	for _, entry := range strings.Split(fragment, "&") {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || value == "" {
			continue
		}
		switch key {
		case "commit":
			if (len(value) == 40 || len(value) == 64) && isHex(value) {
				return "commit pinned by full hash"
			}
			return "declared commit reference"
		case "tag":
			return "declared tag · mutable VCS reference"
		case "branch":
			return "declared branch · mutable VCS reference"
		}
	}
	if source.Kind == "vcs" {
		return "mutable VCS head"
	}
	return ""
}

func isHex(value string) bool {
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return value != ""
}

func networkPromptTTYDecorationFor(getenv func(string) string, lookupEnv func(string) (string, bool)) networkPromptDecoration {
	marker := "#"
	locale := getenv("LC_ALL")
	if locale == "" {
		locale = getenv("LC_CTYPE")
	}
	if locale == "" {
		locale = getenv("LANG")
	}
	locale = strings.ToLower(locale)
	if strings.Contains(locale, "utf-8") || strings.Contains(locale, "utf8") {
		marker = "◆"
	}
	plain := marker + " PROLEWATCH · NETWORK INTERVENTION"
	term := strings.ToLower(getenv("TERM"))
	if term == "" || term == "dumb" {
		return networkPromptDecoration{header: plain}
	}
	if _, present := lookupEnv("NO_COLOR"); present {
		return networkPromptDecoration{header: plain}
	}
	blue := "36"
	colorTerm := strings.ToLower(getenv("COLORTERM"))
	switch {
	case strings.Contains(colorTerm, "truecolor") || strings.Contains(colorTerm, "24bit") || strings.Contains(term, "direct"):
		blue = "38;2;23;147;209"
	case strings.Contains(term, "256color"):
		blue = "38;5;32"
	}
	return networkPromptDecoration{
		header:    "\x1b[" + blue + "m" + marker + "\x1b[0m \x1b[1mPROLEWATCH\x1b[0m · NETWORK INTERVENTION",
		blueStart: "\x1b[" + blue + "m", boldStart: "\x1b[1m", reset: "\x1b[0m",
	}
}

func networkPromptTTYHeader(getenv func(string) string, lookupEnv func(string) (string, bool)) string {
	return networkPromptTTYDecorationFor(getenv, lookupEnv).header
}

// declaredHostDetail says whether the destination is anywhere in the recipe.
//
// This is the single most useful fact about a mid-build connection and the
// prompt did not carry it. A host the package declares as a source is ordinary;
// a host that appears nowhere in the recipe is the anomaly the broker exists to
// surface, and only Prolewatch can tell the user which one this is.
//
// It explains, and never decides: a declared host still has to be approved, and
// the grant remains one destination for the current makepkg phase.
func declaredHostDetail(host string, cfg egress.Config) string {
	if len(cfg.DeclaredHosts) == 0 {
		return ""
	}
	requested := strings.ToLower(strings.TrimSpace(host))
	for _, declared := range cfg.DeclaredHosts {
		if strings.ToLower(strings.TrimSpace(declared)) == requested {
			return "one of the sources the recipe declares"
		}
	}
	return "appears nowhere in the recipe's declared sources"
}

// openTTY opens the controlling terminal for a question, discarding input the
// user typed before it was asked. See safe.OpenPromptTerminal.
func openTTY() (*safe.PromptTerminal, error) {
	return safe.OpenPromptTerminal()
}
