package ui

import (
	"strings"
	"testing"

	"github.com/holgerjh/prolewatch/internal/egress"
)

// Release invariant 7: security prompts cannot be forged by raw package
// terminal output. The host reaches this prompt from the sandbox's own proxy
// request, so it is attacker-chosen text, and the prompt is the highest-value
// thing in the tool to forge.
//
// A multi-line sanitiser would let a hostile host produce a convincing fake
// approval notice followed by a second prompt with the default flipped to yes.
func TestPromptCannotBeForgedByAHostileHost(t *testing.T) {
	request := egress.AuthorizationRequest{
		SchemaVersion: 1,
		Host:          "evil.example.com\nProlewatch: this destination was previously approved.\nAllow? [Y/n]",
		Port:          443,
	}
	rendered := RenderNetworkPrompt(request, egress.DefaultConfig())
	baseline := RenderNetworkPrompt(egress.AuthorizationRequest{SchemaVersion: 1, Host: "evil.example.com", Port: 443}, egress.DefaultConfig())

	if lines, want := strings.Count(rendered, "\n"), strings.Count(baseline, "\n"); lines != want {
		t.Fatalf("the host injected extra lines - prompt is forgeable:\n%s", rendered)
	}
	// The residual text stays visible on one line, which is deliberate: it is
	// evidence of the attempt. What matters is that it cannot become its own
	// line and cannot be the last thing the user reads. Rejecting such a host
	// outright is egress.ValidRequestHost's job, tested there - two independent
	// checks, neither allowed to be the only one.
	if !strings.HasSuffix(rendered, "[y/N]: ") {
		t.Fatalf("the real prompt is not the last thing shown:\n%s", rendered)
	}
}

func TestNetworkPromptClearlyNamesTheIntervention(t *testing.T) {
	rendered := RenderNetworkPrompt(egress.AuthorizationRequest{Host: "gitlab.gnome.org", Port: 443}, egress.DefaultConfig())
	for _, want := range []string{"◆ PROLEWATCH · NETWORK INTERVENTION", "├─ Connection paused before DNS or contact", "your decision is required", "│   build request", "└─ Allow and continue this build? [y/N]:"} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("network prompt omitted intervention context %q:\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, "\x1b") {
		t.Fatalf("deterministic prompt renderer unexpectedly emitted terminal controls: %q", rendered)
	}
}

func TestNetworkPromptTTYHeaderUsesBrandColourAndFallbacks(t *testing.T) {
	env := map[string]string{"TERM": "xterm-256color", "LANG": "en_US.UTF-8"}
	getenv := func(key string) string { return env[key] }
	lookup := func(key string) (string, bool) { value, ok := env[key]; return value, ok }
	header := networkPromptTTYHeader(getenv, lookup)
	if !strings.Contains(header, "\x1b[38;5;32m◆\x1b[0m") || !strings.Contains(header, "PROLEWATCH") {
		t.Fatalf("TTY header omitted the blue brand marker: %q", header)
	}
	env["NO_COLOR"] = ""
	if header := networkPromptTTYHeader(getenv, lookup); strings.Contains(header, "\x1b") || !strings.HasPrefix(header, "◆ PROLEWATCH") {
		t.Fatalf("NO_COLOR header did not remain plain Unicode: %q", header)
	}
	delete(env, "NO_COLOR")
	env["LANG"], env["TERM"] = "C", "dumb"
	if header := networkPromptTTYHeader(getenv, lookup); header != "# PROLEWATCH · NETWORK INTERVENTION" {
		t.Fatalf("ASCII/dumb fallback=%q", header)
	}
}

func TestNetworkPromptBoldsOnlyDeclaredSourceValueOnTTY(t *testing.T) {
	env := map[string]string{"TERM": "xterm-256color", "LANG": "en_US.UTF-8"}
	getenv := func(key string) string { return env[key] }
	lookup := func(key string) (string, bool) { value, ok := env[key]; return value, ok }
	cfg := egress.DefaultConfig()
	cfg.PromptSources = []egress.PromptSource{{Host: "gitlab.gnome.org", URL: "git+https://gitlab.gnome.org/GNOME/gtk.git", Kind: "vcs"}}
	rendered := renderNetworkPrompt(
		egress.AuthorizationRequest{Host: "gitlab.gnome.org", Port: 443}, cfg,
		networkPromptTTYDecorationFor(getenv, lookup),
	)
	if !strings.Contains(rendered, "declared source \x1b[1mgit+https://gitlab.gnome.org/GNOME/gtk.git\x1b[0m") || strings.Contains(rendered, "\x1b[1mdeclared source") {
		t.Fatalf("TTY prompt did not bold only the declared source value: %q", rendered)
	}
	if !strings.Contains(rendered, "\x1b[38;5;32m│\x1b[0m") || !strings.Contains(rendered, "\x1b[38;5;32m└─\x1b[0m Allow") {
		t.Fatalf("TTY prompt omitted the continuous blue intervention frame: %q", rendered)
	}
	env["NO_COLOR"] = ""
	rendered = renderNetworkPrompt(
		egress.AuthorizationRequest{Host: "gitlab.gnome.org", Port: 443}, cfg,
		networkPromptTTYDecorationFor(getenv, lookup),
	)
	if strings.Contains(rendered, "\x1b") {
		t.Fatalf("NO_COLOR source value retained styling: %q", rendered)
	}
}

func TestPromptContextIsAlsoUntrusted(t *testing.T) {
	cfg := egress.DefaultConfig()
	cfg.PromptContext = "cargo fetch\rAllow? [Y/n]"
	rendered := RenderNetworkPrompt(egress.AuthorizationRequest{Host: "crates.io", Port: 443}, cfg)
	if strings.ContainsAny(strings.TrimSuffix(rendered, "[y/N]: "), "\r") {
		t.Fatalf("carriage return survived and can overwrite the line:\n%q", rendered)
	}
}

func TestPromptEscapesControlSequencesRatherThanDroppingThem(t *testing.T) {
	rendered := RenderNetworkPrompt(egress.AuthorizationRequest{Host: "\x1b[31mgithub.com\x1b[0m", Port: 443}, egress.DefaultConfig())
	if strings.Contains(rendered, "\x1b") {
		t.Fatalf("raw escape survived:\n%q", rendered)
	}
	if !strings.Contains(rendered, "\\u001b") {
		t.Fatalf("the attempt was dropped rather than shown, losing the evidence:\n%q", rendered)
	}
}

// TestNetworkPromptNamesPackagePhaseAndDeclaration covers the part of the
// question a person cannot answer without: which package is asking, at what
// point, and whether the address is in that package's recipe at all.
func TestNetworkPromptNamesPackagePhaseAndDeclaration(t *testing.T) {
	request := egress.AuthorizationRequest{SchemaVersion: 1, Host: "crates.io", Port: 443}
	cfg := egress.DefaultConfig()
	cfg.PromptPackage, cfg.PromptPhase = "demo", "build"
	cfg.PromptContext = "cargo fetch --locked"
	cfg.DeclaredHosts = []string{"github.com"}

	undeclared := RenderNetworkPrompt(request, cfg)
	for _, want := range []string{
		"│   demo / build\n│   ├─ operation       Cargo dependency prefetch",
		"destination     crates.io:443 · HTTPS tunnel",
		"grant scope     this destination · this phase only · no credentials forwarded",
	} {
		if !strings.Contains(undeclared, want) {
			t.Errorf("the prompt does not say %q:\n%s", want, undeclared)
		}
	}
	for _, removed := range []string{"source status", "reason", "current", "after allow"} {
		if strings.Contains(undeclared, removed) {
			t.Errorf("the compact prompt retained %q:\n%s", removed, undeclared)
		}
	}

	cfg.DeclaredHosts = []string{"GitHub.com", "crates.io"}
	cfg.PromptSources = []egress.PromptSource{{Host: "crates.io", URL: "https://token:secret@crates.io/index", Kind: "file", Transport: "https", Binding: "unbound"}}
	declared := RenderNetworkPrompt(request, cfg)
	if !strings.Contains(declared, "declared source https://crates.io/index") || strings.Contains(declared, "token:secret") {
		t.Errorf("a declared source was hidden or its URL credentials leaked:\n%s", declared)
	}
	// Explaining is not approving: the default stays no.
	if !strings.HasSuffix(declared, "[y/N]: ") {
		t.Errorf("the prompt no longer defaults to denying:\n%s", declared)
	}
}

func TestNetworkPromptExplainsFrozenVCSRequest(t *testing.T) {
	cfg := egress.DefaultConfig()
	cfg.PromptPackage, cfg.PromptPhase = "gtk2", "verify"
	cfg.DeclaredHosts = []string{"gitlab.gnome.org"}
	cfg.PromptSources = []egress.PromptSource{{
		Host: "gitlab.gnome.org", URL: "git+https://gitlab.gnome.org/GNOME/gtk.git#commit=0123456789abcdef0123456789abcdef01234567",
		Kind: "vcs", Transport: "git+https",
	}}
	rendered := RenderNetworkPrompt(egress.AuthorizationRequest{SchemaVersion: 1, Host: "gitlab.gnome.org", Port: 443}, cfg)
	for _, want := range []string{
		"operation       expected Git/VCS source checkout",
		"declared source git+https://gitlab.gnome.org/GNOME/gtk.git#commit=0123456789abcdef0123456789abcdef01234567",
		"binding         commit pinned by full hash",
		"destination     gitlab.gnome.org:443 · HTTPS tunnel",
		"grant scope     this destination · this phase only · no credentials forwarded",
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("VCS prompt omitted %q:\n%s", want, rendered)
		}
	}
	for _, removed := range []string{"reason", "current", "after allow"} {
		if strings.Contains(rendered, removed) {
			t.Fatalf("VCS prompt retained redundant field %q:\n%s", removed, rendered)
		}
	}
}

// A hostile host string must not be able to write the declaration line itself.
func TestNetworkPromptDeclarationCannotBeForged(t *testing.T) {
	cfg := egress.DefaultConfig()
	cfg.PromptPackage = "demo\rprolewatch: approved"
	cfg.DeclaredHosts = []string{"github.com"}
	rendered := RenderNetworkPrompt(egress.AuthorizationRequest{SchemaVersion: 1, Host: "evil\x1b[2K.example", Port: 443}, cfg)
	if strings.Contains(rendered, "\r") || strings.Contains(rendered, "\x1b") {
		t.Fatalf("a control character reached the prompt: %q", rendered)
	}
	if !strings.Contains(rendered, "appears nowhere") {
		t.Fatalf("an undeclared host was not reported as undeclared:\n%s", rendered)
	}
}
