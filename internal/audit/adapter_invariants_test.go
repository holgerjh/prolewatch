package audit

import (
	"os"
	"strings"
	"testing"
)

// TestProviderAdaptersSuppressTools holds the flags that actually do the work
// the attestation used to claim it had measured.
//
// no_tools, no_commands and strict_schema were written into every attestation
// as observed successes. Nothing observed them - the outer canary never invokes
// the provider, and a schema-shaped verdict says nothing about what the CLI was
// allowed to do while producing it. They are gone from the attestation, so this
// is where the property lives now: an exact flag set, asserted, and named in
// AdapterPolicy which is part of the policy fingerprint.
//
// A flag removed here is a real regression in what attacker-authored package
// text can reach through the reviewer, and it should fail loudly rather than be
// certified true by a boolean nobody checked.
func TestProviderAdaptersSuppressTools(t *testing.T) {
	withStateAndShare(t)
	source := adapterSource(t)

	t.Run("codex", func(t *testing.T) {
		for _, flag := range []string{
			`"--ephemeral"`,          // no state survives the review
			`"--ignore-user-config"`, // the user's codex config cannot widen it
			`"--ignore-rules"`,
			`"--strict-config"`,
			`"--sandbox", "read-only"`,
			`"--output-schema"`, // structured output is required, not hoped for
			`"web_search=\"disabled\""`,
			`"--disable", feature`, // every feature the CLI reports is turned off
		} {
			if !strings.Contains(source, flag) {
				t.Errorf("the Codex adapter no longer passes %s", flag)
			}
		}
	})

	t.Run("claude", func(t *testing.T) {
		for _, flag := range []string{
			`"--safe-mode"`,
			`"--strict-mcp-config"`,
			`"--tools", ""`,                 // no tool surface at all
			`"--disallowedTools", "mcp__*"`, // and no MCP server can add one
			`"--disable-slash-commands"`,
			`"--no-session-persistence"`,
			`"--permission-mode", "dontAsk"`, // never falls back to asking
			`"--json-schema"`,
		} {
			if !strings.Contains(source, flag) {
				t.Errorf("the Claude adapter no longer passes %s", flag)
			}
		}
	})

	// AdapterPolicy names the flag set and is hashed into the policy
	// fingerprint, so changing suppression invalidates decisions taken under the
	// old policy rather than silently applying to them.
	for _, policy := range []string{"codex-cli-v2:disable-current-", "claude-cli-v1:safe-no-tools"} {
		if !strings.Contains(source, policy) {
			t.Errorf("the adapter policy string %q is gone, so a suppression change would not move the fingerprint", policy)
		}
	}
}

// The supported CLI range is pinned for the same reason: these flags are a
// contract with a specific CLI, and a version outside the tested range may
// interpret or ignore them differently.
func TestSupportedProviderVersionsArePinned(t *testing.T) {
	for name, bounds := range map[string][2]string{
		"codex":  {MinCodexVersion, MaxCodexVersion},
		"claude": {MinClaudeVersion, MaxClaudeVersion},
	} {
		if bounds[0] == "" || bounds[1] == "" {
			t.Errorf("%s has no pinned version range", name)
			continue
		}
		if compareVersions(mustVersion(bounds[0]), mustVersion(bounds[1])) >= 0 {
			t.Errorf("%s minimum %s is not below maximum %s", name, bounds[0], bounds[1])
		}
	}
}

// adapterSource reads the file the argv is built in. Asserting against the
// source is deliberate: constructing the arguments here instead would test a
// copy, and a copy is what drifts.
func adapterSource(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("providers.go")
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
