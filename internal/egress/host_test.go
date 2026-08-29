package egress

import "testing"

func TestValidRequestHostAcceptsRealDestinations(t *testing.T) {
	for _, host := range []string{
		"github.com", "codeload.github.com", "crates.io", "proxy.golang.org",
		"example.com.", "a-b.example.com", "xn--bcher-kva.example", "127.0.0.1",
		"::1", "[::1]", "2001:db8::1", "under_score.example.com",
	} {
		if !ValidRequestHost(host) {
			t.Fatalf("rejected a legitimate destination: %q", host)
		}
	}
}

// The host is attacker-chosen and ends up in the approval prompt. Anything
// that is not a hostname has no legitimate reason to arrive, and every case
// below is a way to make the prompt say something it should not.
func TestValidRequestHostRejectsPromptForgeryAttempts(t *testing.T) {
	for name, host := range map[string]string{
		"newline injection": "evil.example.com\nProlewatch: previously approved.\nAllow? [Y/n]",
		"carriage return":   "evil.example.com\rgithub.com",
		"ANSI escape":       "\x1b[31mgithub.com\x1b[0m",
		"spaces":            "github.com and also evil.example.com",
		"empty":             "",
		"empty label":       "github..com",
		"leading dash":      "-evil.example.com",
		"NUL":               "github.com\x00.evil.example.com",
		"oversized":         string(make([]byte, 300)),
	} {
		if ValidRequestHost(host) {
			t.Fatalf("%s accepted: %q", name, host)
		}
	}
}
