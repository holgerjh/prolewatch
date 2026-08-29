package safe

import (
	"strings"
	"testing"
)

// Release invariant 7: security prompts cannot be forged by raw package
// terminal output. Each case below is a way a package name or host could
// otherwise rewrite what the user is looking at.
func TestTextNeutralisesTerminalControlSequences(t *testing.T) {
	for name, payload := range map[string]string{
		"ANSI colour":      "\x1b[31mDANGER\x1b[0m",
		"cursor up":        "safe\x1b[1A\x1b[2Kforged prompt",
		"OSC window title": "\x1b]0;forged\x07",
		"carriage return":  "allow? [y/N]\rdeny? [Y/n]",
		"backspace":        "safe\x08\x08\x08\x08evil",
		"NUL":              "safe\x00evil",
		"bidi override":    "safe‮gnp.exe",
		"zero width":       "git​hub.com",
	} {
		got := Text(payload, 4096)
		for _, r := range got {
			if r == '\n' || r == '\t' {
				continue
			}
			if r < 0x20 || r == 0x7f {
				t.Fatalf("%s: raw control %q survived: %q", name, r, got)
			}
		}
		if !strings.Contains(got, "\\u") {
			t.Fatalf("%s: control character was dropped rather than escaped, losing the evidence: %q", name, got)
		}
	}
}

func TestTextKeepsNewlineAndTab(t *testing.T) {
	if got := Text("a\nb\tc", 4096); got != "a\nb\tc" {
		t.Fatalf("multi-line evidence was mangled: %q", got)
	}
}

func TestTextTruncatesByRunesAndMarksIt(t *testing.T) {
	got := Text("a\x01bc", 2)
	if !strings.Contains(got, "\\u0001") || !strings.HasSuffix(got, "…") {
		t.Fatalf("expected escaped control and a truncation mark, got %q", got)
	}
	// Truncation counts runes, not bytes: a limit applied to bytes would cut a
	// multi-byte rune in half and could emit invalid UTF-8.
	if got := Text("äöüß", 2); got != "äö…" {
		t.Fatalf("rune truncation is wrong: %q", got)
	}
}

func TestInlineCollapsesToOneRow(t *testing.T) {
	if got := Inline("a\nb\rc\td", 4096); strings.ContainsAny(got, "\n\r\t") {
		t.Fatalf("inline text still spans rows: %q", got)
	}
}

// The buffer must refuse rather than truncate: a caller that receives
// truncated evidence cannot tell it was truncated.
func TestLimitedBufferRejectsRatherThanTruncating(t *testing.T) {
	buffer := NewLimitedBuffer(8)
	if _, err := buffer.Write([]byte("12345678")); err != nil {
		t.Fatalf("write within the limit failed: %v", err)
	}
	if _, err := buffer.Write([]byte("9")); err == nil {
		t.Fatal("write past the limit must fail")
	}
	if buffer.String() != "12345678" {
		t.Fatalf("rejected write altered the buffer: %q", buffer.String())
	}
	if _, err := NewLimitedBuffer(0).Write([]byte("x")); err == nil {
		t.Fatal("a zero limit must reject everything")
	}
}

// A lenient decoder would let a forged or newer document be reinterpreted as
// an older, less restrictive one: the receiver drops the fields it does not
// know and acts on the permissive remainder.
func TestDecodeJSONRejectsSkewAndTrailingContent(t *testing.T) {
	var target struct {
		Allow bool `json:"allow"`
	}
	if err := DecodeJSON([]byte(`{"allow":true}`), &target); err != nil || !target.Allow {
		t.Fatalf("valid document rejected: %v", err)
	}
	for name, document := range map[string]string{
		"unknown field":  `{"allow":false,"allow_all":true}`,
		"trailing value": `{"allow":false} {"allow":true}`,
		"trailing junk":  `{"allow":false} garbage`,
	} {
		if err := DecodeJSON([]byte(document), &target); err == nil {
			t.Fatalf("%s was accepted: %s", name, document)
		}
	}
}
