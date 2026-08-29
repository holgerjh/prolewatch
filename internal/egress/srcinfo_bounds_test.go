package egress

import (
	"strings"
	"testing"
)

// Everything downstream of a declared source is per-source: a prompt, a fetch,
// a file in SRCDEST. Without a cap, one PKGBUILD turns into an unbounded amount
// of trusted-side work.
func TestDeclaringMoreSourcesThanTheCapIsRefused(t *testing.T) {
	var lines []string
	for i := 0; i <= MaxDeclaredSources; i++ {
		lines = append(lines, "\tsource = https://example.com/"+strings.Repeat("a", i%8+1)+itoa(i)+".tar.gz")
	}
	if _, err := ParseSrcinfoSources([]byte(strings.Join(lines, "\n"))); err == nil {
		t.Fatalf("a package declaring more than %d sources was accepted", MaxDeclaredSources)
	}
	// The cap is well above anything real, so a normal package is unaffected.
	sources, err := ParseSrcinfoSources([]byte("\tsource = https://example.com/a.tar.gz\n\tsource = https://example.com/b.tar.gz\n"))
	if err != nil || len(sources) != 2 {
		t.Fatalf("an ordinary package was refused: %d sources, %v", len(sources), err)
	}
}

// A partial parse is the worst available outcome: the user is shown a short
// list of sources, agrees to it, and the ones that did not fit are exactly the
// ones nobody looked at. Overflow must fail, not truncate.
func TestAnOverlongLineFailsRatherThanTruncatingTheSourceSet(t *testing.T) {
	overlong := "\tsource = https://example.com/" + strings.Repeat("a", maxSrcinfoLineBytes) + ".tar.gz\n"
	raw := "\tsource = https://example.com/first.tar.gz\n" + overlong + "\tsource = https://evil.example.com/last.tar.gz\n"
	sources, err := ParseSrcinfoSources([]byte(raw))
	if err == nil {
		t.Fatalf("an unparseable .SRCINFO produced %d sources instead of an error", len(sources))
	}
	if sources != nil {
		t.Fatalf("a failed parse returned a partial source set: %+v", sources)
	}
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
