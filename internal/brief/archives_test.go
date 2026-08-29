package brief

import (
	"bytes"
	"os/exec"
	"testing"
)

// A decompressor sizes its buffers from numbers the attacker wrote, and the
// scanner's entry, byte and depth limits only count what comes *out*. The xz
// library treats a stream's declared LZMA2 dictionary as a floor and allocates
// it in full before decoding a byte, so a few hundred well-formed bytes cost
// the trusted scanner gigabytes. The declaration is checked first.
func TestXZDictionaryDeclarationIsCheckedBeforeAllocation(t *testing.T) {
	// A minimal xz stream head: 12-byte stream header, then a block header
	// whose single LZMA2 filter carries the dictionary byte under test.
	stream := func(encoded byte) []byte {
		head := append([]byte{0xfd, '7', 'z', 'X', 'Z', 0x00, 0x00, 0x04}, 0, 0, 0, 0)
		block := []byte{0x02, 0x00, 0x21, 0x01, encoded, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		return append(head, block...)
	}
	// 40 is the format's maximum: a 4 GiB dictionary from a stream this size.
	if err := checkXZDictionary(stream(40)); err == nil {
		t.Fatal("a 4 GiB LZMA2 dictionary declaration was accepted")
	}
	// 24 encodes 8 MiB, which is what ordinary compression levels use.
	if err := checkXZDictionary(stream(24)); err != nil {
		t.Fatalf("an ordinary 8 MiB dictionary was refused: %v", err)
	}
	// 41 and above are not valid encodings at all.
	if err := checkXZDictionary(stream(41)); err == nil {
		t.Fatal("an invalid dictionary encoding was accepted")
	}
	// A header that does not fit in the inspected prefix is refused rather than
	// guessed at; the caller turns that into a coverage finding.
	if err := checkXZDictionary([]byte{0xfd, '7', 'z', 'X', 'Z', 0, 0, 4, 0, 0, 0, 0, 0xff}); err == nil {
		t.Fatal("an unreadable block header was accepted")
	}
	if err := checkXZDictionary([]byte{0xfd, '7', 'z', 'X', 'Z', 0, 0, 4}); err == nil {
		t.Fatal("a truncated stream header was accepted")
	}

	// The real path: a genuine xz archive must still scan.
	if err := checkXZDictionary(realXZHead(t)); err != nil {
		t.Fatalf("a real xz archive was refused: %v", err)
	}
}

func realXZHead(t *testing.T) []byte {
	t.Helper()
	binary, err := exec.LookPath("xz")
	if err != nil {
		t.Skip("xz not available")
	}
	command := exec.Command(binary, "-9", "-c")
	command.Stdin = bytes.NewReader(bytes.Repeat([]byte("prolewatch archive payload\n"), 4096))
	out, err := command.Output()
	if err != nil {
		t.Skipf("xz failed: %v", err)
	}
	if len(out) > 512 {
		out = out[:512]
	}
	return out
}
