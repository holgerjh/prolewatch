package safe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// ContentValidator must reach the same verdict regardless of where the chunk
// boundaries fall. Without the carried partial rune, a multi-byte character
// split across a Write reads as invalid - and worse, hostile content could be
// arranged to straddle boundaries so malformed bytes appear valid.
func TestContentValidatorIsIndifferentToChunkBoundaries(t *testing.T) {
	text := []byte("gültig — multibyte ✓ text")
	for size := 1; size <= len(text); size++ {
		var validator ContentValidator
		for start := 0; start < len(text); start += size {
			end := start + size
			if end > len(text) {
				end = len(text)
			}
			validator.Write(text[start:end])
		}
		validator.Finish()
		if validator.Invalid || validator.NUL {
			t.Fatalf("chunk size %d turned valid UTF-8 into invalid=%t nul=%t", size, validator.Invalid, validator.NUL)
		}
	}
}

func TestContentValidatorReportsNULAndTruncatedRunes(t *testing.T) {
	var withNUL ContentValidator
	withNUL.Write([]byte("before\x00after"))
	withNUL.Finish()
	if !withNUL.NUL {
		t.Fatal("a NUL byte was not reported")
	}
	// A stream that ends mid-rune is malformed, not merely unfinished.
	var truncated ContentValidator
	truncated.Write([]byte("ok")[:2])
	truncated.Write([]byte("é")[:1])
	truncated.Finish()
	if !truncated.Invalid {
		t.Fatal("a trailing partial rune was accepted")
	}
	var invalid ContentValidator
	invalid.Write([]byte{0xff, 0xfe})
	invalid.Finish()
	if !invalid.Invalid {
		t.Fatal("invalid UTF-8 was accepted")
	}
}

func TestValidUTF8OrReplacementKeepsValidTextUnchanged(t *testing.T) {
	if got := ValidUTF8OrReplacement([]byte("plain ünicode")); got != "plain ünicode" {
		t.Fatalf("valid text was altered: %q", got)
	}
	got := ValidUTF8OrReplacement([]byte{'a', 0xff, 'b'})
	if strings.ContainsRune(got, 0xff) || !strings.Contains(got, "a") || !strings.Contains(got, "b") {
		t.Fatalf("invalid bytes were not replaced: %q", got)
	}
}

func TestSHA256BytesAndValidHexDigest(t *testing.T) {
	digest := SHA256Bytes([]byte("prolewatch"))
	if len(digest) != 64 || !ValidHexDigest(digest) {
		t.Fatalf("digest is not a valid lowercase sha256: %q", digest)
	}
	// Digests arrive from attacker-authored documents, so shape is checked
	// before a value is compared or stored.
	for _, bad := range []string{
		"", "abc", strings.ToUpper(digest), strings.Repeat("g", 64),
		digest[:63], digest + "0", strings.Repeat("a", 63) + "!",
	} {
		if ValidHexDigest(bad) {
			t.Fatalf("accepted a malformed digest: %q", bad)
		}
	}
}

func TestCanonicalJSONIsStableAcrossMapOrdering(t *testing.T) {
	first, err := CanonicalJSON(map[string]any{"b": 2, "a": 1, "c": 3})
	if err != nil {
		t.Fatal(err)
	}
	second, err := CanonicalJSON(map[string]any{"c": 3, "a": 1, "b": 2})
	if err != nil {
		t.Fatal(err)
	}
	// Stability is what makes the output usable for hashing and content binding.
	if string(first) != string(second) {
		t.Fatalf("map ordering changed the encoding: %s vs %s", first, second)
	}
	if _, err := CanonicalJSON(make(chan int)); err == nil {
		t.Fatal("an unencodable value was accepted")
	}
}

func TestLimitedBufferExposesWhatItAccepted(t *testing.T) {
	buffer := NewLimitedBuffer(16)
	buffer.Write([]byte("kept"))
	if string(buffer.Bytes()) != "kept" || buffer.String() != "kept" {
		t.Fatalf("buffer contents = %q / %q", buffer.Bytes(), buffer.String())
	}
}

// HashFileNoFollow is what content binding rests on: it hashes the opened inode
// and refuses anything that is not a regular file it opened itself.
func TestHashFileNoFollowBindsToTheOpenedInode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact")
	if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest, err := HashFileNoFollow(path)
	if err != nil {
		t.Fatalf("hashing a regular file failed: %v", err)
	}
	if digest != SHA256Bytes([]byte("payload")) {
		t.Fatalf("digest does not match the contents: %s", digest)
	}

	// A symlink must not be followed: the whole point is that a pathname
	// swapped for a link cannot redirect the hash to other bytes.
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	if _, err := HashFileNoFollow(link); err == nil {
		t.Fatal("a symlink was followed")
	}

	// Directories and missing paths are not artifacts.
	if _, err := HashFileNoFollow(dir); err == nil {
		t.Fatal("a directory was hashed as an artifact")
	}
	if _, err := HashFileNoFollow(filepath.Join(dir, "absent")); err == nil {
		t.Fatal("a missing path was hashed")
	}
}

// SameStat exists because mtime alone is not a sufficient race detector: an
// owner can restore an earlier mtime after changing bytes.
func TestSameStatComparesEveryRaceRelevantField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := os.WriteFile(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := statOf(path)
	if err != nil {
		t.Fatal(err)
	}
	if !SameStat(before, before) {
		t.Fatal("a stat did not equal itself")
	}
	if err := os.WriteFile(path, []byte("two!"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := statOf(path)
	if err != nil {
		t.Fatal(err)
	}
	if SameStat(before, after) {
		t.Fatal("a changed file compared equal")
	}
}

func statOf(path string) (unix.Stat_t, error) {
	var st unix.Stat_t
	err := unix.Stat(path, &st)
	return st, err
}
