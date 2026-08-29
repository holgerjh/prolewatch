// Package safe holds the primitives for handling attacker-controlled bytes at
// a boundary: rendering untrusted text into a terminal, and bounding untrusted
// subprocess output.
//
// It is the lowest layer - below contain - and imports nothing else from this
// project. Keeping the primitives here lets egress, brief, and ui share them
// without importing sideways or upward through the package layers.
//
// The terminal rendering here is load-bearing. Release invariant 7 is that
// security prompts cannot be forged by raw package terminal output, and this
// is where that is enforced - a hostile package name carrying ANSI or OSC
// sequences must not be able to redraw a prompt, move the cursor over a
// warning, or retitle the window.
package safe

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// Text renders untrusted text for terminal display, truncated to limit runes.
//
// Control characters are escaped rather than dropped, so a log keeps visible
// evidence that ANSI/OSC deception was attempted. Dropping them would make the
// output look innocent and lose the finding.
//
// Newline and tab survive because they are needed for legitimate multi-line
// evidence; neither can reposition the cursor or alter styling.
func Text(value any, limit int) string {
	text := fmt.Sprint(value)
	var result strings.Builder
	count := 0
	for _, r := range text {
		if count >= limit {
			result.WriteRune('…')
			break
		}
		count++
		switch {
		case r == '\n' || r == '\t':
			result.WriteRune(r)
		case unicode.IsControl(r), unicode.In(r, unicode.Cf, unicode.Cs):
			fmt.Fprintf(&result, "\\u%04x", r)
		default:
			result.WriteRune(r)
		}
	}
	return result.String()
}

// Inline is Text collapsed to a single line, for output that must occupy one
// row - a status line, a table cell, a prompt.
func Inline(value any, limit int) string {
	return strings.NewReplacer("\n", " ", "\r", " ", "\t", " ").Replace(Text(value, limit))
}

// LimitedBuffer accumulates untrusted output up to a hard limit.
//
// It rejects at the boundary rather than truncating. A silently truncated
// success or error stream may have dropped the decisive evidence, and the
// caller cannot tell that it happened.
type LimitedBuffer struct {
	buffer bytes.Buffer
	limit  int64
}

func NewLimitedBuffer(limit int64) *LimitedBuffer { return &LimitedBuffer{limit: limit} }

func (b *LimitedBuffer) Write(value []byte) (int, error) {
	if b.limit <= 0 || int64(len(value)) > b.limit-int64(b.buffer.Len()) {
		return 0, errors.New("subprocess output exceeds hard limit")
	}
	return b.buffer.Write(value)
}

func (b *LimitedBuffer) Bytes() []byte  { return b.buffer.Bytes() }
func (b *LimitedBuffer) String() string { return b.buffer.String() }

// DecodeJSON decodes JSON strictly: unknown fields and trailing values are
// rejected.
//
// This is a protocol-skew defence, not tidiness. A lenient decoder lets a newer
// or forged document be silently reinterpreted as an older, less restrictive
// one - the receiver ignores the fields it does not recognise and acts on the
// permissive remainder.
func DecodeJSON(data []byte, value any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return fmt.Errorf("invalid trailing JSON: %w", err)
	}
	return nil
}

// CanonicalJSON emits stable compact JSON. encoding/json sorts string map keys,
// which makes map output suitable for hashing and content binding. Struct
// fields retain declaration order, so that order and their JSON tags are part
// of the fingerprint contract: reordering or retagging a bound struct must be
// treated as a content-binding change, not as a formatting-only refactor.
func CanonicalJSON(value any) ([]byte, error) { return json.Marshal(value) }

// ContentValidator inspects a byte stream for NUL bytes and invalid UTF-8
// without retaining it.
//
// It deliberately carries an incomplete rune across Write calls. Without that,
// a multi-byte rune split across a chunk boundary reads as invalid, and worse,
// hostile content could be arranged to straddle boundaries so that malformed
// bytes appear valid. Chunking must not change the verdict.
type ContentValidator struct {
	carry   []byte
	NUL     bool
	Invalid bool
}

func (v *ContentValidator) Write(value []byte) (int, error) {
	original := len(value)
	if bytes.IndexByte(value, 0) >= 0 {
		v.NUL = true
	}
	data := append(append([]byte(nil), v.carry...), value...)
	v.carry = v.carry[:0]
	for len(data) > 0 {
		if !utf8.FullRune(data) {
			v.carry = append(v.carry, data...)
			break
		}
		r, size := utf8.DecodeRune(data)
		if r == utf8.RuneError && size == 1 {
			v.Invalid = true
		}
		data = data[size:]
	}
	return original, nil
}

// Finish reports a trailing partial rune as invalid: a stream that ends
// mid-rune is malformed, not merely unfinished.
func (v *ContentValidator) Finish() {
	if len(v.carry) > 0 {
		v.Invalid = true
	}
}

// ValidUTF8OrReplacement returns the text unchanged when it is valid UTF-8,
// and otherwise substitutes replacement characters. Used where invalid bytes
// must not propagate but the content still has to be shown.
func ValidUTF8OrReplacement(raw []byte) string {
	if utf8.Valid(raw) {
		return string(raw)
	}
	return strings.ToValidUTF8(string(raw), "�")
}

// HashFileNoFollow hashes a file by descriptor and refuses symlinks.
//
// The metadata comparison after the read is the point: it hashes the opened
// inode and verifies that nothing race-relevant changed, so a pathname swapped
// underneath cannot alter the returned digest. Content binding rests on this.
func HashFileNoFollow(path string) (string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var before, after unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG {
		return "", fmt.Errorf("artifact is not a regular file: %s", path)
	}
	digest := sha256.New()
	written, err := io.Copy(digest, file)
	if err != nil {
		return "", err
	}
	if err := unix.Fstat(fd, &after); err != nil {
		return "", err
	}
	if !SameStat(before, after) || written != after.Size {
		return "", fmt.Errorf("artifact changed while hashing: %s", path)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// SameStat compares every race-relevant field of two stat results.
//
// mtime alone is not a sufficient race detector for caller-owned files: an
// owner can restore an earlier mtime after changing bytes. ctime cannot be set
// directly by that owner, and the identity, mode, and link checks catch
// replacement and metadata changes on the already-open descriptor.
func SameStat(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim &&
		a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink
}

// SHA256Bytes hashes a byte slice. Content binding uses it, so it lives beside
// the file-hashing primitive rather than being reimplemented per layer.
func SHA256Bytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

// ValidHexDigest reports whether a string is a full lowercase SHA-256 digest.
// Digests arrive from attacker-authored documents, so shape is checked before
// a value is compared or stored.
func ValidHexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// PromptTerminal is the controlling terminal, opened for a security question.
//
// Prompts read and write /dev/tty rather than stdin and stdout because package
// output must never be able to answer a question on the user's behalf. That is
// necessary and was not sufficient: it stops package bytes becoming input
// directly, and does nothing about input the user has already typed.
//
// A package can print a convincing fake prompt as ordinary build output. The
// user answers it while the real work is still running, the keystroke sits in
// the terminal's input queue, and the next genuine prompt reads it. The user's
// answer is then bound to a question the attacker wrote rather than the one
// Prolewatch asked. Reading from /dev/tty does not help, because the buffered
// keystroke is on /dev/tty.
//
// So opening a prompt terminal discards whatever is already queued, and resets
// the rendition the package may have left behind, before anything is drawn.
type PromptTerminal struct{ *os.File }

// ErrYesNoPromptTimeout reports that a single-key prompt received no valid
// answer within its complete prompt budget.
var ErrYesNoPromptTimeout = errors.New("yes/no prompt timed out")

// OpenPromptTerminal opens the controlling terminal and makes it safe to ask a
// question on. Every security prompt in Prolewatch goes through here, so the
// flush cannot be forgotten on one surface and remembered on another.
func OpenPromptTerminal() (*PromptTerminal, error) {
	file, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	terminal := &PromptTerminal{File: file}
	terminal.Discard()
	// Undo styling and restore cursor visibility without moving the cursor or
	// switching screens. Package output is neutralized before replay; emitting a
	// scroll-region or alternate-screen reset here would make parallel yay
	// workers overwrite unrelated terminal output. Failure is not fatal: a
	// terminal that rejects this is still usable.
	_, _ = file.WriteString("\x1b[0m\x1b[?25h")
	return terminal, nil
}

// Discard throws away input typed before now.
//
// It is called when the terminal is opened, immediately before a prompt is
// rendered. Anything queued at that moment was typed in response to something
// other than the question about to be asked.
func (t *PromptTerminal) Discard() {
	if t == nil || t.File == nil {
		return
	}
	// TCIFLUSH discards data received but not read. A terminal that does not
	// support it leaves the queue intact, which is the pre-existing behaviour
	// rather than a new failure.
	_ = unix.IoctlSetInt(int(t.File.Fd()), unix.TCFLSH, unix.TCIFLUSH)
}

// ReadYesNo reads a single y/n decision without requiring Enter.
//
// Only canonical line buffering and echo are disabled. ISIG remains enabled,
// so Ctrl-C retains the terminal's ordinary behavior. Unrelated keys are
// ignored rather than guessed into a security decision; Enter selects the
// displayed default, no. Restoring with TCSETSF also discards unread bytes from
// a pasted "yes" so they cannot spill into yay's next prompt.
func (t *PromptTerminal) ReadYesNo(timeout time.Duration) (bool, error) {
	choice, err := t.ReadChoice(timeout, "yn", 'n')
	return choice == 'y', err
}

// ReadChoice reads one ASCII choice without requiring Enter. Uppercase input
// is normalized to lower case, unrelated keys are ignored, and Enter selects
// defaultChoice. Keeping this terminal-mode handling in the same primitive as
// ReadYesNo preserves the input-flush boundary when a security prompt offers a
// non-authorizing action such as viewing already-scanned evidence.
func (t *PromptTerminal) ReadChoice(timeout time.Duration, choices string, defaultChoice byte) (byte, error) {
	if t == nil || t.File == nil {
		return 0, os.ErrInvalid
	}
	if defaultChoice < 'a' || defaultChoice > 'z' || !strings.ContainsRune(choices, rune(defaultChoice)) {
		return 0, os.ErrInvalid
	}
	for _, choice := range choices {
		if choice < 'a' || choice > 'z' {
			return 0, os.ErrInvalid
		}
	}
	fd := int(t.File.Fd())
	original, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return 0, err
	}
	keyMode := *original
	keyMode.Lflag &^= unix.ICANON | unix.ECHO
	keyMode.Cc[unix.VMIN] = 1
	keyMode.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &keyMode); err != nil {
		return 0, err
	}
	defer func() {
		// Restore the user's settings and discard any suffix from pasted or
		// habitual line input. The next application must not inherit an answer
		// intended for this prompt.
		_ = unix.IoctlSetTermios(fd, unix.TCSETSF, original)
	}()

	deadline := time.Time{}
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	var key [1]byte
	for {
		if !deadline.IsZero() {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return 0, ErrYesNoPromptTimeout
			}
			milliseconds := int((remaining + time.Millisecond - 1) / time.Millisecond)
			ready, pollErr := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, milliseconds)
			if errors.Is(pollErr, unix.EINTR) {
				continue
			}
			if pollErr != nil {
				return 0, pollErr
			}
			if ready < 1 {
				return 0, ErrYesNoPromptTimeout
			}
		}
		count, readErr := t.File.Read(key[:])
		if errors.Is(readErr, unix.EINTR) {
			continue
		}
		if readErr != nil {
			return 0, readErr
		}
		if count == 0 {
			return 0, io.EOF
		}
		choice := key[0]
		if choice >= 'A' && choice <= 'Z' {
			choice += 'a' - 'A'
		}
		if strings.IndexByte(choices, choice) >= 0 {
			_, _ = t.File.Write([]byte{choice, '\n'})
			return choice, nil
		}
		if key[0] == '\r' || key[0] == '\n' {
			_, _ = t.File.WriteString("\n")
			return defaultChoice, nil
		}
	}
}
