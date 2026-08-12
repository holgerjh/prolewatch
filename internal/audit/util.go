package audit

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

var packageBaseRE = regexp.MustCompile(`^[A-Za-z0-9@._+][A-Za-z0-9@._+-]*$`)
var reportIDRE = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}-[0-9a-f]{8}$`)

func bytesReader(value []byte) *bytes.Reader { return bytes.NewReader(value) }

type limitedBuffer struct {
	buffer bytes.Buffer
	limit  int64
}

func newLimitedBuffer(limit int64) *limitedBuffer { return &limitedBuffer{limit: limit} }
func (b *limitedBuffer) Write(value []byte) (int, error) {
	if b.limit <= 0 || int64(len(value)) > b.limit-int64(b.buffer.Len()) {
		return 0, errors.New("subprocess output exceeds hard limit")
	}
	return b.buffer.Write(value)
}
func (b *limitedBuffer) Bytes() []byte  { return b.buffer.Bytes() }
func (b *limitedBuffer) String() string { return b.buffer.String() }

// contentValidator validates a byte stream without retaining it. It deliberately
// carries an incomplete UTF-8 rune across Write calls so chunk boundaries cannot
// turn malformed control content into apparently valid text.
type contentValidator struct {
	carry   []byte
	NUL     bool
	Invalid bool
}

func (v *contentValidator) Write(value []byte) (int, error) {
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

func (v *contentValidator) Finish() {
	if len(v.carry) > 0 {
		v.Invalid = true
	}
}

func CanonicalJSON(value any) ([]byte, error) {
	// encoding/json sorts string map keys and emits stable compact JSON.
	return json.Marshal(value)
}

func SHA256Bytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func NewReportID(contentHash string) (string, error) {
	if len(contentHash) < 12 {
		return "", errors.New("content hash is too short")
	}
	random := make([]byte, 4)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return time.Now().UTC().Format("20060102T150405Z") + "-" + contentHash[:12] + "-" + hex.EncodeToString(random), nil
}

func UTCNow() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func ValidatePackageBase(value string) error {
	if !packageBaseRE.MatchString(value) {
		return fmt.Errorf("invalid package base %q", value)
	}
	return nil
}

func EnsurePrivateDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), path)
	defer directory.Close()
	if err := unix.Fchmod(fd, 0o700); err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Uid != uint32(os.Getuid()) || stat.Mode&0o777 != 0o700 {
		return fmt.Errorf("unsafe state directory permissions: %s", path)
	}
	return nil
}

func AtomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(mode); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err == nil {
		err = dir.Sync()
		dir.Close()
	}
	return err
}

func AtomicWriteJSON(path string, value any) error {
	raw, err := CanonicalJSON(value)
	if err != nil {
		return err
	}
	return AtomicWrite(path, append(raw, '\n'), 0o600)
}

func ReadJSONFile(path string, maxBytes int64, value any) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var before, after unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size > maxBytes {
		return fmt.Errorf("unsafe JSON file: %s", path)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > maxBytes {
		return fmt.Errorf("JSON file exceeds limit: %s", path)
	}
	if err := unix.Fstat(fd, &after); err != nil {
		return err
	}
	if !sameStat(before, after) || int64(len(raw)) != after.Size {
		return fmt.Errorf("JSON file changed while reading: %s", path)
	}
	return DecodeStrict(raw, value)
}

func sameStat(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Size == b.Size && a.Mtim == b.Mtim
}

func TerminalText(value any, limit int) string {
	text := fmt.Sprint(value)
	var result strings.Builder
	count := 0
	for _, r := range text {
		if count >= limit {
			result.WriteRune('…')
			break
		}
		count++
		if r == '\n' || r == '\t' {
			result.WriteRune(r)
		} else if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Cs) {
			fmt.Fprintf(&result, "\\u%04x", r)
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

type ProcessIdentity struct {
	PID       int    `json:"pid"`
	StartTime string `json:"start_time"`
	BootID    string `json:"boot_id"`
	UID       uint32 `json:"uid"`
}

func IdentityForPID(pid int) (ProcessIdentity, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ProcessIdentity{}, err
	}
	end := strings.LastIndex(string(raw), ") ")
	if end < 0 {
		return ProcessIdentity{}, errors.New("cannot parse process stat")
	}
	fields := strings.Fields(string(raw)[end+2:])
	if len(fields) < 20 {
		return ProcessIdentity{}, errors.New("incomplete process stat")
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ProcessIdentity{}, err
	}
	info, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	if err != nil {
		return ProcessIdentity{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ProcessIdentity{}, errors.New("cannot determine process owner")
	}
	return ProcessIdentity{PID: pid, StartTime: fields[19], BootID: strings.TrimSpace(string(boot)), UID: stat.Uid}, nil
}

func TransactionIdentity() (ProcessIdentity, error) {
	pid := os.Getpid()
	fallback := pid
	for range 16 {
		comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if err != nil {
			break
		}
		if strings.TrimSpace(string(comm)) == "yay" {
			return IdentityForPID(pid)
		}
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			break
		}
		end := strings.LastIndex(string(raw), ") ")
		fields := strings.Fields(string(raw)[end+2:])
		if end < 0 || len(fields) < 2 {
			break
		}
		parent, err := strconv.Atoi(fields[1])
		if err != nil || parent <= 1 || parent == pid {
			break
		}
		pid = parent
	}
	return IdentityForPID(fallback)
}

func IdentityIsLive(identity ProcessIdentity) bool {
	current, err := IdentityForPID(identity.PID)
	return err == nil && current == identity
}

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
	h := sha256.New()
	written, err := io.Copy(h, file)
	if err != nil {
		return "", err
	}
	if err := unix.Fstat(fd, &after); err != nil {
		return "", err
	}
	if !sameStat(before, after) || written != after.Size {
		return "", fmt.Errorf("artifact changed while hashing: %s", path)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func SortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func validUTF8OrReplacement(raw []byte) string {
	if utf8.Valid(raw) {
		return string(raw)
	}
	return strings.ToValidUTF8(string(raw), "�")
}
