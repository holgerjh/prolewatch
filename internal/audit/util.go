package audit

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/holgerjh/prolewatch/internal/safe"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var packageBaseRE = regexp.MustCompile(`^[A-Za-z0-9@._+][A-Za-z0-9@._+-]*$`)
var reportIDRE = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}-[0-9a-f]{8}$`)

type limitedBuffer = safe.LimitedBuffer

func newLimitedBuffer(limit int64) *limitedBuffer { return safe.NewLimitedBuffer(limit) }

func CanonicalJSON(value any) ([]byte, error) { return safe.CanonicalJSON(value) }

func NewReportID(contentHash string) (string, error) {
	if len(contentHash) < 12 {
		return "", errors.New("content hash is too short")
	}
	// The ID exposes 12 digest hex characters for human correlation and adds a
	// 32-bit random suffix so same-second reports for identical content differ.
	random := make([]byte, 4)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return time.Now().UTC().Format("20060102T150405Z") + "-" + contentHash[:12] + "-" + hex.EncodeToString(random), nil
}

func UTCNow() string { return time.Now().UTC().Format(time.RFC3339Nano) }

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
	// Commit through a same-directory temporary inode, fsync file contents, then
	// fsync the directory entry. Readers see either the old complete document or
	// the new complete document, including across a crash.
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
	// Read an already-open no-follow inode and compare its metadata afterward.
	// This centralizes the stable-read contract for user- and root-owned state.
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
	if !safe.SameStat(before, after) || int64(len(raw)) != after.Size {
		return fmt.Errorf("JSON file changed while reading: %s", path)
	}
	return DecodeStrict(raw, value)
}

// TerminalText delegates to the shared terminal-sanitisation implementation.
// Keeping one implementation lets audit, egress, brief, and ui apply identical
// escaping without violating package layering.
func TerminalText(value any, limit int) string { return safe.Text(value, limit) }

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
	// After removing pid/comm, field index 19 is proc(5)'s starttime (field 22).
	// Pairing it with boot ID distinguishes PID reuse both within and across boots.
	return ProcessIdentity{PID: pid, StartTime: fields[19], BootID: strings.TrimSpace(string(boot)), UID: stat.Uid}, nil
}

func TransactionIdentity() (ProcessIdentity, error) {
	// Walk a bounded parent chain looking for yay so related hook/makepkg
	// processes share one transaction identity. Fall back to the current process
	// when invoked outside yay; 16 levels avoid an unbounded procfs walk.
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

// truncate, truncateTail and valueOr are small local helpers. They are
// duplicated in internal/brief rather than shared, because a package that
// exists to hold three string helpers is worse than three string helpers.
func truncate(value string, limit int) string {
	if len(value) > limit {
		return value[:limit]
	}
	return value
}

func truncateTail(value string, limit int) string {
	const marker = "[earlier output omitted]\n"
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	if limit <= len(marker) {
		return value[len(value)-limit:]
	}
	return marker + value[len(value)-(limit-len(marker)):]
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
