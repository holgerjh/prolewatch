package brief

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/holgerjh/prolewatch/internal/safe"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type ToolIdentity struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

func ArchiveProbeIdentity(ctx context.Context) (ToolIdentity, error) {
	// Reports bind both bsdtar's version text and executable digest because this
	// external parser decides whether makepkg would treat an unknown file as an
	// extractable archive.
	const binary = "/usr/bin/bsdtar"
	versionCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	command := exec.CommandContext(versionCtx, binary, "--version")
	command.Env = []string{"PATH=/usr/bin", "LANG=C.UTF-8"}
	output := safe.NewLimitedBuffer(64 * 1024)
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil {
		return ToolIdentity{}, fmt.Errorf("cannot execute archive probe: %w", err)
	}
	digest, err := safe.HashFileNoFollow(binary)
	if err != nil {
		return ToolIdentity{}, err
	}
	return ToolIdentity{Path: binary, Version: strings.TrimSpace(output.String()), SHA256: digest}, nil
}

func archiveProbeBwrapArgs() []string {
	// FD 3 is mounted as the only input. The probe gets no package tree, network,
	// writable host path, environment, or nested user-namespace capability.
	return []string{
		"--die-with-parent", "--new-session", "--unshare-all", "--unshare-user",
		"--disable-userns", "--assert-userns-disabled",
		"--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin",
		"--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
		"--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
		"--ro-bind-fd", "3", "/input", "--clearenv",
		"--setenv", "PATH", "/usr/bin", "--setenv", "LANG", "C.UTF-8",
		"/usr/bin/bsdtar", "-tf", "/input", "-q", "*",
	}
}

// probeMakepkgArchive applies makepkg's bsdtar fallback to an already safely
// opened descriptor. The parser sees no package tree or writable host path.
func probeMakepkgArchive(fd int) (bool, error) {
	dup, err := unix.Dup(fd)
	if err != nil {
		return false, err
	}
	input := os.NewFile(uintptr(dup), "archive-probe-input")
	defer input.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	args := archiveProbeBwrapArgs()
	command := exec.CommandContext(ctx, "/usr/bin/bwrap", args...)
	command.ExtraFiles = []*os.File{input}
	stderr := safe.NewLimitedBuffer(256 * 1024)
	command.Stdout = safe.NewLimitedBuffer(256 * 1024)
	command.Stderr = stderr
	err = command.Run()
	exitCode := -1
	if exit, ok := err.(*exec.ExitError); ok {
		exitCode = exit.ExitCode()
	}
	return classifyArchiveProbeResult(ctx.Err(), err, exitCode, strings.TrimSpace(stderr.String()))
}

func classifyArchiveProbeResult(contextErr, runErr error, exitCode int, stderr string) (bool, error) {
	if runErr == nil {
		return true, nil
	}
	if errors.Is(contextErr, context.DeadlineExceeded) {
		return false, errors.New("archive probe timed out")
	}
	// bsdtar uses exit 1 plus its own diagnostic prefix for ordinary
	// "not an archive" input. Other exits indicate an isolation/tool failure and
	// must not be downgraded to a harmless negative classification.
	if exitCode == 1 && strings.HasPrefix(stderr, "bsdtar:") {
		return false, nil
	}
	return false, fmt.Errorf("isolated bsdtar probe failed: %w: %s", runErr, truncate(stderr, 1000))
}

func ParseExtractableSources(raw []byte, limit int64) map[string]bool {
	// Mirror makepkg's source/noextract basename rules only far enough to decide
	// which downloaded files require archive inspection; this is not a shell or
	// complete SRCINFO evaluator.
	result := map[string]bool{}
	noextract := map[string]bool{}
	var sources []string
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 4096), int(min(limit, 4*1024*1024)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		key, value, ok := strings.Cut(line, " = ")
		if !ok {
			continue
		}
		switch {
		case key == "source" || strings.HasPrefix(key, "source_"):
			sources = append(sources, value)
		case key == "noextract":
			noextract[value] = true
		}
	}
	for _, source := range sources {
		name := makepkgSourceName(source)
		if name != "" && !noextract[name] && path.Base(name) == name {
			result[name] = true
		}
	}
	return result
}

func readActiveControlPaths(rootFD int, limit int64) map[string]bool {
	// Discover install scripts and simple sourced control files that remain
	// mandatory even if an extension-based selector would otherwise omit them.
	// Dynamic shell expressions are rejected rather than guessed.
	result := map[string]bool{}
	if raw, ok := readSmallRegularAt(rootFD, ".SRCINFO", limit); ok {
		scanner := bufio.NewScanner(strings.NewReader(string(raw)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "install = ") {
				candidate := path.Clean(strings.TrimSpace(strings.TrimPrefix(line, "install = ")))
				if candidate != "." && path.Base(candidate) == candidate {
					result[candidate] = true
				}
			}
		}
	}
	if raw, ok := readSmallRegularAt(rootFD, "PKGBUILD", limit); ok {
		for _, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			var value string
			if strings.HasPrefix(trimmed, "source ") {
				value = strings.TrimSpace(strings.TrimPrefix(trimmed, "source "))
			} else if strings.HasPrefix(trimmed, ". ") {
				value = strings.TrimSpace(strings.TrimPrefix(trimmed, ". "))
			}
			if strings.HasPrefix(value, "-- ") {
				value = strings.TrimSpace(strings.TrimPrefix(value, "-- "))
			}
			value = strings.Trim(value, "'\"")
			value = strings.TrimPrefix(value, "$srcdir/")
			value = strings.TrimPrefix(value, "${srcdir}/")
			candidate := path.Clean(value)
			if value != "" && !strings.ContainsAny(value, "$`(){};|&<>") && candidate != "." && !strings.HasPrefix(candidate, "../") && !strings.HasPrefix(candidate, "/") {
				result[candidate] = true
			}
		}
	}
	return result
}

func readSmallRegularAt(rootFD int, name string, limit int64) ([]byte, bool) {
	fd, err := unix.Openat(rootFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, false
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size < 0 || before.Size > limit {
		return nil, false
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit || unix.Fstat(fd, &after) != nil || !safe.SameStat(before, after) {
		return nil, false
	}
	return raw, true
}

func makepkgSourceName(value string) string {
	if alias, _, ok := strings.Cut(value, "::"); ok {
		return alias
	}
	proto := "local"
	if index := strings.Index(value, "://"); index >= 0 {
		proto = strings.SplitN(value[:index], "+", 2)[0]
	}
	switch proto {
	case "bzr", "fossil", "git", "hg", "svn":
		name := strings.SplitN(value, "#", 2)[0]
		name = strings.SplitN(name, "?", 2)[0]
		name = strings.TrimSuffix(name, "/")
		name = path.Base(name)
		if proto == "fossil" {
			name += ".fossil"
		}
		if proto == "git" {
			name = strings.SplitN(name, ".git", 2)[0]
		}
		return name
	default:
		name := strings.SplitN(value, "#", 2)[0]
		name = strings.SplitN(name, "?", 2)[0]
		return path.Base(strings.TrimSuffix(name, "/"))
	}
}
