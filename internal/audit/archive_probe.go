package audit

import (
	"bufio"
	"context"
	"errors"
	"fmt"
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

func archiveProbeIdentity(ctx context.Context) (ToolIdentity, error) {
	const binary = "/usr/bin/bsdtar"
	versionCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	command := exec.CommandContext(versionCtx, binary, "--version")
	command.Env = []string{"PATH=/usr/bin", "LANG=C.UTF-8"}
	output := newLimitedBuffer(64 * 1024)
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil {
		return ToolIdentity{}, fmt.Errorf("cannot execute archive probe: %w", err)
	}
	digest, err := HashFileNoFollow(binary)
	if err != nil {
		return ToolIdentity{}, err
	}
	return ToolIdentity{Path: binary, Version: strings.TrimSpace(output.String()), SHA256: digest}, nil
}

func archiveProbeBwrapArgs() []string {
	return []string{
		"--die-with-parent", "--new-session", "--unshare-all",
		"--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin",
		"--symlink", "usr/lib", "/lib", "--symlink", "usr/lib", "/lib64",
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
	stderr := newLimitedBuffer(256 * 1024)
	command.Stdout = newLimitedBuffer(256 * 1024)
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
	if exitCode == 1 && strings.HasPrefix(stderr, "bsdtar:") {
		return false, nil
	}
	return false, fmt.Errorf("isolated bsdtar probe failed: %w: %s", runErr, truncate(stderr, 1000))
}

func readExtractableSources(rootFD int, limit int64) map[string]bool {
	fd, err := unix.Openat(rootFD, ".SRCINFO", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return map[string]bool{}
	}
	file := os.NewFile(uintptr(fd), ".SRCINFO")
	defer file.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size < 0 || st.Size > limit {
		return map[string]bool{}
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return map[string]bool{}
	}
	return parseExtractableSources(raw, limit)
}

func parseExtractableSources(raw []byte, limit int64) map[string]bool {
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
	if err != nil || int64(len(raw)) > limit || unix.Fstat(fd, &after) != nil || !sameStat(before, after) {
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
