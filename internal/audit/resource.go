package audit

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/holgerjh/prolewatch/internal/contain"
	"golang.org/x/sys/unix"
)

type SandboxEnforcement struct {
	// This structure records the limits that were actually applied, not merely
	// requested configuration, so an audit report can explain its containment.
	MemoryBytes    int64  `json:"memory_bytes"`
	CPUCount       int    `json:"cpu_count"`
	TasksMax       int    `json:"tasks_max"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	WorkspaceBytes int64  `json:"workspace_bytes"`
	WorkspaceFiles int    `json:"workspace_files"`
	OutputBytes    int64  `json:"output_bytes"`
	NetworkPolicy  string `json:"network_policy"`
	Termination    string `json:"termination,omitempty"`
}

const (
	freezeMaxMemoryBytes    = 2 << 30
	freezeMaxCPUCount       = 2
	freezeMaxTasks          = 128
	freezeMaxTimeoutSeconds = 60
	freezeMaxFileBytes      = 64 << 20
	freezeMaxOutputBytes    = 4 << 20
	freezeMinMemoryBytes    = 512 << 20
	freezeMinCPUCount       = 1
	freezeMinTasks          = 64
	workspacePollInterval   = 25 * time.Millisecond
	workspaceScanInterval   = 250 * time.Millisecond
	scopeCollectionGrace    = 10 * time.Second
)

// limits renders the recorded envelope as the containment primitive's own type.
// SandboxEnforcement stays the reporting shape - it also carries workspace and
// termination facts that are not systemd properties - and contain.Limits is
// what actually reaches systemd-run.
func (s SandboxEnforcement) limits() contain.Limits {
	return contain.Limits{
		MemoryBytes:    s.MemoryBytes,
		CPUCount:       s.CPUCount,
		TasksMax:       s.TasksMax,
		TimeoutSeconds: s.TimeoutSeconds,
		FileSizeBytes:  s.WorkspaceBytes,
		OutputBytes:    s.OutputBytes,
	}
}

func (s SandboxEnforcement) Validate() error {
	if s.MemoryBytes <= 0 || s.CPUCount <= 0 || s.TasksMax <= 0 || s.TimeoutSeconds <= 0 ||
		s.WorkspaceBytes <= 0 || s.WorkspaceFiles <= 0 || s.OutputBytes <= 0 {
		return errors.New("sandbox enforcement contains non-positive limits")
	}
	if s.NetworkPolicy != "isolated" && s.NetworkPolicy != "public-web-broker" {
		return errors.New("sandbox enforcement has an invalid network policy")
	}
	validTermination := map[string]bool{"": true, "sandbox-setup": true, "workspace-accounting": true, "systemd-start": true, "process-exit": true, "output-limit": true, "workspace-limit": true, "timeout": true, "cancelled": true, "network-broker": true, "network-request-limit": true}
	if !validTermination[s.Termination] {
		return errors.New("sandbox enforcement has an invalid termination reason")
	}
	return nil
}

func effectiveBuildLimits(cfg BuildConfig) SandboxEnforcement {
	memory := cfg.MemoryBytes
	var info unix.Sysinfo_t
	if unix.Sysinfo(&info) == nil {
		total := int64(info.Totalram) * int64(info.Unit)
		// Never promise the build more than 80% of physical RAM. The remaining 20%
		// protects the desktop and supervisor even when config asks for more.
		if cap := total * 8 / 10; cap > 0 && memory > cap {
			memory = cap
		}
	}
	cpus := min(cfg.CPUCount, runtime.NumCPU())
	if cpus < 1 {
		cpus = 1
	}
	return SandboxEnforcement{MemoryBytes: memory, CPUCount: cpus, TasksMax: cfg.TasksMax,
		TimeoutSeconds: cfg.TimeoutSeconds, WorkspaceBytes: cfg.WorkspaceBytes,
		WorkspaceFiles: cfg.WorkspaceFiles, OutputBytes: cfg.OutputBytes, NetworkPolicy: "isolated"}
}

// freezeLimits is the envelope for PKGBUILD evaluation.
//
// It is deliberately tighter than the build's. Evaluating a PKGBUILD is
// supposed to print a few dozen lines and exit; a build is supposed to compile
// software for minutes. Giving the evaluation the build's envelope would mean a
// top-level `while :; do :; done` hangs for the full build timeout before the
// user sees anything, which is most of the attack with none of the work.
//
// Every value is a floor-capped narrowing of the configured build limits, so a
// deployment that tightens the build tightens this too, and one that loosens
// the build does not loosen this.
func freezeLimits(cfg BuildConfig) contain.Limits {
	build := effectiveBuildLimits(cfg)
	limits := contain.Limits{
		MemoryBytes:    min(build.MemoryBytes, freezeMaxMemoryBytes),
		CPUCount:       min(build.CPUCount, freezeMaxCPUCount),
		TasksMax:       min(build.TasksMax, freezeMaxTasks),
		TimeoutSeconds: min(build.TimeoutSeconds, freezeMaxTimeoutSeconds),
		FileSizeBytes:  min(build.WorkspaceBytes, freezeMaxFileBytes),
		OutputBytes:    min(build.OutputBytes, freezeMaxOutputBytes),
	}
	// A configuration with a non-positive build limit would otherwise produce a
	// non-positive freeze limit, and Validate would reject it - failing the
	// audit for a reason the user cannot act on. Clamp up to a usable floor.
	if limits.MemoryBytes <= 0 {
		limits.MemoryBytes = freezeMinMemoryBytes
	}
	if limits.CPUCount <= 0 {
		limits.CPUCount = freezeMinCPUCount
	}
	if limits.TasksMax <= 0 {
		limits.TasksMax = freezeMinTasks
	}
	if limits.TimeoutSeconds <= 0 {
		limits.TimeoutSeconds = freezeMaxTimeoutSeconds
	}
	if limits.FileSizeBytes <= 0 {
		limits.FileSizeBytes = freezeMaxFileBytes
	}
	if limits.OutputBytes <= 0 {
		limits.OutputBytes = freezeMaxOutputBytes
	}
	return limits
}

type workspaceMonitor struct {
	root          string
	cfg           BuildConfig
	fd            int
	watches       map[int]string
	errors        chan error
	done          chan struct{}
	once          sync.Once
	makepkgLocked bool
}

var errWorkspaceTreeChanging = errors.New("workspace tree changed during accounting")

const workspaceReconcileChangeLimit = 15 * time.Second

func startWorkspaceMonitor(root string, cfg BuildConfig) (*workspaceMonitor, error) {
	// Recursive scans enforce byte/file/free-space limits authoritatively. inotify
	// is the low-latency signal to repeat that accounting as the build mutates the
	// tree; neither mechanism alone is sufficient for newly created directories.
	monitor := &workspaceMonitor{root: root, cfg: cfg, fd: -1, watches: map[int]string{}, errors: make(chan error, 1), done: make(chan struct{})}
	if err := monitor.reconcile(); err != nil {
		return nil, err
	}
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	monitor.fd = fd
	if err := monitor.addTree(); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := monitor.reconcile(); err != nil {
		unix.Close(fd)
		return nil, err
	}
	go monitor.run()
	return monitor, nil
}

func (m *workspaceMonitor) stop() {
	m.once.Do(func() {
		close(m.done)
		if m.fd >= 0 {
			_ = unix.Close(m.fd)
		}
	})
}

func (m *workspaceMonitor) fail(err error) {
	select {
	case m.errors <- err:
	default:
	}
}

func (m *workspaceMonitor) addTree() error {
	m.makepkgLocked = false
	return filepath.WalkDir(m.root, func(current string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			return nil
		}
		if m.makepkgLockedDirectory(current) {
			m.makepkgLocked = true
			return filepath.SkipDir
		}
		wd, err := unix.InotifyAddWatch(m.fd, current, unix.IN_CREATE|unix.IN_MOVED_TO|unix.IN_DELETE|unix.IN_MOVED_FROM|unix.IN_CLOSE_WRITE|unix.IN_ATTRIB|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF|unix.IN_ONLYDIR)
		if err != nil {
			return fmt.Errorf("watch %s: %w", current, err)
		}
		m.watches[wd] = current
		return nil
	})
}

func transientWorkspaceWatchError(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) || errors.Is(err, unix.ESTALE)
}

func (m *workspaceMonitor) makepkgLockedDirectory(current string) bool {
	// makepkg temporarily makes pkg/ execute-only (0111) while packaging. That
	// expected, caller-owned state is skipped until readable again; other access
	// errors remain accounting failures.
	if current != filepath.Join(m.root, "pkg") {
		return false
	}
	var stat unix.Stat_t
	return unix.Lstat(current, &stat) == nil && stat.Mode&unix.S_IFMT == unix.S_IFDIR &&
		stat.Uid == uint32(os.Geteuid()) && stat.Mode&0o7777 == 0o111 && errors.Is(unix.Access(current, unix.R_OK), unix.EACCES)
}

func (m *workspaceMonitor) reconcile() error {
	deadline := time.Now().Add(workspaceReconcileChangeLimit)
	for {
		err := m.reconcileOnce()
		if !errors.Is(err, errWorkspaceTreeChanging) {
			return err
		}
		if time.Now().After(deadline) {
			return errors.New("workspace tree remained unstable during accounting")
		}
		time.Sleep(workspacePollInterval)
	}
}

func (m *workspaceMonitor) reconcileOnce() error {
	var files int
	var bytes int64
	err := filepath.WalkDir(m.root, func(current string, entry fs.DirEntry, err error) error {
		if err != nil {
			if m.makepkgLockedDirectory(current) {
				return nil
			}
			if transientWorkspaceAccountingError(m.root, current, err) {
				return fmt.Errorf("%w: %v", errWorkspaceTreeChanging, err)
			}
			return err
		}
		if current == m.root {
			return nil
		}
		files++
		if files > m.cfg.WorkspaceFiles {
			return errors.New("workspace file limit exceeded")
		}
		if entry.Type().IsRegular() {
			info, err := entry.Info()
			if err != nil {
				if transientWorkspaceAccountingError(m.root, current, err) {
					return fmt.Errorf("%w: %v", errWorkspaceTreeChanging, err)
				}
				return err
			}
			if info.Size() < 0 || bytes > m.cfg.WorkspaceBytes-info.Size() {
				return errors.New("workspace byte limit exceeded")
			}
			bytes += info.Size()
		}
		return nil
	})
	if err != nil {
		return err
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(m.root, &stat); err != nil {
		return err
	}
	total := int64(stat.Blocks) * stat.Bsize
	available := int64(stat.Bavail) * stat.Bsize
	// Preserve whichever is larger: the configured reserve or 10% of this
	// filesystem. This bounds collateral disk exhaustion outside the workspace.
	reserve := max(m.cfg.DiskReserveBytes, total/10)
	if available < reserve {
		return fmt.Errorf("workspace filesystem reserve violated: available=%d required=%d", available, reserve)
	}
	return nil
}

func transientWorkspaceAccountingError(root, current string, err error) bool {
	if filepath.Clean(current) == filepath.Clean(root) {
		return false
	}
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ESTALE)
}

func (m *workspaceMonitor) run() {
	// Reconcile every 250 ms and poll nonblocking inotify every 25 ms. The short
	// poll catches new directories quickly; the slower full walk prevents missed
	// or coalesced events from becoming an accounting bypass.
	ticker := time.NewTicker(workspaceScanInterval)
	poll := time.NewTicker(workspacePollInterval)
	defer ticker.Stop()
	defer poll.Stop()
	buffer := make([]byte, 64*1024)
	refreshWatches := false
	for {
		select {
		case <-m.done:
			return
		case <-ticker.C:
			if err := m.reconcile(); err != nil {
				m.fail(fmt.Errorf("workspace accounting failed: %w", err))
				return
			}
			// A directory may disappear or briefly deny traversal between its
			// creation event and inotify registration. Rebuild the watch set
			// after the authoritative recursive accounting pass; persistent
			// inaccessible content still fails that pass above.
			if m.makepkgLocked && !m.makepkgLockedDirectory(filepath.Join(m.root, "pkg")) {
				refreshWatches = true
			}
			if refreshWatches {
				if err := m.addTree(); err == nil {
					refreshWatches = false
				} else if !transientWorkspaceWatchError(err) {
					m.fail(fmt.Errorf("cannot refresh workspace watches: %w", err))
					return
				}
			}
		case <-poll.C:
			n, err := unix.Read(m.fd, buffer)
			if err != nil && !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) && !errors.Is(err, unix.EBADF) {
				m.fail(fmt.Errorf("inotify accounting failed: %w", err))
				return
			}
			for offset := 0; offset+unix.SizeofInotifyEvent <= n; {
				// Linux inotify_event stores mask at bytes 4..7 and the trailing
				// name length at bytes 12..15, both in native byte order.
				mask := binary.NativeEndian.Uint32(buffer[offset+4 : offset+8])
				length := int(binary.NativeEndian.Uint32(buffer[offset+12 : offset+16]))
				offset += unix.SizeofInotifyEvent + length
				if mask&unix.IN_Q_OVERFLOW != 0 {
					m.fail(errors.New("inotify accounting queue overflowed"))
					return
				}
				if mask&unix.IN_ISDIR != 0 && mask&(unix.IN_CREATE|unix.IN_MOVED_TO) != 0 {
					if err := m.addTree(); err != nil {
						if !transientWorkspaceWatchError(err) {
							m.fail(fmt.Errorf("cannot watch new workspace directory: %w", err))
							return
						}
						refreshWatches = true
					}
				}
			}
		}
	}
}

type notifyingBuffer struct {
	buffer   *limitedBuffer
	once     sync.Once
	errors   chan<- error
	stream   commandOutputStream
	observer commandOutputObserver
}

func (w *notifyingBuffer) Write(value []byte) (int, error) {
	n, err := w.buffer.Write(value)
	if err != nil {
		w.once.Do(func() { w.errors <- err })
	} else if w.observer != nil && n > 0 {
		w.observer(w.stream, value[:n])
	}
	return n, err
}

type commandOutputStream uint8

const (
	commandStdout commandOutputStream = iota
	commandStderr
)

type commandOutputObserver func(commandOutputStream, []byte)

// outputTranscript records both streams in the order they were observed.
//
// stdout and stderr are captured into separate buffers because some phases
// parse stdout as data, and replaying those two buffers one after the other
// destroys the chronology. makepkg reports progress with msg() on stdout and
// failures with error() on stderr, so a failed build printed "A failure
// occurred in package()" and "Aborting..." several lines *above* "Starting
// build()". Anyone reading that misreads cause and effect, which is the
// opposite of what a diagnostic is for.
//
// The order is the order the copy goroutines delivered, not a guarantee about
// the child's own write order: os/exec drains two pipes concurrently, so two
// writes racing across the two pipes can be observed either way round. It is
// exact enough for reading a build log and is described as observed order
// rather than promised as write order.
//
// It is display-only. The separate buffers remain the source of truth for
// anything that parses output.
type outputTranscript struct {
	mu sync.Mutex
	// buffer keeps the most recent limit bytes. The tail is what matters: a
	// build that failed says why at the end, so discarding the end to preserve
	// the compiler's opening banner would drop the one part worth printing.
	buffer  []byte
	limit   int
	dropped bool
}

// newOutputTranscript bounds the transcript by the total the two streams may
// each produce, so a transcript cannot truncate while both streams are still
// inside their own allowance.
func newOutputTranscript(limit int64) *outputTranscript {
	if limit <= 0 {
		return &outputTranscript{}
	}
	return &outputTranscript{limit: int(limit)}
}

// Observe is called from the stdout and stderr copy goroutines, so it locks.
func (t *outputTranscript) Observe(_ commandOutputStream, value []byte) {
	if t == nil || len(value) == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.limit <= 0 {
		return
	}
	if len(value) >= t.limit {
		// This write alone fills the window; keep its tail.
		t.buffer = append(t.buffer[:0], value[len(value)-t.limit:]...)
		t.dropped = true
		return
	}
	t.buffer = append(t.buffer, value...)
	if len(t.buffer) <= t.limit {
		return
	}
	// Trim only once the buffer has grown a full window past the limit, so the
	// copy is amortised rather than paid on every write past the ceiling.
	if len(t.buffer) >= 2*t.limit {
		t.buffer = append(t.buffer[:0], t.buffer[len(t.buffer)-t.limit:]...)
	}
	t.dropped = true
}

// Bytes returns the observed transcript and whether earlier output was dropped
// to make room. The window is applied on read so that a buffer allowed to grow
// past the limit between trims still returns exactly the most recent bytes.
func (t *outputTranscript) Bytes() ([]byte, bool) {
	if t == nil {
		return nil, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.limit > 0 && len(t.buffer) > t.limit {
		return t.buffer[len(t.buffer)-t.limit:], t.dropped
	}
	return t.buffer, t.dropped
}

func runConstrainedCommand(ctx context.Context, bwrapArgs []string, extraFiles []*os.File, workdir string, cfg Config, observer commandOutputObserver) ([]byte, []byte, SandboxEnforcement, error) {
	// Bubblewrap supplies namespace/filesystem isolation; a transient user-systemd
	// scope supplies cgroup memory, CPU, task, runtime, and whole-process-tree kill
	// semantics. The workspace monitor and bounded output close the remaining
	// resource channels that systemd properties do not model precisely here.
	effective := effectiveBuildLimits(cfg.Build)
	monitor, err := startWorkspaceMonitor(workdir, cfg.Build)
	if err != nil {
		effective.Termination = "workspace-accounting"
		return nil, nil, effective, err
	}
	defer monitor.stop()
	unit, err := contain.ScopeUnit()
	if err != nil {
		return nil, nil, effective, err
	}
	args := contain.ScopeArgs(unit, effective.limits())
	executable, sandboxArgs, err := contain.NamespaceJoiningCommand(bwrapArgs)
	if err != nil {
		effective.Termination = "sandbox-setup"
		return nil, nil, effective, err
	}
	args = append(args, executable)
	args = append(args, sandboxArgs...)
	command := exec.Command("/usr/bin/systemd-run", args...)
	command.ExtraFiles = extraFiles
	// Wait must not outlive the unit: WaitDelay closes the output pipes if a
	// survivor of the cgroup still holds them after the client exits.
	command.WaitDelay = contain.ScopeStopBudget
	overflow := make(chan error, 2)
	stdoutBuffer := newLimitedBuffer(effective.OutputBytes)
	stderrBuffer := newLimitedBuffer(effective.OutputBytes)
	command.Stdout = &notifyingBuffer{buffer: stdoutBuffer, errors: overflow, stream: commandStdout, observer: observer}
	command.Stderr = &notifyingBuffer{buffer: stderrBuffer, errors: overflow, stream: commandStderr, observer: observer}
	if err := command.Start(); err != nil {
		effective.Termination = "systemd-start"
		return nil, nil, effective, err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	// systemd owns the configured RuntimeMaxSec. The outer timer gives it ten
	// seconds to report/collect the stopped unit before enforcing a final kill.
	timer := time.NewTimer(time.Duration(effective.TimeoutSeconds)*time.Second + scopeCollectionGrace)
	defer timer.Stop()
	// Every abandonment path kills the unit and then waits for the systemd-run
	// client under a hard ceiling. An unbounded wait here would let a wedged user
	// manager outlive the timer above, which is the one thing this timer exists
	// to prevent.
	finish := func(termination string, cause error) ([]byte, []byte, SandboxEnforcement, error) {
		effective.Termination = termination
		contain.KillScope(unit)
		if err := contain.AwaitScopeExit(command, done); err != nil {
			// The output copiers may still be writing, so the buffers are not
			// safe to read and are not returned.
			return nil, nil, effective, fmt.Errorf("%w: %w", err, cause)
		}
		return stdoutBuffer.Bytes(), stderrBuffer.Bytes(), effective, cause
	}
	select {
	case err := <-done:
		contain.KillScope(unit)
		if err != nil {
			effective.Termination = "process-exit"
		}
		return stdoutBuffer.Bytes(), stderrBuffer.Bytes(), effective, err
	case err := <-overflow:
		return finish("output-limit", err)
	case err := <-monitor.errors:
		termination := "workspace-accounting"
		if strings.Contains(err.Error(), "workspace byte limit exceeded") ||
			strings.Contains(err.Error(), "workspace file limit exceeded") ||
			strings.Contains(err.Error(), "workspace filesystem reserve violated") {
			termination = "workspace-limit"
		}
		return finish(termination, err)
	case <-timer.C:
		return finish("timeout", errors.New("build sandbox timed out"))
	case <-ctx.Done():
		return finish("cancelled", context.Cause(ctx))
	}
}
