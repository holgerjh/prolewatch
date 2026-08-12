package audit

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type SandboxEnforcement struct {
	MemoryBytes    int64              `json:"memory_bytes"`
	CPUCount       int                `json:"cpu_count"`
	TasksMax       int                `json:"tasks_max"`
	TimeoutSeconds int                `json:"timeout_seconds"`
	WorkspaceBytes int64              `json:"workspace_bytes"`
	WorkspaceFiles int                `json:"workspace_files"`
	OutputBytes    int64              `json:"output_bytes"`
	NetworkPolicy  string             `json:"network_policy"`
	Termination    string             `json:"termination,omitempty"`
	CleanRoot      *CleanRootManifest `json:"clean_root"`
}

func (s SandboxEnforcement) Validate() error {
	if s.MemoryBytes <= 0 || s.CPUCount <= 0 || s.TasksMax <= 0 || s.TimeoutSeconds <= 0 ||
		s.WorkspaceBytes <= 0 || s.WorkspaceFiles <= 0 || s.OutputBytes <= 0 {
		return errors.New("sandbox enforcement contains non-positive limits")
	}
	if s.NetworkPolicy != "isolated" && s.NetworkPolicy != "public-web-broker" {
		return errors.New("sandbox enforcement has an invalid network policy")
	}
	if s.CleanRoot != nil && s.CleanRoot.Validate() != nil {
		return errors.New("sandbox enforcement has an invalid clean-root manifest")
	}
	validTermination := map[string]bool{"": true, "sandbox-setup": true, "workspace-accounting": true, "systemd-start": true, "process-exit": true, "output-limit": true, "workspace-limit": true, "timeout": true}
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
		time.Sleep(25 * time.Millisecond)
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
	ticker := time.NewTicker(250 * time.Millisecond)
	poll := time.NewTicker(25 * time.Millisecond)
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

func runConstrainedCommand(bwrapArgs []string, extraFiles []*os.File, workdir string, cfg Config, activity *ActivityRecorder, observer commandOutputObserver) ([]byte, []byte, SandboxEnforcement, error) {
	effective := effectiveBuildLimits(cfg.Build)
	monitor, err := startWorkspaceMonitor(workdir, cfg.Build)
	if err != nil {
		effective.Termination = "workspace-accounting"
		return nil, nil, effective, err
	}
	defer monitor.stop()
	random := make([]byte, 4)
	if _, err := rand.Read(random); err != nil {
		return nil, nil, effective, err
	}
	unit := fmt.Sprintf("prolewatch-%d-%x.service", os.Getpid(), random)
	properties := []string{
		"MemoryMax=" + strconv.FormatInt(effective.MemoryBytes, 10), "MemorySwapMax=0",
		"TasksMax=" + strconv.Itoa(effective.TasksMax), "CPUQuota=" + strconv.Itoa(effective.CPUCount*100) + "%",
		"RuntimeMaxSec=" + strconv.Itoa(effective.TimeoutSeconds), "LimitFSIZE=" + strconv.FormatInt(effective.WorkspaceBytes, 10),
		"KillMode=control-group", "SendSIGKILL=yes", "TimeoutStopSec=5s",
	}
	args := []string{"--user", "--wait", "--collect", "--pipe", "--quiet", "--service-type=exec", "--same-dir", "--unit", unit}
	for _, property := range properties {
		args = append(args, "--property", property)
	}
	args = append(args, "/usr/bin/bwrap")
	args = append(args, bwrapArgs...)
	command := exec.Command("/usr/bin/systemd-run", args...)
	command.ExtraFiles = extraFiles
	overflow := make(chan error, 2)
	stdoutBuffer := newLimitedBuffer(effective.OutputBytes)
	stderrBuffer := newLimitedBuffer(effective.OutputBytes)
	command.Stdout = &notifyingBuffer{buffer: stdoutBuffer, errors: overflow, stream: commandStdout, observer: observer}
	command.Stderr = &notifyingBuffer{buffer: stderrBuffer, errors: overflow, stream: commandStderr, observer: observer}
	if err := command.Start(); err != nil {
		effective.Termination = "systemd-start"
		return nil, nil, effective, err
	}
	if activity != nil {
		activity.update(func(value *Activity) {
			value.Stage = StageSandboxExecution
			value.Containment.SandboxState = "running"
		})
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	timer := time.NewTimer(time.Duration(effective.TimeoutSeconds+10) * time.Second)
	defer timer.Stop()
	killUnit := func() {
		_ = exec.Command("/usr/bin/systemctl", "--user", "kill", "--kill-whom=all", "--signal=KILL", unit).Run()
		_ = exec.Command("/usr/bin/systemctl", "--user", "stop", unit).Run()
	}
	select {
	case err := <-done:
		killUnit()
		if err != nil {
			effective.Termination = "process-exit"
		}
		return stdoutBuffer.Bytes(), stderrBuffer.Bytes(), effective, err
	case err := <-overflow:
		effective.Termination = "output-limit"
		killUnit()
		<-done
		return stdoutBuffer.Bytes(), stderrBuffer.Bytes(), effective, err
	case err := <-monitor.errors:
		effective.Termination = "workspace-accounting"
		if strings.Contains(err.Error(), "workspace byte limit exceeded") ||
			strings.Contains(err.Error(), "workspace file limit exceeded") ||
			strings.Contains(err.Error(), "workspace filesystem reserve violated") {
			effective.Termination = "workspace-limit"
		}
		killUnit()
		<-done
		return stdoutBuffer.Bytes(), stderrBuffer.Bytes(), effective, err
	case <-timer.C:
		effective.Termination = "timeout"
		killUnit()
		<-done
		return stdoutBuffer.Bytes(), stderrBuffer.Bytes(), effective, errors.New("build sandbox timed out")
	}
}
