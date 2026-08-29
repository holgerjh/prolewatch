package contain

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/holgerjh/prolewatch/internal/safe"
)

// Limits is the resource envelope a contained command runs under.
//
// Bubblewrap supplies namespace and filesystem isolation; it supplies no
// resource accounting at all. Everything here is enforced by a transient
// systemd user unit: cgroup memory, CPU, task count, wall clock, and
// whole-process-tree kill semantics.
//
// The envelope lives next to the containment it completes so every contained
// caller can use the same resource controls. Keeping one property list avoids
// callers silently omitting part of the envelope.
type Limits struct {
	MemoryBytes    int64
	CPUCount       int
	TasksMax       int
	TimeoutSeconds int
	// FileSizeBytes caps any single file the command writes (RLIMIT_FSIZE).
	FileSizeBytes int64
	// OutputBytes caps captured stdout and stderr, each independently. It is
	// not a systemd property: unbounded output is a memory channel in the
	// supervisor, not in the unit.
	OutputBytes int64
}

func (l Limits) Validate() error {
	if l.MemoryBytes <= 0 || l.CPUCount <= 0 || l.TasksMax <= 0 ||
		l.TimeoutSeconds <= 0 || l.FileSizeBytes <= 0 || l.OutputBytes <= 0 {
		return errors.New("containment limits contain non-positive values")
	}
	return nil
}

// ScopeUnit returns a fresh transient unit name.
//
// Four random bytes add a 32-bit collision-resistant suffix to the PID; it is
// uniqueness, not an authorization secret.
func ScopeUnit() (string, error) {
	random := make([]byte, 4)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return fmt.Sprintf("prolewatch-%d-%x.service", os.Getpid(), random), nil
}

// ScopeArgs renders the systemd-run argument prefix for one transient unit.
//
// KillMode=control-group with SendSIGKILL is what makes the envelope hold
// against a process that forks away from its parent: the whole cgroup dies,
// not just the process that was started.
func ScopeArgs(unit string, limits Limits) []string {
	properties := []string{
		"MemoryMax=" + strconv.FormatInt(limits.MemoryBytes, 10), "MemorySwapMax=0",
		"TasksMax=" + strconv.Itoa(limits.TasksMax),
		"CPUQuota=" + strconv.Itoa(limits.CPUCount*100) + "%",
		"RuntimeMaxSec=" + strconv.Itoa(limits.TimeoutSeconds),
		"LimitFSIZE=" + strconv.FormatInt(limits.FileSizeBytes, 10),
		"KillMode=control-group", "SendSIGKILL=yes", "TimeoutStopSec=5s",
	}
	args := []string{"--user", "--wait", "--collect", "--pipe", "--quiet", "--service-type=exec", "--same-dir", "--unit", unit}
	for _, property := range properties {
		args = append(args, "--property", property)
	}
	return args
}

// ScopeStopBudget bounds every step of talking to the user manager.
//
// The envelope exists to stop package code that will not stop on its own, so
// its own teardown must not become the thing that hangs. Both `systemctl --user`
// and `systemd-run --wait` are clients of the same user manager over the same
// bus; if the manager or the bus wedges, an unbounded call here outlives the
// outer timeout the design promises and the operation never returns.
// It is a var only so tests can shrink it; nothing in the product writes it.
var ScopeStopBudget = 5 * time.Second

// systemctlBinary is a seam for the same reason: a test needs a `systemctl`
// that never returns to show that the budget above is real.
var systemctlBinary = "/usr/bin/systemctl"

// ErrScopeCleanup reports that a unit could not be confirmed stopped inside the
// cleanup budget.
//
// It is deliberately distinct from whatever triggered the stop. The operation is
// over either way, but a cleanup that could not be confirmed means something may
// still be running under the user manager, and that is worth saying rather than
// reporting the original timeout as if the process tree were gone.
var ErrScopeCleanup = errors.New("transient unit could not be confirmed stopped within the cleanup budget")

// systemctlUser runs one bounded `systemctl --user` call.
func systemctlUser(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), ScopeStopBudget)
	defer cancel()
	command := exec.CommandContext(ctx, systemctlBinary, append([]string{"--user"}, args...)...)
	command.WaitDelay = ScopeStopBudget
	return command.Run()
}

// KillScope terminates a transient unit and everything in its cgroup. It is
// idempotent and reports nothing: it runs on paths where the unit has usually
// already exited, and a failure to kill an already-dead unit is not news.
func KillScope(unit string) {
	_ = systemctlUser("kill", "--kill-whom=all", "--signal=KILL", unit)
	_ = systemctlUser("stop", unit)
}

// AwaitScopeExit waits for a killed unit's systemd-run client to return, with a
// hard ceiling.
//
// The client is not the unit. Killing the cgroup ends the contained process
// tree, but `systemd-run --wait` still has to be told so by the user manager,
// and the plain `<-done` this replaces trusted that to happen. It usually does,
// and when it does not there is no later timer: the caller's own timeout has
// already fired, and the operation blocks forever on its own cleanup.
//
// So the client is killed once the budget expires. Its WaitDelay then closes the
// output pipes, because Wait would otherwise block on a descriptor that some
// survivor of the cgroup still holds open.
func AwaitScopeExit(client *exec.Cmd, done <-chan error) error {
	select {
	case <-done:
		return nil
	case <-time.After(ScopeStopBudget):
	}
	if client != nil && client.Process != nil {
		_ = client.Process.Kill()
	}
	select {
	case <-done:
		return nil
	case <-time.After(2 * ScopeStopBudget):
		return ErrScopeCleanup
	}
}

// NamespaceRunnerMarker prefixes an argument list that must join a pre-created
// user namespace before exec'ing Bubblewrap.
const NamespaceRunnerMarker = "--prolewatch-userns"

// NamespaceJoiningCommand renders the argument list into an executable and
// arguments for the transient systemd unit.
//
// Bubblewrap takes the namespace as an open descriptor (--userns FD), and the
// obvious way to supply one is to inherit it into the child. That is not done
// here, because the child is started by systemd-run and inherited descriptors
// do not reliably survive the user manager.
//
// Rather than depend on a property that could not be measured in the
// development environment (no user session bus), the descriptor is opened on
// the far side: a shell inside the unit opens the namespace path and execs
// Bubblewrap with it. Nothing is inherited, so there is nothing to survive.
//
// The path names a /proc entry for a process this code started, and the shell
// receives it as a positional argument rather than interpolated into the
// script, so it is not a place where package-controlled text can reach a shell.
//
// Why by-path is safe, not merely convenient. The obvious worry is a TOCTOU:
// the anchor dies, its PID is recycled, and the unit opens a stranger's
// namespace. That cannot happen. The anchor is a direct child of this process
// and is not reaped until Namespace.Close calls Wait, and an unreaped zombie
// still holds its PID - the kernel cannot recycle a PID whose exit status has
// not been collected. So while this path is in use the PID is ours, and if the
// anchor is already gone the open fails and the script exits 71. Either the
// still-anchored namespace is joined or the unit fails loudly; there is no
// branch that silently joins the wrong namespace.
func NamespaceJoiningCommand(args []string) (string, []string, error) {
	if len(args) == 0 || args[0] != NamespaceRunnerMarker {
		return "/usr/bin/bwrap", args, nil
	}
	if len(args) < 3 || !strings.HasPrefix(args[1], "/proc/") {
		return "", nil, errors.New("invalid namespace launcher arguments")
	}
	script := `exec 3<"$1" || exit 71; shift; exec /usr/bin/bwrap "$@"`
	return "/bin/sh", append([]string{"-c", script, "prolewatch-userns", args[1]}, args[2:]...), nil
}

// UserManagerAvailable reports whether a transient user unit can be started.
//
// The envelope is not optional, so this is a precondition rather than a
// feature test: a system without a user manager cannot run a contained build
// either, and saying so plainly beats surfacing a D-Bus address error from
// three layers down.
func UserManagerAvailable() bool {
	if os.Getenv("XDG_RUNTIME_DIR") == "" && os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		return false
	}
	// Bounded like every other call to the manager: an unreachable one must fail
	// this precondition, not hang the caller before any timeout exists.
	return systemctlUser("--quiet", "is-system-running") == nil ||
		systemctlUser("show", "--property=Version") == nil
}

// ErrNoUserManager is returned when the systemd user manager is unreachable.
var ErrNoUserManager = errors.New("no systemd user manager: the resource envelope cannot be applied " +
	"(a session with XDG_RUNTIME_DIR, or `loginctl enable-linger`, is required)")

// RunLimited runs a contained command inside a transient systemd user unit, so
// that the resource envelope applies to it, and returns its bounded output.
//
// Use this rather than Run for anything that executes package-authored code.
// Run gives a command namespace and filesystem isolation and nothing else: a
// fork bomb, an allocator, or an infinite loop under Run exhausts the host and
// hangs until the user intervenes. The distinction matters most where it is
// least obvious - `makepkg --printsrcinfo` looks like a query and is in fact
// arbitrary shell, because makepkg sources the PKGBUILD on every invocation.
//
// Output is captured into bounded buffers rather than files. Unbounded capture
// is a memory channel in the supervisor, which no systemd property closes.
func RunLimited(ctx context.Context, ns *Namespace, spec Spec, limits Limits) (stdout, stderr []byte, err error) {
	if ns == nil || ns.file == nil {
		return nil, nil, errors.New("contain.RunLimited: no user namespace")
	}
	if err := limits.Validate(); err != nil {
		return nil, nil, err
	}
	if !UserManagerAvailable() {
		return nil, nil, ErrNoUserManager
	}
	const usernsFD = 3
	unit, err := ScopeUnit()
	if err != nil {
		return nil, nil, err
	}
	launcher := append([]string{NamespaceRunnerMarker, ns.Path()}, spec.BwrapArgs(usernsFD)...)
	executable, sandboxArgs, err := NamespaceJoiningCommand(launcher)
	if err != nil {
		return nil, nil, err
	}
	args := append(ScopeArgs(unit, limits), executable)
	args = append(args, sandboxArgs...)

	command := exec.Command("/usr/bin/systemd-run", args...)
	// Wait must not outlive the unit: WaitDelay closes the output pipes if a
	// survivor of the cgroup still holds them after the client exits.
	command.WaitDelay = ScopeStopBudget
	overflow := make(chan error, 2)
	outBuffer := safe.NewLimitedBuffer(limits.OutputBytes)
	errBuffer := safe.NewLimitedBuffer(limits.OutputBytes)
	command.Stdout = &overflowWriter{buffer: outBuffer, errors: overflow}
	command.Stderr = &overflowWriter{buffer: errBuffer, errors: overflow}
	if spec.Stdin != nil {
		command.Stdin = spec.Stdin
	}
	if err := command.Start(); err != nil {
		return nil, nil, fmt.Errorf("transient scope for %s: %w", strings.Join(spec.Argv, " "), err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	// systemd owns the configured RuntimeMaxSec. The outer timer gives it ten
	// seconds to report and collect the stopped unit before a final kill, and
	// covers the case where systemd-run itself never returns.
	timer := time.NewTimer(time.Duration(limits.TimeoutSeconds+10) * time.Second)
	defer timer.Stop()
	finish := func(cause error) ([]byte, []byte, error) {
		KillScope(unit)
		if err := AwaitScopeExit(command, done); err != nil {
			// The output copiers may still be writing, so the buffers are not
			// safe to read and are not returned. Saying the cleanup could not be
			// confirmed matters more here than the captured bytes.
			return nil, nil, fmt.Errorf("%w: %w", err, cause)
		}
		return outBuffer.Bytes(), errBuffer.Bytes(), cause
	}
	select {
	case err := <-done:
		KillScope(unit)
		if err != nil {
			err = fmt.Errorf("contained %s: %w", strings.Join(spec.Argv, " "), err)
		}
		return outBuffer.Bytes(), errBuffer.Bytes(), err
	case err := <-overflow:
		return finish(err)
	case <-ctx.Done():
		return finish(ctx.Err())
	case <-timer.C:
		return finish(fmt.Errorf("contained %s timed out", strings.Join(spec.Argv, " ")))
	}
}

// overflowWriter reports the first overflow on a channel so the caller can kill
// the unit immediately, rather than letting it run on writing into a buffer
// that is silently discarding.
type overflowWriter struct {
	buffer *safe.LimitedBuffer
	errors chan<- error
	failed bool
}

func (w *overflowWriter) Write(value []byte) (int, error) {
	n, err := w.buffer.Write(value)
	if err != nil && !w.failed {
		w.failed = true
		select {
		case w.errors <- err:
		default:
		}
	}
	// The error is swallowed towards os/exec on purpose: reporting it there
	// races the kill and turns a bounded-output stop into an opaque copy error.
	_ = n
	return len(value), nil
}
