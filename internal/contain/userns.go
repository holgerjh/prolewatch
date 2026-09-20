package contain

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// nsUserMaxNamespaces is the ucount that caps how many user namespaces may be
// created by processes in a given user namespace. Clamping it to zero inside
// the build's namespace restores the property bwrap's --disable-userns would
// have given, which cannot be used here because bwrap rejects it without
// --unshare-user and that is mutually exclusive with --userns.
const (
	nsUserMaxNamespaces = "/proc/sys/user/max_user_namespaces"
	unshareBinary       = "/usr/bin/unshare"
)

// anchorScript runs as namespace-uid 0 inside the freshly created user
// namespace. It exists for exactly two reasons: to apply the ucount clamp
// while it still holds capabilities, and to keep the namespace alive.
//
// It requires unshare --setuid 0. Without it the anchor keeps the caller's own
// uid - which the map sends to itself - and the clamp write fails with EACCES,
// looking exactly like the "belongs to the initial namespace" story below.
//
// The clamp MUST be written from ns-uid 0. A process whose namespace-euid is
// non-zero drops all capabilities at execve - the same mechanism that leaves
// the build itself with an empty CapEff - and the write then fails with EACCES.
// user.* ucounts are per user namespace, and procfs resolves them against the
// opener's namespace.
//
// The final `exec cat >/dev/null` blocks on stdin and exits on EOF, so closing
// the pipe from Go tears the namespace down deterministically. There is no
// sleep and no poll: the readiness line on stdout is the synchronisation point.
//
// Namespace-root is given up as soon as the clamp is applied. The anchor has no
// further need for capabilities, and a process holding a full ns capability set
// for the lifetime of the build is a standing target that costs nothing to
// remove. The build cannot reach it in any case - bwrap gives it a separate PID
// namespace - so this is defence in depth, not a load-bearing control.
func anchorScript(uid, gid uint32) string {
	return fmt.Sprintf(`set -u
if ! echo 0 > %[1]s 2>/dev/null; then
  echo "clamp-write-failed" >&2
  exit 3
fi
read_back=$(cat %[1]s 2>/dev/null || echo unreadable)
if [ "$read_back" != 0 ]; then
  echo "clamp-readback=$read_back" >&2
  exit 4
fi
echo ready
if command -v setpriv >/dev/null 2>&1; then
  exec setpriv --reuid %[2]d --regid %[3]d --clear-groups cat > /dev/null
fi
exec cat > /dev/null
`, nsUserMaxNamespaces, uid, gid)
}

// Namespace is a live user namespace with uid 0 mapped, held open by an anchor
// process. Bubblewrap joins it with --userns rather than creating its own.
//
// The build never runs as namespace-root. The uid 0 mapping exists so that
// chown(2) to an unmapped id fails with EPERM - which libfakeroot absorbs into
// its ownership database - instead of EINVAL, which it does not.
// probe-namespace-properties.sh measures that the mapping confers nothing else:
// CapEff is zero, setpriv --reuid 0 fails, a real chown outside fakeroot still
// fails, and every file the sandbox creates is owned by the invoking uid.
type Namespace struct {
	file   *os.File // /proc/<anchor>/ns/user, passed to bwrap as --userns
	anchor *exec.Cmd
	stdin  io.WriteCloser
	closed bool
}

// mapArgs maps the archive ID space and preserves the caller's own identity.
//
// The whole archive ID space is mapped, not just uid 0. Mapping only uid 0 and
// the caller leaves every other id - notably 65534/nobody - unmapped, and a
// chown to an unmapped id returns EINVAL, which escapes fakeroot.
// probe-stream-filter.sh carries the same mapping and explains how a partial
// map presents as an ownership failure.
//
// Mapping an id does not grant the ability to chown to it. It converts an
// EINVAL that escapes fakeroot into an EPERM that fakeroot swallows, and
// nothing more.
func mapArgs(flag string, id uint32, sub SubIDRange) []string {
	// Before util-linux 2.40, repeated range options silently replace one
	// another. Use one range and let unshare carve out the caller's single-ID
	// mapping. If the caller lies within the range, this consumes one fewer
	// subordinate ID while still covering every namespace ID in that range.
	// The older outer,inner,count syntax also works with util-linux 2.38.
	count := min(sub.Count, uint32(idSpace))
	// unshare also carves a hole when the single ID equals the exclusive
	// range end. Include that ID explicitly so ID 65535 stays mapped when
	// the invoking UID or GID is 65536. The extra slot uses the caller's ID,
	// not an additional subordinate ID.
	if id == count {
		count++
	}
	return []string{
		strings.TrimSuffix(flag, "s"), fmt.Sprint(id),
		flag, fmt.Sprintf("%d,0,%d", sub.Start, count),
	}
}

// NewNamespace creates the mapped user namespace and applies the ucount clamp.
// The caller must Close it once the contained work is finished.
func NewNamespace() (*Namespace, error) {
	uidRange, gidRange, err := LookupSubIDs()
	if err != nil {
		return nil, err
	}
	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())

	args := []string{"--user"}
	args = append(args, mapArgs("--map-users", uid, uidRange)...)
	args = append(args, mapArgs("--map-groups", gid, gidRange)...)
	// --setuid 0 is what makes the anchor namespace-root, and it is required:
	// capabilities are dropped at execve for any process whose namespace-euid is
	// non-zero, and the clamp write then fails.
	args = append(args, "--setuid", "0", "--setgid", "0")
	args = append(args, "--", "/bin/sh", "-c", anchorScript(uid, gid))

	// Resolve the namespace tool independently of the invoking user's PATH.
	// This command runs before Bubblewrap exists, so a PATH-selected replacement
	// would otherwise execute with direct access to the user's host session.
	anchor := exec.Command(unshareBinary, args...)
	anchor.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	stdin, err := anchor.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("anchor stdin: %w", err)
	}
	stdout, err := anchor.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("anchor stdout: %w", err)
	}
	var stderr strings.Builder
	anchor.Stderr = &stderr
	// The anchor must not survive as an orphan if Prolewatch is killed, and the
	// stdin pipe above is what guarantees that: the anchor's last exec is
	// `cat`, blocked on stdin, and the kernel closes the write end when this
	// process dies however it dies. EOF, exit, namespace gone.
	//
	// Pdeathsig is deliberately not used for this. Linux ties PR_SET_PDEATHSIG
	// to the lifetime of the *creating thread*, not the process, and Go retires
	// runtime threads on its own schedule - so the anchor could be killed mid
	// build while Prolewatch is perfectly alive, surfacing as a sporadic
	// namespace failure rather than as anything a reader would connect to this
	// line. Holding the OS thread for the anchor's whole lifetime would be the
	// only correct way to keep it, and the pipe already does the job.

	if err := anchor.Start(); err != nil {
		return nil, fmt.Errorf("start namespace anchor (unshare): %w", err)
	}
	ns := &Namespace{anchor: anchor, stdin: stdin}

	if err := waitReady(stdout); err != nil {
		ns.Close()
		return nil, annotateAnchorFailure(err, stderr.String())
	}
	nsPath := fmt.Sprintf("/proc/%d/ns/user", anchor.Process.Pid)
	file, err := os.Open(nsPath)
	if err != nil {
		ns.Close()
		return nil, fmt.Errorf("open %s: %w", nsPath, err)
	}
	ns.file = file

	if err := ns.verifyMapping(uid, gid); err != nil {
		ns.Close()
		return nil, err
	}
	return ns, nil
}

// waitReady blocks until the anchor reports that the clamp is applied and
// verified, or until it exits without doing so.
func waitReady(stdout io.Reader) error {
	type result struct{ err error }
	done := make(chan result, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if strings.TrimSpace(scanner.Text()) == "ready" {
				done <- result{nil}
				return
			}
		}
		if err := scanner.Err(); err != nil {
			done <- result{err}
			return
		}
		done <- result{errors.New("namespace anchor exited before reporting ready")}
	}()
	select {
	case r := <-done:
		return r.err
	case <-time.After(15 * time.Second):
		return errors.New("namespace anchor did not report ready within 15s")
	}
}

// annotateAnchorFailure turns the anchor's terse exit into something a user can
// act on. These are the failures seen in practice, and each has a distinct
// remedy, so they must not collapse into one opaque message.
func annotateAnchorFailure(err error, stderr string) error {
	switch {
	case strings.Contains(stderr, "unrecognized option") && strings.Contains(stderr, "map-users"):
		return fmt.Errorf("unshare(1) does not support --map-users; util-linux 2.38 or newer is required: %w", err)
	case strings.Contains(stderr, "newuidmap") || strings.Contains(stderr, "newgidmap"):
		return fmt.Errorf("newuidmap/newgidmap failed - check the /etc/subuid and /etc/subgid delegation: %s: %w", strings.TrimSpace(stderr), err)
	case strings.Contains(stderr, "clamp-write-failed"):
		return fmt.Errorf("could not clamp %s inside the namespace; refusing to build without nested-namespace blocking: %w", nsUserMaxNamespaces, err)
	case strings.Contains(stderr, "clamp-readback="):
		return fmt.Errorf("the %s clamp did not take effect (%s); refusing to build: %w", nsUserMaxNamespaces, strings.TrimSpace(stderr), err)
	case strings.TrimSpace(stderr) != "":
		return fmt.Errorf("namespace anchor failed: %s: %w", strings.TrimSpace(stderr), err)
	}
	return fmt.Errorf("namespace anchor failed: %w", err)
}

// verifyMappingText reads back the kernel's own view of one mapping rather than
// trusting that unshare(1) applied what it was asked for. A silently partial
// map is the failure mode that presents as an unrelated ownership bug three
// layers up, so it is checked here where it is cheap to diagnose.
//
// The whole ID space is checked, not two sample points. Spot-checking ns-ID 0
// and the caller was the version of this check that a narrow delegation walked
// straight through: both points map, everything between the caller and 65535
// does not, and the first chown to 65534/nobody inside package() fails with an
// EINVAL that fakeroot passes on unchanged.
func verifyMappingText(kind, text string, id uint32) error {
	type span struct{ nsStart, hostStart, count uint64 }
	var spans []span
	for _, line := range strings.Split(text, "\n") {
		var parsed span
		if _, err := fmt.Sscanf(strings.TrimSpace(line), "%d %d %d", &parsed.nsStart, &parsed.hostStart, &parsed.count); err != nil || parsed.count == 0 {
			continue
		}
		spans = append(spans, parsed)
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].nsStart < spans[j].nsStart })
	// covered is the lowest namespace ID not yet shown to be mapped. Walking the
	// sorted spans stops at the first gap, which is the ID worth naming.
	var covered uint64
	for _, parsed := range spans {
		if parsed.nsStart > covered {
			break
		}
		if end := parsed.nsStart + parsed.count; end > covered {
			covered = end
		}
	}
	if covered < idSpace {
		return fmt.Errorf("namespace %s maps only %d of %d IDs; the first unmapped ID is %d, and chown to an unmapped ID returns EINVAL, which fakeroot does not absorb",
			kind, covered, idSpace, covered)
	}
	for _, parsed := range spans {
		if uint64(id) < parsed.nsStart || uint64(id)-parsed.nsStart >= parsed.count {
			continue
		}
		// The caller's own ID must map to itself, or files the sandbox creates
		// belong to a stranger on the host.
		if host := parsed.hostStart + (uint64(id) - parsed.nsStart); host != uint64(id) {
			return fmt.Errorf("namespace %s maps the invoking ID %d to host ID %d rather than to itself", kind, id, host)
		}
		return nil
	}
	return fmt.Errorf("namespace %s does not map the invoking ID %d", kind, id)
}

// verifyMapping checks both maps. gid_map is not a formality: package() runs
// under fakeroot, `install -g root` goes through the group map, and a gid_map
// that unshare(1) applied differently fails in exactly the same misleading way
// as a partial uid_map.
func (n *Namespace) verifyMapping(uid, gid uint32) error {
	for _, mapping := range []struct {
		kind string
		id   uint32
	}{{"uid_map", uid}, {"gid_map", gid}} {
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/%s", n.anchor.Process.Pid, mapping.kind))
		if err != nil {
			return fmt.Errorf("read namespace %s: %w", mapping.kind, err)
		}
		if err := verifyMappingText(mapping.kind, string(raw), mapping.id); err != nil {
			return err
		}
	}
	return nil
}

// Close tears the namespace down. Closing the anchor's stdin is the ordinary
// path; the kill is the backstop.
func (n *Namespace) Close() error {
	if n == nil || n.closed {
		return nil
	}
	n.closed = true
	if n.file != nil {
		n.file.Close()
	}
	if n.stdin != nil {
		n.stdin.Close()
	}
	if n.anchor != nil && n.anchor.Process != nil {
		done := make(chan struct{})
		go func() { n.anchor.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			n.anchor.Process.Kill()
			<-done
		}
	}
	return nil
}

// Path is the procfs path of the namespace, for callers that must open it
// themselves rather than inherit the descriptor.
func (n *Namespace) Path() string {
	if n == nil || n.anchor == nil || n.anchor.Process == nil {
		return ""
	}
	return fmt.Sprintf("/proc/%d/ns/user", n.anchor.Process.Pid)
}
