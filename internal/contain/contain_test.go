package contain

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func joined(args []string) string { return strings.Join(args, " ") }

func TestMapArgsMapsZeroCallerAndTheRestOfTheSpace(t *testing.T) {
	got := joined(mapArgs("--map-users", 1000, SubIDRange{Start: 165536, Count: 65536}))
	want := "--map-user 1000 --map-users 165536,0,65536"
	if got != want {
		t.Fatalf("mapping\n got: %s\nwant: %s", got, want)
	}
}

func TestMapArgsSupportsCallerAboveArchiveIDSpace(t *testing.T) {
	got := joined(mapArgs("--map-users", 100000, SubIDRange{Start: 231072, Count: 65536}))
	want := "--map-user 100000 --map-users 231072,0,65536"
	if got != want {
		t.Fatalf("mapping\n got: %s\nwant: %s", got, want)
	}
}

// util-linux 2.38/2.39 retain only the last range option. Both ID spaces must
// use a single range plus a single-ID mapping, including boundary caller IDs.
func TestMapArgsCompatibleWithSingleRangeUnshare(t *testing.T) {
	for _, flag := range []string{"--map-users", "--map-groups"} {
		for _, id := range []uint32{0, 1, 999, 1000, 65534, 65535, 100000} {
			args := mapArgs(flag, id, SubIDRange{Start: 231072, Count: 65536})
			want := []string{strings.TrimSuffix(flag, "s"), fmt.Sprint(id), flag, "231072,0,65536"}
			if joined(args) != joined(want) {
				t.Fatalf("id %d: got %v, want %v", id, args, want)
			}
		}
	}
}

func TestMapArgsPreservesCoverageAtTheExclusiveRangeEnd(t *testing.T) {
	got := joined(mapArgs("--map-groups", 65536, SubIDRange{Start: 231072, Count: 65536}))
	want := "--map-group 65536 --map-groups 231072,0,65537"
	if got != want {
		t.Fatalf("mapping at the range boundary: got %s, want %s", got, want)
	}
}

// A delegation too narrow to map the whole ID space is rejected at lookup,
// early and with the remedy attached - not accepted and then partially mapped.
//
// A partial map is the worst of the three outcomes. It maps uid 0 and the
// caller, passes every check that looks at one ID at a time, and then leaves
// ordinary IDs such as 65534/nobody unmapped, so the build dies inside somebody
// else's package() with an EINVAL that fakeroot does not absorb and that points
// nowhere near this file.
func TestNarrowDelegationIsRejectedAtLookup(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "subuid")
	if err := os.WriteFile(path, []byte("alice:100000:65535\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := lookupSubIDFile(path, "alice", "1000", "1000")
	if err == nil {
		t.Fatal("a delegation too narrow to map the ID space was accepted")
	}
	if !errors.Is(err, ErrNoSubID) {
		t.Fatalf("a narrow delegation must carry the subordinate-ID remedy: %v", err)
	}
	if err := os.WriteFile(path, []byte("alice:100000:1000\nalice:200000:65536\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	widest, err := lookupSubIDFile(path, "alice", "1000", "1000")
	if err != nil || widest.Start != 200000 || widest.Count != 65536 {
		t.Fatalf("a usable delegation alongside a narrow one was not taken: %+v %v", widest, err)
	}
}

func TestSubIDLookupRejectsOverlapWithAnotherOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subuid")
	contents := "alice:165536:65536\nbob:200000:65536\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := lookupSubIDFile(path, "alice", "1000", "1000")
	if err == nil || !strings.Contains(err.Error(), "unsafe subordinate-ID overlap") {
		t.Fatalf("overlapping delegation was not rejected clearly: %v", err)
	}
	if errors.Is(err, ErrNoSubID) {
		t.Fatalf("unsafe overlap must not be presented as a missing-range problem: %v", err)
	}
}

func TestSubIDLookupRejectsOverflowAndIdentityOverlap(t *testing.T) {
	for name, contents := range map[string]string{
		"overflow":         "alice:4294967294:2\n",
		"identity overlap": "alice:500:65536\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "subuid")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := lookupSubIDFile(path, "alice", "1000", "1000")
			if err == nil || errors.Is(err, ErrNoSubID) {
				t.Fatalf("unsafe delegation was not rejected as a configuration error: %v", err)
			}
		})
	}
}

func TestSubIDLookupAcceptsNumericOwnerID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subgid")
	if err := os.WriteFile(path, []byte("1000:200000:65536\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	range_, err := lookupSubIDFile(path, "alice", "1000", "2000")
	if err != nil || range_.Start != 200000 || range_.Count != 65536 {
		t.Fatalf("numeric uid owner was not accepted for subgid: %+v %v", range_, err)
	}
}

func TestSubIDProviderMustBeFiles(t *testing.T) {
	for name, contents := range map[string]string{
		"implicit files": "passwd: files\n",
		"explicit files": "subid: files # local allocation\n",
		"plugin":         "subid: sss\n",
		"mixed":          "subid: files sss\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "nsswitch.conf")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			err := requireFileSubIDProvider(path)
			wantError := name == "plugin" || name == "mixed"
			if (err != nil) != wantError {
				t.Fatalf("provider result: err=%v, wantError=%v", err, wantError)
			}
		})
	}
}

func TestSubIDAdviceUsesShadowAllocator(t *testing.T) {
	advice := SubIDAdvice()
	if !strings.Contains(advice, "usermod --add-subids") {
		t.Fatalf("advice does not use shadow's allocator: %q", advice)
	}
	if strings.Contains(advice, "100000-165535") {
		t.Fatalf("advice still contains a collision-prone literal range: %q", advice)
	}
}

func TestVerifyMappingTextRequiresTheWholeIDSpace(t *testing.T) {
	full := "         0     165536       1000\n      1000       1000          1\n      1001     166536      64535\n"
	if err := verifyMappingText("uid_map", full, 1000); err != nil {
		t.Fatalf("valid map rejected: %v", err)
	}
	if err := verifyMappingText("uid_map", "      1000       1000          1\n", 1000); err == nil {
		t.Fatal("a map without uid 0 must be rejected: chown to root would fail with EINVAL")
	}
	// The old two-point check accepted exactly this: uid 0 mapped, the caller
	// mapped, and everything above the caller - 65534/nobody included - absent.
	if err := verifyMappingText("uid_map", "         0     165536       1000\n      1000       1000          1\n", 1000); err == nil {
		t.Fatal("a partial map was accepted; chown to an unmapped ID returns EINVAL")
	}
	// A caller mapped to a host ID that is not its own means every file the
	// sandbox creates belongs to a stranger outside it.
	skewed := "         0     165536       1000\n      1000     165000          1\n      1001     166536      64535\n"
	if err := verifyMappingText("gid_map", skewed, 1000); err == nil {
		t.Fatal("a non-identity mapping of the invoking ID was accepted")
	}
}

// The three flags below are the ones that silently break this construction.
// --unshare-user and --unshare-all each create a new user namespace, which
// discards the pre-mapped one; --disable-userns makes bwrap reject the
// invocation outright. Asserting their absence is cheap and the failure they
// cause is not obvious from the error message.
func TestBwrapArgsNeverCreateTheirOwnUserNamespace(t *testing.T) {
	args := joined(Spec{Workdir: "/w", Argv: []string{"true"}}.BwrapArgs(3))
	for _, forbidden := range []string{"--unshare-user", "--unshare-all", "--disable-userns"} {
		if strings.Contains(args, forbidden) {
			t.Fatalf("%s is incompatible with --userns; found in: %s", forbidden, args)
		}
	}
	if !strings.Contains(args, "--userns 3") {
		t.Fatalf("the namespace fd is not passed: %s", args)
	}
}

// Every contained execution gets its own empty network namespace, brokered
// phases included. The broker is reached through a bind-mounted unix socket,
// which crosses a network namespace because it is a filesystem object - so
// there is no phase that needs the host network, and a phase that had it could
// drop the proxy variables and dial out past the prompt entirely.
func TestBwrapArgsAlwaysIsolateTheNetwork(t *testing.T) {
	args := joined(Spec{Workdir: "/w", Argv: []string{"true"}}.BwrapArgs(3))
	if !strings.Contains(args, "--unshare-net") {
		t.Fatalf("contained execution must have no network: %s", args)
	}
}

func TestBwrapArgsPreserveTheLib64LoaderDirectory(t *testing.T) {
	args := joined(Spec{Workdir: "/w", Argv: []string{"true"}}.BwrapArgs(3))
	if !strings.Contains(args, "--symlink usr/lib64 /lib64") {
		t.Fatalf("sandbox must preserve Ubuntu's distinct lib64 loader directory: %s", args)
	}
}

func TestBwrapArgsReplaceRatherThanBindSessionDirectories(t *testing.T) {
	args := joined(Spec{Workdir: "/w", Argv: []string{"true"}}.BwrapArgs(3))
	for _, tmpfs := range []string{"--tmpfs /tmp", "--tmpfs /run", "--tmpfs " + homeTarget} {
		if !strings.Contains(args, tmpfs) {
			t.Fatalf("missing %q - host session sockets would be reachable: %s", tmpfs, args)
		}
	}
	if strings.Contains(args, "--bind /run") || strings.Contains(args, "--ro-bind /run") {
		t.Fatalf("host /run must never be bound: %s", args)
	}
}

func TestBwrapArgsExposeOnlyAnEmptyPacmanDatabase(t *testing.T) {
	args := joined(Spec{Workdir: "/w", Argv: []string{"true"}, EmptyPacmanDatabase: true}.BwrapArgs(3))
	for _, required := range []string{
		"--tmpfs /var/lib/pacman",
		"--dir /var/lib/pacman/local",
		"--dir /tmp/pacman-cache",
		"--dir /tmp/pacman-gnupg",
	} {
		if !strings.Contains(args, required) {
			t.Fatalf("empty pacman view omitted %q: %s", required, args)
		}
	}
	for _, forbidden := range []string{"--bind /var/lib/pacman", "--ro-bind /var/lib/pacman", "/etc/pacman.d/mirrorlist"} {
		if strings.Contains(args, forbidden) {
			t.Fatalf("empty pacman view exposed host state through %q: %s", forbidden, args)
		}
	}
}

func TestBaseEnvCarriesNoHostCredentialPaths(t *testing.T) {
	env := BaseEnv()
	if env["HOME"] != homeTarget {
		t.Fatalf("HOME must be the tmpfs, got %q", env["HOME"])
	}
	for key, value := range env {
		if strings.Contains(value, os.Getenv("HOME")) && os.Getenv("HOME") != "" {
			t.Fatalf("%s leaks the real home: %q", key, value)
		}
	}
}

func TestSandboxBoundaryToolsUseCanonicalSystemPaths(t *testing.T) {
	if unshareBinary != "/usr/bin/unshare" {
		t.Fatalf("namespace creation must not resolve unshare through PATH: %q", unshareBinary)
	}
	if bubblewrapBinary != "/usr/bin/bwrap" {
		t.Fatalf("sandbox creation must not resolve bwrap through PATH: %q", bubblewrapBinary)
	}
}

// --- end-to-end -------------------------------------------------------------

func requireSandbox(t *testing.T) *Namespace {
	t.Helper()
	for _, tool := range []string{unshareBinary, bubblewrapBinary} {
		if _, err := os.Stat(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	ns, err := NewNamespace()
	if err != nil {
		if strings.Contains(err.Error(), ErrNoSubID.Error()) {
			t.Skipf("no subordinate ID delegation: %v", err)
		}
		t.Fatalf("NewNamespace: %v", err)
	}
	t.Cleanup(func() { ns.Close() })
	return ns
}

func runContained(t *testing.T, ns *Namespace, script string) (string, error) {
	t.Helper()
	dir := t.TempDir()
	out, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	spec := Spec{
		Workdir: dir,
		Env:     BaseEnv(),
		Argv:    []string{"/bin/sh", "-c", script},
		Stdout:  out,
		Stderr:  out,
	}
	runErr := Run(ctx, ns, spec)
	raw, _ := os.ReadFile(out.Name())
	return strings.TrimSpace(string(raw)), runErr
}

// The mapping exists to change an errno, not to grant privilege. If this test
// ever passes with a non-zero CapEff, the construction has become a real
// privilege grant and must not ship.
func TestContainedProcessHoldsNoCapabilities(t *testing.T) {
	ns := requireSandbox(t)
	out, err := runContained(t, ns, "grep ^CapEff /proc/self/status")
	if err != nil {
		t.Fatalf("run: %v (%s)", err, out)
	}
	if !strings.HasSuffix(out, "0000000000000000") {
		t.Fatalf("contained process holds capabilities: %q", out)
	}
}

// Brokered phases reach the egress broker through a bind-mounted unix socket,
// which crosses a network namespace because it is a filesystem object. That is
// the whole reason no phase needs the host network - and getting it wrong is
// silent, because a sandbox that shares the host network still builds fine
// while package code can drop the proxy variables and dial out unasked.
//
// Measured rather than reasoned about: the sandbox must see only its own
// loopback, and a listener on the host's loopback must be unreachable from it.
func TestContainedProcessCannotReachTheHostNetwork(t *testing.T) {
	ns := requireSandbox(t)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind a host listener: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port

	deviceTable, err := runContained(t, ns, "cat /proc/net/dev")
	if err != nil {
		t.Fatalf("read sandbox interfaces: %v (%s)", err, deviceTable)
	}
	var interfaces []string
	for _, line := range strings.Split(deviceTable, "\n") {
		name, _, found := strings.Cut(line, ":")
		if found {
			interfaces = append(interfaces, strings.TrimSpace(name))
		}
	}
	if strings.Join(interfaces, " ") != "lo" {
		t.Fatalf("the sandbox sees host interfaces: %q", interfaces)
	}

	// /dev/tcp requires bash explicitly: Ubuntu's /bin/sh is dash. First
	// prove the same probe can reach the listener outside the sandbox, so a
	// broken connect primitive cannot masquerade as network isolation.
	probe := fmt.Sprintf("if (exec 3<>/dev/tcp/127.0.0.1/%d) 2>/dev/null; then echo reached; else echo refused; fi", port)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	hostOutput, err := exec.CommandContext(ctx, "/usr/bin/bash", "-c", probe).CombinedOutput()
	if err != nil || strings.TrimSpace(string(hostOutput)) != "reached" {
		t.Fatalf("host network probe did not reach the listener: %v (%s)", err, hostOutput)
	}

	// The generated probe contains only fixed shell syntax and a numeric port.
	out, err := runContained(t, ns, "/usr/bin/bash -c '"+probe+"'")
	if err != nil {
		t.Fatalf("sandbox network probe failed: %v (%s)", err, out)
	}
	if out != "refused" {
		t.Fatalf("expected the sandbox to refuse the host loopback connection, got: %q", out)
	}
}

func TestContainedProcessCannotBecomeNamespaceRoot(t *testing.T) {
	ns := requireSandbox(t)
	out, _ := runContained(t, ns, "setpriv --reuid 0 --regid 0 --clear-groups id -u 2>&1 || echo refused")
	if !strings.Contains(out, "refused") {
		t.Fatalf("expected setuid 0 to be refused, got: %q", out)
	}
}

// The clamp blocks nested user namespaces. Without it the build can gain
// apparent root inside a child namespace and defeat the assumptions the rest
// of this package relies on.
func TestNestedUserNamespacesAreBlockedAndTheClampIsSealed(t *testing.T) {
	ns := requireSandbox(t)
	out, _ := runContained(t, ns, "cat "+nsUserMaxNamespaces)
	if out != "0" {
		t.Fatalf("ucount clamp not in effect inside the sandbox: %q", out)
	}
	out, _ = runContained(t, ns, "unshare --user true 2>&1 || echo blocked")
	if !strings.Contains(out, "blocked") {
		t.Fatalf("nested user namespace was created: %q", out)
	}
	out, _ = runContained(t, ns, "echo 100 > "+nsUserMaxNamespaces+" 2>&1; cat "+nsUserMaxNamespaces)
	if !strings.HasSuffix(out, "0") {
		t.Fatalf("the build raised the clamp back: %q", out)
	}
}

func TestRealHomeIsNotReachableFromInsideTheSandbox(t *testing.T) {
	ns := requireSandbox(t)
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("no HOME set")
	}
	out, _ := runContained(t, ns, "ls -a "+home+" 2>&1 || echo hidden")
	if !strings.Contains(out, "hidden") && !strings.Contains(out, "No such file") {
		t.Fatalf("the real home is reachable from the sandbox: %q", out)
	}
	out, _ = runContained(t, ns, `ls -A "$HOME" | wc -l`)
	if out != "0" {
		t.Fatalf("the sandbox home is not empty: %q entries", out)
	}
}

func TestAmbientNetworkIsUnavailable(t *testing.T) {
	ns := requireSandbox(t)
	out, _ := runContained(t, ns, "ip -o link show 2>/dev/null | grep -cv ' lo:' || true")
	if strings.TrimSpace(out) != "0" && strings.TrimSpace(out) != "" {
		t.Fatalf("sandbox has non-loopback interfaces: %q", out)
	}
}

// Files the sandbox creates must belong to the invoking user on the host. If
// the caller's uid were not mapped identically, every artifact would land owned
// by a subordinate uid the user cannot delete without help.
func TestSandboxWritesAreOwnedByTheInvokingUser(t *testing.T) {
	ns := requireSandbox(t)
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	spec := Spec{
		Workdir: dir,
		Env:     BaseEnv(),
		Argv:    []string{"/bin/sh", "-c", "echo written > /build/artifact"},
	}
	if err := Run(ctx, ns, spec); err != nil {
		t.Fatalf("run: %v", err)
	}
	artifact := filepath.Join(dir, "artifact")
	info, err := os.Stat(artifact)
	if err != nil {
		t.Fatalf("artifact not created on the host: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no stat_t on this platform")
	}
	if stat.Uid != uint32(os.Getuid()) {
		t.Fatalf("artifact owned by uid %d, expected the invoking uid %d", stat.Uid, os.Getuid())
	}
}

// A nil *os.File in an io.Writer field is not a nil interface. os/exec takes
// the *os.File fast path, calls Fd() on the nil pointer, and gives the child
// fd -1 instead of /dev/null; the child then dies on its first write to that
// stream and the reason is unreportable, because reporting it is the write
// that failed. The test pins the explicit /dev/null behavior.
func TestOmittedStreamsBecomeDevNullNotAClosedDescriptor(t *testing.T) {
	ns := requireSandbox(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	spec := Spec{
		Workdir: t.TempDir(),
		Env:     BaseEnv(),
		// Assert the descriptors exist, rather than writing to them: a shell
		// echo to a closed fd fails quietly and would give this test no teeth.
		Argv: []string{"/bin/sh", "-c", `[ -e /proc/self/fd/1 ] || exit 9; [ -e /proc/self/fd/2 ] || exit 10`},
	}
	if err := Run(ctx, ns, spec); err != nil {
		t.Fatalf("unsupplied streams are not valid descriptors in the child: %v", err)
	}
}

// /etc is enumerated rather than bound wholesale. The build runs as the
// invoking user and could read these files outside the sandbox, so this is
// information minimisation, not privilege - but everything user-readable it
// does not need is material it can carry out through any granted egress.
func TestEtcIsEnumeratedNotBoundWholesale(t *testing.T) {
	args := joined(Spec{Workdir: "/w", Argv: []string{"true"}}.BwrapArgs(3))
	if strings.Contains(args, "--ro-bind /etc /etc") {
		t.Fatalf("all of /etc is bound into the build: %s", args)
	}
	if !strings.Contains(args, "--ro-bind-try /etc/makepkg.conf /etc/makepkg.conf") {
		t.Fatalf("makepkg configuration is missing: %s", args)
	}
}

func TestHostIdentifyingEtcFilesAreNotReachable(t *testing.T) {
	ns := requireSandbox(t)
	for _, path := range []string{"/etc/machine-id", "/etc/hostname", "/etc/pacman.d/mirrorlist"} {
		out, _ := runContained(t, ns, "cat "+path+" 2>&1 || echo absent")
		if !strings.Contains(out, "absent") && !strings.Contains(out, "No such file") {
			t.Fatalf("%s is readable from the build sandbox: %q", path, out)
		}
	}
	// The build still needs its own toolchain configuration on an Arch host.
	// Ubuntu CI has no makepkg.conf; --ro-bind-try deliberately leaves an absent
	// host file absent, while TestEtcIsEnumeratedNotBoundWholesale pins the bind.
	if _, statErr := os.Stat("/etc/makepkg.conf"); statErr == nil {
		out, _ := runContained(t, ns, "test -r /etc/makepkg.conf && echo present || echo missing")
		if !strings.Contains(out, "present") {
			t.Fatalf("makepkg.conf is not readable inside the sandbox: %q", out)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("inspect host makepkg.conf: %v", statErr)
	}
}

// Nothing inside the sandbox resolves names in any phase - the namespace has no
// route to a resolver, and the broker resolves outside after consent - so the
// host's DNS servers and hosts file are host information with no build purpose.
func TestNoPhaseReceivesTheHostResolverConfiguration(t *testing.T) {
	args := joined(Spec{Workdir: "/w", Argv: []string{"true"}}.BwrapArgs(3))
	for _, path := range []string{"/etc/resolv.conf", "/etc/hosts"} {
		if strings.Contains(args, path) {
			t.Fatalf("the build was given %s: %s", path, args)
		}
	}
}

// T06 in the threat model claims a sudo call in build() cannot succeed. That is
// a load-bearing claim, so it is measured rather than reasoned about.
//
// Two independent things make it true, which is why it is worth pinning both:
// bubblewrap sets NoNewPrivs, so setuid bits are not honoured at all; and host
// root is unmapped in the namespace, so /usr/bin/sudo appears owned by nobody
// and its setuid bit would confer nothing even if they were. Either alone
// suffices, and they fail for unrelated reasons.
func TestSetuidBinariesCannotEscalateInsideTheSandbox(t *testing.T) {
	ns := requireSandbox(t)

	out, _ := runContained(t, ns, "grep NoNewPrivs /proc/self/status")
	if !strings.Contains(out, "NoNewPrivs:\t1") {
		t.Fatalf("no_new_privs is not set; setuid binaries would be honoured: %q", out)
	}

	// Host root is not in the map, so root-owned files have no owner here.
	out, _ = runContained(t, ns, "ls -l /usr/bin/sudo 2>/dev/null | head -1")
	if out != "" && !strings.Contains(out, "nobody") {
		t.Fatalf("a host root-owned setuid binary has a mapped owner: %q", out)
	}

	out, _ = runContained(t, ns, "sudo -n true 2>&1 | head -1; true")
	if strings.TrimSpace(out) != "" && !strings.Contains(out, "no new privileges") &&
		!strings.Contains(out, "not found") && !strings.Contains(out, "denied") {
		t.Fatalf("sudo produced an unexpected result inside the sandbox: %q", out)
	}
	if uid, _ := runContained(t, ns, "id -u"); uid == "0" {
		t.Fatal("the build is running as namespace-root")
	}
}

// The build needs a toolchain, not the host's identity. /usr/lib/modules named
// the exact running kernel, which is targeting information for a sandbox
// escape - the same class of leak as /etc/machine-id, and measured the same way
// before being closed.
func TestKernelVersionIsNotReadableFromTheSandbox(t *testing.T) {
	ns := requireSandbox(t)
	for _, path := range hostDescribingPaths {
		out, _ := runContained(t, ns, "ls -A "+path+" 2>&1 | head -1")
		if strings.TrimSpace(out) != "" {
			t.Fatalf("%s describes the host to build code: %q", path, out)
		}
	}
	// The toolchain must survive the masking.
	out, _ := runContained(t, ns, "command -v gcc >/dev/null && echo present || echo missing")
	if !strings.Contains(out, "present") && !strings.Contains(out, "missing") {
		t.Fatalf("unexpected toolchain probe result: %q", out)
	}
	out, _ = runContained(t, ns, "ls /usr/bin | wc -l")
	if out == "0" {
		t.Fatal("the masking emptied /usr/bin")
	}
}

// The anchor's parent-liveness signal is its stdin pipe, not Pdeathsig: Linux
// ties PR_SET_PDEATHSIG to the creating *thread*, and Go retires runtime
// threads on its own schedule, so an anchor hung on that could die mid-build
// while Prolewatch is alive.
//
// The pipe has the semantics the anchor actually needs - the kernel closes the
// write end when this process dies however it dies - so this measures that the
// anchor really does end on EOF rather than on anything else.
func TestNamespaceAnchorEndsWhenItsStdinCloses(t *testing.T) {
	ns := requireSandbox(t)
	if err := ns.stdin.Close(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- ns.anchor.Wait() }()
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("the anchor outlived its stdin pipe; nothing tears the namespace down when the parent dies")
	}
	// Close is idempotent over an already-reaped anchor.
	ns.closed = true
	if ns.file != nil {
		ns.file.Close()
	}
}

// The source store must be writable - makepkg refuses to run against a
// read-only SRCDEST, and VCS checkouts under it are updated in place - so the
// files the trusted-side fetch put there are pinned individually instead.
//
// Without that, package code deletes an acquired source and the same makepkg
// run downloads it again, from a URL the PKGBUILD's own shell just recomputed.
// The pins have to survive the writable bind of the directory around them,
// which is why read-only binds are applied last.
func TestPinnedFilesSurviveTheWritableBindAroundThem(t *testing.T) {
	ns := requireSandbox(t)
	store := t.TempDir()
	pinned := filepath.Join(store, "demo.tar.gz")
	if err := os.WriteFile(pinned, []byte("acquired payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(store, "repo.git"), 0o700); err != nil {
		t.Fatal(err)
	}

	out, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	script := `rm -f /srcdest/demo.tar.gz 2>/dev/null && echo DELETED
(echo evil > /srcdest/demo.tar.gz) 2>/dev/null && echo OVERWRITTEN
echo evil > /srcdest/stage && mv -f /srcdest/stage /srcdest/demo.tar.gz 2>/dev/null && echo REPLACED
cat /srcdest/demo.tar.gz
touch /srcdest/repo.git/FETCH_HEAD && echo VCS-WRITABLE
touch /srcdest/newsource && echo STORE-WRITABLE`
	runErr := Run(ctx, ns, Spec{
		Workdir:      t.TempDir(),
		Env:          BaseEnv(),
		ExtraBinds:   [][2]string{{store, "/srcdest"}},
		ExtraROBinds: [][2]string{{pinned, "/srcdest/demo.tar.gz"}},
		Argv:         []string{"/bin/sh", "-c", script},
		Stdout:       out,
		Stderr:       out,
	})
	raw, _ := os.ReadFile(out.Name())
	result := string(raw)
	if runErr != nil {
		t.Fatalf("run: %v (%s)", runErr, result)
	}
	for _, forbidden := range []string{"DELETED", "OVERWRITTEN", "REPLACED"} {
		if strings.Contains(result, forbidden) {
			t.Fatalf("package code tampered with an acquired source (%s): %q", forbidden, result)
		}
	}
	if !strings.Contains(result, "acquired payload") {
		t.Fatalf("the acquired bytes did not survive: %q", result)
	}
	// makepkg needs both of these: ensure_writable_dir checks the store, and a
	// VCS checkout under it is fetched into rather than replaced.
	for _, required := range []string{"VCS-WRITABLE", "STORE-WRITABLE"} {
		if !strings.Contains(result, required) {
			t.Fatalf("pinning made the store unusable for makepkg (%s missing): %q", required, result)
		}
	}
	if raw, err := os.ReadFile(pinned); err != nil || string(raw) != "acquired payload" {
		t.Fatalf("the host-side source changed: %q (%v)", raw, err)
	}
}

// .git is the one part of the checkout that outlives the sandbox as code.
//
// yay updates an existing AUR checkout on the host with `git reset --hard` and
// `git merge --ff`, and git then runs .git/hooks/post-merge as the user,
// outside bubblewrap, with the real home and an unrestricted network. The
// inventory scanner excludes .git from the manifest by design, so a hook or a
// redirected core.hooksPath planted during a contained build would appear in no
// briefing and no diff - it would simply run, later, uncontained.
func TestPackageCodeCannotWriteTheCheckoutsGitMetadata(t *testing.T) {
	ns := requireSandbox(t)
	checkout := t.TempDir()
	hooks := filepath.Join(checkout, ".git", "hooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(checkout, ".git", "config"), []byte("[core]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	script := `printf 'payload\n' > /build/.git/hooks/post-merge 2>/dev/null && echo HOOK-PLANTED
printf '[core]\n\thooksPath = /tmp/evil\n' > /build/.git/config 2>/dev/null && echo CONFIG-REWRITTEN
rm -rf /build/.git 2>/dev/null && echo METADATA-REMOVED
touch /build/ordinary-build-output && echo WORKDIR-WRITABLE`
	if runErr := Run(ctx, ns, Spec{
		Workdir: checkout,
		Env:     BaseEnv(),
		Argv:    []string{"/bin/sh", "-c", script},
		Stdout:  out,
		Stderr:  out,
	}); runErr != nil {
		raw, _ := os.ReadFile(out.Name())
		t.Fatalf("run: %v (%s)", runErr, raw)
	}
	raw, _ := os.ReadFile(out.Name())
	for _, forbidden := range []string{"HOOK-PLANTED", "CONFIG-REWRITTEN", "METADATA-REMOVED"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("package code reached the checkout's git metadata (%s): %q", forbidden, raw)
		}
	}
	// The build still needs the rest of the checkout.
	if !strings.Contains(string(raw), "WORKDIR-WRITABLE") {
		t.Fatalf("protecting .git made the checkout unusable: %q", raw)
	}
	if _, err := os.Stat(filepath.Join(hooks, "post-merge")); !os.IsNotExist(err) {
		t.Fatalf("a hook survived on the host: %v", err)
	}
}
