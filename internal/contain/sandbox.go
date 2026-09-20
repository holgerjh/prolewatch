package contain

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Spec describes one contained execution. Every field is deliberately explicit:
// the sandbox composes nothing from ambient state, so what a reviewer reads
// here is what the untrusted code gets.
type Spec struct {
	// Workdir is bound read-write at WorkdirTarget and is, by default, the only
	// writable path that survives the sandbox.
	Workdir       string
	WorkdirTarget string

	// ExtraBinds are additional read-write binds. Each entry is {host, target}.
	// Kept separate from Workdir so that "what can this write" stays a single
	// short list at every call site.
	ExtraBinds [][2]string

	// ExtraROBinds are additional read-only binds, {host, target}. They are
	// applied after ExtraBinds, so a read-only entry inside a writable one wins.
	ExtraROBinds [][2]string

	// EmptyPacmanDatabase exposes an existing but empty package database. The
	// caller must separately bind a synthetic /etc/pacman.conf. This lets
	// makepkg's .BUILDINFO query return no host packages without either reading
	// the host database or printing a missing-configuration error.
	EmptyPacmanDatabase bool

	// Env is the complete environment. Nothing is inherited: HOME, PATH, LANG
	// and TERM are supplied below, and anything else must be named here.
	Env map[string]string

	// Argv is the command to run inside the sandbox.
	Argv []string

	Stdin          *os.File
	Stdout, Stderr *os.File
}

// etcAllowlist is what a build legitimately reads from /etc.
//
// makepkg needs its own configuration and the user/group databases; toolchains
// need the trust store; anything networked needs resolution. Deliberately
// absent: machine-id, hostname, the host's pacman configuration and mirrorlist,
// and every drop-in directory that describes this particular machine. The
// makepkg caller explicitly binds a private no-repository pacman.conf instead.
var etcAllowlist = []string{
	"/etc/makepkg.conf",
	"/etc/makepkg.conf.d",
	"/etc/passwd",
	"/etc/group",
	"/etc/ssl",
	"/etc/ca-certificates",
	"/etc/pki",
	"/etc/localtime",
	"/etc/nsswitch.conf",
	"/etc/ld.so.conf",
	"/etc/ld.so.conf.d",
	"/etc/ld.so.cache",
	"/etc/login.defs",
	"/etc/shells",
}

// hostDescribingPaths are parts of /usr that identify this machine rather than
// supplying build tools. They are replaced with empty tmpfs rather than left
// unbound, so a build that looks finds nothing instead of failing oddly.
var hostDescribingPaths = []string{
	"/usr/lib/modules", // exact kernel version
	"/usr/src",         // kernel headers, same information
}

// homeTarget is a tmpfs. Build code sees a home directory that exists, is
// writable, and contains nothing: no SSH keys, no browser profile, no shell
// startup files, no credential helpers, no token caches.
const (
	homeTarget       = "/build-home"
	bubblewrapBinary = "/usr/bin/bwrap"
)

// BwrapArgs renders the bubblewrap invocation for a spec, given the file
// descriptor number the joined user namespace will occupy in the child.
//
// Note what is absent and why: --unshare-user and --unshare-all are not used,
// because both create a new user namespace and are mutually exclusive with
// joining a pre-mapped one. --disable-userns is not used for the same reason -
// bwrap rejects it without --unshare-user - and the property it would have
// provided is supplied instead by the ucount clamp the namespace anchor
// applies. See docs/architecture.md control 1.
func (s Spec) BwrapArgs(usernsFD int) []string {
	target := s.WorkdirTarget
	if target == "" {
		target = "/build"
	}
	// --unshare-net is unconditional, brokered phases included. The build never
	// gets a route to the host network: it reaches the egress broker through a
	// unix socket that is bind-mounted into the sandbox, and a unix socket is a
	// filesystem object, so it crosses the network-namespace boundary while
	// connect(2) to anything else has nowhere to go. A phase that shared the
	// host network to "reach its broker" would let package code drop the proxy
	// variables and dial out directly, past the prompt, the host and port check,
	// and the byte budget.
	args := []string{
		"--userns", fmt.Sprint(usernsFD),
		"--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup",
		"--unshare-net",
		"--die-with-parent", "--new-session",
		"--ro-bind", "/usr", "/usr",
		"--symlink", "usr/bin", "/bin",
		"--symlink", "usr/bin", "/sbin",
		"--symlink", "usr/lib", "/lib",
		// Arch's /usr/lib64 redirects to lib; Ubuntu keeps its ELF loader
		// in /usr/lib64. Redirecting straight to usr/lib breaks Ubuntu exec.
		"--symlink", "usr/lib64", "/lib64",
		"--proc", "/proc",
		"--dev", "/dev",
		// Host /tmp and /run are replaced, not bound: they carry session
		// sockets, D-Bus, the systemd user socket, and agent sockets.
		"--tmpfs", "/tmp",
		"--tmpfs", "/run",
		"--tmpfs", "/var/tmp",
		"--tmpfs", homeTarget,
		"--dir", "/etc",
	}
	if s.EmptyPacmanDatabase {
		// The database exists so pacman's read-only query is quiet, but contains no
		// local entries. These paths are new mounts inside the sandbox; none of the
		// host's /var/lib/pacman crosses the boundary.
		args = append(args,
			"--tmpfs", "/var/lib/pacman",
			"--dir", "/var/lib/pacman/local",
			"--dir", "/tmp/pacman-cache",
			"--dir", "/tmp/pacman-gnupg",
		)
	}
	// Mask the parts of /usr that describe this particular machine rather than
	// providing a toolchain.
	//
	// Measured: without this the build reads /usr/lib/modules and learns the
	// exact running kernel version, which is targeting information for a
	// sandbox escape. Same class of leak as /etc/machine-id, and the same
	// answer - the build needs a compiler, not the host's identity.
	//
	// This is the cheap half of what a clean root would have given. The rest of
	// /usr stays visible, so the build can still tell roughly what is installed;
	// that is a fingerprint rather than a capability, it is bounded by brokered
	// egress, and closing it properly costs a package-fetching clean-root
	// implementation outside this containment boundary.
	for _, path := range hostDescribingPaths {
		args = append(args, "--tmpfs", path)
	}
	// /etc is enumerated, not bound wholesale. This is information
	// minimisation rather than privilege: the build runs as the invoking user
	// and could read these files outside the sandbox anyway, but everything
	// user-readable under /etc that the build does not need is material it can
	// carry out through any granted egress. /etc/machine-id is the clearest
	// example - a stable unique host identifier with no build purpose.
	//
	// Enumerating the required files also keeps the build and broker sandboxes
	// subject to the same host-information policy.
	//
	// No phase gets /etc/resolv.conf or /etc/hosts. Nothing inside resolves
	// names any more: the private network namespace has no route to a resolver,
	// and the broker resolves outside, after the user has consented to the name.
	for _, path := range etcAllowlist {
		args = append(args, "--ro-bind-try", path, path)
	}
	args = append(args, "--bind", s.Workdir, target)
	for _, bind := range s.ExtraBinds {
		args = append(args, "--bind", bind[0], bind[1])
	}
	// The checkout's own git metadata is read-only, always.
	//
	// It is the one part of the workdir that outlives the sandbox as *code*.
	// yay updates an existing AUR checkout on the host with `git reset --hard`
	// followed by `git merge --ff`, and git then runs .git/hooks/post-merge -
	// as the user, outside bubblewrap, with the real home and an unrestricted
	// network. .git/config can redirect core.hooksPath, the remote, or the
	// transport just as effectively. And the inventory scanner excludes .git
	// from the manifest by design, so nothing a build wrote there would appear
	// in a briefing or a diff either.
	//
	// --ro-bind-try, so a checkout without git metadata is not a failure. It is
	// listed with the read-only binds because those are applied last and must
	// not be shadowed by the writable bind of the checkout above.
	args = append(args, "--ro-bind-try", filepath.Join(s.Workdir, ".git"), path.Join(target, ".git"))
	// Read-only binds are applied last, so a writable bind can never shadow
	// one. bwrap performs these in order, and the useful case is exactly the
	// overlap: a directory the sandbox must be able to write into, with
	// individual files inside it pinned read-only over themselves. Emitting
	// them first would silently undo every such pin.
	for _, bind := range s.ExtraROBinds {
		args = append(args, "--ro-bind", bind[0], bind[1])
	}
	args = append(args, "--chdir", target, "--clearenv")
	for _, key := range sortedKeys(s.Env) {
		args = append(args, "--setenv", key, s.Env[key])
	}
	args = append(args, "--")
	return append(args, s.Argv...)
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// BaseEnv is the closed environment every contained execution starts from.
// Host credentials, agent sockets, proxy bypasses, and user-specific tool
// configuration do not cross into untrusted package execution; anything a
// phase genuinely needs is added explicitly by that phase.
func BaseEnv() map[string]string {
	env := map[string]string{
		"HOME": homeTarget,
		"PATH": "/usr/local/sbin:/usr/local/bin:/usr/bin",
		"LANG": "C.UTF-8",
		"TERM": "dumb",
	}
	// LANG is passed through when set, because build systems emit locale
	// warnings without it, and it carries nothing sensitive.
	if lang := os.Getenv("LANG"); lang != "" {
		env["LANG"] = lang
	}
	return env
}

// Run executes the spec inside ns. The namespace is created by the caller and
// may be reused across the phases of one transaction, which is what keeps the
// clamp and the mapping identical for acquisition, build, and archive parsing.
func Run(ctx context.Context, ns *Namespace, spec Spec) error {
	if ns == nil || ns.file == nil {
		return fmt.Errorf("contain.Run: no user namespace")
	}
	// ExtraFiles[0] becomes fd 3 in the child.
	const usernsFD = 3
	// Bubblewrap is part of the trusted containment boundary. Never select it
	// from an ambient, potentially user-writable PATH.
	cmd := exec.CommandContext(ctx, bubblewrapBinary, spec.BwrapArgs(usernsFD)...)
	cmd.ExtraFiles = []*os.File{ns.file}
	cmd.Env = []string{}
	// Assign only what the caller supplied. A nil *os.File placed in the
	// io.Reader/io.Writer field is a non-nil interface holding a nil pointer,
	// so os/exec takes the *os.File fast path, calls Fd() on nil, and hands the
	// child fd -1 rather than /dev/null. The child then fails on its first
	// write to that stream - makepkg exits 3 - with no diagnostic anywhere,
	// because the diagnostic is what could not be written.
	if spec.Stdin != nil {
		cmd.Stdin = spec.Stdin
	}
	if spec.Stdout != nil {
		cmd.Stdout = spec.Stdout
	}
	if spec.Stderr != nil {
		cmd.Stderr = spec.Stderr
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("contained %s: %w", strings.Join(spec.Argv, " "), err)
	}
	return nil
}
