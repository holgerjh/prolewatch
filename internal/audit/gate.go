package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/contain"
	"github.com/holgerjh/prolewatch/internal/safe"
)

// The privileged-integration gate parses attacker-produced archives, so both of
// its operations run inside the build sandbox rather than in this process.
//
// Streaming with Go's own tar and zstd readers already avoids handing hostile
// bytes to bsdtar, but parser choice is not a containment boundary. Reusing the
// build sandbox contains parser failures at the cost of one subprocess.
const (
	gatePrefixesCommand  = "internal-gate-prefixes"
	gateEnumerateCommand = "internal-gate-enumerate"
	gateFilterCommand    = "internal-gate-filter"
	gatePackageTarget    = "/gate/package.pkg.tar.zst"
	gateOutputTarget     = "/gate/filtered.pkg.tar.zst"
	gateSelfTarget       = "/gate/prolewatch"
)

// runContainedGateCommand dispatches the two operations for which runGate
// re-executes its own binary. In an installed transaction that binary is
// prolewatch-makepkg, not the user-facing prolewatch command, so both entry
// points must share this exact dispatcher. It intentionally excludes prefixes:
// that source-tree introspection command is never needed inside the sandbox.
func runContainedGateCommand(args []string) (int, bool) {
	if len(args) == 0 {
		return 0, false
	}
	switch args[0] {
	case gateEnumerateCommand:
		return RunGateEnumerate(args[1:]), true
	case gateFilterCommand:
		return RunGateFilter(args[1:]), true
	default:
		return 0, false
	}
}

// gateTimeout bounds a contained enumeration or rewrite. Both are linear passes
// over one archive; a package that cannot be read in this time is not one to
// wait longer for.
const gateTimeout = 5 * time.Minute

// RunGateEnumerate is the contained side of enumeration. It prints the surfaces
// as JSON and is not a user-facing command.
func RunGateEnumerate(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "internal-gate-enumerate: PACKAGE")
		return ExitInvalidInvocation
	}
	surfaces, err := brief.EnumerateSurfaces(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "internal-gate-enumerate:", err)
		return ExitExecutionFailure
	}
	if surfaces == nil {
		surfaces = []brief.PrivilegedSurface{}
	}
	raw, err := safe.CanonicalJSON(surfaces)
	if err != nil {
		fmt.Fprintln(os.Stderr, "internal-gate-enumerate:", err)
		return ExitExecutionFailure
	}
	os.Stdout.Write(raw)
	return ExitOK
}

// RunGatePrefixes prints the registered surface prefixes, one per line.
//
// It exists so that probes and packaging checks generate their fixtures from
// the shipping registry rather than from a copy maintained beside them. A probe
// with its own list cannot detect that both copies omit the same hook directory.
func RunGatePrefixes(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "internal-gate-prefixes takes no arguments")
		return ExitInvalidInvocation
	}
	for _, prefix := range brief.SurfacePrefixes() {
		fmt.Println(prefix)
	}
	return ExitOK
}

// RunGateFilter is the contained side of the rewrite.
func RunGateFilter(args []string) int {
	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "internal-gate-filter: SOURCE TARGET MEMBER [MEMBER...]")
		return ExitInvalidInvocation
	}
	result, err := brief.FilterArchive(args[0], args[1], args[2:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "internal-gate-filter:", err)
		return ExitExecutionFailure
	}
	raw, err := safe.CanonicalJSON(result)
	if err != nil {
		fmt.Fprintln(os.Stderr, "internal-gate-filter:", err)
		return ExitExecutionFailure
	}
	os.Stdout.Write(raw)
	return ExitOK
}

// gateNamespace is a seam: tests that cannot create user namespaces substitute
// a direct call. Production always contains.
var gateNamespace = contain.NewNamespace

// gateBinary resolves the executable the contained half runs.
//
// It is a seam because os.Executable() inside a Go test names the test binary,
// which would re-run the suite instead of performing a gate operation. Tests
// substitute a compiled prolewatch; production always uses the running binary.
var gateBinary = func() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(self)
}

// EnumerateSurfacesContained lists the privileged-integration surfaces of a
// built package, parsing it inside the sandbox.
func EnumerateSurfacesContained(ctx context.Context, packagePath string) ([]brief.PrivilegedSurface, error) {
	raw, err := runGate(ctx, packagePath, "", gateEnumerateCommand, gatePackageTarget)
	if err != nil {
		return nil, err
	}
	var surfaces []brief.PrivilegedSurface
	if err := safe.DecodeJSON(raw, &surfaces); err != nil {
		return nil, fmt.Errorf("gate enumeration returned unreadable output: %w", err)
	}
	return surfaces, nil
}

// FilterArchiveContained rewrites a package with the named members removed,
// inside the sandbox, and returns the result including the new content hash.
func FilterArchiveContained(ctx context.Context, packagePath, targetPath string, strip []string) (brief.FilterResult, error) {
	if len(strip) == 0 {
		return brief.FilterResult{}, errors.New("gate filter called with nothing to strip")
	}
	args := append([]string{gateFilterCommand, gatePackageTarget, gateOutputTarget}, strip...)
	raw, err := runGate(ctx, packagePath, targetPath, args...)
	if err != nil {
		return brief.FilterResult{}, err
	}
	var result brief.FilterResult
	if err := safe.DecodeJSON(raw, &result); err != nil {
		return brief.FilterResult{}, fmt.Errorf("gate rewrite returned unreadable output: %w", err)
	}
	// The hash was computed inside the sandbox on a file this process can also
	// see. Recompute it here rather than trusting the subprocess's report: the
	// transaction is about to be re-bound to this value, and a content binding
	// that trusts a number it was handed is not a binding.
	digest, err := safe.HashFileNoFollow(targetPath)
	if err != nil {
		return brief.FilterResult{}, err
	}
	if digest != result.SHA256 {
		return brief.FilterResult{}, errors.New("rewritten package changed between the sandbox and this process")
	}
	return result, nil
}

// runGate executes one gate operation inside containment. The package is bound
// read-only; an output directory is bound read-write only when a rewrite needs
// somewhere to land.
func runGate(ctx context.Context, packagePath, outputPath string, argv ...string) ([]byte, error) {
	namespace, err := gateNamespace()
	if err != nil {
		if errors.Is(err, contain.ErrNoSubID) {
			return nil, fmt.Errorf("%w\n\n%s", err, contain.SubIDAdvice())
		}
		return nil, err
	}
	defer namespace.Close()

	// Bind the binary that is running, not the one that happens to be
	// installed. The contained half and the orchestrating half are two entry
	// points into the same program, and letting them come from different builds
	// would be a version-skew bug with no symptom until the JSON shapes drift.
	self, err := gateBinary()
	if err != nil {
		return nil, fmt.Errorf("resolve own binary for the contained gate: %w", err)
	}

	scratch, err := os.MkdirTemp("", "prolewatch-gate")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(scratch)

	// The workdir is an empty directory: the gate needs no writable state of
	// its own, and binding the package's own directory would give a rewrite
	// somewhere to land that the caller did not choose.
	empty, err := os.MkdirTemp(scratch, "work")
	if err != nil {
		return nil, err
	}
	spec := contain.Spec{
		Workdir:      empty,
		Env:          contain.BaseEnv(),
		ExtraROBinds: [][2]string{{packagePath, gatePackageTarget}, {self, gateSelfTarget}},
		Argv:         append([]string{gateSelfTarget}, argv...),
	}
	if outputPath != "" {
		// Create the target first so bwrap binds a file rather than a directory.
		//
		// O_EXCL and O_NOFOLLOW are both load-bearing. Without O_NOFOLLOW a
		// symlink left at this path is followed and its target truncated by a
		// trusted process; without O_EXCL an existing entry is silently reused.
		// The directory is freshly created with an unpredictable name, so this
		// should never fire - which is exactly why it must be an error rather
		// than an overwrite if it does.
		file, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			return nil, fmt.Errorf("create gate output: %w", err)
		}
		file.Close()
		spec.ExtraBinds = append(spec.ExtraBinds, [2]string{outputPath, gateOutputTarget})
	}

	// RunLimited, not Run. The gate parses an archive the package produced, and
	// a namespace bounds what that parse can reach, not what it can allocate: a
	// decompressor sizes its buffers from numbers in the archive, so an
	// unbounded parse is a host OOM with full filesystem isolation. The same
	// rule the build follows applies here - anything reading attacker-authored
	// input gets the resource envelope, not just namespace isolation.
	runCtx, cancel := context.WithTimeout(ctx, gateTimeout)
	defer cancel()
	stdout, stderr, err := contain.RunLimited(runCtx, namespace, spec, gateLimits())
	if err != nil {
		return nil, fmt.Errorf("contained gate operation: %w: %s", err, safe.Inline(string(stderr), 1000))
	}
	return stdout, nil
}

// gateLimits is the envelope for one gate operation.
//
// It is a fixed, tight envelope rather than the configured build one: this is a
// bounded archive parse with a known shape, not a compile, and a limit derived
// from build configuration would let a generous build budget widen it.
func gateLimits() contain.Limits {
	return contain.Limits{
		MemoryBytes:    2 << 30,
		CPUCount:       2,
		TasksMax:       64,
		TimeoutSeconds: int(gateTimeout / time.Second),
		// A rewritten package is written through this envelope, so the file
		// ceiling has to clear a large but sane .pkg.tar.*.
		FileSizeBytes: 8 << 30,
		// Only the operation's small JSON result crosses back.
		OutputBytes: 32 << 20,
	}
}

// gateScratchPrefix names the directory a rewrite lands in before replacing the
// original. It is a prefix, not a fixed name: os.MkdirTemp appends random
// characters and creates the directory exclusively.
const gateScratchPrefix = ".prolewatch-gate-"

// filteredPackagePath creates a private directory beside the package and
// returns the path the rewrite should be written to.
//
// The directory is created in the package's own directory so the replacing
// rename stays on one filesystem and therefore atomic. That directory is
// package-controlled, so a fixed scratch name and a truncating open would let
// package code pre-create
//
//	.prolewatch-gate/<predicted-package-name>.pkg.tar.zst -> ~/.bashrc
//
// during its build. A trusted truncating open would then follow the symlink and
// damage the user's file; detecting it during a later hash is too late.
//
// The name is unpredictable, MkdirTemp creates it exclusively, and lstat
// verifies that the result remains an owned directory. Together these prevent
// package code from pre-seeding an entry that the trusted process reuses.
//
// It is also out of reach of the "*.pkg.tar.*" glob that finds built packages -
// Go's filepath.Glob matches dotfiles, unlike shell globbing, so an interrupted
// rewrite left beside the original would otherwise be handed to yay as a
// package in its own right.
func filteredPackagePath(packagePath string) (string, error) {
	scratch, err := os.MkdirTemp(filepath.Dir(packagePath), gateScratchPrefix)
	if err != nil {
		return "", fmt.Errorf("create gate scratch directory: %w", err)
	}
	info, err := os.Lstat(scratch)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("gate scratch directory is not a directory: %s", scratch)
	}
	if err := os.Chmod(scratch, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(scratch, filepath.Base(packagePath)), nil
}
