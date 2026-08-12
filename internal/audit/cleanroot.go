package audit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	CleanRootProtocolVersion       = 2
	cleanRootManifestSchemaVersion = 2
	cleanRootStagingBackend        = "bubblewrap-v1"
	cleanRootHookPolicy            = "untrusted-disabled-v1"
	cleanRootArtifactTrust         = "caller-supplied-content-addressed"
	maxPacmanConfigBytes           = 4 * 1024 * 1024
	cleanRootPacmanConfigMode      = 0o444
)

var (
	cleanRootStateRoot = "/var/lib/prolewatch"
	cleanRootCommand   = exec.CommandContext
	cleanRootSudo      = exec.CommandContext
	cleanRootOwnerUID  = uint32(0)
	cleanRootOwnerGID  = 0
	cleanRootDepRE     = regexp.MustCompile(`^[A-Za-z0-9@._+:-]+(?:[<>=]{1,2}[A-Za-z0-9@._+:-]+)?$`)
	cleanRootTokenRE   = regexp.MustCompile(`^[0-9]+-[0-9a-f]{32}$`)
)

type CleanRootRequest struct {
	ProtocolVersion   int      `json:"protocol_version"`
	Operation         string   `json:"operation"`
	CallerUID         uint32   `json:"caller_uid"`
	Dependencies      []string `json:"dependencies,omitempty"`
	PolicyFingerprint string   `json:"policy_fingerprint,omitempty"`
	Token             string   `json:"token,omitempty"`
	ArtifactPath      string   `json:"artifact_path,omitempty"`
	ArtifactSHA256    string   `json:"artifact_sha256,omitempty"`
}

type CleanRootPolicyIdentity struct {
	Available      bool   `json:"available"`
	Generation     string `json:"generation,omitempty"`
	ManifestSHA256 string `json:"manifest_sha256,omitempty"`
}

type CleanRootManifest struct {
	SchemaVersion     int      `json:"schema_version"`
	Generation        string   `json:"generation"`
	BaseManifestHash  string   `json:"base_manifest_hash"`
	PolicyFingerprint string   `json:"policy_fingerprint"`
	StagingBackend    string   `json:"staging_backend"`
	HookPolicy        string   `json:"hook_policy"`
	ArtifactTrust     string   `json:"artifact_trust"`
	Packages          []string `json:"packages"`
	ArtifactHashes    []string `json:"artifact_hashes"`
	PacmanConfigHash  string   `json:"pacman_config_hash"`
	PacmanVersion     string   `json:"pacman_version"`
	MkarchrootVersion string   `json:"mkarchroot_version"`
	ManifestSHA256    string   `json:"manifest_sha256"`
}

type CleanRootResponse struct {
	ProtocolVersion int                     `json:"protocol_version"`
	OK              bool                    `json:"ok"`
	Error           string                  `json:"error,omitempty"`
	Token           string                  `json:"token,omitempty"`
	RootPath        string                  `json:"root_path,omitempty"`
	Manifest        *CleanRootManifest      `json:"manifest,omitempty"`
	Identity        CleanRootPolicyIdentity `json:"identity"`
	RemovedJobs     int                     `json:"removed_jobs,omitempty"`
}

type cleanRootActive struct {
	SchemaVersion int    `json:"schema_version"`
	Generation    string `json:"generation"`
	ManifestHash  string `json:"manifest_hash"`
}

type cleanRootArtifact struct {
	SHA256             string   `json:"sha256"`
	File               string   `json:"file"`
	Names              []string `json:"names"`
	Version            string   `json:"version"`
	Provides           []string `json:"provides"`
	PolicyFingerprints []string `json:"policy_fingerprints"`
}

type cleanRootArtifactIndex struct {
	SchemaVersion int                 `json:"schema_version"`
	Artifacts     []cleanRootArtifact `json:"artifacts"`
}

func (r CleanRootRequest) Validate() error {
	if r.ProtocolVersion != CleanRootProtocolVersion || r.CallerUID == 0 {
		return errors.New("invalid clean-root request identity")
	}
	if len(r.Dependencies) > 4096 {
		return errors.New("too many clean-root dependencies")
	}
	for _, dependency := range r.Dependencies {
		if len(dependency) > 512 || !cleanRootDepRE.MatchString(dependency) {
			return fmt.Errorf("invalid clean-root dependency %q", dependency)
		}
	}
	switch r.Operation {
	case "status", "init", "update", "prune":
		if len(r.Dependencies) > 0 || r.PolicyFingerprint != "" || r.Token != "" || r.ArtifactPath != "" || r.ArtifactSHA256 != "" {
			return errors.New("clean-root lifecycle request contains unexpected fields")
		}
	case "prepare":
		if !validHexDigest(r.PolicyFingerprint) || r.Token != "" || r.ArtifactPath != "" || r.ArtifactSHA256 != "" {
			return errors.New("invalid clean-root prepare request")
		}
	case "cleanup":
		if !cleanRootTokenRE.MatchString(r.Token) || len(r.Dependencies) > 0 || r.PolicyFingerprint != "" || r.ArtifactPath != "" || r.ArtifactSHA256 != "" {
			return errors.New("invalid clean-root cleanup request")
		}
	case "import-artifact":
		if !validHexDigest(r.PolicyFingerprint) || !validHexDigest(r.ArtifactSHA256) || !filepath.IsAbs(r.ArtifactPath) || len(r.ArtifactPath) > 8192 || len(r.Dependencies) > 0 || r.Token != "" {
			return errors.New("invalid clean-root artifact import request")
		}
	default:
		return errors.New("unsupported clean-root operation")
	}
	return nil
}

func (m CleanRootManifest) Validate() error {
	if m.SchemaVersion != cleanRootManifestSchemaVersion || !cleanRootTokenRE.MatchString(m.Generation) || !validHexDigest(m.BaseManifestHash) ||
		!validHexDigest(m.PolicyFingerprint) || !validHexDigest(m.PacmanConfigHash) || m.PacmanVersion == "" ||
		m.StagingBackend != cleanRootStagingBackend || m.HookPolicy != cleanRootHookPolicy || m.ArtifactTrust != cleanRootArtifactTrust ||
		m.MkarchrootVersion == "" || !validHexDigest(m.ManifestSHA256) || len(m.Packages) > 200000 || len(m.ArtifactHashes) > 4096 {
		return errors.New("invalid clean-root manifest")
	}
	copy := m
	copy.ManifestSHA256 = ""
	raw, err := CanonicalJSON(copy)
	if err != nil || SHA256Bytes(raw) != m.ManifestSHA256 {
		return errors.New("clean-root manifest hash mismatch")
	}
	for _, hash := range m.ArtifactHashes {
		if !validHexDigest(hash) {
			return errors.New("invalid clean-root artifact hash")
		}
	}
	return nil
}

func cleanRootPath(parts ...string) string {
	values := append([]string{cleanRootStateRoot}, parts...)
	return filepath.Join(values...)
}

func activeCleanRootIdentity() (CleanRootPolicyIdentity, error) {
	var active cleanRootActive
	path := cleanRootPath("build-roots", "active.json")
	file, err := openRootOwnedPath(path, false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return CleanRootPolicyIdentity{Available: false}, nil
		}
		return CleanRootPolicyIdentity{}, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	if err != nil || len(raw) > 64*1024 || DecodeStrict(raw, &active) != nil {
		return CleanRootPolicyIdentity{}, errors.New("invalid active clean-root document")
	}
	if active.SchemaVersion != 1 || !cleanRootTokenRE.MatchString(active.Generation) || !validHexDigest(active.ManifestHash) {
		return CleanRootPolicyIdentity{}, errors.New("invalid active clean-root generation")
	}
	return CleanRootPolicyIdentity{Available: true, Generation: active.Generation, ManifestSHA256: active.ManifestHash}, nil
}

func invokeCleanRootDispatcher(ctx context.Context, request CleanRootRequest) (CleanRootResponse, error) {
	if err := request.Validate(); err != nil {
		return CleanRootResponse{}, err
	}
	raw, err := CanonicalJSON(request)
	if err != nil {
		return CleanRootResponse{}, err
	}
	command := cleanRootSudo(ctx, "/usr/bin/sudo", "-n", "/usr/libexec/prolewatch/build-dispatch")
	command.Stdin = bytes.NewReader(raw)
	stdout, stderr := newLimitedBuffer(4*1024*1024), newLimitedBuffer(1024*1024)
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil {
		var rejection CleanRootResponse
		if DecodeStrict(stdout.Bytes(), &rejection) == nil && rejection.ProtocolVersion == CleanRootProtocolVersion && !rejection.OK && rejection.Error != "" {
			return CleanRootResponse{}, fmt.Errorf("clean-root dispatcher rejected request: %s", rejection.Error)
		}
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = strings.TrimSpace(stdout.String())
		}
		return CleanRootResponse{}, fmt.Errorf("clean-root dispatcher failed: %w: %s", err, truncate(detail, 1000))
	}
	var response CleanRootResponse
	if err := DecodeStrict(stdout.Bytes(), &response); err != nil {
		return CleanRootResponse{}, fmt.Errorf("clean-root dispatcher returned invalid JSON: %w", err)
	}
	if response.ProtocolVersion != CleanRootProtocolVersion || !response.OK || response.Error != "" {
		return CleanRootResponse{}, fmt.Errorf("clean-root dispatcher rejected request: %s", response.Error)
	}
	if request.Operation == "prepare" {
		if !cleanRootTokenRE.MatchString(response.Token) || response.RootPath != cleanRootPath("build-jobs", response.Token, "root") || response.Manifest == nil {
			return CleanRootResponse{}, errors.New("clean-root dispatcher returned unsafe preparation metadata")
		}
		if err := response.Manifest.Validate(); err != nil || response.Manifest.PolicyFingerprint != request.PolicyFingerprint {
			return CleanRootResponse{}, errors.New("clean-root dispatcher returned an invalid manifest")
		}
	}
	return response, nil
}

// RunBuildDispatcher is Prolewatch's only root build boundary.
//
// Root is needed to materialize an Arch userspace with correct ownership and a
// pacman database. It is deliberately not a build runner: the dispatcher must
// never source a PKGBUILD, run a makepkg phase, execute an AUR scriptlet or
// hook, accept an arbitrary command, mount, environment, or destination path,
// or enter a package worktree. Its fixed sudo protocol can only report the
// active generation, prepare a disposable root from validated dependency
// names, import an exact caller-supplied artifact into an untrusted
// content-addressed cache, and remove a job identified by an opaque
// caller-bound token. The caller's policy fingerprint partitions honest cache
// reuse; it is not root authorization. Generation changes require the separate
// interactive administrator command. Signed repository packages may run their
// system hooks inside the isolated staging sandbox; custom hooks are disabled.
// AUR scriptlets and every ALPM hook are disabled for the later untrusted AUR
// transaction. Untrusted build phases run as the normal user in a separate
// Bubblewrap sandbox.
//
// Keep this contract synchronized with docs/architecture.md's clean-root and
// dispatcher sections. Any expansion is a security-boundary change.
func RunBuildDispatcher(ctx context.Context) int {
	if os.Geteuid() != 0 || len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "prolewatch build dispatcher requires root and accepts no arguments")
		return 20
	}
	callerText := os.Getenv("SUDO_UID")
	caller, err := strconv.ParseUint(callerText, 10, 32)
	if err != nil || caller == 0 {
		fmt.Fprintln(os.Stderr, "prolewatch build dispatcher requires a non-root sudo caller")
		return 20
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 256*1024+1))
	if err != nil || len(raw) > 256*1024 {
		fmt.Fprintln(os.Stderr, "invalid clean-root dispatcher input")
		return 20
	}
	var request CleanRootRequest
	if err := DecodeStrict(raw, &request); err != nil || request.CallerUID != uint32(caller) || request.Validate() != nil {
		fmt.Fprintln(os.Stderr, "invalid clean-root dispatcher request")
		return 20
	}
	if request.Operation == "init" || request.Operation == "update" || request.Operation == "prune" {
		fmt.Fprintln(os.Stderr, "clean-root administrator operations require the interactive prolewatch command")
		return 20
	}
	response, err := executeCleanRootRequest(ctx, request)
	if err != nil {
		response = CleanRootResponse{ProtocolVersion: CleanRootProtocolVersion, OK: false, Error: truncate(err.Error(), 2000)}
	}
	encoded, encodeErr := CanonicalJSON(response)
	if encodeErr != nil {
		fmt.Fprintln(os.Stderr, encodeErr)
		return 23
	}
	_, _ = os.Stdout.Write(append(encoded, '\n'))
	if err != nil {
		return 23
	}
	return 0
}

func executeCleanRootRequest(ctx context.Context, request CleanRootRequest) (CleanRootResponse, error) {
	return executeCleanRootRequestWithStatusReader(ctx, request, activeCleanRootIdentity)
}

func executeCleanRootRequestWithStatusReader(ctx context.Context, request CleanRootRequest, readStatus func() (CleanRootPolicyIdentity, error)) (CleanRootResponse, error) {
	cfg, err := LoadConfig("")
	if err != nil {
		return CleanRootResponse{}, err
	}
	if err := ensureCleanRootDirectories(); err != nil {
		return CleanRootResponse{}, err
	}
	response := CleanRootResponse{ProtocolVersion: CleanRootProtocolVersion, OK: true}
	if request.Operation == "status" {
		identity, err := readStatus()
		response.Identity = identity
		return response, err
	}

	operationContext, cancel := cleanRootOperationContext(ctx, request.Operation, cfg.Build.CleanRootPrepareTimeoutSeconds)
	defer cancel()
	lock, err := acquireCleanRootLock(operationContext)
	if err != nil {
		return CleanRootResponse{}, err
	}
	defer lock.Close()
	switch request.Operation {
	case "init":
		identity, err := createCleanRootGeneration(operationContext, false)
		response.Identity = identity
		return response, err
	case "update":
		identity, err := createCleanRootGeneration(operationContext, true)
		response.Identity = identity
		return response, err
	case "prune":
		removed, err := prunePreparedRoots(request.CallerUID)
		response.RemovedJobs = removed
		return response, err
	case "prepare":
		token, root, manifest, err := prepareCleanRoot(operationContext, request, cfg)
		if err != nil {
			return CleanRootResponse{}, err
		}
		response.Token, response.RootPath, response.Manifest = token, root, manifest
		return response, nil
	case "cleanup":
		return response, cleanupCleanRoot(request.CallerUID, request.Token)
	case "import-artifact":
		return response, importCleanRootArtifact(operationContext, request, cfg)
	}
	return CleanRootResponse{}, errors.New("unsupported clean-root operation")
}

func ensureCleanRootDirectories() error {
	buildRoots := cleanRootPath("build-roots")
	directories := []struct {
		path string
		mode os.FileMode
	}{
		{cleanRootStateRoot, 0o711},
		{buildRoots, 0o711},
		{cleanRootPath("build-roots", "generations"), 0o700},
		{cleanRootPath("artifact-pool"), 0o700},
		{cleanRootPath("build-jobs"), 0o711},
	}
	for _, directory := range directories {
		if err := secureCleanRootDirectory(directory.path, directory.mode); err != nil {
			return err
		}
	}
	active := cleanRootPath("build-roots", "active.json")
	if fd, err := unix.Open(active, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0); err == nil {
		file := os.NewFile(uintptr(fd), active)
		defer file.Close()
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
			stat.Uid != cleanRootOwnerUID || int(stat.Gid) != cleanRootOwnerGID || stat.Mode&0o022 != 0 ||
			unix.Fchmod(fd, 0o644) != nil {
			return errors.New("active clean-root document has unsafe ownership, mode, or type")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func secureCleanRootDirectory(path string, mode os.FileMode) error {
	if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), path)
	defer directory.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Uid != cleanRootOwnerUID || int(stat.Gid) != cleanRootOwnerGID || stat.Mode&0o022 != 0 {
		return fmt.Errorf("clean-root directory has unsafe ownership, mode, or type: %s", path)
	}
	if err := unix.Fchmod(fd, uint32(mode.Perm())); err != nil {
		return err
	}
	return nil
}

func acquireCleanRootLock(ctx context.Context) (*os.File, error) {
	path := cleanRootPath("dispatcher.lock")
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != cleanRootOwnerUID || stat.Mode&0o022 != 0 {
		file.Close()
		return nil, errors.New("clean-root dispatcher lock has unsafe ownership or mode")
	}
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return file, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			file.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			file.Close()
			return nil, errors.New("timed out waiting for clean-root dispatcher lock")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func randomCleanRootToken(uid uint32) (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return strconv.FormatUint(uint64(uid), 10) + "-" + hex.EncodeToString(random), nil
}

func createCleanRootGeneration(ctx context.Context, update bool) (CleanRootPolicyIdentity, error) {
	if !update {
		if current, err := activeCleanRootIdentity(); err == nil && current.Available {
			return CleanRootPolicyIdentity{}, errors.New("a clean-root generation already exists; use update")
		}
	}
	token, err := randomCleanRootToken(1)
	if err != nil {
		return CleanRootPolicyIdentity{}, err
	}
	generation := cleanRootPath("build-roots", "generations", token)
	if _, err := os.Lstat(generation); err == nil {
		return CleanRootPolicyIdentity{}, errors.New("clean-root generation token already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return CleanRootPolicyIdentity{}, err
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(generation)
		}
	}()
	command := newCleanRootCommand(ctx, "/usr/bin/mkarchroot", generation, "base-devel")
	configureCleanRootProcessGroup(command)
	output := newLimitedBuffer(16 * 1024 * 1024)
	command.Stdout, command.Stderr = output, output
	if err := command.Run(); err != nil {
		_ = terminateCleanRootProcessGroup(command)
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return CleanRootPolicyIdentity{}, fmt.Errorf("mkarchroot failed: %w: %s", err, cleanRootFailureOutput(output.String()))
	}
	if err := secureCleanRootDirectory(generation, 0o700); err != nil {
		return CleanRootPolicyIdentity{}, fmt.Errorf("validate new clean-root generation: %w", err)
	}
	manifest, err := baseRootManifest(ctx, generation)
	if err != nil {
		return CleanRootPolicyIdentity{}, err
	}
	active := cleanRootActive{SchemaVersion: 1, Generation: token, ManifestHash: manifest}
	if err := atomicWriteRootJSON(cleanRootPath("build-roots", "active.json"), active, 0o644); err != nil {
		return CleanRootPolicyIdentity{}, err
	}
	success = true
	return CleanRootPolicyIdentity{Available: true, Generation: token, ManifestSHA256: manifest}, nil
}

func baseRootManifest(ctx context.Context, root string) (string, error) {
	packages, err := rootPackageList(ctx, root)
	if err != nil {
		return "", err
	}
	pacmanConfig, err := HashFileNoFollow(filepath.Join(root, "etc", "pacman.conf"))
	if err != nil {
		return "", err
	}
	raw, err := CanonicalJSON(map[string]any{"packages": packages, "pacman_config_sha256": pacmanConfig})
	if err != nil {
		return "", err
	}
	return SHA256Bytes(raw), nil
}

func prepareCleanRoot(ctx context.Context, request CleanRootRequest, cfg Config) (string, string, *CleanRootManifest, error) {
	active, err := readActiveCleanRoot()
	if err != nil {
		return "", "", nil, err
	}
	staleAge := time.Duration(cfg.Build.TimeoutSeconds+cfg.Build.CleanRootPrepareTimeoutSeconds+3600) * time.Second
	if err := removeStalePreparedRoots(request.CallerUID, staleAge, time.Now()); err != nil {
		return "", "", nil, err
	}
	if err := enforcePreparedRootCount(request.CallerUID, cfg.Build.CleanRootMaxPrepared); err != nil {
		return "", "", nil, err
	}
	token, err := randomCleanRootToken(request.CallerUID)
	if err != nil {
		return "", "", nil, err
	}
	job := cleanRootPath("build-jobs", token)
	root := filepath.Join(job, "root")
	if err := os.Mkdir(job, 0o700); err != nil {
		return "", "", nil, err
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(job)
		}
	}()
	base := cleanRootPath("build-roots", "generations", active.Generation)
	if err := copyCleanRoot(ctx, base, root); err != nil {
		return "", "", nil, err
	}
	if err := cleanRootDiskUsage(root, cfg.Build.CleanRootBytes); err != nil {
		return "", "", nil, err
	}
	artifacts, official, err := selectDependencyArtifacts(request.Dependencies, request.PolicyFingerprint)
	if err != nil {
		return "", "", nil, err
	}
	disabledHooks := filepath.Join(job, "disabled-hooks")
	if err := os.Mkdir(disabledHooks, 0o555); err != nil {
		return "", "", nil, err
	}
	for _, relative := range []string{
		"usr/bin", "usr/share/libalpm/hooks", "etc/pacman.d/hooks", "etc/makepkg.conf.d",
		"var/tmp", "home", "root", "run", "tmp", "proc", "dev", "build", "build-home", "broker",
	} {
		if err := ensureCleanRootMountDirectory(root, relative); err != nil {
			return "", "", nil, err
		}
	}
	for _, relative := range []string{"etc/makepkg.conf", "usr/bin/prolewatch-net"} {
		if err := ensureCleanRootMountFile(root, relative); err != nil {
			return "", "", nil, err
		}
	}
	effectiveConfig, err := effectiveCleanRootPacmanConfig(ctx, root)
	if err != nil {
		return "", "", nil, err
	}
	hardenedConfig, err := hardenCleanRootPacmanConfig(effectiveConfig)
	if err != nil {
		return "", "", nil, err
	}
	if len(official) > 0 {
		officialConfig, err := hardenOfficialCleanRootPacmanConfig(effectiveConfig)
		if err != nil {
			return "", "", nil, err
		}
		if err := replaceCleanRootFile(filepath.Join(root, "etc", "pacman.conf"), officialConfig, cleanRootPacmanConfigMode, true); err != nil {
			return "", "", nil, err
		}
		if err := snapshotCleanRootResolver(root); err != nil {
			return "", "", nil, err
		}
		official, err = missingCleanRootDependencies(ctx, root, official)
		if err != nil {
			return "", "", nil, err
		}
	}
	if len(official) > 0 {
		args := append([]string{"-S", "--noconfirm", "--needed", "--"}, official...)
		if err := runCleanRootPacman(ctx, root, disabledHooks, false, true, args...); err != nil {
			return "", "", nil, fmt.Errorf("install official dependencies: %w", err)
		}
	}
	if err := replaceCleanRootFile(filepath.Join(root, "etc", "pacman.conf"), hardenedConfig, cleanRootPacmanConfigMode, true); err != nil {
		return "", "", nil, err
	}
	packages, err := rootPackageList(ctx, root)
	if err != nil {
		return "", "", nil, err
	}
	pacmanVersion := cleanRootCommandVersionText(ctx, root, "/usr/bin/pacman", "--version")
	mkarchrootVersion := commandVersionText(ctx, "/usr/bin/mkarchroot", "--version")
	artifactHashes := make([]string, 0, len(artifacts))
	if len(artifacts) > 0 {
		pool := filepath.Join(root, "prolewatch-pool")
		if err := os.Mkdir(pool, 0o700); err != nil {
			return "", "", nil, err
		}
		var inRoot []string
		for _, artifact := range artifacts {
			target := filepath.Join(pool, artifact.File)
			if err := copyVerifiedFile(cleanRootPath("artifact-pool", artifact.File), target, artifact.SHA256, 0o400); err != nil {
				return "", "", nil, err
			}
			inRoot = append(inRoot, "/prolewatch-pool/"+artifact.File)
			artifactHashes = append(artifactHashes, artifact.SHA256)
		}
		args := append([]string{"-U", "--noconfirm", "--needed", "--noscriptlet", "--"}, inRoot...)
		if err := runCleanRootPacman(ctx, root, disabledHooks, true, false, args...); err != nil {
			return "", "", nil, fmt.Errorf("install sealed AUR dependencies: %w", err)
		}
		for _, artifact := range artifacts {
			packages = append(packages, artifact.Names[0]+"="+artifact.Version)
		}
		sort.Strings(packages)
	}
	if err := cleanRootDiskUsage(root, cfg.Build.CleanRootBytes); err != nil {
		return "", "", nil, err
	}
	pacmanHash, err := HashFileNoFollow(filepath.Join(root, "etc", "pacman.conf"))
	if err != nil {
		return "", "", nil, err
	}
	manifest := &CleanRootManifest{SchemaVersion: cleanRootManifestSchemaVersion, Generation: active.Generation, BaseManifestHash: active.ManifestHash,
		PolicyFingerprint: request.PolicyFingerprint, StagingBackend: cleanRootStagingBackend, HookPolicy: cleanRootHookPolicy,
		ArtifactTrust: cleanRootArtifactTrust, Packages: packages, ArtifactHashes: artifactHashes,
		PacmanConfigHash: pacmanHash, PacmanVersion: pacmanVersion, MkarchrootVersion: mkarchrootVersion}
	sort.Strings(manifest.ArtifactHashes)
	copy := *manifest
	copy.ManifestSHA256 = ""
	raw, _ := CanonicalJSON(copy)
	manifest.ManifestSHA256 = SHA256Bytes(raw)
	if err := manifest.Validate(); err != nil {
		return "", "", nil, err
	}
	if err := atomicWriteRootJSON(filepath.Join(job, "manifest.json"), manifest, 0o400); err != nil {
		return "", "", nil, err
	}
	if err := makeRootReadable(root); err != nil {
		return "", "", nil, err
	}
	success = true
	return token, root, manifest, nil
}

func readActiveCleanRoot() (cleanRootActive, error) {
	var active cleanRootActive
	if err := ReadJSONFile(cleanRootPath("build-roots", "active.json"), 64*1024, &active); err != nil {
		return active, errors.New("clean build root is not initialized; run sudo prolewatch clean-root init")
	}
	if active.SchemaVersion != 1 || !cleanRootTokenRE.MatchString(active.Generation) || !validHexDigest(active.ManifestHash) {
		return active, errors.New("active clean build root is invalid")
	}
	return active, nil
}

func copyCleanRoot(ctx context.Context, source, target string) error {
	if err := os.Mkdir(target, 0o700); err != nil {
		return err
	}
	return runCleanRootCommand(ctx, "/usr/bin/cp", "-a", "--reflink=auto", source+"/.", target+"/")
}

func rootPackageList(ctx context.Context, root string) ([]string, error) {
	command := cleanRootSandboxCommand(ctx, root, false, false, "", "/usr/bin/pacman", "-Q")
	output := newLimitedBuffer(32 * 1024 * 1024)
	command.Stdout, command.Stderr = output, output
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("read clean-root package list: %w: %s", err, truncate(output.String(), 2000))
	}
	packages := strings.Fields(strings.ReplaceAll(output.String(), "\n", " "))
	if len(packages)%2 != 0 {
		return nil, errors.New("invalid clean-root package list")
	}
	result := make([]string, 0, len(packages)/2)
	for index := 0; index < len(packages); index += 2 {
		result = append(result, packages[index]+"="+packages[index+1])
	}
	sort.Strings(result)
	return result, nil
}

func cleanRootBwrapArgs(root string, writable, network bool, disabledHooks string, blockSystemHooks bool, command ...string) []string {
	rootMode := "--ro-bind"
	if writable {
		rootMode = "--bind"
	}
	args := []string{
		"--die-with-parent", "--new-session", "--unshare-all", "--unshare-user",
		"--disable-userns", "--assert-userns-disabled", "--hostname", "prolewatch-stage",
		rootMode, root, "/", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/run", "--tmpfs", "/tmp",
	}
	if network {
		args = append(args, "--share-net")
	}
	if disabledHooks != "" {
		if blockSystemHooks {
			args = append(args, "--ro-bind", disabledHooks, "/usr/share/libalpm/hooks")
		}
		args = append(args, "--ro-bind", disabledHooks, "/etc/pacman.d/hooks")
	}
	args = append(args,
		"--cap-drop", "ALL",
		"--cap-add", "CAP_CHOWN",
		"--cap-add", "CAP_DAC_OVERRIDE",
		"--cap-add", "CAP_FOWNER",
		"--cap-add", "CAP_FSETID",
		"--cap-add", "CAP_SETUID",
		"--cap-add", "CAP_SETGID",
		"--cap-add", "CAP_SETFCAP",
		"--cap-add", "CAP_SYS_CHROOT",
		"--chdir", "/", "--clearenv",
		"--setenv", "HOME", "/root",
		"--setenv", "LANG", "C.UTF-8",
		"--setenv", "LC_ALL", "C.UTF-8",
		"--setenv", "PATH", "/usr/bin",
		"--setenv", "TMPDIR", "/tmp",
		"--setenv", "SYSTEMD_IN_CHROOT", "1")
	return append(args, command...)
}

func cleanRootSandboxCommand(ctx context.Context, root string, writable, network bool, disabledHooks string, command ...string) *exec.Cmd {
	return newCleanRootCommand(ctx, "/usr/bin/bwrap", cleanRootBwrapArgs(root, writable, network, disabledHooks, false, command...)...)
}

func runCleanRootPacman(ctx context.Context, root, disabledHooks string, blockSystemHooks, network bool, args ...string) error {
	targets := []string{"etc/pacman.d/hooks"}
	if blockSystemHooks {
		targets = append(targets, "usr/share/libalpm/hooks")
	}
	for _, relative := range targets {
		if err := ensureCleanRootMountDirectory(root, relative); err != nil {
			return err
		}
	}
	command := newCleanRootCommand(ctx, "/usr/bin/bwrap", cleanRootBwrapArgs(root, true, network, disabledHooks, blockSystemHooks, append([]string{"/usr/bin/pacman"}, args...)...)...)
	output := newLimitedBuffer(32 * 1024 * 1024)
	command.Stdout, command.Stderr = output, output
	if err := command.Run(); err != nil {
		return fmt.Errorf("pacman failed: %w: %s", err, truncate(output.String(), 2000))
	}
	return nil
}

func missingCleanRootDependencies(ctx context.Context, root string, dependencies []string) ([]string, error) {
	if len(dependencies) == 0 {
		return []string{}, nil
	}
	args := append([]string{"/usr/bin/pacman", "-T", "--"}, dependencies...)
	command := cleanRootSandboxCommand(ctx, root, false, false, "", args...)
	output := newLimitedBuffer(1024 * 1024)
	stderr := newLimitedBuffer(1024 * 1024)
	command.Stdout, command.Stderr = output, stderr
	err := command.Run()
	if err != nil {
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 127 {
			return nil, fmt.Errorf("check clean-root dependencies: %w: %s", err, truncate(stderr.String(), 1000))
		}
	}
	missing := strings.Fields(output.String())
	if (err == nil && len(missing) != 0) || (err != nil && len(missing) == 0) {
		return nil, errors.New("pacman returned an invalid dependency check result")
	}
	requested := make(map[string]bool, len(dependencies))
	for _, dependency := range dependencies {
		requested[dependency] = true
	}
	seen := make(map[string]bool, len(missing))
	for _, dependency := range missing {
		if !requested[dependency] || seen[dependency] {
			return nil, errors.New("pacman returned an unexpected missing dependency")
		}
		seen[dependency] = true
	}
	return missing, nil
}

func cleanRootCommandVersionText(ctx context.Context, root string, commandAndArgs ...string) string {
	command := cleanRootSandboxCommand(ctx, root, false, false, "", commandAndArgs...)
	output, err := command.Output()
	if err != nil {
		return "unknown"
	}
	return versionOutputText(output)
}

func effectiveCleanRootPacmanConfig(ctx context.Context, root string) ([]byte, error) {
	command := cleanRootSandboxCommand(ctx, root, false, false, "", "/usr/bin/pacman-conf")
	output := newLimitedBuffer(maxPacmanConfigBytes)
	stderr := newLimitedBuffer(1024 * 1024)
	command.Stdout, command.Stderr = output, stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("resolve clean-root pacman configuration: %w: %s", err, truncate(stderr.String(), 1000))
	}
	return append([]byte(nil), output.Bytes()...), nil
}

func hardenCleanRootPacmanConfig(raw []byte) ([]byte, error) {
	return hardenCleanRootPacmanConfigForHooks(raw, true)
}

func hardenOfficialCleanRootPacmanConfig(raw []byte) ([]byte, error) {
	return hardenCleanRootPacmanConfigForHooks(raw, false)
}

func hardenCleanRootPacmanConfigForHooks(raw []byte, blockSystemHooks bool) ([]byte, error) {
	if len(raw) == 0 || len(raw) > maxPacmanConfigBytes || bytes.IndexByte(raw, 0) >= 0 {
		return nil, errors.New("invalid effective pacman configuration")
	}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var result []string
	inOptions, sawOptions, inserted := false, false, false
	insertPolicy := func() {
		result = append(result, "HookDir = /etc/pacman.d/hooks/")
		if blockSystemHooks {
			result = append(result, "NoExtract = usr/share/libalpm/hooks/*")
		}
		result = append(result,
			"NoExtract = etc/pacman.d/hooks/*",
			"NoExtract = etc/pacman.conf")
		inserted = true
	}
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			if inOptions && !inserted {
				insertPolicy()
			}
			inOptions = trimmed == "[options]"
			if inOptions {
				if sawOptions {
					return nil, errors.New("effective pacman configuration has multiple options sections")
				}
				sawOptions = true
			}
			result = append(result, line)
			continue
		}
		key := trimmed
		if before, _, ok := strings.Cut(trimmed, "="); ok {
			key = strings.TrimSpace(before)
		}
		if key == "Include" {
			return nil, errors.New("effective pacman configuration was not fully resolved")
		}
		if inOptions && key == "HookDir" {
			continue
		}
		// The staging user namespace intentionally maps only root. Pacman 7's
		// host DownloadUser (normally "alpm") cannot be represented there, so
		// chown(2) fails with EINVAL before any package is downloaded. Keep
		// pacman's own download sandbox enabled, but run its downloader as the
		// already-contained staging root by omitting this host-only identity.
		if inOptions && key == "DownloadUser" {
			continue
		}
		result = append(result, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.New("effective pacman configuration contains an oversized line")
	}
	if !sawOptions {
		return nil, errors.New("effective pacman configuration is missing [options]")
	}
	if inOptions && !inserted {
		insertPolicy()
	}
	encoded := []byte(strings.Join(result, "\n") + "\n")
	if len(encoded) > maxPacmanConfigBytes {
		return nil, errors.New("hardened pacman configuration exceeds its size limit")
	}
	return encoded, nil
}

func ensureCleanRootMountDirectory(root, relative string) error {
	target := filepath.Join(root, filepath.FromSlash(relative))
	if !strings.HasPrefix(target, root+string(os.PathSeparator)) {
		return errors.New("unsafe clean-root mount directory")
	}
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return os.MkdirAll(target, 0o755)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("clean-root mount target is not a directory: %s", relative)
	}
	return nil
}

func ensureCleanRootMountFile(root, relative string) error {
	target := filepath.Join(root, filepath.FromSlash(relative))
	if !strings.HasPrefix(target, root+string(os.PathSeparator)) {
		return errors.New("unsafe clean-root mount file")
	}
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		file, createErr := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0)
		if createErr != nil {
			return createErr
		}
		return file.Close()
	}
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != cleanRootOwnerUID || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("clean-root mount target is not a safe file: %s", relative)
	}
	return nil
}

func replaceCleanRootFile(path string, content []byte, mode os.FileMode, requireExisting bool) error {
	if info, err := os.Lstat(path); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != cleanRootOwnerUID || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("clean-root file has unsafe ownership, mode, or type: %s", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) || requireExisting {
		return err
	}
	temporary := path + ".prolewatch-new"
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	success := false
	defer func() {
		if !success {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(content); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	success = true
	return nil
}

func snapshotCleanRootResolver(root string) error {
	source, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return fmt.Errorf("open resolver configuration: %w", err)
	}
	defer source.Close()
	raw, err := io.ReadAll(io.LimitReader(source, 64*1024+1))
	if err != nil || len(raw) == 0 || len(raw) > 64*1024 {
		return errors.New("resolver configuration is empty or exceeds its size limit")
	}
	target := filepath.Join(root, "etc", "resolv.conf")
	if info, statErr := os.Lstat(target); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		if err := os.Remove(target); err != nil {
			return err
		}
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	return replaceCleanRootFile(target, raw, 0o444, false)
}

func runCleanRootCommand(ctx context.Context, name string, args ...string) error {
	command := newCleanRootCommand(ctx, name, args...)
	output := newLimitedBuffer(32 * 1024 * 1024)
	command.Stdout, command.Stderr = output, output
	if err := command.Run(); err != nil {
		return fmt.Errorf("%s failed: %w: %s", filepath.Base(name), err, truncate(output.String(), 2000))
	}
	return nil
}

func commandVersionText(ctx context.Context, name string, args ...string) string {
	command := newCleanRootCommand(ctx, name, args...)
	output, err := command.Output()
	if err != nil {
		return "unknown"
	}
	return versionOutputText(output)
}

func versionOutputText(output []byte) string {
	for _, line := range strings.Split(string(output), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return truncate(line, 256)
		}
	}
	return "unknown"
}

func makeRootReadable(root string) error {
	for _, path := range []string{cleanRootStateRoot, cleanRootPath("build-jobs"), filepath.Dir(root), root} {
		if err := os.Chmod(path, 0o711); err != nil {
			return err
		}
	}
	return nil
}

func cleanupCleanRoot(uid uint32, token string) error {
	if !strings.HasPrefix(token, strconv.FormatUint(uint64(uid), 10)+"-") || !cleanRootTokenRE.MatchString(token) {
		return errors.New("clean-root token does not belong to caller")
	}
	target := cleanRootPath("build-jobs", token)
	if filepath.Dir(target) != cleanRootPath("build-jobs") {
		return errors.New("unsafe clean-root cleanup target")
	}
	return os.RemoveAll(target)
}

func enforcePreparedRootCount(uid uint32, maximum int) error {
	entries, err := os.ReadDir(cleanRootPath("build-jobs"))
	if err != nil {
		return err
	}
	prefix, count := strconv.FormatUint(uint64(uid), 10)+"-", 0
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), prefix) {
			count++
		}
	}
	if count >= maximum {
		return errors.New("maximum concurrent prepared clean roots reached; wait for active builds or, after confirming none remain, run sudo prolewatch clean-root prune")
	}
	return nil
}

func prunePreparedRoots(uid uint32) (int, error) {
	entries, err := os.ReadDir(cleanRootPath("build-jobs"))
	if err != nil {
		return 0, err
	}
	prefix := strconv.FormatUint(uint64(uid), 10) + "-"
	removed := 0
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) || !cleanRootTokenRE.MatchString(entry.Name()) {
			continue
		}
		target := cleanRootPath("build-jobs", entry.Name())
		if filepath.Dir(target) != cleanRootPath("build-jobs") {
			return removed, errors.New("unsafe abandoned clean-root target")
		}
		if err := os.RemoveAll(target); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

func removeStalePreparedRoots(uid uint32, maximumAge time.Duration, now time.Time) error {
	entries, err := os.ReadDir(cleanRootPath("build-jobs"))
	if err != nil {
		return err
	}
	prefix := strconv.FormatUint(uint64(uid), 10) + "-"
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) || !cleanRootTokenRE.MatchString(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if maximumAge <= 0 || now.Sub(info.ModTime()) <= maximumAge {
			continue
		}
		target := cleanRootPath("build-jobs", entry.Name())
		if filepath.Dir(target) != cleanRootPath("build-jobs") {
			return errors.New("unsafe stale clean-root target")
		}
		if err := os.RemoveAll(target); err != nil {
			return err
		}
	}
	return nil
}

func importCleanRootArtifact(ctx context.Context, request CleanRootRequest, cfg Config) error {
	info, err := os.Lstat(request.ArtifactPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("artifact import source is not a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != request.CallerUID || info.Mode().Perm()&0o002 != 0 {
		return errors.New("artifact import source has unsafe ownership or mode")
	}
	hash := request.ArtifactSHA256
	file := hash + ".pkg.tar"
	target := cleanRootPath("artifact-pool", file)
	created := false
	if _, err := os.Lstat(target); errors.Is(err, os.ErrNotExist) {
		if err := cleanRootDiskUsage(cleanRootPath("artifact-pool"), cfg.Build.CleanRootCacheBytes-info.Size()); err != nil {
			return err
		}
		if err := copyVerifiedFile(request.ArtifactPath, target, hash, 0o400); err != nil {
			return err
		}
		created = true
	} else if err != nil {
		return err
	} else if existing, hashErr := HashFileNoFollow(target); hashErr != nil || existing != hash {
		return errors.New("existing artifact cache entry does not match its content hash")
	}
	if err := cleanRootDiskUsage(cleanRootPath("artifact-pool"), cfg.Build.CleanRootCacheBytes); err != nil {
		if created {
			_ = os.Remove(target)
		}
		return err
	}
	names, version, provides, err := packageArchiveMetadata(ctx, target)
	if err != nil {
		if created {
			_ = os.Remove(target)
		}
		return err
	}
	index, err := readArtifactIndex()
	if err != nil {
		return err
	}
	for artifactIndex, artifact := range index.Artifacts {
		if artifact.SHA256 == hash {
			if !containsStringExact(artifact.PolicyFingerprints, request.PolicyFingerprint) {
				index.Artifacts[artifactIndex].PolicyFingerprints = append(index.Artifacts[artifactIndex].PolicyFingerprints, request.PolicyFingerprint)
				sort.Strings(index.Artifacts[artifactIndex].PolicyFingerprints)
				return atomicWriteRootJSON(cleanRootPath("artifact-pool", "index.json"), index, 0o600)
			}
			return nil
		}
	}
	index.Artifacts = append(index.Artifacts, cleanRootArtifact{SHA256: hash, File: file, Names: names, Version: version, Provides: provides, PolicyFingerprints: []string{request.PolicyFingerprint}})
	sort.Slice(index.Artifacts, func(i, j int) bool { return index.Artifacts[i].SHA256 < index.Artifacts[j].SHA256 })
	return atomicWriteRootJSON(cleanRootPath("artifact-pool", "index.json"), index, 0o600)
}

func packageArchiveMetadata(ctx context.Context, artifact string) ([]string, string, []string, error) {
	fd, err := unix.Open(artifact, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, "", nil, err
	}
	input := os.NewFile(uintptr(fd), artifact)
	defer input.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Uid != cleanRootOwnerUID || int(stat.Gid) != cleanRootOwnerGID || stat.Mode&0o022 != 0 {
		return nil, "", nil, errors.New("package archive has unsafe ownership, mode, or type")
	}
	command := newCleanRootCommand(ctx, "/usr/bin/bsdtar", "-xOf", "-", ".PKGINFO")
	command.Stdin = input
	dropArchiveParserPrivileges(command, os.Geteuid())
	output := newLimitedBuffer(4 * 1024 * 1024)
	command.Stdout, command.Stderr = output, output
	if err := command.Run(); err != nil {
		return nil, "", nil, fmt.Errorf("read package metadata: %w: %s", err, truncate(output.String(), 1000))
	}
	var names, versions, provides []string
	scanner := bufio.NewScanner(bytes.NewReader(output.Bytes()))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), " = ")
		if !ok {
			continue
		}
		if key == "pkgver" {
			if validCleanRootVersion(value) {
				versions = append(versions, value)
			}
			continue
		}
		value = dependencyName(value)
		if !cleanRootDepRE.MatchString(value) {
			continue
		}
		switch key {
		case "pkgname":
			names = append(names, value)
		case "provides":
			provides = append(provides, value)
		}
	}
	if err := scanner.Err(); err != nil || len(names) != 1 || len(versions) != 1 {
		return nil, "", nil, errors.New("package archive has invalid metadata")
	}
	sort.Strings(provides)
	return names, versions[0], provides, nil
}

func dropArchiveParserPrivileges(command *exec.Cmd, effectiveUID int) {
	if effectiveUID == 0 {
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
			Uid: 65534, Gid: 65534, NoSetGroups: true,
		}}
		command.Env = []string{"HOME=/tmp", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "PATH=/usr/bin", "TMPDIR=/tmp"}
	}
}

func readArtifactIndex() (cleanRootArtifactIndex, error) {
	path := cleanRootPath("artifact-pool", "index.json")
	var index cleanRootArtifactIndex
	if err := ReadJSONFile(path, 16*1024*1024, &index); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cleanRootArtifactIndex{SchemaVersion: 1, Artifacts: []cleanRootArtifact{}}, nil
		}
		return index, err
	}
	if index.SchemaVersion != 1 || len(index.Artifacts) > 100000 {
		return index, errors.New("invalid clean-root artifact index")
	}
	seen := make(map[string]bool, len(index.Artifacts))
	for _, artifact := range index.Artifacts {
		if !validHexDigest(artifact.SHA256) || artifact.File != artifact.SHA256+".pkg.tar" || !validCleanRootVersion(artifact.Version) ||
			len(artifact.PolicyFingerprints) == 0 || len(artifact.PolicyFingerprints) > 1024 || len(artifact.Names) != 1 || len(artifact.Provides) > 4096 || seen[artifact.SHA256] {
			return index, errors.New("invalid clean-root artifact index entry")
		}
		seen[artifact.SHA256] = true
		seenPolicies := map[string]bool{}
		for _, policy := range artifact.PolicyFingerprints {
			if !validHexDigest(policy) || seenPolicies[policy] {
				return index, errors.New("invalid clean-root artifact policy identity")
			}
			seenPolicies[policy] = true
		}
		values := append(append([]string{}, artifact.Names...), artifact.Provides...)
		for _, value := range values {
			if len(value) > 512 || !cleanRootDepRE.MatchString(value) {
				return index, errors.New("invalid clean-root artifact identity")
			}
		}
	}
	return index, nil
}

func validCleanRootVersion(value string) bool {
	return value != "" && len(value) <= 512 && !strings.ContainsAny(value, "\x00\r\n\t ")
}

func selectDependencyArtifacts(dependencies []string, policy string) ([]cleanRootArtifact, []string, error) {
	index, err := readArtifactIndex()
	if err != nil {
		return nil, nil, err
	}
	var selected []cleanRootArtifact
	var official []string
	seenHashes := map[string]bool{}
	for _, dependency := range dependencies {
		name := dependencyName(dependency)
		var exact, providers []cleanRootArtifact
		for _, artifact := range index.Artifacts {
			if !containsStringExact(artifact.PolicyFingerprints, policy) {
				continue
			}
			if containsString(artifact.Names, name) {
				exact = append(exact, artifact)
			} else if containsString(artifact.Provides, name) {
				providers = append(providers, artifact)
			}
		}
		candidates := exact
		if len(candidates) == 0 {
			candidates = providers
		}
		if len(candidates) > 1 {
			return nil, nil, fmt.Errorf("ambiguous sealed provider for dependency %q", dependency)
		}
		if len(candidates) == 1 {
			if !seenHashes[candidates[0].SHA256] {
				selected = append(selected, candidates[0])
				seenHashes[candidates[0].SHA256] = true
			}
		} else {
			official = append(official, dependency)
		}
	}
	return selected, official, nil
}

func dependencyName(value string) string {
	for index, character := range value {
		if character == '<' || character == '>' || character == '=' {
			return value[:index]
		}
	}
	return value
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if dependencyName(value) == wanted {
			return true
		}
	}
	return false
}

func containsStringExact(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func copyVerifiedFile(source, target, expected string, mode os.FileMode) error {
	fd, err := unix.Open(source, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	input := os.NewFile(uintptr(fd), source)
	defer input.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("artifact copy source is not a regular file")
	}
	output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(output, hash), input)
	closeErr := output.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(target)
		return errors.New("copy artifact failed")
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected {
		_ = os.Remove(target)
		return errors.New("copied artifact hash mismatch")
	}
	return os.Chmod(target, mode)
}

func atomicWriteRootJSON(path string, value any, mode os.FileMode) error {
	raw, err := CanonicalJSON(value)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".root-state-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if temporary.Chmod(mode) != nil {
		temporary.Close()
		return errors.New("cannot secure root state file")
	}
	if _, err := temporary.Write(append(raw, '\n')); err != nil || temporary.Sync() != nil || temporary.Close() != nil {
		return errors.New("cannot write root state file")
	}
	return os.Rename(name, path)
}

func validatePreparedRoot(path string) error {
	clean := filepath.Clean(path)
	if clean != path || !strings.HasPrefix(clean, cleanRootPath("build-jobs")+string(os.PathSeparator)) || filepath.Base(clean) != "root" {
		return errors.New("unsafe prepared root path")
	}
	file, err := openRootOwnedDirectoryHandle(clean)
	if err != nil {
		return err
	}
	return file.Close()
}

func cleanRootDependencies(context YayContext) []string {
	seen := map[string]bool{}
	var result []string
	for _, values := range [][]string{context.Depends, context.MakeDepends, context.CheckDepends} {
		for _, value := range values {
			if !seen[value] {
				seen[value] = true
				result = append(result, value)
			}
		}
	}
	sort.Strings(result)
	return result
}

func cleanRootRequestFor(operation string) CleanRootRequest {
	return CleanRootRequest{ProtocolVersion: CleanRootProtocolVersion, Operation: operation, CallerUID: uint32(os.Getuid())}
}

func newCleanRootCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	command := cleanRootCommand(ctx, name, args...)
	command.Env = []string{"HOME=/root", "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "PATH=/usr/bin", "TMPDIR=/tmp", "USER=root"}
	return command
}

func configureCleanRootProcessGroup(command *exec.Cmd) {
	if command.SysProcAttr == nil {
		command.SysProcAttr = &syscall.SysProcAttr{}
	}
	command.SysProcAttr.Setpgid = true
	command.Cancel = func() error {
		return terminateCleanRootProcessGroup(command)
	}
	command.WaitDelay = 5 * time.Second
}

func terminateCleanRootProcessGroup(command *exec.Cmd) error {
	if command.Process == nil {
		return os.ErrProcessDone
	}
	if err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	return nil
}

func cleanRootFailureOutput(value string) string {
	const limit = 8 * 1024
	const marker = "[earlier mkarchroot output omitted]\n"
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return marker + value[len(value)-(limit-len(marker)):]
}

func cleanRootWithTimeout(parent context.Context, seconds int) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, time.Duration(seconds)*time.Second)
}

func cleanRootOperationContext(parent context.Context, operation string, seconds int) (context.Context, context.CancelFunc) {
	if operation == "init" || operation == "update" {
		return context.WithCancel(parent)
	}
	return cleanRootWithTimeout(parent, seconds)
}

func cleanRootDiskUsage(root string, limit int64) error {
	if limit <= 0 {
		return errors.New("clean-root disk limit is exhausted")
	}
	var total int64
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if info.Size() < 0 || total > limit-info.Size() {
				return errors.New("prepared clean root exceeds disk limit")
			}
			total += info.Size()
		}
		return nil
	})
	return err
}

func runCleanRootCLI(ctx context.Context, args []string) int {
	if len(args) != 1 || (args[0] != "status" && args[0] != "init" && args[0] != "update" && args[0] != "prune") {
		return cliError(20, errors.New("clean-root requires exactly one of: status, init, update, prune"))
	}
	operation := args[0]
	request := cleanRootRequestFor(operation)
	var response CleanRootResponse
	var err error
	if os.Geteuid() == 0 {
		caller, parseErr := strconv.ParseUint(os.Getenv("SUDO_UID"), 10, 32)
		if parseErr != nil || caller == 0 {
			return cliError(20, errors.New("run clean-root root operations through sudo from a non-root account"))
		}
		request.CallerUID = uint32(caller)
		if operation == "prune" {
			info, _ := os.Stdin.Stat()
			if info == nil || info.Mode()&os.ModeCharDevice == 0 {
				return cliError(20, errors.New("clean-root prune requires a real TTY"))
			}
			fmt.Fprintln(os.Stderr, "This removes disposable prepared roots for the invoking user. Confirm that no Prolewatch build is still active.")
			fmt.Fprint(os.Stderr, "Type PRUNE to continue: ")
			answer, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			if strings.TrimSpace(answer) != "PRUNE" {
				return cliError(20, errors.New("clean-root prune declined"))
			}
		}
		response, err = executeCleanRootRequest(ctx, request)
	} else {
		if operation != "status" {
			return cliError(20, errors.New("clean-root init, update, and prune must be run with sudo"))
		}
		response, err = cleanRootDispatcher(ctx, request)
	}
	if err != nil {
		return cliError(24, err)
	}
	if operation == "prune" {
		fmt.Println(rendererFor(os.Stdout).successLine(fmt.Sprintf("Removed %d disposable prepared clean-root job(s).", response.RemovedJobs)))
		return 0
	}
	if !response.Identity.Available {
		fmt.Println(rendererFor(os.Stdout).blockLine("Clean build root is not initialized."))
		return 24
	}
	fmt.Println(rendererFor(os.Stdout).successLine(fmt.Sprintf("Clean build root: generation=%s manifest=%s", response.Identity.Generation, response.Identity.ManifestSHA256)))
	if operation == "init" || operation == "update" {
		fmt.Println(rendererFor(os.Stdout).detailLine("The policy fingerprint changed; run prolewatch doctor before the next build."))
	}
	return 0
}

func rootPathOnSameFilesystem(a, b string) bool {
	var left, right unix.Statfs_t
	return unix.Statfs(a, &left) == nil && unix.Statfs(b, &right) == nil && left.Type == right.Type
}
