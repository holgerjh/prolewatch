package audit

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func withCleanRootState(t *testing.T) string {
	t.Helper()
	previous, previousOwner, previousGroup := cleanRootStateRoot, cleanRootOwnerUID, cleanRootOwnerGID
	root := t.TempDir()
	cleanRootStateRoot = root
	cleanRootOwnerUID = uint32(os.Getuid())
	cleanRootOwnerGID = os.Getgid()
	t.Cleanup(func() {
		cleanRootStateRoot = previous
		cleanRootOwnerUID = previousOwner
		cleanRootOwnerGID = previousGroup
	})
	return root
}

func withCleanRootCommand(t *testing.T, command func(context.Context, string, ...string) *exec.Cmd) {
	t.Helper()
	previous := cleanRootCommand
	cleanRootCommand = command
	t.Cleanup(func() { cleanRootCommand = previous })
}

func cleanRootTestCommand(t *testing.T) func(context.Context, string, ...string) *exec.Cmd {
	t.Helper()
	return func(ctx context.Context, name string, args ...string) *exec.Cmd {
		switch name {
		case "/usr/bin/cp":
			return exec.CommandContext(ctx, name, args...)
		case "/usr/bin/mkarchroot":
			if len(args) > 0 && args[0] == "--version" {
				return exec.CommandContext(ctx, "/usr/bin/printf", "mkarchroot test\n")
			}
			generation := args[0]
			if _, err := os.Lstat(generation); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("mkarchroot target existed before invocation: %s", generation)
			}
			if err := os.Mkdir(generation, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(generation, "etc"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(generation, "etc", "pacman.conf"), []byte("[core]\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			return exec.CommandContext(ctx, "/usr/bin/true")
		case "/usr/bin/bwrap":
			joined := strings.Join(args, " ")
			switch {
			case strings.Contains(joined, "/usr/bin/pacman-conf"):
				return exec.CommandContext(ctx, "/usr/bin/printf", "[options]\nHookDir = /etc/pacman.d/hooks/\nArchitecture = x86_64\n[core]\nServer = https://example.invalid/core\n")
			case strings.Contains(joined, "/usr/bin/pacman -T"):
				return exec.CommandContext(ctx, "/usr/bin/sh", "-c", "printf 'glibc\\n'; exit 127")
			case strings.Contains(joined, "/usr/bin/pacman --version"):
				return exec.CommandContext(ctx, "/usr/bin/printf", "\n .--. Pacman v7.1.0\n")
			case strings.Contains(joined, "/usr/bin/pacman -Q"):
				return exec.CommandContext(ctx, "/usr/bin/printf", "base-devel 1.0-1\n")
			default:
				return exec.CommandContext(ctx, "/usr/bin/true")
			}
		case "/usr/bin/pacman":
			return exec.CommandContext(ctx, "/usr/bin/printf", "pacman test\n")
		case "/usr/bin/bsdtar":
			return exec.CommandContext(ctx, "/usr/bin/printf", "pkgname = aur-dep\npkgver = 1.0-1\nprovides = virtual-dep=1\n")
		default:
			return exec.CommandContext(ctx, "/usr/bin/false")
		}
	}
}

func TestVersionOutputTextUsesFirstNonEmptyLine(t *testing.T) {
	if got := versionOutputText([]byte("\n\t\n .--. Pacman v7.1.0\nmore\n")); got != ".--. Pacman v7.1.0" {
		t.Fatalf("unexpected version text: %q", got)
	}
	if got := versionOutputText([]byte("\n\t\n")); got != "unknown" {
		t.Fatalf("empty version output was not normalized: %q", got)
	}
}

func TestCleanRootRequestValidation(t *testing.T) {
	policy := strings.Repeat("a", 64)
	hash := strings.Repeat("b", 64)
	valid := []CleanRootRequest{
		{ProtocolVersion: CleanRootProtocolVersion, Operation: "status", CallerUID: 1001},
		{ProtocolVersion: CleanRootProtocolVersion, Operation: "init", CallerUID: 1001},
		{ProtocolVersion: CleanRootProtocolVersion, Operation: "update", CallerUID: 1001},
		{ProtocolVersion: CleanRootProtocolVersion, Operation: "prune", CallerUID: 1001},
		{ProtocolVersion: CleanRootProtocolVersion, Operation: "prepare", CallerUID: 1001, Dependencies: []string{"glibc>=2", "go"}, PolicyFingerprint: policy},
		{ProtocolVersion: CleanRootProtocolVersion, Operation: "cleanup", CallerUID: 1001, Token: "1001-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{ProtocolVersion: CleanRootProtocolVersion, Operation: "import-artifact", CallerUID: 1001, ArtifactPath: "/tmp/demo.pkg.tar.zst", ArtifactSHA256: hash, PolicyFingerprint: policy},
	}
	for _, request := range valid {
		if err := request.Validate(); err != nil {
			t.Errorf("valid %s request rejected: %v", request.Operation, err)
		}
	}
	invalid := []CleanRootRequest{
		{ProtocolVersion: CleanRootProtocolVersion + 1, Operation: "status", CallerUID: 1001},
		{ProtocolVersion: CleanRootProtocolVersion, Operation: "status", CallerUID: 0},
		{ProtocolVersion: CleanRootProtocolVersion, Operation: "status", CallerUID: 1001, Token: "1001-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{ProtocolVersion: CleanRootProtocolVersion, Operation: "prepare", CallerUID: 1001, Dependencies: []string{"$(id)"}, PolicyFingerprint: policy},
		{ProtocolVersion: CleanRootProtocolVersion, Operation: "prepare", CallerUID: 1001, PolicyFingerprint: "short"},
		{ProtocolVersion: CleanRootProtocolVersion, Operation: "cleanup", CallerUID: 1001, Token: "../../root"},
		{ProtocolVersion: CleanRootProtocolVersion, Operation: "import-artifact", CallerUID: 1001, ArtifactPath: "relative", ArtifactSHA256: hash, PolicyFingerprint: policy},
		{ProtocolVersion: CleanRootProtocolVersion, Operation: "shell", CallerUID: 1001},
	}
	for index, request := range invalid {
		if err := request.Validate(); err == nil {
			t.Errorf("invalid clean-root request %d accepted", index)
		}
	}
}

func TestCleanRootManifestBindsEveryField(t *testing.T) {
	manifest := validTestCleanRootManifest()
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*CleanRootManifest){
		func(value *CleanRootManifest) { value.SchemaVersion++ },
		func(value *CleanRootManifest) { value.Generation = "1001-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
		func(value *CleanRootManifest) { value.BaseManifestHash = strings.Repeat("e", 64) },
		func(value *CleanRootManifest) { value.PolicyFingerprint = strings.Repeat("e", 64) },
		func(value *CleanRootManifest) { value.StagingBackend = "arch-chroot" },
		func(value *CleanRootManifest) { value.HookPolicy = "enabled" },
		func(value *CleanRootManifest) { value.ArtifactTrust = "trusted" },
		func(value *CleanRootManifest) { value.Packages = append(value.Packages, "go=1") },
		func(value *CleanRootManifest) {
			value.ArtifactHashes = append(value.ArtifactHashes, strings.Repeat("e", 64))
		},
		func(value *CleanRootManifest) { value.PacmanConfigHash = strings.Repeat("e", 64) },
		func(value *CleanRootManifest) { value.PacmanVersion = "changed" },
		func(value *CleanRootManifest) { value.MkarchrootVersion = "changed" },
	}
	for index, mutate := range mutations {
		copy := *manifest
		copy.Packages = append([]string{}, manifest.Packages...)
		copy.ArtifactHashes = append([]string{}, manifest.ArtifactHashes...)
		mutate(&copy)
		if err := copy.Validate(); err == nil {
			t.Errorf("clean-root manifest mutation %d accepted", index)
		}
	}
}

func TestHardenCleanRootPacmanConfigDisablesEveryHookSource(t *testing.T) {
	raw := []byte("[options]\nHookDir = /etc/pacman.d/hooks/\nHookDir = /custom/hooks/\nDownloadUser = alpm\nNoExtract = !usr/share/libalpm/hooks/keep.hook\nArchitecture = x86_64\n[core]\nServer = https://mirror.invalid/core\n")
	hardened, err := hardenCleanRootPacmanConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	text := string(hardened)
	if strings.Count(text, "HookDir =") != 1 || !strings.Contains(text, "HookDir = /etc/pacman.d/hooks/\n") {
		t.Fatalf("hook directories were not reduced to one controlled path: %s", text)
	}
	if strings.Contains(text, "DownloadUser") || strings.Contains(text, "DisableSandbox") {
		t.Fatalf("host download identity survived or pacman's sandbox was disabled: %s", text)
	}
	for _, required := range []string{
		"NoExtract = usr/share/libalpm/hooks/*",
		"NoExtract = etc/pacman.d/hooks/*",
		"NoExtract = etc/pacman.conf",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("missing mandatory pacman policy %q: %s", required, text)
		}
	}
	if strings.Index(text, "NoExtract = !usr/share/libalpm/hooks/keep.hook") > strings.Index(text, "NoExtract = usr/share/libalpm/hooks/*") {
		t.Fatalf("a pre-existing whitelist can override the mandatory hook exclusion: %s", text)
	}
	if strings.Index(text, "NoExtract = etc/pacman.conf") > strings.Index(text, "[core]") {
		t.Fatalf("mandatory options were emitted outside [options]: %s", text)
	}
}

func TestHardenOfficialCleanRootPacmanConfigAllowsOnlySystemHooks(t *testing.T) {
	raw := []byte("[options]\nHookDir = /custom/hooks/\nDownloadUser = alpm\n[core]\nServer = https://mirror.invalid/core\n")
	hardened, err := hardenOfficialCleanRootPacmanConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	text := string(hardened)
	if strings.Contains(text, "NoExtract = usr/share/libalpm/hooks/*") {
		t.Fatalf("official system hooks were disabled: %s", text)
	}
	if strings.Count(text, "HookDir =") != 1 || !strings.Contains(text, "HookDir = /etc/pacman.d/hooks/\n") ||
		!strings.Contains(text, "NoExtract = etc/pacman.d/hooks/*") || !strings.Contains(text, "NoExtract = etc/pacman.conf") {
		t.Fatalf("custom hook policy was not enforced for official packages: %s", text)
	}
	if strings.Contains(text, "DownloadUser") || strings.Contains(text, "DisableSandbox") {
		t.Fatalf("official staging retained an unmapped user or disabled pacman's sandbox: %s", text)
	}
}

func TestHardenCleanRootPacmanConfigRejectsUnresolvedOrMalformedInput(t *testing.T) {
	invalid := [][]byte{
		{},
		[]byte("[core]\nServer = https://mirror.invalid/core\n"),
		[]byte("[options]\n[options]\n"),
		[]byte("[options]\nInclude = /etc/pacman.d/mirrorlist\n"),
		append([]byte("[options]\n"), 0),
		bytes.Repeat([]byte("x"), maxPacmanConfigBytes+1),
	}
	for index, raw := range invalid {
		if _, err := hardenCleanRootPacmanConfig(raw); err == nil {
			t.Errorf("invalid pacman configuration %d was accepted", index)
		}
	}
}

func TestCleanRootHookMountTargetsRejectSymlinks(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "usr", "share", "libalpm", "hooks")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), target); err != nil {
		t.Fatal(err)
	}
	if err := ensureCleanRootMountDirectory(root, "usr/share/libalpm/hooks"); err == nil {
		t.Fatal("symlinked clean-root hook mount target was accepted")
	}
}

func TestCleanRootFileMountTargetsAreSafePlaceholders(t *testing.T) {
	root := withCleanRootState(t)
	if err := os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ensureCleanRootMountFile(root, "usr/bin/prolewatch-net"); err != nil {
		t.Fatal(err)
	}
	placeholder := filepath.Join(root, "usr", "bin", "prolewatch-net")
	info, err := os.Lstat(placeholder)
	if err != nil || !info.Mode().IsRegular() || info.Size() != 0 || info.Mode().Perm() != 0 {
		t.Fatalf("unsafe clean-root mount placeholder: %#v %v", info, err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(placeholder); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, placeholder); err != nil {
		t.Fatal(err)
	}
	if err := ensureCleanRootMountFile(root, "usr/bin/prolewatch-net"); err == nil {
		t.Fatal("symlinked clean-root file mount target was accepted")
	}
	raw, err := os.ReadFile(outside)
	if err != nil || string(raw) != "unchanged" {
		t.Fatalf("mount target validation modified symlink target: %q %v", raw, err)
	}
}

func TestReplaceCleanRootPacmanConfigRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "pacman.conf")
	outside := filepath.Join(t.TempDir(), "outside.conf")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, config); err != nil {
		t.Fatal(err)
	}
	if err := replaceCleanRootFile(config, []byte("changed"), 0o400, true); err == nil {
		t.Fatal("symlinked clean-root pacman configuration was accepted")
	}
	raw, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "unchanged" {
		t.Fatalf("symlink target was modified: %q", raw)
	}
}

func TestCleanRootArtifactSelectionIsPolicyBound(t *testing.T) {
	root := withCleanRootState(t)
	pool := filepath.Join(root, "artifact-pool")
	if err := os.MkdirAll(pool, 0o700); err != nil {
		t.Fatal(err)
	}
	policy := strings.Repeat("a", 64)
	index := cleanRootArtifactIndex{SchemaVersion: 1, Artifacts: []cleanRootArtifact{
		{SHA256: strings.Repeat("b", 64), File: strings.Repeat("b", 64) + ".pkg.tar", Names: []string{"aur-dep"}, Version: "1-1", Provides: []string{"virtual-dep=1"}, PolicyFingerprints: []string{policy}},
		{SHA256: strings.Repeat("c", 64), File: strings.Repeat("c", 64) + ".pkg.tar", Names: []string{"old-dep"}, Version: "1-1", Provides: []string{}, PolicyFingerprints: []string{strings.Repeat("d", 64)}},
	}}
	if err := atomicWriteRootJSON(filepath.Join(pool, "index.json"), index, 0o600); err != nil {
		t.Fatal(err)
	}
	sealed, official, err := selectDependencyArtifacts([]string{"aur-dep>=1", "virtual-dep", "glibc"}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) != 1 || sealed[0].Names[0] != "aur-dep" || len(official) != 1 || official[0] != "glibc" {
		t.Fatalf("unexpected dependency selection: sealed=%#v official=%#v", sealed, official)
	}
	index.Artifacts = append(index.Artifacts, cleanRootArtifact{SHA256: strings.Repeat("e", 64), File: strings.Repeat("e", 64) + ".pkg.tar", Names: []string{"another"}, Version: "1-1", Provides: []string{"virtual-dep"}, PolicyFingerprints: []string{policy}})
	if err := atomicWriteRootJSON(filepath.Join(pool, "index.json"), index, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := selectDependencyArtifacts([]string{"virtual-dep"}, policy); err == nil {
		t.Fatal("ambiguous sealed dependency provider accepted")
	}
}

func TestMissingCleanRootDependenciesSkipsSatisfiedPackages(t *testing.T) {
	withCleanRootCommand(t, func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if name != "/usr/bin/bwrap" {
			return exec.CommandContext(ctx, "/usr/bin/false")
		}
		joined := strings.Join(args, " ")
		if strings.HasSuffix(joined, "pacman -T -- glib2") {
			return exec.CommandContext(ctx, "/usr/bin/true")
		}
		if strings.HasSuffix(joined, "pacman -T -- glib2 nasm") {
			return exec.CommandContext(ctx, "/usr/bin/sh", "-c", "printf 'nasm\\n'; exit 127")
		}
		return exec.CommandContext(ctx, "/usr/bin/false")
	})
	satisfied, err := missingCleanRootDependencies(context.Background(), t.TempDir(), []string{"glib2"})
	if err != nil || len(satisfied) != 0 {
		t.Fatalf("satisfied dependency was not filtered: %#v %v", satisfied, err)
	}
	missing, err := missingCleanRootDependencies(context.Background(), t.TempDir(), []string{"glib2", "nasm"})
	if err != nil || len(missing) != 1 || missing[0] != "nasm" {
		t.Fatalf("missing dependency was not preserved: %#v %v", missing, err)
	}
}

func TestCleanRootHelpersRejectUnsafeState(t *testing.T) {
	root := withCleanRootState(t)
	jobs := filepath.Join(root, "build-jobs")
	pool := filepath.Join(root, "artifact-pool")
	if err := os.MkdirAll(jobs, 0o711); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(pool, 0o700); err != nil {
		t.Fatal(err)
	}
	token := "1001-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := os.Mkdir(filepath.Join(jobs, token), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := cleanupCleanRoot(1002, token); err == nil {
		t.Fatal("another caller's clean root was removable")
	}
	if err := cleanupCleanRoot(1001, token); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(jobs, token)); !os.IsNotExist(err) {
		t.Fatal("clean-root job was not removed")
	}

	source := filepath.Join(root, "source")
	if err := os.WriteFile(source, []byte("artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(pool, "copy")
	if err := copyVerifiedFile(source, target, SHA256Bytes([]byte("artifact")), 0o400); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "source-link")
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	if err := copyVerifiedFile(link, filepath.Join(pool, "link-copy"), SHA256Bytes([]byte("artifact")), 0o400); err == nil {
		t.Fatal("symlinked artifact source accepted")
	}
	badTarget := filepath.Join(pool, "bad-hash-copy")
	if err := copyVerifiedFile(source, badTarget, strings.Repeat("f", 64), 0o400); err == nil {
		t.Fatal("artifact copy with the wrong expected hash succeeded")
	}
	if _, err := os.Stat(badTarget); !os.IsNotExist(err) {
		t.Fatal("failed artifact copy was not removed")
	}
	if err := cleanRootDiskUsage(pool, 1); err == nil {
		t.Fatal("clean-root disk overflow accepted")
	}

	bad := cleanRootArtifactIndex{SchemaVersion: 1, Artifacts: []cleanRootArtifact{{SHA256: strings.Repeat("a", 64), File: "different.pkg.tar", Names: []string{"demo"}, Version: "1-1", PolicyFingerprints: []string{strings.Repeat("b", 64)}}}}
	if err := atomicWriteRootJSON(filepath.Join(pool, "index.json"), bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readArtifactIndex(); err == nil {
		t.Fatal("unsafe artifact index entry accepted")
	}
}

func TestPackageArchiveMetadataFailsClosed(t *testing.T) {
	previous := cleanRootCommand
	t.Cleanup(func() { cleanRootCommand = previous })
	cleanRootCommand = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/usr/bin/false")
	}
	if _, _, _, err := packageArchiveMetadata(context.Background(), "/tmp/missing"); err == nil {
		t.Fatal("failed package metadata command accepted")
	}
	cleanRootCommand = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "/usr/bin/printf", "pkgname = demo\n")
	}
	if _, _, _, err := packageArchiveMetadata(context.Background(), "/tmp/incomplete"); err == nil {
		t.Fatal("incomplete package metadata accepted")
	}
}

func TestPackageArchiveMetadataReadsOpenedDescriptor(t *testing.T) {
	root := withCleanRootState(t)
	artifact := filepath.Join(root, "demo.pkg.tar")
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	metadata := []byte("pkgname = demo\npkgver = 1.0-1\nprovides = virtual-demo=1\n")
	if err := writer.WriteHeader(&tar.Header{Name: ".PKGINFO", Mode: 0o400, Size: int64(len(metadata))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(metadata); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifact, archive.Bytes(), 0o400); err != nil {
		t.Fatal(err)
	}
	names, version, provides, err := packageArchiveMetadata(context.Background(), artifact)
	if err != nil || len(names) != 1 || names[0] != "demo" || version != "1.0-1" || len(provides) != 1 || provides[0] != "virtual-demo" {
		t.Fatalf("package metadata mismatch: %#v %q %#v %v", names, version, provides, err)
	}
}

func TestRootArchiveParserDropsPrivileges(t *testing.T) {
	command := exec.Command("/usr/bin/true")
	dropArchiveParserPrivileges(command, 0)
	credential := command.SysProcAttr.Credential
	if credential == nil || credential.Uid != 65534 || credential.Gid != 65534 || !credential.NoSetGroups {
		t.Fatalf("root archive parser retained privilege: %#v", command.SysProcAttr)
	}
	if strings.Join(command.Env, "\n") != "HOME=/tmp\nLANG=C.UTF-8\nLC_ALL=C.UTF-8\nPATH=/usr/bin\nTMPDIR=/tmp" {
		t.Fatalf("unexpected archive parser environment: %#v", command.Env)
	}

	unprivileged := exec.Command("/usr/bin/true")
	dropArchiveParserPrivileges(unprivileged, os.Getuid())
	if unprivileged.SysProcAttr != nil {
		t.Fatal("unprivileged test command received an unusable credential transition")
	}
}

func TestPrepareCleanRootInstallsAURLast(t *testing.T) {
	root := withCleanRootState(t)
	baseCommand := cleanRootTestCommand(t)
	var sandboxCalls []string
	withCleanRootCommand(t, func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if name == "/usr/bin/bwrap" {
			sandboxCalls = append(sandboxCalls, strings.Join(args, " "))
		}
		return baseCommand(ctx, name, args...)
	})
	baseToken := "1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	base := filepath.Join(root, "build-roots", "generations", baseToken)
	for _, path := range []string{filepath.Join(base, "etc"), filepath.Join(base, "var", "empty"), filepath.Join(root, "build-jobs"), filepath.Join(root, "artifact-pool")} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(base, "etc", "pacman.conf"), []byte("[core]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	active := cleanRootActive{SchemaVersion: 1, Generation: baseToken, ManifestHash: strings.Repeat("b", 64)}
	if err := atomicWriteRootJSON(filepath.Join(root, "build-roots", "active.json"), active, 0o600); err != nil {
		t.Fatal(err)
	}
	artifactContent := []byte("sealed dependency")
	artifactHash := SHA256Bytes(artifactContent)
	artifactFile := artifactHash + ".pkg.tar"
	if err := os.WriteFile(filepath.Join(root, "artifact-pool", artifactFile), artifactContent, 0o400); err != nil {
		t.Fatal(err)
	}
	index := cleanRootArtifactIndex{SchemaVersion: 1, Artifacts: []cleanRootArtifact{{SHA256: artifactHash, File: artifactFile, Names: []string{"aur-dep"}, Version: "1.0-1", Provides: []string{}, PolicyFingerprints: []string{strings.Repeat("c", 64)}}}}
	if err := atomicWriteRootJSON(filepath.Join(root, "artifact-pool", "index.json"), index, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	request := CleanRootRequest{ProtocolVersion: CleanRootProtocolVersion, Operation: "prepare", CallerUID: uint32(os.Getuid()), Dependencies: []string{"glibc", "aur-dep"}, PolicyFingerprint: strings.Repeat("c", 64)}
	token, prepared, manifest, err := prepareCleanRoot(context.Background(), request, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, stringCallerUID()+"-") || prepared != filepath.Join(root, "build-jobs", token, "root") || manifest.Validate() != nil {
		t.Fatalf("invalid prepared root response: %q %q %#v", token, prepared, manifest)
	}
	if len(manifest.Packages) != 2 || manifest.Packages[0] != "aur-dep=1.0-1" || manifest.Packages[1] != "base-devel=1.0-1" {
		t.Fatalf("unexpected clean-root packages: %#v", manifest.Packages)
	}
	if len(sandboxCalls) != 6 || !strings.Contains(sandboxCalls[0], "pacman-conf") || !strings.Contains(sandboxCalls[1], "pacman -T") || !strings.Contains(sandboxCalls[2], "pacman -S") || !strings.Contains(sandboxCalls[3], "pacman -Q") || !strings.Contains(sandboxCalls[4], "pacman --version") || !strings.Contains(sandboxCalls[5], "pacman -U") {
		t.Fatalf("unsafe clean-root command ordering: %#v", sandboxCalls)
	}
	if strings.Contains(sandboxCalls[1], "--share-net") || !strings.Contains(sandboxCalls[2], "--share-net") || strings.Contains(sandboxCalls[5], "--share-net") ||
		!strings.Contains(sandboxCalls[2], "--tmpfs /run") || !strings.Contains(sandboxCalls[5], "--tmpfs /run") ||
		strings.Contains(sandboxCalls[2], " /usr/share/libalpm/hooks") || !strings.Contains(sandboxCalls[2], " /etc/pacman.d/hooks") ||
		!strings.Contains(sandboxCalls[5], "--ro-bind "+filepath.Join(root, "build-jobs", token, "disabled-hooks")+" /usr/share/libalpm/hooks") ||
		!strings.Contains(sandboxCalls[5], " /etc/pacman.d/hooks") || !strings.Contains(sandboxCalls[5], "--noscriptlet") ||
		strings.Contains(sandboxCalls[2], "--hookdir") || strings.Contains(sandboxCalls[5], "--hookdir") ||
		strings.Contains(sandboxCalls[2], "CAP_SYS_ADMIN") || strings.Contains(sandboxCalls[5], "CAP_SYS_ADMIN") {
		t.Fatalf("clean-root sandbox policy mismatch: %#v", sandboxCalls)
	}
	hardened, err := os.ReadFile(filepath.Join(prepared, "etc", "pacman.conf"))
	if err != nil {
		t.Fatal(err)
	}
	configInfo, err := os.Stat(filepath.Join(prepared, "etc", "pacman.conf"))
	if err != nil || configInfo.Mode().Perm() != cleanRootPacmanConfigMode {
		t.Fatalf("prepared pacman configuration is unreadable to the normal build user: %#v %v", configInfo, err)
	}
	if !bytes.Contains(hardened, []byte("NoExtract = usr/share/libalpm/hooks/*")) ||
		!bytes.Contains(hardened, []byte("NoExtract = etc/pacman.d/hooks/*")) ||
		SHA256Bytes(hardened) != manifest.PacmanConfigHash || manifest.StagingBackend != cleanRootStagingBackend ||
		manifest.HookPolicy != cleanRootHookPolicy || manifest.ArtifactTrust != cleanRootArtifactTrust {
		t.Fatalf("prepared root did not retain hardened staging provenance: %#v\n%s", manifest, hardened)
	}
	if err := cleanupCleanRoot(uint32(os.Getuid()), token); err != nil {
		t.Fatal(err)
	}
}

func TestCreateCleanRootGenerationAndBaseManifest(t *testing.T) {
	root := withCleanRootState(t)
	command := cleanRootTestCommand(t)
	withCleanRootCommand(t, func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if name == "/usr/bin/mkarchroot" {
			return command(ctx, name, args...)
		}
		if name == "/usr/bin/bwrap" {
			return command(ctx, name, args...)
		}
		return command(ctx, name, args...)
	})
	if err := os.MkdirAll(filepath.Join(root, "build-roots", "generations"), 0o700); err != nil {
		t.Fatal(err)
	}
	identity, err := createCleanRootGeneration(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !identity.Available || !cleanRootTokenRE.MatchString(identity.Generation) || !validHexDigest(identity.ManifestSHA256) {
		t.Fatalf("invalid generation identity: %#v", identity)
	}
	generation := filepath.Join(root, "build-roots", "generations", identity.Generation)
	info, statErr := os.Stat(generation)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("new generation mode=%v, want 0700", info.Mode().Perm())
	}
	var active cleanRootActive
	if err := ReadJSONFile(filepath.Join(root, "build-roots", "active.json"), 64*1024, &active); err != nil || active.Generation != identity.Generation {
		t.Fatalf("active generation not committed: %#v %v", active, err)
	}
}

func TestCreateCleanRootGenerationReportsEndOfMkarchrootFailure(t *testing.T) {
	root := withCleanRootState(t)
	if err := os.MkdirAll(filepath.Join(root, "build-roots", "generations"), 0o700); err != nil {
		t.Fatal(err)
	}
	finalError := "final pacman failure"
	commandOutput := "Create subvolume\n" + strings.Repeat("package progress\n", 1024) + finalError + "\n"
	withCleanRootCommand(t, func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if name != "/usr/bin/mkarchroot" {
			t.Fatalf("unexpected command after failed mkarchroot: %s", name)
		}
		return exec.CommandContext(ctx, "/usr/bin/sh", "-c", `printf '%s' "$1"; exit 1`, "sh", commandOutput)
	})

	_, err := createCleanRootGeneration(context.Background(), true)
	if err == nil || !strings.Contains(err.Error(), finalError) {
		t.Fatalf("mkarchroot error omitted its final cause: %v", err)
	}
	if !strings.Contains(err.Error(), "earlier mkarchroot output omitted") {
		t.Fatalf("mkarchroot error did not mark truncated output: %v", err)
	}
}

func TestImportCleanRootArtifactAndMetadata(t *testing.T) {
	root := withCleanRootState(t)
	withCleanRootCommand(t, cleanRootTestCommand(t))
	pool := filepath.Join(root, "artifact-pool")
	if err := os.MkdirAll(pool, 0o700); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(root, "demo.pkg.tar.zst")
	content := []byte("synthetic package")
	if err := os.WriteFile(artifact, content, 0o600); err != nil {
		t.Fatal(err)
	}
	request := CleanRootRequest{ProtocolVersion: CleanRootProtocolVersion, Operation: "import-artifact", CallerUID: uint32(os.Getuid()), ArtifactPath: artifact, ArtifactSHA256: SHA256Bytes(content), PolicyFingerprint: strings.Repeat("a", 64)}
	cfg := DefaultConfig()
	if err := importCleanRootArtifact(context.Background(), request, cfg); err != nil {
		t.Fatal(err)
	}
	if err := importCleanRootArtifact(context.Background(), request, cfg); err != nil {
		t.Fatal(err)
	}
	request.PolicyFingerprint = strings.Repeat("d", 64)
	if err := importCleanRootArtifact(context.Background(), request, cfg); err != nil {
		t.Fatal(err)
	}
	index, err := readArtifactIndex()
	if err != nil || len(index.Artifacts) != 1 || index.Artifacts[0].Version != "1.0-1" || len(index.Artifacts[0].PolicyFingerprints) != 2 {
		t.Fatalf("unexpected imported artifact index: %#v %v", index, err)
	}
	if err := os.Chmod(artifact, 0o606); err != nil {
		t.Fatal(err)
	}
	if err := importCleanRootArtifact(context.Background(), request, cfg); err == nil {
		t.Fatal("world-writable artifact import accepted")
	}
	second := filepath.Join(root, "second.pkg.tar.zst")
	secondContent := []byte("second package")
	if err := os.WriteFile(second, secondContent, 0o600); err != nil {
		t.Fatal(err)
	}
	secondHash := SHA256Bytes(secondContent)
	if err := os.WriteFile(filepath.Join(pool, secondHash+".pkg.tar"), []byte("wrong cache content"), 0o400); err != nil {
		t.Fatal(err)
	}
	secondRequest := request
	secondRequest.ArtifactPath, secondRequest.ArtifactSHA256 = second, secondHash
	if err := importCleanRootArtifact(context.Background(), secondRequest, cfg); err == nil {
		t.Fatal("mismatched existing artifact cache entry accepted")
	}
	directoryRequest := request
	directoryRequest.ArtifactPath = root
	if err := importCleanRootArtifact(context.Background(), directoryRequest, cfg); err == nil {
		t.Fatal("directory artifact import accepted")
	}
}

func TestCleanRootCommandAndCLIErrorPaths(t *testing.T) {
	withCleanRootState(t)
	if token, err := randomCleanRootToken(uint32(os.Getuid())); err != nil || !cleanRootTokenRE.MatchString(token) {
		t.Fatalf("invalid random token: %q %v", token, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, cancelFn := cleanRootWithTimeout(ctx, 1)
	if cancelFn == nil {
		t.Fatal("clean-root timeout did not return a cancellation function")
	}
	cancelFn()
	lifecycleContext, lifecycleCancel := cleanRootOperationContext(context.Background(), "init", 1)
	defer lifecycleCancel()
	if _, hasDeadline := lifecycleContext.Deadline(); hasDeadline {
		t.Fatal("clean-root init unexpectedly inherited the per-build preparation timeout")
	}
	prepareContext, prepareCancel := cleanRootOperationContext(context.Background(), "prepare", 1)
	defer prepareCancel()
	if _, hasDeadline := prepareContext.Deadline(); !hasDeadline {
		t.Fatal("clean-root prepare is missing its configured timeout")
	}
	if status := runCleanRootCLI(context.Background(), []string{}); status != 20 {
		t.Fatalf("invalid clean-root CLI status=%d", status)
	}
	if os.Geteuid() != 0 {
		if status := runCleanRootCLI(context.Background(), []string{"init"}); status != 20 {
			t.Fatalf("unprivileged clean-root init status=%d", status)
		}
		if status := RunBuildDispatcher(context.Background()); status != 20 {
			t.Fatalf("unprivileged root dispatcher status=%d", status)
		}
	}

	previous := cleanRootDispatcher
	t.Cleanup(func() { cleanRootDispatcher = previous })
	cleanRootDispatcher = func(context.Context, CleanRootRequest) (CleanRootResponse, error) {
		return CleanRootResponse{Identity: CleanRootPolicyIdentity{Available: true, Generation: "1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ManifestSHA256: strings.Repeat("b", 64)}}, nil
	}
	if status := runCleanRootCLI(context.Background(), []string{"status"}); status != 0 {
		t.Fatalf("clean-root status failed: %d", status)
	}
	cleanRootDispatcher = func(context.Context, CleanRootRequest) (CleanRootResponse, error) {
		return CleanRootResponse{}, errors.New("unavailable")
	}
	if status := runCleanRootCLI(context.Background(), []string{"status"}); status != 24 {
		t.Fatalf("clean-root dispatcher error status=%d", status)
	}
	cleanRootDispatcher = func(context.Context, CleanRootRequest) (CleanRootResponse, error) {
		return CleanRootResponse{Identity: CleanRootPolicyIdentity{Available: false}}, nil
	}
	if status := runCleanRootCLI(context.Background(), []string{"status"}); status != 24 {
		t.Fatalf("uninitialized clean-root status=%d", status)
	}
	if !rootPathOnSameFilesystem(t.TempDir(), t.TempDir()) {
		t.Fatal("temporary paths unexpectedly use different filesystems")
	}
	command := newCleanRootCommand(context.Background(), "/usr/bin/true")
	if strings.Join(command.Env, "\n") != "HOME=/root\nLANG=C.UTF-8\nLC_ALL=C.UTF-8\nPATH=/usr/bin\nTMPDIR=/tmp\nUSER=root" {
		t.Fatalf("unexpected privileged command environment: %#v", command.Env)
	}
	configureCleanRootProcessGroup(command)
	if command.SysProcAttr == nil || !command.SysProcAttr.Setpgid || command.Cancel == nil || command.WaitDelay <= 0 {
		t.Fatal("mkarchroot command is not protected by process-group cancellation")
	}
}

func TestExecuteCleanRootCleanupUsesSecuredLock(t *testing.T) {
	root := withCleanRootState(t)
	previousOwner, previousGroup, previousConfig := cleanRootOwnerUID, cleanRootOwnerGID, SystemConfigPath
	cleanRootOwnerUID = uint32(os.Getuid())
	cleanRootOwnerGID = os.Getgid()
	SystemConfigPath = writeCurrentConfig(t, DefaultConfig())
	t.Cleanup(func() {
		cleanRootOwnerUID = previousOwner
		cleanRootOwnerGID = previousGroup
		SystemConfigPath = previousConfig
	})
	token := stringCallerUID() + "-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := os.MkdirAll(filepath.Join(root, "build-roots"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "build-roots", "active.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "build-jobs", token), 0o700); err != nil {
		t.Fatal(err)
	}
	request := CleanRootRequest{ProtocolVersion: CleanRootProtocolVersion, Operation: "cleanup", CallerUID: uint32(os.Getuid()), Token: token}
	response, err := executeCleanRootRequest(context.Background(), request)
	if err != nil || !response.OK || response.ProtocolVersion != CleanRootProtocolVersion {
		t.Fatalf("clean-root cleanup dispatch failed: %#v %v", response, err)
	}
	if _, err := os.Stat(filepath.Join(root, "build-jobs", token)); !os.IsNotExist(err) {
		t.Fatal("dispatched clean-root cleanup left its job behind")
	}
	for path, mode := range map[string]os.FileMode{root: 0o711, filepath.Join(root, "build-roots"): 0o711, filepath.Join(root, "build-roots", "active.json"): 0o644, filepath.Join(root, "build-jobs"): 0o711, filepath.Join(root, "artifact-pool"): 0o700} {
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Errorf("clean-root directory %s is missing: %v", path, statErr)
			continue
		}
		if info.Mode().Perm() != mode {
			t.Errorf("clean-root directory %s has mode %v", path, info.Mode().Perm())
		}
	}
	lock, err := acquireCleanRootLock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	lockContext, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if _, err := acquireCleanRootLock(lockContext); err == nil {
		t.Fatal("concurrent clean-root dispatcher lock unexpectedly succeeded")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(root, "dispatcher.lock")
	if err := os.Chmod(lockPath, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireCleanRootLock(context.Background()); err == nil {
		t.Fatal("writable clean-root dispatcher lock accepted")
	}
}

func TestExecuteCleanRootStatusDoesNotWaitForDispatcherLock(t *testing.T) {
	withCleanRootState(t)
	previousConfig := SystemConfigPath
	SystemConfigPath = writeCurrentConfig(t, DefaultConfig())
	t.Cleanup(func() {
		SystemConfigPath = previousConfig
	})
	if err := ensureCleanRootDirectories(); err != nil {
		t.Fatal(err)
	}
	expected := CleanRootPolicyIdentity{
		Available:      true,
		Generation:     stringCallerUID() + "-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ManifestSHA256: strings.Repeat("b", 64),
	}
	lock, err := acquireCleanRootLock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()

	statusContext, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	request := CleanRootRequest{
		ProtocolVersion: CleanRootProtocolVersion,
		Operation:       "status",
		CallerUID:       uint32(os.Getuid()),
	}
	response, err := executeCleanRootRequestWithStatusReader(statusContext, request, func() (CleanRootPolicyIdentity, error) {
		return expected, nil
	})
	if err != nil {
		t.Fatalf("clean-root status waited for the dispatcher lock: %v", err)
	}
	if !response.OK || response.Identity != expected {
		t.Fatalf("unexpected clean-root status response: %#v", response)
	}
}

func TestEnsureCleanRootDirectoriesRejectsSymlinkState(t *testing.T) {
	target := t.TempDir()
	state := filepath.Join(t.TempDir(), "state")
	if err := os.Symlink(target, state); err != nil {
		t.Fatal(err)
	}
	previousRoot, previousOwner, previousGroup := cleanRootStateRoot, cleanRootOwnerUID, cleanRootOwnerGID
	cleanRootStateRoot = state
	cleanRootOwnerUID = uint32(os.Getuid())
	cleanRootOwnerGID = os.Getgid()
	t.Cleanup(func() {
		cleanRootStateRoot = previousRoot
		cleanRootOwnerUID = previousOwner
		cleanRootOwnerGID = previousGroup
	})
	if err := ensureCleanRootDirectories(); err == nil {
		t.Fatal("symlinked clean-root state accepted")
	}
}

func TestCleanRootStateFailureBranches(t *testing.T) {
	root := withCleanRootState(t)
	if _, err := readActiveCleanRoot(); err == nil {
		t.Fatal("missing active clean root accepted")
	}
	if err := os.MkdirAll(filepath.Join(root, "build-roots"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "build-roots", "active.json"), []byte(`{"schema_version":1,"generation":"bad","manifest_hash":"bad"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readActiveCleanRoot(); err == nil {
		t.Fatal("invalid active clean root accepted")
	}
	jobs := filepath.Join(root, "build-jobs")
	if err := os.MkdirAll(filepath.Join(jobs, stringCallerUID()+"-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := enforcePreparedRootCount(uint32(os.Getuid()), 1); err == nil {
		t.Fatal("prepared-root concurrency limit was not enforced")
	}
	stale := filepath.Join(jobs, stringCallerUID()+"-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if err := os.Mkdir(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-4 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	if err := removeStalePreparedRoots(uint32(os.Getuid()), 3*time.Hour, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("stale clean-root job was not removed")
	}
	if err := validatePreparedRoot("/tmp/not-a-clean-root"); err == nil {
		t.Fatal("out-of-scope prepared root accepted")
	}
}

func TestPrunePreparedRootsIsCallerScoped(t *testing.T) {
	root := withCleanRootState(t)
	jobs := filepath.Join(root, "build-jobs")
	owned := filepath.Join(jobs, stringCallerUID()+"-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	other := filepath.Join(jobs, "424242-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	for _, path := range []string{owned, other} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := prunePreparedRoots(uint32(os.Getuid()))
	if err != nil || removed != 1 {
		t.Fatalf("prune result=%d err=%v", removed, err)
	}
	if _, err := os.Stat(owned); !os.IsNotExist(err) {
		t.Fatal("caller-owned disposable root was retained")
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("another caller's prepared root was removed")
	}
}

func TestInvokeCleanRootDispatcherProtocol(t *testing.T) {
	previous := cleanRootSudo
	t.Cleanup(func() { cleanRootSudo = previous })
	script := writeExecutable(t, fmt.Sprintf("printf '{\"protocol_version\":%d,\"ok\":true,\"identity\":{\"available\":false}}'", CleanRootProtocolVersion))
	cleanRootSudo = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		return exec.CommandContext(ctx, script)
	}
	request := CleanRootRequest{ProtocolVersion: CleanRootProtocolVersion, Operation: "status", CallerUID: uint32(os.Getuid())}
	response, err := invokeCleanRootDispatcher(context.Background(), request)
	if err != nil || !response.OK {
		t.Fatalf("valid dispatcher response rejected: %#v %v", response, err)
	}
	bad := writeExecutable(t, "printf 'not-json'")
	cleanRootSudo = func(ctx context.Context, _ string, _ ...string) *exec.Cmd { return exec.CommandContext(ctx, bad) }
	if _, err := invokeCleanRootDispatcher(context.Background(), request); err == nil {
		t.Fatal("invalid dispatcher JSON accepted")
	}
	failing := writeExecutable(t, "printf 'denied' >&2; exit 2")
	cleanRootSudo = func(ctx context.Context, _ string, _ ...string) *exec.Cmd { return exec.CommandContext(ctx, failing) }
	if _, err := invokeCleanRootDispatcher(context.Background(), request); err == nil {
		t.Fatal("failed dispatcher process accepted")
	}
	rejectionRaw, _ := CanonicalJSON(CleanRootResponse{ProtocolVersion: CleanRootProtocolVersion, OK: false, Error: "prepared clean-root job limit reached"})
	rejected := writeExecutable(t, "printf '%s' '"+string(rejectionRaw)+"'; exit 23")
	cleanRootSudo = func(ctx context.Context, _ string, _ ...string) *exec.Cmd { return exec.CommandContext(ctx, rejected) }
	if _, err := invokeCleanRootDispatcher(context.Background(), request); err == nil || !strings.Contains(err.Error(), "prepared clean-root job limit reached") {
		t.Fatalf("structured dispatcher rejection was lost: %v", err)
	}

	manifest := validTestCleanRootManifest()
	prepareToken := stringCallerUID() + "-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	manifest.Generation = prepareToken
	manifest.PolicyFingerprint = strings.Repeat("e", 64)
	manifest.ManifestSHA256 = ""
	rawManifest, _ := CanonicalJSON(*manifest)
	manifest.ManifestSHA256 = SHA256Bytes(rawManifest)
	responseRaw, _ := CanonicalJSON(CleanRootResponse{ProtocolVersion: CleanRootProtocolVersion, OK: true, Token: prepareToken, RootPath: cleanRootPath("build-jobs", prepareToken, "root"), Manifest: manifest})
	prepared := writeExecutable(t, "printf '%s' '"+string(responseRaw)+"'")
	cleanRootSudo = func(ctx context.Context, _ string, _ ...string) *exec.Cmd { return exec.CommandContext(ctx, prepared) }
	prepareRequest := CleanRootRequest{ProtocolVersion: CleanRootProtocolVersion, Operation: "prepare", CallerUID: uint32(os.Getuid()), PolicyFingerprint: manifest.PolicyFingerprint}
	if _, err := invokeCleanRootDispatcher(context.Background(), prepareRequest); err != nil {
		t.Fatalf("valid prepare dispatcher response rejected: %v", err)
	}
	prepareRequest.PolicyFingerprint = strings.Repeat("f", 64)
	if _, err := invokeCleanRootDispatcher(context.Background(), prepareRequest); err == nil {
		t.Fatal("prepare response for another policy was accepted")
	}
}

func TestSourceVerificationDoesNotStageTransactionDependencies(t *testing.T) {
	yayContext := YayContext{Depends: []string{"aur-dependency>=1"}, MakeDepends: []string{"nasm"}, CheckDepends: []string{"check-tool"}}
	if got := cleanRootDependenciesForProfile("verify", yayContext); len(got) != 0 {
		t.Fatalf("source verification staged transaction dependencies: %v", got)
	}
	if got := cleanRootDependenciesForProfile("build", yayContext); strings.Join(got, ",") != "aur-dependency>=1,check-tool,nasm" {
		t.Fatalf("build dependency staging changed: %v", got)
	}
}

func stringCallerUID() string {
	return strconv.FormatUint(uint64(os.Getuid()), 10)
}
