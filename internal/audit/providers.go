package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/holgerjh/prolewatch/internal/brief"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var (
	codexHostBinary        = "/usr/bin/codex"
	claudeHostBinary       = "/usr/bin/claude"
	providerSandboxBinary  = "/usr/bin/bwrap"
	providerEffectiveUID   = os.Geteuid
	providerConfigLoader   = func() (Config, error) { return LoadConfig("") }
	providerAdapterFactory = activeAdapter
	providerShareRoot      = ShareRoot
)

type providerAdapter interface {
	// Adapters own the exact supported CLI contract. Callers cannot select argv,
	// environment, credential paths, tools, or endpoints through the protocol.
	Metadata(context.Context) (ProviderMetadata, error)
	Review(context.Context, ReviewSnapshot) (Verdict, error)
	CredentialPath() string
}

type adapterBase struct {
	cfg      Config
	provider ProviderConfig
}

func activeAdapter(cfg Config) providerAdapter {
	if cfg.Provider == "anthropic" {
		return &claudeAdapter{adapterBase{cfg, cfg.Providers.Anthropic}}
	}
	return &codexAdapter{adapterBase{cfg, cfg.Providers.Codex}}
}

type codexAdapter struct{ adapterBase }

func (a *codexAdapter) CredentialPath() string { return providerCredentialPath("codex", "auth.json") }
func (a *codexAdapter) Metadata(ctx context.Context) (ProviderMetadata, error) {
	version, parsed, err := commandVersion(ctx, codexHostBinary, "--version")
	if err != nil {
		return ProviderMetadata{}, err
	}
	if compareVersions(parsed, mustVersion(MinCodexVersion)) < 0 {
		return ProviderMetadata{}, fmt.Errorf("Codex %s or newer is required; found %s", MinCodexVersion, version)
	}
	// See MaxCodexVersion: the upper bound is a warning boundary, not a
	// refusal. The feature enumeration below is the check that actually
	// matters, and it fails closed on its own.
	var warning string
	if compareVersions(parsed, mustVersion(MaxCodexVersion)) >= 0 {
		warning = fmt.Sprintf("%s is newer than the checked ceiling (< %s); the adapter's invocation flags have not been verified against it", version, MaxCodexVersion)
	}
	features, err := codexFeatures(ctx)
	if err != nil {
		return ProviderMetadata{}, err
	}
	return ProviderMetadata{Provider: "codex", Transport: "cli", RuntimeVersion: canonicalRuntimeVersion("codex-cli", parsed), Model: a.provider.Model, Effort: a.provider.Effort, AdapterPolicy: fmt.Sprintf("codex-cli-v2:disable-current-%d", len(features)), CompatibilityWarning: warning}, nil
}
func (a *codexAdapter) Review(ctx context.Context, snapshot ReviewSnapshot) (Verdict, error) {
	// Codex runs ephemeral, read-only, without web search, user config, rules, or
	// enabled feature surfaces. Only stdin and the fixed output schema cross the
	// empty-workspace sandbox boundary.
	metadata, err := a.Metadata(ctx)
	if err != nil {
		return Verdict{}, err
	}
	_ = metadata
	features, err := codexFeatures(ctx)
	if err != nil {
		return Verdict{}, err
	}
	home, err := providerCredentialHome(a)
	if err != nil {
		return Verdict{}, err
	}
	args := providerBwrapBase(home, "/provider-home")
	args = append(args, "--ro-bind", filepath.Join(providerShareRoot(), "verdict.schema.json"), "/schema.json", "--setenv", "HOME", "/provider-home", "--setenv", "CODEX_HOME", "/provider-home", "/usr/bin/codex", "-a", "never", "exec", "--ephemeral", "--ignore-user-config", "--ignore-rules", "--strict-config", "--skip-git-repo-check", "--sandbox", "read-only", "--output-schema", "/schema.json", "--color", "never", "--model", a.provider.Model, "-c", fmt.Sprintf("model_reasoning_effort=%q", a.provider.Effort), "-c", "web_search=\"disabled\"")
	for _, feature := range features {
		args = append(args, "--disable", feature)
	}
	args = append(args, "-")
	snapshotRaw, _ := CanonicalJSON(snapshot)
	prompt, err := os.ReadFile(filepath.Join(providerShareRoot(), "review-prompt.md"))
	if err != nil {
		return Verdict{}, err
	}
	if schema, err := os.ReadFile(filepath.Join(providerShareRoot(), "verdict.schema.json")); err != nil {
		return Verdict{}, err
	} else if err := brief.ValidateVerdictSchema(schema); err != nil {
		return Verdict{}, fmt.Errorf("invalid verdict schema: %w", err)
	}
	stdout, stderr, err := runProcessGroup(ctx, providerSandboxBinary, args, append(append(prompt, '\n'), snapshotRaw...), a.cfg)
	if err != nil {
		return Verdict{}, fmt.Errorf("isolated Codex review failed: %w: %s", err, truncateTail(string(stderr), 8*1024))
	}
	var verdict Verdict
	if err := DecodeStrict(stdout, &verdict); err != nil {
		return Verdict{}, fmt.Errorf("invalid Codex verdict: %w", err)
	}
	return verdict, verdict.Validate()
}

type claudeAdapter struct{ adapterBase }

func (a *claudeAdapter) CredentialPath() string {
	return providerCredentialPath("anthropic", ".credentials.json")
}
func (a *claudeAdapter) Metadata(ctx context.Context) (ProviderMetadata, error) {
	version, parsed, err := commandVersion(ctx, claudeHostBinary, "--version")
	if err != nil {
		return ProviderMetadata{}, err
	}
	if compareVersions(parsed, mustVersion(MinClaudeVersion)) < 0 {
		return ProviderMetadata{}, fmt.Errorf("Claude Code %s or newer is required; found %s", MinClaudeVersion, version)
	}
	if compareVersions(parsed, mustVersion(MaxClaudeVersion)) >= 0 {
		return ProviderMetadata{}, fmt.Errorf("Claude Code must be older than %s; found %s", MaxClaudeVersion, version)
	}
	return ProviderMetadata{Provider: "anthropic", Transport: "cli", RuntimeVersion: canonicalRuntimeVersion("claude-code", parsed), Model: a.provider.Model, Effort: a.provider.Effort, AdapterPolicy: "claude-cli-v1:safe-no-tools"}, nil
}
func (a *claudeAdapter) Review(ctx context.Context, snapshot ReviewSnapshot) (Verdict, error) {
	// Claude's adapter disables tools, MCP, slash commands, history, sessions,
	// and interactive permission fallback before accepting structured output.
	if _, err := a.Metadata(ctx); err != nil {
		return Verdict{}, err
	}
	schema, err := os.ReadFile(filepath.Join(providerShareRoot(), "verdict.schema.json"))
	if err != nil {
		return Verdict{}, err
	}
	if err := brief.ValidateVerdictSchema(schema); err != nil {
		return Verdict{}, fmt.Errorf("invalid verdict schema: %w", err)
	}
	home, err := providerCredentialHome(a)
	if err != nil {
		return Verdict{}, err
	}
	args := providerBwrapBase(home, "/provider-home")
	args = append(args, "--ro-bind", filepath.Join(providerShareRoot(), "review-prompt.md"), "/prompt.md", "--setenv", "HOME", "/provider-home", "--setenv", "CLAUDE_CONFIG_DIR", "/provider-home", "--setenv", "CLAUDE_CODE_SKIP_PROMPT_HISTORY", "1", "--setenv", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1", "/usr/bin/claude", "-p", "--output-format", "json", "--json-schema", string(schema), "--safe-mode", "--setting-sources", "", "--strict-mcp-config", "--tools", "", "--disallowedTools", "mcp__*", "--disable-slash-commands", "--no-session-persistence", "--permission-mode", "dontAsk", "--model", a.provider.Model, "--effort", a.provider.Effort, "--system-prompt-file", "/prompt.md")
	snapshotRaw, _ := CanonicalJSON(snapshot)
	stdout, stderr, err := runProcessGroup(ctx, providerSandboxBinary, args, snapshotRaw, a.cfg)
	if err != nil {
		return Verdict{}, fmt.Errorf("isolated Claude review failed: %w: %s", err, truncateTail(string(stderr), 8*1024))
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(stdout, &envelope); err != nil {
		return Verdict{}, fmt.Errorf("invalid Claude envelope: %w", err)
	}
	var subtype string
	if raw := envelope["subtype"]; raw != nil {
		_ = json.Unmarshal(raw, &subtype)
	}
	if subtype != "success" {
		return Verdict{}, fmt.Errorf("Claude structured output failed with subtype %q", subtype)
	}
	structured := envelope["structured_output"]
	if len(structured) == 0 || bytes.Equal(structured, []byte("null")) {
		return Verdict{}, errors.New("Claude omitted structured output")
	}
	var verdict Verdict
	if err := DecodeStrict(structured, &verdict); err != nil {
		return Verdict{}, fmt.Errorf("invalid Claude verdict: %w", err)
	}
	return verdict, verdict.Validate()
}

func providerBwrapBase(hostHome, sandboxHome string) []string {
	// The provider needs host networking for its configured remote API, but sees
	// only immutable runtime files, minimal resolver/TLS files, its dedicated
	// credential home, and a fresh empty workspace. --unshare-user is explicit:
	// --unshare-all makes that namespace best-effort, while --disable-userns
	// requires one that Bubblewrap definitely created before it can clamp nested
	// namespaces.
	return []string{"--die-with-parent", "--new-session", "--unshare-all", "--share-net", "--unshare-user", "--disable-userns", "--assert-userns-disabled", "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/bin", "/sbin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib", "/lib64", "--dir", "/etc", "--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf", "--ro-bind-try", "/etc/hosts", "/etc/hosts", "--ro-bind-try", "/etc/nsswitch.conf", "/etc/nsswitch.conf", "--ro-bind-try", "/etc/ssl", "/etc/ssl", "--ro-bind-try", "/etc/ca-certificates", "/etc/ca-certificates", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", sandboxHome, "--bind", hostHome, sandboxHome, "--dir", "/workspace", "--chdir", "/workspace", "--clearenv", "--setenv", "PATH", "/usr/bin", "--setenv", "LANG", "C.UTF-8"}
}

var versionRE = regexp.MustCompile(`(?m)(\d+)\.(\d+)\.(\d+)`)

func commandVersion(ctx context.Context, binary string, args ...string) (string, []int, error) {
	// Metadata probes get a fixed 15-second ceiling independent of the longer AI
	// review timeout; a hung --version must fail fast before consuming a worker.
	probe, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	command := exec.CommandContext(probe, binary, args...)
	command.Env = []string{"PATH=/usr/bin", "LANG=C.UTF-8"}
	// Own process group so a hung provider CLI can be killed as a tree.
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	output := newLimitedBuffer(64 * 1024)
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	version := strings.TrimSpace(output.String())
	if err != nil {
		return version, nil, fmt.Errorf("cannot execute %s: %w", binary, err)
	}
	match := versionRE.FindStringSubmatch(version)
	if match == nil {
		return version, nil, fmt.Errorf("cannot parse version %q", version)
	}
	return version, []int{atoi(match[1]), atoi(match[2]), atoi(match[3])}, nil
}
func mustVersion(value string) []int {
	match := versionRE.FindStringSubmatch(value)
	return []int{atoi(match[1]), atoi(match[2]), atoi(match[3])}
}
func compareVersions(a, b []int) int {
	for i := range 3 {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}
func canonicalRuntimeVersion(name string, parsed []int) string {
	return fmt.Sprintf("%s %d.%d.%d", name, parsed[0], parsed[1], parsed[2])
}
func atoi(value string) int { result, _ := strconv.Atoi(value); return result }

var featureRE = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

func codexFeatures(ctx context.Context) ([]string, error) {
	// Discover every non-removed feature and explicitly disable it. This makes a
	// newly default-enabled CLI feature fail toward less capability rather than
	// silently expanding the adapter surface.
	home, err := os.MkdirTemp("", "prolewatch-codex-features-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(home)
	probe, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	command := exec.CommandContext(probe, codexHostBinary, "features", "list")
	command.Env = []string{"PATH=/usr/bin", "HOME=" + home, "CODEX_HOME=" + home, "LANG=C.UTF-8"}
	// Own process group so a hung provider CLI can be killed as a tree.
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	output := newLimitedBuffer(1024 * 1024)
	command.Stdout = output
	err = command.Run()
	if err != nil {
		return nil, errors.New("cannot enumerate Codex features")
	}
	seen := map[string]bool{}
	var features []string
	for _, line := range strings.Split(strings.TrimSpace(output.String()), "\n") {
		parts := strings.Fields(line)
		if len(parts) < 3 || (parts[len(parts)-1] != "true" && parts[len(parts)-1] != "false") || !featureRE.MatchString(parts[0]) || seen[parts[0]] {
			return nil, fmt.Errorf("cannot parse Codex feature entry %q", truncate(line, 160))
		}
		seen[parts[0]] = true
		lifecycle := strings.Join(parts[1:len(parts)-1], " ")
		if lifecycle == "deprecated" || lifecycle == "removed" {
			continue
		}
		features = append(features, parts[0])
	}
	if len(features) == 0 {
		return nil, errors.New("Codex returned an empty feature list")
	}
	sort.Strings(features)
	return features, nil
}

func runProcessGroup(parent context.Context, binary string, args []string, input []byte, cfg Config) ([]byte, []byte, error) {
	// Give the CLI a graceful TERM window, then kill the entire process group so
	// helper descendants cannot survive cancellation or the review deadline.
	command := exec.Command(binary, args...)
	command.Stdin = bytes.NewReader(input)
	stdout := newLimitedBuffer(cfg.Limits.MaxDispatchBytes)
	stderr := newLimitedBuffer(1024 * 1024)
	command.Stdout = stdout
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		return nil, nil, err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	timer := time.NewTimer(time.Duration(cfg.Review.TimeoutSeconds) * time.Second)
	defer timer.Stop()
	select {
	case err := <-done:
		return stdout.Bytes(), stderr.Bytes(), err
	case <-parent.Done():
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(time.Duration(cfg.Review.KillGraceSeconds) * time.Second):
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			<-done
		}
		return stdout.Bytes(), stderr.Bytes(), parent.Err()
	case <-timer.C:
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(time.Duration(cfg.Review.KillGraceSeconds) * time.Second):
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			<-done
		}
		return stdout.Bytes(), stderr.Bytes(), ErrProviderTimeout
	}
}

// providerCredentialPath locates the AI provider credential under the invoking
// user's own state directory.
//
// The invoking user is the administrator and owns the provider process, so a
// separate service-account path would not create a privilege boundary. File
// ownership and mode checks below protect the credential that the provider CLI
// uses.
func providerCredentialPath(provider, file string) string {
	return filepath.Join(StateRoot(), "providers", provider, file)
}

// providerCredentialHome is the single derivation of the host directory bound
// into the provider sandbox, and it is deliberately the parent of the path the
// worker validates.
//
// Deriving it a second time is how the credential ends up checked at one path
// and mounted from another: the check passes, the provider sees an empty or
// absent home, and the failure reads like a provider outage rather than a
// misconfiguration here. EnsurePrivateDir also holds the directory itself to the
// same ownership and mode rule the credential file is held to.
//
// The bind is read-write because both supported CLIs refresh their own OAuth
// token in place; nothing else of the user's is in this directory.
func providerCredentialHome(adapter providerAdapter) (string, error) {
	home := filepath.Dir(adapter.CredentialPath())
	if err := EnsurePrivateDir(home); err != nil {
		return "", fmt.Errorf("provider credential home %s is unusable: %w", home, err)
	}
	return home, nil
}

func validateCredential(path string, uid uint32) error {
	// Credentials must be regular, owned by the invoking user, and inaccessible
	// to group and other. O_NOFOLLOW rejects path substitution.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("dedicated provider credential is missing: %w", err)
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uid || st.Mode&0o077 != 0 {
		return fmt.Errorf("provider credential %s must be a regular file owned by uid %d with no group or other access", path, uid)
	}
	return nil
}

func runProviderWorker(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer) int {
	// The worker accepts only the three typed DispatchRequest operations and
	// derives provider/model/credentials from installed configuration. It runs
	// as the invoking user and validates that user's credential ownership.
	uid64 := uint64(providerEffectiveUID())
	cfg, err := providerConfigLoader()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitInvalidInvocation
	}
	if cfg.Review.Mode != ReviewModeAI {
		fmt.Fprintln(stderr, "provider worker is disabled by review.mode")
		return ExitReviewUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, cfg.Limits.MaxDispatchBytes+1))
	if err != nil || int64(len(raw)) > cfg.Limits.MaxDispatchBytes {
		fmt.Fprintln(stderr, "provider worker input limit exceeded")
		return ExitReviewUnavailable
	}
	var request DispatchRequest
	if err := DecodeStrict(raw, &request); err != nil {
		fmt.Fprintln(stderr, "provider worker input is invalid:", err)
		return ExitReviewUnavailable
	}
	if err := request.Validate(); err != nil {
		fmt.Fprintln(stderr, "provider worker request is invalid:", err)
		return ExitReviewUnavailable
	}
	adapter := providerAdapterFactory(cfg)
	if err := validateCredential(adapter.CredentialPath(), uint32(uid64)); err != nil {
		fmt.Fprintln(stderr, err)
		return ExitReviewUnavailable
	}
	metadata, err := adapter.Metadata(ctx)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitReviewUnavailable
	}
	response := DispatchResponse{ProtocolVersion: DispatchProtocolVersion, Metadata: metadata}
	if request.Operation == "canary" {
		if err := providerOuterSandboxCanary(ctx, cfg); err != nil {
			fmt.Fprintln(stderr, err)
			return ExitReviewUnavailable
		}
	}
	if request.Operation == "review" {
		verdict, err := adapter.Review(ctx, *request.Snapshot)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return ExitReviewUnavailable
		}
		response.Verdict = &verdict
	}
	encoded, err := CanonicalJSON(response)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitReviewUnavailable
	}
	_, _ = stdout.Write(append(encoded, '\n'))
	return ExitOK
}

func init() { signal.Ignore(syscall.SIGPIPE) }
