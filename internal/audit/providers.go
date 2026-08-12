package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const auditUser = "prolewatch"

var (
	codexHostBinary        = "/usr/bin/codex"
	claudeHostBinary       = "/usr/bin/claude"
	providerSandboxBinary  = "/usr/bin/bwrap"
	providerUserLookup     = user.Lookup
	providerEffectiveUID   = os.Geteuid
	providerConfigLoader   = func() (Config, error) { return LoadConfig("") }
	providerAdapterFactory = activeAdapter
	providerShareRoot      = ShareRoot
)

type providerAdapter interface {
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

func (a *codexAdapter) CredentialPath() string {
	return "/var/lib/prolewatch/providers/codex/auth.json"
}
func (a *codexAdapter) Metadata(ctx context.Context) (ProviderMetadata, error) {
	version, parsed, err := commandVersion(ctx, codexHostBinary, "--version")
	if err != nil {
		return ProviderMetadata{}, err
	}
	if compareVersions(parsed, mustVersion(MinCodexVersion)) < 0 {
		return ProviderMetadata{}, fmt.Errorf("Codex %s or newer is required; found %s", MinCodexVersion, version)
	}
	if compareVersions(parsed, mustVersion(MaxCodexVersion)) >= 0 {
		return ProviderMetadata{}, fmt.Errorf("Codex must be older than %s; found %s", MaxCodexVersion, version)
	}
	features, err := codexFeatures(ctx)
	if err != nil {
		return ProviderMetadata{}, err
	}
	return ProviderMetadata{Provider: "codex", Transport: "cli", RuntimeVersion: canonicalRuntimeVersion("codex-cli", parsed), Model: a.provider.Model, Effort: a.provider.Effort, AdapterPolicy: fmt.Sprintf("codex-cli-v2:disable-current-%d", len(features))}, nil
}
func (a *codexAdapter) Review(ctx context.Context, snapshot ReviewSnapshot) (Verdict, error) {
	metadata, err := a.Metadata(ctx)
	if err != nil {
		return Verdict{}, err
	}
	_ = metadata
	features, err := codexFeatures(ctx)
	if err != nil {
		return Verdict{}, err
	}
	args := providerBwrapBase("/var/lib/prolewatch/providers/codex", "/provider-home")
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
	} else if err := validateVerdictSchema(schema); err != nil {
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
	return "/var/lib/prolewatch/providers/anthropic/.credentials.json"
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
	if _, err := a.Metadata(ctx); err != nil {
		return Verdict{}, err
	}
	schema, err := os.ReadFile(filepath.Join(providerShareRoot(), "verdict.schema.json"))
	if err != nil {
		return Verdict{}, err
	}
	if err := validateVerdictSchema(schema); err != nil {
		return Verdict{}, fmt.Errorf("invalid verdict schema: %w", err)
	}
	args := providerBwrapBase("/var/lib/prolewatch/providers/anthropic", "/provider-home")
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
	return []string{"--die-with-parent", "--new-session", "--unshare-all", "--share-net", "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/bin", "/sbin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib", "/lib64", "--dir", "/etc", "--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf", "--ro-bind-try", "/etc/hosts", "/etc/hosts", "--ro-bind-try", "/etc/nsswitch.conf", "/etc/nsswitch.conf", "--ro-bind-try", "/etc/ssl", "/etc/ssl", "--ro-bind-try", "/etc/ca-certificates", "/etc/ca-certificates", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", sandboxHome, "--bind", hostHome, sandboxHome, "--dir", "/workspace", "--chdir", "/workspace", "--clearenv", "--setenv", "PATH", "/usr/bin", "--setenv", "LANG", "C.UTF-8"}
}

var versionRE = regexp.MustCompile(`(?m)(\d+)\.(\d+)\.(\d+)`)

func commandVersion(ctx context.Context, binary string, args ...string) (string, []int, error) {
	probe, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	command := exec.CommandContext(probe, binary, args...)
	command.Env = []string{"PATH=/usr/bin", "LANG=C.UTF-8"}
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
	home, err := os.MkdirTemp("", "prolewatch-codex-features-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(home)
	probe, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	command := exec.CommandContext(probe, codexHostBinary, "features", "list")
	command.Env = []string{"PATH=/usr/bin", "HOME=" + home, "CODEX_HOME=" + home, "LANG=C.UTF-8"}
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

func validateCredential(path string, uid uint32) error {
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
		return errors.New("dedicated provider credential has unsafe ownership or permissions")
	}
	return nil
}

func RunProviderDispatcher(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer) int {
	account, err := providerUserLookup(auditUser)
	if err != nil {
		fmt.Fprintln(stderr, "prolewatch user does not exist")
		return 22
	}
	uid64, _ := strconv.ParseUint(account.Uid, 10, 32)
	if providerEffectiveUID() != int(uid64) {
		fmt.Fprintln(stderr, "provider-dispatch must run as prolewatch")
		return 22
	}
	cfg, err := providerConfigLoader()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 20
	}
	if cfg.Review.Mode != ReviewModeAI {
		fmt.Fprintln(stderr, "provider-dispatch is disabled by review.mode")
		return 22
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, cfg.Limits.MaxDispatchBytes+1))
	if err != nil || int64(len(raw)) > cfg.Limits.MaxDispatchBytes {
		fmt.Fprintln(stderr, "dispatcher input limit exceeded")
		return 22
	}
	var request DispatchRequest
	if err := DecodeStrict(raw, &request); err != nil {
		fmt.Fprintln(stderr, "dispatcher input is invalid:", err)
		return 22
	}
	if err := request.Validate(); err != nil {
		fmt.Fprintln(stderr, "dispatcher request is invalid:", err)
		return 22
	}
	adapter := providerAdapterFactory(cfg)
	if err := validateCredential(adapter.CredentialPath(), uint32(uid64)); err != nil {
		fmt.Fprintln(stderr, err)
		return 22
	}
	metadata, err := adapter.Metadata(ctx)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 22
	}
	response := DispatchResponse{ProtocolVersion: DispatchProtocolVersion, Metadata: metadata}
	if request.Operation == "canary" {
		if err := providerOuterSandboxCanary(ctx, cfg); err != nil {
			fmt.Fprintln(stderr, err)
			return 22
		}
	}
	if request.Operation == "review" {
		verdict, err := adapter.Review(ctx, *request.Snapshot)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 22
		}
		response.Verdict = &verdict
	}
	encoded, err := CanonicalJSON(response)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 22
	}
	_, _ = stdout.Write(append(encoded, '\n'))
	return 0
}

func init() { signal.Ignore(syscall.SIGPIPE) }
