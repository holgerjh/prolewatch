package audit

import (
	"context"
	"errors"
	"fmt"
	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/safe"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Version 7 replaces an ambiguous service-enable fixture with an unequivocally
// malicious cross-file persistence chain. A pass over the older corpus must not
// be reinterpreted as evidence that the runtime detected the stronger case.
const providerCanaryVersion = 7
const providerAttestationSchemaVersion = 3

// CanaryChecks records what doctor observed, and only that.
//
// It used to carry no_tools, no_commands and strict_schema as well, written
// unconditionally true once the two canaries passed. Nothing observed them: the
// outer canary runs a fixed shell and never invokes the provider, and the
// semantic canary sees one structured verdict - a conforming answer says
// nothing about what capabilities were available or attempted while producing
// it, and one schema-shaped response does not prove the CLI enforced the schema.
//
// That mattered because it was presented as evidence. Tool and command
// suppression is a real boundary for attacker-authored package text, and the
// attestation claimed to have verified a regression had not happened while
// being structurally incapable of detecting one.
//
// Suppression is enforced instead as an adapter invariant: the argv is built in
// one place, its exact flags are asserted by TestProviderAdaptersSuppressTools,
// the supported CLI range is pinned, and AdapterPolicy - which names that flag
// set - is part of both policy and provider-semantic identity, so changing it
// invalidates every decision and attestation taken under the old one.
type CanaryChecks struct {
	// EmptyWorkspace and NoHostRead come from the outer sandbox canary: a host
	// sentinel is unreachable and /workspace starts empty.
	EmptyWorkspace bool `json:"empty_workspace,omitempty"`
	NoHostRead     bool `json:"no_host_read,omitempty"`
	// HTTP-only observations. They are omitted for CLI providers, just as the
	// two Bubblewrap observations above are omitted for Ollama.
	LoopbackEndpoint    bool `json:"loopback_endpoint,omitempty"`
	LocalModel          bool `json:"local_model,omitempty"`
	ContextVerified     bool `json:"context_verified,omitempty"`
	StructuredOutput    bool `json:"structured_output,omitempty"`
	QualityGatePassed   bool `json:"quality_gate_passed,omitempty"`
	PerformanceMeasured bool `json:"performance_measured,omitempty"`
	TruncationRefused   bool `json:"truncation_refused,omitempty"`
	// ObservedBytesPerToken is aggregated across the seven live quality cases.
	// Zero means it was not observed and is valid only for CLI attestations.
	ObservedBytesPerToken float64 `json:"observed_bytes_per_token,omitempty"`
	// PromptInjectionRecognised comes from the semantic canary: the provider
	// returned exactly one verdict, it was a block, and it reported the
	// injection. That is a statement about the provider's answer, not about its
	// sandbox, and it is named so it cannot be read as more.
	PromptInjectionRecognised bool `json:"prompt_injection_recognised"`
}

type ProviderAttestation struct {
	// The attestation caches a successful live canary only for inputs that can
	// change provider requests or responses. Transaction policy still has its
	// own broader fingerprint on reports, approvals, and markers; changing a
	// gate selection or build envelope must not require repeating model tests.
	SchemaVersion       int                        `json:"schema_version"`
	CanaryVersion       int                        `json:"canary_version"`
	CreatedAt           string                     `json:"created_at"`
	SemanticFingerprint string                     `json:"semantic_fingerprint"`
	Metadata            ProviderMetadata           `json:"metadata"`
	ProviderBinary      *brief.ToolIdentity        `json:"provider_binary,omitempty"`
	LocalHTTP           *LocalHTTPProviderIdentity `json:"local_http,omitempty"`
	Checks              CanaryChecks               `json:"checks"`
}

type LocalHTTPProviderIdentity struct {
	Endpoint       string `json:"endpoint"`
	RuntimeVersion string `json:"runtime_version"`
	Model          string `json:"model"`
	ModelDigest    string `json:"model_digest"`
	ContextTokens  int    `json:"context_tokens"`
	AdapterPolicy  string `json:"adapter_policy"`
}

func localHTTPProviderIdentity(metadata ProviderMetadata) *LocalHTTPProviderIdentity {
	if metadata.Provider != "ollama" || metadata.Transport != "http-loopback" {
		return nil
	}
	return &LocalHTTPProviderIdentity{Endpoint: ollamaLoopbackEndpoint, RuntimeVersion: metadata.RuntimeVersion,
		Model: metadata.Model, ModelDigest: metadata.ModelDigest, ContextTokens: metadata.ContextTokens, AdapterPolicy: metadata.AdapterPolicy}
}

func providerBinaryIdentity(ctx context.Context, cfg Config, metadata ProviderMetadata) (brief.ToolIdentity, error) {
	if cfg.Provider == "ollama" {
		// The client binary does not identify an already running daemon. Ollama
		// attestations bind HTTP/runtime/model evidence instead.
		return brief.ToolIdentity{}, nil
	}
	path := "/usr/bin/codex"
	if cfg.Provider == "anthropic" {
		path = claudeHostBinary
	} else {
		path = codexHostBinary
	}
	digest, err := safe.HashFileNoFollow(path)
	if err != nil {
		return brief.ToolIdentity{}, err
	}
	return brief.ToolIdentity{Path: path, Version: metadata.RuntimeVersion, SHA256: digest}, nil
}

func providerAttestationPath() string {
	return filepath.Join(StateRoot(), "provider-attestation.json")
}

func ComputeProviderAttestationFingerprint(cfg Config, metadata ProviderMetadata) (string, error) {
	prompt, err := os.ReadFile(filepath.Join(ShareRoot(), "review-prompt.md"))
	if err != nil {
		return "", err
	}
	schema, err := os.ReadFile(filepath.Join(ShareRoot(), "verdict.schema.json"))
	if err != nil {
		return "", err
	}
	material := map[string]any{
		"attestation_schema_version": providerAttestationSchemaVersion,
		"canary_version":             providerCanaryVersion,
		"review_snapshot_version":    ReviewSnapshotVersion,
		"provider":                   cfg.Provider,
		"metadata":                   metadata,
		"review_batch_bytes":         cfg.Review.BatchBytes,
		"guidance_minimum_severity":  cfg.Review.ManualReviewMinimumSeverity,
		"prompt_sha256":              safe.SHA256Bytes(prompt),
		"schema_sha256":              safe.SHA256Bytes(schema),
	}
	if cfg.Provider == "ollama" {
		material["ollama_reasoning"] = cfg.Providers.Ollama.Reasoning
	}
	raw, err := CanonicalJSON(material)
	if err != nil {
		return "", err
	}
	return safe.SHA256Bytes(raw), nil
}

func (a ProviderAttestation) Validate(fingerprint string, metadata ProviderMetadata, provider brief.ToolIdentity) error {
	if metadata.Provider == "ollama" && a.Metadata.Provider == "ollama" {
		switch {
		case a.Metadata.RuntimeVersion != metadata.RuntimeVersion:
			return fmt.Errorf("Ollama runtime changed from %q to %q; run 'prolewatch doctor --probe-llm-quality' to repeat the local quality gate", a.Metadata.RuntimeVersion, metadata.RuntimeVersion)
		case a.Metadata.ModelDigest != metadata.ModelDigest:
			return errors.New("Ollama model digest changed; run 'prolewatch doctor --probe-llm-quality' to repeat the local quality gate")
		case a.Metadata.ContextTokens != metadata.ContextTokens:
			return errors.New("Ollama context configuration changed; run 'prolewatch doctor --probe-llm-quality' to repeat the local quality gate")
		}
	}
	identityOK := false
	if metadata.Provider == "ollama" {
		expected := localHTTPProviderIdentity(metadata)
		identityOK = a.ProviderBinary == nil && a.LocalHTTP != nil && *a.LocalHTTP == *expected && provider == (brief.ToolIdentity{})
	} else {
		identityOK = a.ProviderBinary != nil && *a.ProviderBinary == provider && a.LocalHTTP == nil
	}
	if a.SchemaVersion != providerAttestationSchemaVersion || a.CanaryVersion != providerCanaryVersion || a.SemanticFingerprint != fingerprint ||
		a.Metadata != metadata || !identityOK {
		if metadata.Provider == "ollama" {
			return errors.New("provider semantic attestation is absent, stale, or bound to different runtime or provider inputs; run 'prolewatch doctor --probe-llm-quality' to renew it")
		}
		return errors.New("provider semantic attestation is absent, stale, or bound to different binaries or provider inputs; run 'prolewatch doctor' to renew it")
	}
	if _, err := time.Parse(time.RFC3339Nano, a.CreatedAt); err != nil {
		if metadata.Provider == "ollama" {
			return errors.New("provider semantic attestation has invalid time; run 'prolewatch doctor --probe-llm-quality' to replace it")
		}
		return errors.New("provider semantic attestation has invalid time")
	}
	cliChecks := validCLICanaryChecks(a.Checks)
	httpChecks := validOllamaCanaryChecks(a.Checks)
	if (metadata.Provider == "ollama" && !httpChecks) || (metadata.Provider != "ollama" && !cliChecks) {
		if metadata.Provider == "ollama" {
			return errors.New("provider semantic attestation did not pass every observed check; run 'prolewatch doctor --probe-llm-quality' to replace it")
		}
		return errors.New("provider semantic attestation did not pass every observed check")
	}
	return nil
}

func loadProviderAttestation(fingerprint string, metadata ProviderMetadata, provider brief.ToolIdentity) error {
	refreshCommand := "'prolewatch doctor'"
	if metadata.Provider == "ollama" {
		refreshCommand = "'prolewatch doctor --probe-llm-quality'"
	}
	var attestation ProviderAttestation
	if err := ReadJSONFile(providerAttestationPath(), 1024*1024, &attestation); err != nil {
		// Keep strict decoding: an old or newer document must never be silently
		// reinterpreted. The raw decoder error is not useful recovery guidance,
		// though, especially across the CLI/HTTP evidence split introduced in v4.
		if strings.Contains(err.Error(), "json: unknown field") {
			return fmt.Errorf("stored provider semantic attestation uses an incompatible schema; run %s to replace it", refreshCommand)
		}
		return fmt.Errorf("run %s to create a provider semantic attestation: %w", refreshCommand, err)
	}
	return attestation.Validate(fingerprint, metadata, provider)
}

// storedOllamaTruncationRefused lets a fresh process reconstruct the verified
// adapter-policy variant before full attestation validation. It deliberately
// requires the exact current daemon/model/context tuple and every current HTTP
// observation; NewAuditService subsequently validates the complete policy
// fingerprint and archive identity before enabling AI review.
func storedOllamaTruncationRefused(metadata ProviderMetadata) bool {
	if metadata.Provider != "ollama" || metadata.Transport != "http-loopback" {
		return false
	}
	var attestation ProviderAttestation
	if err := ReadJSONFile(providerAttestationPath(), 1024*1024, &attestation); err != nil {
		return false
	}
	verified := ollamaMetadataWithTruncationPolicy(metadata, true)
	expectedHTTP := localHTTPProviderIdentity(verified)
	return attestation.SchemaVersion == providerAttestationSchemaVersion && attestation.CanaryVersion == providerCanaryVersion &&
		attestation.Metadata == verified && attestation.ProviderBinary == nil && attestation.LocalHTTP != nil &&
		*attestation.LocalHTTP == *expectedHTTP && validOllamaCanaryChecks(attestation.Checks)
}

// saveProviderAttestation persists an attestation for checks that passed.
//
// The checks are an argument rather than a constant so that persisting one is a
// statement about a run. Refusing to write a false observation makes "only what
// was seen" structural instead of a convention a later edit can quietly break.
func saveProviderAttestation(fingerprint string, metadata ProviderMetadata, provider brief.ToolIdentity, checks CanaryChecks) error {
	cliChecks := validCLICanaryChecks(checks)
	httpChecks := validOllamaCanaryChecks(checks)
	if (metadata.Provider == "ollama" && !httpChecks) || (metadata.Provider != "ollama" && !cliChecks) {
		return errors.New("refusing to attest a check the live run did not establish")
	}
	attestation := ProviderAttestation{SchemaVersion: providerAttestationSchemaVersion, CanaryVersion: providerCanaryVersion, CreatedAt: UTCNow(),
		SemanticFingerprint: fingerprint, Metadata: metadata, LocalHTTP: localHTTPProviderIdentity(metadata),
		Checks: checks}
	if metadata.Provider != "ollama" {
		attestation.ProviderBinary = &provider
	}
	return AtomicWriteJSON(providerAttestationPath(), attestation)
}

func validCLICanaryChecks(checks CanaryChecks) bool {
	return checks.EmptyWorkspace && checks.NoHostRead && checks.PromptInjectionRecognised &&
		!checks.LoopbackEndpoint && !checks.LocalModel && !checks.ContextVerified && !checks.StructuredOutput &&
		!checks.QualityGatePassed && !checks.PerformanceMeasured && !checks.TruncationRefused && checks.ObservedBytesPerToken == 0
}

func validOllamaCanaryChecks(checks CanaryChecks) bool {
	return !checks.EmptyWorkspace && !checks.NoHostRead && checks.PromptInjectionRecognised &&
		checks.LoopbackEndpoint && checks.LocalModel && checks.ContextVerified && checks.StructuredOutput &&
		checks.QualityGatePassed && checks.PerformanceMeasured && checks.TruncationRefused &&
		!math.IsNaN(checks.ObservedBytesPerToken) && !math.IsInf(checks.ObservedBytesPerToken, 0) &&
		checks.ObservedBytesPerToken >= ollamaMinimumObservedBytesPerToken()
}

func providerOuterSandboxCanary(ctx context.Context, cfg Config) error {
	// Place a random sentinel in host /tmp and assert that the provider sandbox
	// cannot see it and starts with an empty workspace. The fixed shell fragment
	// contains no provider- or package-controlled interpolation.
	sentinel, err := os.CreateTemp("", "prolewatch-provider-host-sentinel-")
	if err != nil {
		return err
	}
	sentinelPath := sentinel.Name()
	if _, err := sentinel.WriteString("host-only-sentinel"); err != nil {
		sentinel.Close()
		os.Remove(sentinelPath)
		return err
	}
	sentinel.Close()
	defer os.Remove(sentinelPath)
	hostHome, err := providerCredentialHome(providerAdapterFactory(cfg))
	if err != nil {
		return err
	}
	args := providerBwrapBase(hostHome, "/provider-home")
	check := fmt.Sprintf("test ! -e %q && test -z \"$(find /workspace -mindepth 1 -maxdepth 1 -print -quit)\"", sentinelPath)
	args = append(args, "/usr/bin/sh", "-c", check)
	probe, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	output := newLimitedBuffer(64 * 1024)
	command := exec.CommandContext(probe, providerSandboxBinary, args...)
	command.Stdout, command.Stderr = output, output
	if err := command.Run(); err != nil {
		return fmt.Errorf("provider outer sandbox canary failed: %w: %s", err, truncateTail(output.String(), 4*1024))
	}
	return nil
}
