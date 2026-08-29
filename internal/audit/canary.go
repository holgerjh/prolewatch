package audit

import (
	"context"
	"errors"
	"fmt"
	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/safe"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// providerCanaryVersion 3 dropped three checks that were never performed. An
// attestation written by an older version is rejected rather than reinterpreted,
// because its booleans meant something the run did not establish.
const providerCanaryVersion = 3

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
// set - is part of the policy fingerprint, so changing it invalidates every
// decision taken under the old one.
type CanaryChecks struct {
	// EmptyWorkspace and NoHostRead come from the outer sandbox canary: a host
	// sentinel is unreachable and /workspace starts empty.
	EmptyWorkspace bool `json:"empty_workspace"`
	NoHostRead     bool `json:"no_host_read"`
	// PromptInjectionRecognised comes from the semantic canary: the provider
	// returned exactly one verdict, it was a block, and it reported the
	// injection. That is a statement about the provider's answer, not about its
	// sandbox, and it is named so it cannot be read as more.
	PromptInjectionRecognised bool `json:"prompt_injection_recognised"`
}

type ProviderAttestation struct {
	// The attestation caches a successful live canary only for the exact policy,
	// provider binary, provider metadata, and archive-probe binary identities.
	SchemaVersion     int                `json:"schema_version"`
	CanaryVersion     int                `json:"canary_version"`
	CreatedAt         string             `json:"created_at"`
	PolicyFingerprint string             `json:"policy_fingerprint"`
	Metadata          ProviderMetadata   `json:"metadata"`
	ProviderBinary    brief.ToolIdentity `json:"provider_binary"`
	ArchiveProbe      brief.ToolIdentity `json:"archive_probe"`
	Checks            CanaryChecks       `json:"checks"`
}

func providerBinaryIdentity(ctx context.Context, cfg Config, metadata ProviderMetadata) (brief.ToolIdentity, error) {
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

func (a ProviderAttestation) Validate(fingerprint string, metadata ProviderMetadata, provider, archive brief.ToolIdentity) error {
	if a.SchemaVersion != 1 || a.CanaryVersion != providerCanaryVersion || a.PolicyFingerprint != fingerprint ||
		a.Metadata != metadata || a.ProviderBinary != provider || a.ArchiveProbe != archive {
		return errors.New("provider semantic attestation is absent, stale, or bound to different binaries or policy; run 'prolewatch doctor' to renew it")
	}
	if _, err := time.Parse(time.RFC3339Nano, a.CreatedAt); err != nil {
		return errors.New("provider semantic attestation has invalid time")
	}
	if !a.Checks.EmptyWorkspace || !a.Checks.NoHostRead || !a.Checks.PromptInjectionRecognised {
		return errors.New("provider semantic attestation did not pass every observed check")
	}
	return nil
}

func loadProviderAttestation(fingerprint string, metadata ProviderMetadata, provider, archive brief.ToolIdentity) error {
	var attestation ProviderAttestation
	if err := ReadJSONFile(providerAttestationPath(), 1024*1024, &attestation); err != nil {
		return fmt.Errorf("run 'prolewatch doctor' to create a provider semantic attestation: %w", err)
	}
	return attestation.Validate(fingerprint, metadata, provider, archive)
}

// saveProviderAttestation persists an attestation for checks that passed.
//
// The checks are an argument rather than a constant so that persisting one is a
// statement about a run. Refusing to write a false observation makes "only what
// was seen" structural instead of a convention a later edit can quietly break.
func saveProviderAttestation(fingerprint string, metadata ProviderMetadata, provider, archive brief.ToolIdentity, checks CanaryChecks) error {
	if !checks.EmptyWorkspace || !checks.NoHostRead || !checks.PromptInjectionRecognised {
		return errors.New("refusing to attest a check the live run did not establish")
	}
	attestation := ProviderAttestation{SchemaVersion: 1, CanaryVersion: providerCanaryVersion, CreatedAt: UTCNow(),
		PolicyFingerprint: fingerprint, Metadata: metadata, ProviderBinary: provider, ArchiveProbe: archive,
		Checks: checks}
	return AtomicWriteJSON(providerAttestationPath(), attestation)
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
