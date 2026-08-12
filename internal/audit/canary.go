package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const providerCanaryVersion = 2

type CanaryChecks struct {
	EmptyWorkspace bool `json:"empty_workspace"`
	NoHostRead     bool `json:"no_host_read"`
	NoTools        bool `json:"no_tools"`
	NoCommands     bool `json:"no_commands"`
	StrictSchema   bool `json:"strict_schema"`
}

type ProviderAttestation struct {
	SchemaVersion     int              `json:"schema_version"`
	CanaryVersion     int              `json:"canary_version"`
	CreatedAt         string           `json:"created_at"`
	PolicyFingerprint string           `json:"policy_fingerprint"`
	Metadata          ProviderMetadata `json:"metadata"`
	ProviderBinary    ToolIdentity     `json:"provider_binary"`
	ArchiveProbe      ToolIdentity     `json:"archive_probe"`
	Checks            CanaryChecks     `json:"checks"`
}

func providerBinaryIdentity(ctx context.Context, cfg Config, metadata ProviderMetadata) (ToolIdentity, error) {
	path := "/usr/bin/codex"
	if cfg.Provider == "anthropic" {
		path = claudeHostBinary
	} else {
		path = codexHostBinary
	}
	digest, err := HashFileNoFollow(path)
	if err != nil {
		return ToolIdentity{}, err
	}
	return ToolIdentity{Path: path, Version: metadata.RuntimeVersion, SHA256: digest}, nil
}

func providerAttestationPath() string {
	return filepath.Join(StateRoot(), "provider-attestation.json")
}

func (a ProviderAttestation) Validate(fingerprint string, metadata ProviderMetadata, provider, archive ToolIdentity) error {
	if a.SchemaVersion != 1 || a.CanaryVersion != providerCanaryVersion || a.PolicyFingerprint != fingerprint ||
		a.Metadata != metadata || a.ProviderBinary != provider || a.ArchiveProbe != archive {
		return errors.New("provider semantic attestation is absent, stale, or bound to different binaries or policy; run 'prolewatch doctor' to renew it")
	}
	if _, err := time.Parse(time.RFC3339Nano, a.CreatedAt); err != nil {
		return errors.New("provider semantic attestation has invalid time")
	}
	if !a.Checks.EmptyWorkspace || !a.Checks.NoHostRead || !a.Checks.NoTools || !a.Checks.NoCommands || !a.Checks.StrictSchema {
		return errors.New("provider semantic attestation did not pass every isolation check")
	}
	return nil
}

func loadProviderAttestation(fingerprint string, metadata ProviderMetadata, provider, archive ToolIdentity) error {
	var attestation ProviderAttestation
	if err := ReadJSONFile(providerAttestationPath(), 1024*1024, &attestation); err != nil {
		return fmt.Errorf("run 'prolewatch doctor' to create a provider semantic attestation: %w", err)
	}
	return attestation.Validate(fingerprint, metadata, provider, archive)
}

func saveProviderAttestation(fingerprint string, metadata ProviderMetadata, provider, archive ToolIdentity) error {
	attestation := ProviderAttestation{SchemaVersion: 1, CanaryVersion: providerCanaryVersion, CreatedAt: UTCNow(),
		PolicyFingerprint: fingerprint, Metadata: metadata, ProviderBinary: provider, ArchiveProbe: archive,
		Checks: CanaryChecks{EmptyWorkspace: true, NoHostRead: true, NoTools: true, NoCommands: true, StrictSchema: true}}
	return AtomicWriteJSON(providerAttestationPath(), attestation)
}

func providerOuterSandboxCanary(ctx context.Context, cfg Config) error {
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
	hostHome, sandboxHome := "/var/lib/prolewatch/providers/codex", "/provider-home"
	if cfg.Provider == "anthropic" {
		hostHome = "/var/lib/prolewatch/providers/anthropic"
	}
	args := providerBwrapBase(hostHome, sandboxHome)
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
