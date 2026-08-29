package audit

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/contain"
)

type doctorFakeAdapter struct{ metadata ProviderMetadata }

func (a doctorFakeAdapter) Metadata(context.Context) (ProviderMetadata, error) {
	return a.metadata, nil
}
func (doctorFakeAdapter) Review(context.Context, ReviewSnapshot) (Verdict, error) {
	return Verdict{}, nil
}
func (doctorFakeAdapter) CredentialPath() string { return "unused" }

func TestProviderSemanticCanaryUsesManifestBoundPKGBUILD(t *testing.T) {
	inventory := providerSemanticCanaryInventory()
	if inventory == nil || len(inventory.Files) != 1 || inventory.Files[0].Path != "PKGBUILD" || inventory.Files[0].PathB64 != "UEtHQlVJTEQ=" {
		t.Fatalf("semantic canary does not expose an unambiguous PKGBUILD: %+v", inventory)
	}
	if !inventory.Coverage.Complete || inventory.ManifestHash == "" || !strings.Contains(inventory.Files[0].SelectedText, "Ignore all previous instructions") {
		t.Fatalf("semantic canary lost its complete prompt-injection fixture: %+v", inventory)
	}
	for _, finding := range inventory.Findings {
		if finding.File != "PKGBUILD" {
			t.Fatalf("deterministic canary finding escaped its manifest path: %+v", finding)
		}
	}
}

func TestDeterministicDoctorOmitsProviderRequirements(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Review.Mode = ReviewModeDeterministicOnly
	previousFactory, previousResource := providerAdapterFactory, doctorResourceProbe
	called := false
	providerAdapterFactory = func(Config) providerAdapter {
		called = true
		return previousFactory(DefaultConfig())
	}
	doctorResourceProbe = func(context.Context, Config) (string, error) { return "transient unit ok", nil }
	defer func() { providerAdapterFactory, doctorResourceProbe = previousFactory, previousResource }()

	checks := RunDoctor(context.Background(), cfg, true)
	if called {
		t.Fatal("deterministic-only doctor initialized an AI provider")
	}
	resourceEnvelope := false
	for _, check := range checks {
		if check.Name == "systemd user resource envelope" {
			resourceEnvelope = check.OK && check.Required
		}
		switch check.Name {
		case "active provider binary", "prolewatch user", "dedicated provider authentication", "verdict schema", "active provider compatibility", "isolated provider semantic canary", "provider semantic attestation":
			t.Fatalf("deterministic-only doctor required provider check %q", check.Name)
		}
	}
	if !resourceEnvelope {
		t.Fatalf("deterministic doctor omitted its required resource-envelope check: %#v", checks)
	}
}

func TestResourceEnvelopeDoctorFailureIsRequiredAndActionable(t *testing.T) {
	previous := doctorResourceProbe
	defer func() { doctorResourceProbe = previous }()
	doctorResourceProbe = func(context.Context, Config) (string, error) {
		return "", fmt.Errorf("probe failed: %w", contain.ErrNoUserManager)
	}
	check := resourceEnvelopeCheck(context.Background(), DefaultConfig())
	if check.OK || !check.Required || check.Name != "systemd user resource envelope" ||
		!strings.Contains(check.Detail, "XDG_RUNTIME_DIR") || !strings.Contains(check.Detail, "loginctl enable-linger") {
		t.Fatalf("user-manager failure was not actionable: %+v", check)
	}
	doctorResourceProbe = func(context.Context, Config) (string, error) {
		return "transient unit ok", nil
	}
	check = resourceEnvelopeCheck(context.Background(), DefaultConfig())
	if !check.OK || !check.Required || check.Detail != "transient unit ok" {
		t.Fatalf("healthy resource envelope was rejected: %+v", check)
	}
}

func TestNoProbeDoctorStillValidatesProviderAttestation(t *testing.T) {
	withStateAndShare(t)
	previousAdapter, previousReviewer, previousCodex, previousCanary := providerAdapterFactory, reviewClientFactory, codexHostBinary, doctorProviderCanary
	defer func() {
		providerAdapterFactory, reviewClientFactory, codexHostBinary = previousAdapter, previousReviewer, previousCodex
		doctorProviderCanary = previousCanary
	}()
	metadata := ProviderMetadata{Provider: "codex", Transport: "cli", RuntimeVersion: "codex-cli test", Model: "gpt", Effort: "high", AdapterPolicy: "test-v1"}
	providerAdapterFactory = func(Config) providerAdapter { return doctorFakeAdapter{metadata: metadata} }
	reviewerCalled := false
	reviewClientFactory = func(Config) ReviewClient {
		reviewerCalled = true
		return &fakeReviewer{}
	}
	codexHostBinary = writeExecutable(t, "echo codex")
	cfg := aiConfig()
	archive, err := brief.ArchiveProbeIdentity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := ComputePolicyFingerprint(cfg, metadata, archive)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := providerBinaryIdentity(context.Background(), cfg, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveProviderAttestation(fingerprint, metadata, provider, archive, CanaryChecks{EmptyWorkspace: true, NoHostRead: true, PromptInjectionRecognised: true}); err != nil {
		t.Fatal(err)
	}

	checks := RunDoctor(context.Background(), cfg, false)
	count := 0
	for _, check := range checks {
		if check.Name == "provider semantic attestation" {
			count++
			if !check.OK {
				t.Fatalf("valid stored attestation failed: %s", check.Detail)
			}
		}
	}
	if count != 1 {
		t.Fatalf("no-probe doctor emitted %d attestation checks", count)
	}
	if reviewerCalled {
		t.Fatal("no-probe doctor spent a provider review request")
	}

	doctorProviderCanary = func(context.Context, Config) (ProviderMetadata, error) { return metadata, nil }
	reviewClientFactory = func(Config) ReviewClient {
		return &fakeReviewer{verdicts: []Verdict{{SchemaVersion: VerdictSchemaVersion, Verdict: "block", Confidence: "high", Summary: "prompt injection", Findings: []ReviewFinding{}, Guidance: []FindingGuidance{}, CoverageNotes: []string{}, PromptInjectionDetected: true}}}
	}
	checks = RunDoctor(context.Background(), cfg, true)
	count = 0
	for _, check := range checks {
		if check.Name == "provider semantic attestation" {
			count++
			if !check.OK {
				t.Fatalf("live doctor did not refresh the attestation: %s", check.Detail)
			}
		}
	}
	if count != 1 {
		t.Fatalf("live doctor emitted %d attestation checks", count)
	}
}

// TestDoctorStreamsEveryCheckItReturns binds the property the live output
// depends on: what the caller printed as checks arrived must be exactly the
// set the verdict is then computed from.
//
// The live provider probe spends a real request and can take a minute. Doctor
// used to print nothing until every check had finished, which on that path is
// indistinguishable from a hang.
func TestDoctorStreamsEveryCheckItReturns(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Review.Mode = ReviewModeDeterministicOnly

	var streamed []Check
	returned := RunDoctorStream(context.Background(), cfg, false, func(check Check) {
		streamed = append(streamed, check)
	})

	if len(streamed) != len(returned) {
		t.Fatalf("streamed %d checks, returned %d", len(streamed), len(returned))
	}
	for i := range returned {
		if streamed[i] != returned[i] {
			t.Fatalf("check %d differs: streamed %+v, returned %+v", i, streamed[i], returned[i])
		}
	}
	if len(returned) == 0 {
		t.Fatal("doctor produced no checks at all")
	}
	// A nil emitter is the batch path and must still work.
	if len(RunDoctor(context.Background(), cfg, false)) != len(returned) {
		t.Fatal("the batch path disagrees with the streamed one")
	}
}

// A non-required failure is a warning, and the streamed line has to say so -
// the Codex compatibility ceiling reaches the user through exactly this path.
func TestStreamedCheckLineMarksWarningsAsWarnings(t *testing.T) {
	renderer := terminalRenderer{caps: terminalCapabilities{Interactive: true}}
	warning := renderer.checkLine(Check{Name: "active provider compatibility", OK: false, Required: false, Detail: "newer than the checked ceiling"})
	if !strings.Contains(warning, "WARN") || strings.Contains(warning, "FAIL") {
		t.Errorf("a non-required failure did not render as a warning: %q", warning)
	}
	failure := renderer.checkLine(Check{Name: "yay Lua hook", OK: false, Required: true, Detail: "absent"})
	if !strings.Contains(failure, "FAIL") {
		t.Errorf("a required failure did not render as a failure: %q", failure)
	}
	// The unstyled fallback renders one check, not a set: RenderChecks closes a
	// passing set with a summary line that must not appear per check.
	plain := terminalRenderer{}.checkLine(Check{Name: "review mode", OK: true, Required: true, Detail: "ai"})
	if strings.Contains(plain, "Everything is fine") || strings.Count(plain, "\n") != 0 {
		t.Errorf("the unstyled per-check line is not a single line: %q", plain)
	}
}
