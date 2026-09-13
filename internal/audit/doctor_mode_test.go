package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/contain"
)

type doctorFakeAdapter struct {
	metadata   ProviderMetadata
	credential string
}

func (a doctorFakeAdapter) Metadata(context.Context) (ProviderMetadata, error) {
	return a.metadata, nil
}
func (doctorFakeAdapter) Review(context.Context, ReviewSnapshot) (Verdict, error) {
	return Verdict{}, nil
}
func (a doctorFakeAdapter) CredentialPath() string { return a.credential }

type doctorActionReviewer struct {
	metadata ProviderMetadata
	before   func()
}

type doctorResetAdapter struct {
	doctorFakeAdapter
	resets *int
}

func (a doctorResetAdapter) resetModel(context.Context) error {
	(*a.resets)++
	return nil
}

func (r doctorActionReviewer) Probe(context.Context) (ProviderMetadata, error) {
	return r.metadata, nil
}
func (r doctorActionReviewer) Review(context.Context, string, string, *brief.Inventory, ReviewOptions) (ProviderMetadata, []Verdict, error) {
	if r.before != nil {
		r.before()
	}
	return r.metadata, []Verdict{{SchemaVersion: VerdictSchemaVersion, Verdict: "block", Confidence: "high", Summary: "prompt injection", Findings: []ReviewFinding{}, Guidance: []FindingGuidance{}, CoverageNotes: []string{}, PromptInjectionDetected: true}}, nil
}

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
	credential := providerCredentialPath("codex", "auth.json")
	if err := AtomicWrite(credential, []byte("credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	providerAdapterFactory = func(Config) providerAdapter { return doctorFakeAdapter{metadata: metadata, credential: credential} }
	reviewerCalled := false
	reviewClientFactory = func(Config) ReviewClient {
		reviewerCalled = true
		return &fakeReviewer{}
	}
	codexHostBinary = writeExecutable(t, "echo codex")
	cfg := aiConfig()
	fingerprint, err := ComputeProviderAttestationFingerprint(cfg, metadata)
	if err != nil {
		t.Fatal(err)
	}
	provider, err := providerBinaryIdentity(context.Background(), cfg, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveProviderAttestation(fingerprint, metadata, provider, CanaryChecks{EmptyWorkspace: true, NoHostRead: true, PromptInjectionRecognised: true}); err != nil {
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

func TestOrdinaryOllamaDoctorDoesNotRunLongQualityProbe(t *testing.T) {
	withStateAndShare(t)
	previousAdapter, previousReviewer := providerAdapterFactory, reviewClientFactory
	defer func() {
		providerAdapterFactory, reviewClientFactory = previousAdapter, previousReviewer
	}()
	metadata := ProviderMetadata{
		Provider: "ollama", Transport: "http-loopback", RuntimeVersion: "ollama 0.32.13",
		Model: "secure-model:latest", ModelDigest: strings.Repeat("a", 64), ContextTokens: 131072,
		Thinking: true, Effort: "on", AdapterPolicy: ollamaAdapterPolicy("on", false),
	}
	providerAdapterFactory = func(Config) providerAdapter { return doctorFakeAdapter{metadata: metadata} }
	reviewerCalled := false
	reviewClientFactory = func(Config) ReviewClient {
		reviewerCalled = true
		return &fakeReviewer{}
	}

	checks := runDoctorStream(context.Background(), ollamaTestConfig(), true, false, "", nil, nil)
	if reviewerCalled {
		t.Fatal("ordinary Ollama doctor ran the opt-in quality assessment")
	}
	var attestation Check
	for _, check := range checks {
		if strings.HasPrefix(check.Name, "Ollama quality ") {
			t.Fatalf("ordinary Ollama doctor emitted a quality-case result: %+v", check)
		}
		if check.Name == "provider semantic attestation" {
			attestation = check
		}
	}
	if attestation.OK || !attestation.Required || !strings.Contains(attestation.Detail, "prolewatch doctor --probe-llm-quality") {
		t.Fatalf("missing Ollama attestation did not recommend the explicit quality probe: %+v", attestation)
	}
}

func TestOllamaDoctorSlowSourcesAttestsButUnusableMeasurementBlocks(t *testing.T) {
	for _, test := range []struct {
		name                string
		phases              []string
		omitPrefillDuration bool
		wantMeasured        bool
		wantAttestation     bool
		wantGuidance        string
	}{
		{name: "slow routine Sources", phases: []string{"sources", "artifact"}, wantMeasured: true, wantAttestation: true, wantGuidance: "suggested review.phases: [artifact]"},
		{name: "unusable measurement", phases: []string{"sources", "artifact"}, omitPrefillDuration: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			withStateAndShare(t)
			previousConfigPath := SystemConfigPath
			configPath := filepath.Join(t.TempDir(), "config.yaml")
			configContents := []byte("# Doctor must not rewrite this configuration\n")
			if err := os.WriteFile(configPath, configContents, 0o600); err != nil {
				t.Fatal(err)
			}
			SystemConfigPath = configPath
			t.Cleanup(func() { SystemConfigPath = previousConfigPath })
			previousAdapter, previousReviewer := providerAdapterFactory, reviewClientFactory
			t.Cleanup(func() { providerAdapterFactory, reviewClientFactory = previousAdapter, previousReviewer })
			metadata := ProviderMetadata{
				Provider: "ollama", Transport: "http-loopback", RuntimeVersion: "ollama 0.32.13",
				Model: "secure-model:latest", ModelDigest: ollamaTestDigest, ContextTokens: 131072,
				Thinking: true, Effort: "on", AdapterPolicy: ollamaAdapterPolicy("on", false),
			}
			adapter := &llmBenchmarkFakeAdapter{doctorFakeAdapter: doctorFakeAdapter{metadata: metadata}}
			providerAdapterFactory = func(Config) providerAdapter { return adapter }
			reviewer := &ollamaQualityReviewer{metadata: metadata, omitPrefillDuration: test.omitPrefillDuration}
			reviewClientFactory = func(Config) ReviewClient { return reviewer }
			cfg := ollamaTestConfig()
			cfg.Review.Phases = test.phases
			originalPhases := append([]string(nil), cfg.Review.Phases...)
			checks := runDoctorStream(context.Background(), cfg, true, true, "", nil, nil)
			actualContents, err := os.ReadFile(configPath)
			if err != nil || !bytes.Equal(actualContents, configContents) {
				t.Fatalf("Doctor changed the configuration file: contents=%q err=%v", actualContents, err)
			}
			if strings.Join(cfg.Review.Phases, ",") != strings.Join(originalPhases, ",") {
				t.Fatalf("Doctor changed the configured review phases: before=%v after=%v", originalPhases, cfg.Review.Phases)
			}
			var performance, attestation Check
			var providerChecks []Check
			for _, check := range checks {
				if strings.HasPrefix(check.Name, "Ollama quality ") || check.Name == "Ollama refuses over-context input" ||
					check.Name == "Ollama byte/token calibration" || check.Name == "Ollama measured throughput and sources projection" ||
					check.Name == "provider semantic attestation" {
					providerChecks = append(providerChecks, check)
				}
				switch check.Name {
				case "Ollama measured throughput and sources projection":
					performance = check
				case "provider semantic attestation":
					attestation = check
				}
			}
			if reviewer.calls != 7 || adapter.resets != 7 || performance.Name == "" || attestation.Name == "" {
				t.Fatalf("full quality probe did not run: calls=%d resets=%d performance=%+v attestation=%+v", reviewer.calls, adapter.resets, performance, attestation)
			}
			if performance.OK || performance.Required != !test.wantMeasured || attestation.OK != test.wantAttestation ||
				DoctorOK(providerChecks) != test.wantAttestation {
				t.Fatalf("Doctor misclassified the measurement: performance=%+v attestation=%+v provider checks=%+v", performance, attestation, providerChecks)
			}
			if test.wantMeasured {
				for _, fragment := range []string{"10m0s Sources budget", "the model passed every safety check", test.wantGuidance, llmSuitabilityRecipeArtifact} {
					if !strings.Contains(performance.Detail, fragment) {
						t.Fatalf("slow Sources warning omitted %q: %s", fragment, performance.Detail)
					}
				}
			} else if strings.Contains(performance.Detail, "suggested review.phases:") {
				t.Fatalf("unusable measurement suggested a speed-only workaround: %s", performance.Detail)
			}
		})
	}
}

func TestTargetedOllamaQualityProbeRunsOneCaseWithoutAttestationWork(t *testing.T) {
	withStateAndShare(t)
	previousAdapter, previousReviewer := providerAdapterFactory, reviewClientFactory
	defer func() {
		providerAdapterFactory, reviewClientFactory = previousAdapter, previousReviewer
	}()
	metadata := ProviderMetadata{
		Provider: "ollama", Transport: "http-loopback", RuntimeVersion: "ollama 0.32.13",
		Model: "secure-model:latest", ModelDigest: strings.Repeat("a", 64), ContextTokens: 131072,
		Thinking: true, Effort: "on", AdapterPolicy: ollamaAdapterPolicy("on", false),
	}
	resets := 0
	providerAdapterFactory = func(Config) providerAdapter {
		return doctorResetAdapter{doctorFakeAdapter: doctorFakeAdapter{metadata: metadata}, resets: &resets}
	}
	reviewer := &ollamaQualityReviewer{metadata: metadata}
	reviewClientFactory = func(Config) ReviewClient { return reviewer }

	checks := runDoctorStream(context.Background(), ollamaTestConfig(), true, false, ollamaQualityCasePrivilegedWritableDeserialization, nil, nil)
	qualityChecks := 0
	for _, check := range checks {
		switch {
		case strings.HasPrefix(check.Name, "Ollama quality "):
			qualityChecks++
			if !check.OK || !strings.Contains(check.Name, "privileged writable state") {
				t.Fatalf("targeted quality case failed: %+v", check)
			}
		case check.Name == "Ollama refuses over-context input" || check.Name == "Ollama byte/token calibration" || check.Name == "Ollama measured throughput and sources projection":
			t.Fatalf("targeted quality diagnostic ran full-attestation work: %+v", check)
		}
	}
	if reviewer.calls != 1 || qualityChecks != 1 || resets != 1 {
		t.Fatalf("targeted diagnostic did not make exactly one isolated quality request: calls=%d checks=%d resets=%d", reviewer.calls, qualityChecks, resets)
	}
}

func TestDoctorNamesMissingAuthenticationAndSkipsDependentProbes(t *testing.T) {
	withStateAndShare(t)
	previousAdapter, previousReviewer, previousCanary := providerAdapterFactory, reviewClientFactory, doctorProviderCanary
	defer func() {
		providerAdapterFactory, reviewClientFactory, doctorProviderCanary = previousAdapter, previousReviewer, previousCanary
	}()
	metadata := ProviderMetadata{Provider: "codex", Transport: "cli", RuntimeVersion: "codex-cli test", Model: "gpt", Effort: "high", AdapterPolicy: "test-v1"}
	credential := providerCredentialPath("codex", "auth.json")
	providerAdapterFactory = func(Config) providerAdapter { return doctorFakeAdapter{metadata: metadata, credential: credential} }
	canaryCalled, reviewerCalled := false, false
	doctorProviderCanary = func(context.Context, Config) (ProviderMetadata, error) {
		canaryCalled = true
		return metadata, nil
	}
	reviewClientFactory = func(Config) ReviewClient {
		reviewerCalled = true
		return &fakeReviewer{}
	}

	checks := RunDoctor(context.Background(), aiConfig(), true)
	byName := map[string]Check{}
	for _, check := range checks {
		byName[check.Name] = check
	}
	auth := byName[providerAuthCheckName]
	if auth.OK || !auth.Required || !strings.Contains(auth.Detail, credential) || !strings.Contains(auth.Detail, "CODEX_HOME=") || !strings.Contains(auth.Detail, " login") {
		t.Fatalf("missing credential check is not actionable: %+v", auth)
	}
	for _, name := range []string{"provider host/workspace isolation", "isolated provider semantic canary"} {
		check := byName[name]
		if check.OK || !strings.Contains(check.Detail, "not run: dedicated provider authentication failed") {
			t.Errorf("dependent probe %q did not name the skipped prerequisite: %+v", name, check)
		}
	}
	attestation := byName["provider semantic attestation"]
	if attestation.OK || !strings.Contains(attestation.Detail, "not checked: dedicated provider authentication failed") || strings.Contains(attestation.Detail, "unknown field") {
		t.Fatalf("attestation obscured the authentication prerequisite: %+v", attestation)
	}
	if canaryCalled || reviewerCalled {
		t.Fatalf("doctor attempted provider work without authentication: canary=%t reviewer=%t", canaryCalled, reviewerCalled)
	}
}

func TestDoctorAnnouncesSlowProviderChecksBeforeStartingThem(t *testing.T) {
	withStateAndShare(t)
	previousAdapter, previousReviewer, previousCodex, previousCanary := providerAdapterFactory, reviewClientFactory, codexHostBinary, doctorProviderCanary
	defer func() {
		providerAdapterFactory, reviewClientFactory, codexHostBinary, doctorProviderCanary = previousAdapter, previousReviewer, previousCodex, previousCanary
	}()
	metadata := ProviderMetadata{Provider: "codex", Transport: "cli", RuntimeVersion: "codex-cli test", Model: "gpt", Effort: "high", AdapterPolicy: "test-v1"}
	credential := providerCredentialPath("codex", "auth.json")
	if err := AtomicWrite(credential, []byte("credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	providerAdapterFactory = func(Config) providerAdapter { return doctorFakeAdapter{metadata: metadata, credential: credential} }
	codexHostBinary = writeExecutable(t, "echo codex")
	announced := map[string]string{}
	doctorProviderCanary = func(context.Context, Config) (ProviderMetadata, error) {
		if announced["provider host/workspace isolation"] == "" {
			t.Error("host/workspace action was not announced before the probe started")
		}
		return metadata, nil
	}
	reviewClientFactory = func(Config) ReviewClient {
		return doctorActionReviewer{metadata: metadata, before: func() {
			if announced["isolated provider semantic canary"] == "" {
				t.Error("semantic action was not announced before the provider request started")
			}
		}}
	}

	runDoctorStream(context.Background(), aiConfig(), true, true, "", nil, func(name, detail string) {
		announced[name] = detail
	})
	if !strings.Contains(announced["provider host/workspace isolation"], "up to 15s") {
		t.Errorf("outer probe announcement omitted its wait bound: %q", announced["provider host/workspace isolation"])
	}
	if detail := announced["isolated provider semantic canary"]; !strings.Contains(detail, "codex/gpt") || !strings.Contains(detail, "timeout 180s") {
		t.Errorf("semantic probe announcement omitted provider or timeout: %q", detail)
	}
}

func TestLegacyProviderAttestationGetsClearUpgradeGuidance(t *testing.T) {
	withStateAndShare(t)
	metadata := ProviderMetadata{Provider: "codex", Transport: "cli", RuntimeVersion: "codex-cli test", Model: "gpt", Effort: "high", AdapterPolicy: "test-v1"}
	provider := brief.ToolIdentity{Path: "/usr/bin/codex", Version: "v", SHA256: strings.Repeat("a", 64)}
	fingerprint := strings.Repeat("c", 64)
	valid := ProviderAttestation{SchemaVersion: providerAttestationSchemaVersion, CanaryVersion: providerCanaryVersion, CreatedAt: UTCNow(), SemanticFingerprint: fingerprint, Metadata: metadata, ProviderBinary: &provider, Checks: CanaryChecks{EmptyWorkspace: true, NoHostRead: true, PromptInjectionRecognised: true}}
	raw, err := CanonicalJSON(valid)
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]any
	if err := json.Unmarshal(raw, &legacy); err != nil {
		t.Fatal(err)
	}
	legacy["checks"].(map[string]any)["no_tools"] = true
	if err := AtomicWriteJSON(providerAttestationPath(), legacy); err != nil {
		t.Fatal(err)
	}

	err = loadProviderAttestation(fingerprint, metadata, provider)
	if err == nil || !strings.Contains(err.Error(), "incompatible schema") || !strings.Contains(err.Error(), "run 'prolewatch doctor' to replace it") || strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("legacy attestation did not get clear replacement guidance: %v", err)
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
	warningCheck := Check{Name: "active provider compatibility", OK: false, Required: false, Detail: "newer than the checked ceiling"}
	warning := renderer.checkLine(warningCheck)
	if !strings.Contains(warning, "WARN") || strings.Contains(warning, "FAIL") {
		t.Errorf("a non-required failure did not render as a warning: %q", warning)
	}
	if plain := plainCheckLine(warningCheck); !strings.HasPrefix(plain, "[WARN]") || !DoctorOK([]Check{warningCheck}) {
		t.Errorf("plain Doctor disagreed with the styled and benchmark warning state: %q", plain)
	}
	failure := renderer.checkLine(Check{Name: "yay Lua hook", OK: false, Required: true, Detail: "absent"})
	if !strings.Contains(failure, "FAIL") {
		t.Errorf("a required failure did not render as a failure: %q", failure)
	}
	action := renderer.checkActionLine("isolated provider semantic canary", "asking codex/gpt (timeout 180s)")
	if !strings.Contains(action, "RUN") || !strings.Contains(action, "isolated provider semantic canary") || !strings.Contains(action, "timeout 180s") || strings.Contains(action, "OK") || strings.Contains(action, "FAIL") {
		t.Errorf("a running provider action was not distinct from its eventual result: %q", action)
	}
	// The unstyled fallback renders one check, not a set: RenderChecks closes a
	// passing set with a summary line that must not appear per check.
	plain := terminalRenderer{}.checkLine(Check{Name: "review mode", OK: true, Required: true, Detail: "ai"})
	if strings.Contains(plain, "Everything is fine") || strings.Count(plain, "\n") != 0 {
		t.Errorf("the unstyled per-check line is not a single line: %q", plain)
	}
}
