package audit

import (
	"context"
	"strings"
	"testing"
)

func TestRunScanWarnsImmediatelyWhenOllamaQualityAttestationIsMissing(t *testing.T) {
	withStateAndShare(t)
	checkout := t.TempDir()
	writePackageFixture(t, checkout)
	cfg := ollamaTestConfig()
	metadata := ProviderMetadata{
		Provider: "ollama", Transport: "http-loopback", RuntimeVersion: "ollama 0.32.13",
		Model: cfg.Providers.Ollama.Model, ModelDigest: ollamaTestDigest,
		ContextTokens: cfg.Providers.Ollama.ContextTokens, Thinking: true, Effort: "on",
		AdapterPolicy: ollamaAdapterPolicy("on", false),
	}
	previousFactory := reviewClientFactory
	reviewClientFactory = func(Config) ReviewClient { return &ollamaQualityReviewer{metadata: metadata} }
	t.Cleanup(func() { reviewClientFactory = previousFactory })

	status := -1
	output := captureStderr(t, func() {
		status = runScan(context.Background(), cfg, []string{"--phase", "pre", "--dir", checkout, "--package-base", "demo"})
	})
	if status != ExitOK {
		t.Fatalf("missing optional attestation blocked a clean deterministic scan: status=%d output=%s", status, output)
	}
	for _, fragment := range []string{
		"[WARN] Ollama AI review disabled", "model quality attestation is missing or invalid",
		"false sense of security", "only deterministic inspection runs",
		"prolewatch doctor --probe-llm-quality", "review.mode: deterministic-only",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("startup warning omitted %q: %s", fragment, output)
		}
	}
	if strings.Count(output, "[WARN] Ollama AI review disabled") != 1 {
		t.Fatalf("startup warning was not emitted exactly once: %s", output)
	}
	if warning, report := strings.Index(output, "[WARN] Ollama AI review disabled"), strings.Index(output, "demo / pre:"); report < 0 || warning > report {
		t.Fatalf("attestation warning did not precede the scan briefing: %s", output)
	}
}

func TestOllamaAttestationStartupWarningIsSpecificToItsFailure(t *testing.T) {
	cfg := ollamaTestConfig()
	missing := &AuditService{InitializationError: "provider attestation validation failed; AI review disabled for this run: absent"}
	if _, ok := ollamaAttestationStartupWarning(cfg, missing); !ok {
		t.Fatal("missing Ollama attestation did not produce a warning")
	}
	for _, test := range []struct {
		name    string
		cfg     Config
		service *AuditService
	}{
		{name: "nil service", cfg: cfg},
		{name: "healthy Ollama", cfg: cfg, service: &AuditService{}},
		{name: "Ollama outage", cfg: cfg, service: &AuditService{InitializationError: "provider compatibility probe failed; AI review disabled for this run"}},
		{name: "reviewer retained", cfg: cfg, service: &AuditService{Reviewer: &ollamaQualityReviewer{}, InitializationError: missing.InitializationError}},
		{name: "deterministic mode", cfg: func() Config { other := cfg; other.Review.Mode = ReviewModeDeterministicOnly; return other }(), service: missing},
		{name: "CLI provider", cfg: func() Config { other := cfg; other.Provider = "codex"; return other }(), service: missing},
	} {
		t.Run(test.name, func(t *testing.T) {
			if warning, ok := ollamaAttestationStartupWarning(test.cfg, test.service); ok {
				t.Fatalf("unrelated state produced an Ollama attestation warning: %+v", warning)
			}
		})
	}
}
