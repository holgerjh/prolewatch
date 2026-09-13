package audit

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"
)

// TestOllamaLiveQualityBenchmark is an opt-in, quality-only model comparison.
// It reuses Doctor's real seven-case corpus and production review path without
// changing the installed configuration or writing provider attestation.
//
// Example:
//
//	PROLEWATCH_BENCH_MODEL=qwen3:8b PROLEWATCH_BENCH_CONTEXT_TOKENS=40960 \
//	  PROLEWATCH_BENCH_REASONING=off \
//	  go test ./internal/audit -run '^TestOllamaLiveQualityBenchmark$' -count=1 -v -timeout 30m
//
// This is a focused comparison, not a substitute for the full llm-benchmark
// command, which also verifies truncation refusal and byte/token calibration.
func TestOllamaLiveQualityBenchmark(t *testing.T) {
	model := os.Getenv("PROLEWATCH_BENCH_MODEL")
	if model == "" {
		t.Skip("set PROLEWATCH_BENCH_MODEL to opt in to a live Ollama benchmark")
	}
	contextText := os.Getenv("PROLEWATCH_BENCH_CONTEXT_TOKENS")
	contextTokens, err := strconv.Atoi(contextText)
	if err != nil {
		t.Fatalf("PROLEWATCH_BENCH_CONTEXT_TOKENS must be an integer: %v", err)
	}
	reasoning := os.Getenv("PROLEWATCH_BENCH_REASONING")
	if reasoning == "" {
		reasoning = "auto"
	}

	cfg := DefaultConfig()
	cfg.Provider = "ollama"
	cfg.Review.Mode = ReviewModeAI
	cfg.Providers.Ollama.Model = model
	cfg.Providers.Ollama.ContextTokens = contextTokens
	cfg.Providers.Ollama.Reasoning = reasoning
	if err := cfg.Validate(); err != nil {
		t.Fatalf("invalid live benchmark configuration: %v", err)
	}

	// The in-process dispatcher normally reloads the installed policy. Only
	// this opt-in test substitutes its candidate configuration, then restores
	// the loader before any other test runs. No production command does this.
	previousLoader := providerConfigLoader
	providerConfigLoader = func() (Config, error) { return cfg, nil }
	t.Cleanup(func() { providerConfigLoader = previousLoader })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	adapter := providerAdapterFactory(cfg)
	metadata, err := adapter.Metadata(ctx)
	if err != nil {
		t.Fatalf("cannot identify local Ollama model: %v", err)
	}
	resetter, ok := adapter.(ollamaQualityModelResetter)
	if !ok {
		t.Fatal("Ollama adapter cannot isolate benchmark cases")
	}
	t.Logf("MODEL model=%s digest=%s context=%d configured_reasoning=%s effective_reasoning=%s generation_cap=%d input_byte_ceiling=%d",
		metadata.Model, metadata.ModelDigest, metadata.ContextTokens, reasoning, metadata.Effort,
		ollamaGenerationLimit(metadata.Effort), ollamaInputByteCeiling(metadata.ContextTokens, metadata.Effort))

	started := time.Now()
	announce := func(name, _ string) { t.Logf("RUN %s", name) }
	complete := func(check Check) {
		status := "FAIL"
		if check.OK {
			status = "OK"
		} else if !check.Required {
			status = "WARN"
		}
		t.Logf("%s %s", status, check.Name)
	}
	_, qualityOK, metrics, cases := runOllamaQualityGate(ctx, cfg, metadata, "", resetter.resetModel, announce, complete)

	passed, warnings := 0, 0
	for _, result := range cases {
		if result.Passed {
			passed++
		}
		if result.SourceBindingWarning {
			warnings++
		}
		t.Logf("CASE id=%s passed=%t failure_stage=%s source_binding_warning=%t duration=%s requests=%d",
			result.ID, result.Passed, result.FailureStage, result.SourceBindingWarning,
			result.Duration, len(result.Metrics))
	}
	residency := benchmarkResidency(metrics)
	performance, performanceErr := measureOllamaPerformance(cfg, metadata.Effort, metrics)
	if performanceErr == nil {
		t.Logf("SPEED prefill_tokens_per_second=%.1f visible_output_tokens_per_second=%.1f max_request=%s projected_8mib_sources=%s",
			performance.PrefillPerSecond, performance.OutputPerSecond,
			performance.MaximumRequest.Round(time.Millisecond), performance.ProjectedDuration.Round(time.Second))
	} else {
		t.Log("SPEED unavailable: insufficient valid request metrics")
	}
	t.Logf("RESULT passed=%d/%d quality_ok=%t binding_warnings=%d wall=%s requests=%d gpu_residency_reported=%t gpu_residency_percent=%.1f",
		passed, len(cases), qualityOK, warnings, time.Since(started).Round(time.Millisecond),
		len(metrics), residency.Reported, residency.ModelVRAMPercent)
	if !qualityOK || len(cases) != len(ollamaDoctorQualityCases()) {
		t.Error("Ollama model did not pass the complete seven-case quality gate")
	}
	if performanceErr != nil {
		t.Error("Ollama model did not return usable performance metrics")
	}
}
