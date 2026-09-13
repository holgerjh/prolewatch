package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

type llmBenchmarkFakeAdapter struct {
	doctorFakeAdapter
	resets int
}

func (a *llmBenchmarkFakeAdapter) resetModel(context.Context) error {
	a.resets++
	return nil
}

func (a *llmBenchmarkFakeAdapter) VerifyTruncationRefusal(context.Context) (ProviderMetadata, error) {
	return ollamaMetadataWithTruncationPolicy(a.metadata, true), nil
}

func TestLLMBenchmarkEmitsShareableProfileAndCanAttest(t *testing.T) {
	withStateAndShare(t)
	previousAdapter, previousReviewer, previousGPUInventory := providerAdapterFactory, reviewClientFactory, llmBenchmarkGPUInventory
	t.Cleanup(func() {
		providerAdapterFactory, reviewClientFactory, llmBenchmarkGPUInventory = previousAdapter, previousReviewer, previousGPUInventory
	})
	metadata := ProviderMetadata{
		Provider: "ollama", Transport: "http-loopback", RuntimeVersion: "ollama 0.32.13",
		Model: "secure-model:latest", ModelDigest: ollamaTestDigest, ContextTokens: 131072,
		Thinking: true, Effort: "on", AdapterPolicy: ollamaAdapterPolicy("on", false),
	}
	adapter := &llmBenchmarkFakeAdapter{doctorFakeAdapter: doctorFakeAdapter{metadata: metadata}}
	providerAdapterFactory = func(Config) providerAdapter { return adapter }
	reviewer := &ollamaQualityReviewer{metadata: metadata}
	reviewClientFactory = func(Config) ReviewClient { return reviewer }
	llmBenchmarkGPUInventory = func(context.Context) []LLMBenchmarkGPU {
		return []LLMBenchmarkGPU{{Model: "NVIDIA Test GPU", VRAMMiB: 16384}}
	}

	privateValues := []string{"benchmark-private-user", "/private/benchmark/home", "private-benchmark-host"}
	t.Setenv("USER", privateValues[0])
	t.Setenv("HOME", privateValues[1])
	t.Setenv("HOSTNAME", privateValues[2])
	cfg := ollamaTestConfig()
	// The fake timing intentionally projects above ten minutes. Omitting Sources
	// makes that an advisory recipe/artifact profile while still allowing the
	// exact semantic evidence to renew an attestation.
	cfg.Review.Phases = []string{"recipe", "artifact"}
	var stdout, stderr bytes.Buffer
	status := runLLMBenchmarkCommand(context.Background(), cfg, []string{"--attest"}, &stdout, &stderr)
	if status != ExitOK {
		t.Fatalf("benchmark failed with status %d: %s", status, stderr.String())
	}
	var report LLMBenchmarkReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("benchmark output is not JSON: %v\n%s", err, stdout.String())
	}
	if err := validateLLMBenchmarkReport(report); err != nil {
		t.Fatalf("benchmark report failed validation: %v", err)
	}
	if !report.BenchmarkPassed || !report.AttestationRequested || !report.AttestationSaved || !report.TruncationRefused ||
		report.Suitability != llmSuitabilityRecipeArtifact || len(report.QualityCases) != 7 || adapter.resets != 7 {
		t.Fatalf("benchmark result is incomplete: %+v", report)
	}
	if len(report.Hardware.GPUs) != 1 || report.Hardware.GPUs[0].Model != "NVIDIA Test GPU" ||
		report.Throughput.PrefillTokensPerSecond <= 0 || report.Throughput.MaximumRequestSeconds <= 0 {
		t.Fatalf("benchmark omitted decision-useful hardware or speed: %+v", report)
	}
	if report.Provider.Reasoning != "on" || report.Configuration.InputByteCeiling != ollamaInputByteCeiling(131072, "on") || report.Configuration.GenerationLimitTokens != 6144 {
		t.Fatalf("benchmark omitted distinct context and generation bounds: %+v", report.Configuration)
	}
	mutated := report
	mutated.Configuration.GenerationLimitTokens++
	if validateLLMBenchmarkReport(mutated) == nil {
		t.Fatal("benchmark accepted a mutated generation limit")
	}
	if _, err := os.Stat(providerAttestationPath()); err != nil {
		t.Fatalf("--attest did not save provider evidence: %v", err)
	}
	combined := stdout.String() + stderr.String()
	for _, private := range privateValues {
		if strings.Contains(combined, private) {
			t.Fatalf("benchmark output leaked private host metadata %q", private)
		}
	}
	for _, forbiddenKey := range []string{`"hostname"`, `"username"`, `"home"`, `"serial"`, `"uuid"`, `"driver_version"`, `"pci_bus"`} {
		if strings.Contains(stdout.String(), forbiddenKey) {
			t.Fatalf("benchmark schema contains forbidden host field %s", forbiddenKey)
		}
	}
}

func TestLLMBenchmarkKeepsSlowSourcesUnqualifiedForAllGates(t *testing.T) {
	withStateAndShare(t)
	previousAdapter, previousReviewer, previousGPUInventory := providerAdapterFactory, reviewClientFactory, llmBenchmarkGPUInventory
	t.Cleanup(func() {
		providerAdapterFactory, reviewClientFactory, llmBenchmarkGPUInventory = previousAdapter, previousReviewer, previousGPUInventory
	})
	metadata := ProviderMetadata{
		Provider: "ollama", Transport: "http-loopback", RuntimeVersion: "ollama 0.32.13",
		Model: "secure-model:latest", ModelDigest: ollamaTestDigest, ContextTokens: 131072,
		Thinking: true, Effort: "on", AdapterPolicy: ollamaAdapterPolicy("on", false),
	}
	adapter := &llmBenchmarkFakeAdapter{doctorFakeAdapter: doctorFakeAdapter{metadata: metadata}}
	providerAdapterFactory = func(Config) providerAdapter { return adapter }
	reviewer := &ollamaQualityReviewer{metadata: metadata}
	reviewClientFactory = func(Config) ReviewClient { return reviewer }
	llmBenchmarkGPUInventory = func(context.Context) []LLMBenchmarkGPU { return nil }
	cfg := ollamaTestConfig()
	cfg.Review.Phases = []string{"sources", "artifact"}
	var stdout, stderr bytes.Buffer
	status := runLLMBenchmarkCommand(context.Background(), cfg, []string{"--attest"}, &stdout, &stderr)
	if status != ExitReviewUnavailable {
		t.Fatalf("slow all-gates benchmark status=%d stderr=%s", status, stderr.String())
	}
	var report LLMBenchmarkReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("benchmark emitted invalid JSON: %v", err)
	}
	if report.BenchmarkPassed || report.AttestationSaved || !report.AttestationRequested ||
		report.Suitability != llmSuitabilityRecipeArtifact || report.Throughput.ProjectedSourcesSeconds <= ollamaSourcesProjectionBudget.Seconds() ||
		!strings.Contains(stderr.String(), "[WARN] Ollama measured throughput and sources projection") {
		t.Fatalf("slow Sources did not retain benchmark classification: report=%+v stderr=%s", report, stderr.String())
	}
	if _, err := os.Stat(providerAttestationPath()); !os.IsNotExist(err) {
		t.Fatalf("benchmark unexpectedly attested slow all-gates profile: %v", err)
	}
}

func TestOllamaResidencyWarningReportsCPUOffload(t *testing.T) {
	metrics := []OllamaRequestMetrics{{ModelBytes: 14 << 30, ModelVRAMBytes: 12 << 30, LoadedContextTokens: 40_960}}
	check := ollamaResidencyCheck(metrics)
	if check.OK || check.Required || !strings.Contains(check.Detail, "2.00 GiB") || !strings.Contains(check.Detail, "smaller providers.ollama.context_tokens") {
		t.Fatalf("CPU spill did not produce actionable warning: %+v", check)
	}
	metrics[0].ModelVRAMBytes = metrics[0].ModelBytes
	if check := ollamaResidencyCheck(metrics); !check.OK {
		t.Fatalf("fully resident model warned: %+v", check)
	}
}

func TestLLMBenchmarkRequestSeparatesUnaccountedAndWallTime(t *testing.T) {
	metric := OllamaRequestMetrics{RequestBytes: 10000, PromptTokens: 1000, OutputTokens: 100,
		LoadDurationNS: int64(time.Second), PromptDurationNS: int64(time.Second), OutputDurationNS: int64(time.Second),
		UnaccountedDurationNS: int64(7 * time.Second), TotalDurationNS: int64(10 * time.Second), WallDurationNS: int64(11 * time.Second)}
	public := publicLLMBenchmarkRequest(metric)
	if public.UnaccountedMilliseconds != 7000 || public.TotalMilliseconds != 10000 || public.WallMilliseconds != 11000 || public.OutputTokensPerSecond != 100 {
		t.Fatalf("benchmark conflated visible output, daemon remainder, or wall time: %+v", public)
	}
	metric.UnaccountedDurationNS = -1
	if metric.Validate() == nil {
		t.Fatal("negative unaccounted duration accepted")
	}
}

func TestLLMBenchmarkSuitabilityUsesQualityAndSourcesBudget(t *testing.T) {
	fast := ollamaPerformanceMeasurement{ProjectedDuration: 9 * time.Minute, MaximumRequest: time.Minute}
	slow := ollamaPerformanceMeasurement{ProjectedDuration: 11 * time.Minute, MaximumRequest: time.Minute}
	stalled := ollamaPerformanceMeasurement{ProjectedDuration: 9 * time.Minute, MaximumRequest: 6 * time.Minute}
	if got := llmBenchmarkSuitability(true, true, true, fast, nil); got != llmSuitabilityAllGates {
		t.Fatalf("fast qualified model got suitability %q", got)
	}
	if got := llmBenchmarkSuitability(true, true, true, slow, nil); got != llmSuitabilityRecipeArtifact {
		t.Fatalf("slow qualified model got suitability %q", got)
	}
	if got := llmBenchmarkSuitability(false, true, true, fast, nil); got != llmSuitabilityNotQualified {
		t.Fatalf("unsafe model got suitability %q", got)
	}
	if got := llmBenchmarkSuitability(true, true, true, stalled, nil); got != llmSuitabilityNotQualified {
		t.Fatalf("stalled model got suitability %q", got)
	}
}

func TestLLMBenchmarkRejectsNonLocalProviderWithoutOutput(t *testing.T) {
	cfg := DefaultConfig()
	var stdout, stderr bytes.Buffer
	if status := runLLMBenchmarkCommand(context.Background(), cfg, nil, &stdout, &stderr); status != ExitInvalidInvocation || stdout.Len() != 0 || !strings.Contains(stderr.String(), "provider=ollama") {
		t.Fatalf("invalid benchmark invocation status=%d stdout=%q stderr=%q", status, stdout.String(), stderr.String())
	}
}

func TestLLMBenchmarkHardwareAndResidencyStayCoarse(t *testing.T) {
	gpus, ok := parseNVIDIAGPUs("NVIDIA Test GPU, 16384\nNVIDIA Example Accelerator, 24576\n")
	if !ok || len(gpus) != 2 || gpus[0].Model != "NVIDIA Test GPU" || gpus[0].VRAMMiB != 16384 {
		t.Fatalf("allowlisted GPU inventory did not parse: ok=%t gpus=%+v", ok, gpus)
	}
	if _, ok := parseNVIDIAGPUs("NVIDIA Test GPU, 16384, GPU-secret-uuid"); ok {
		t.Fatal("GPU inventory accepted an unexpected identifying field")
	}
	residency := benchmarkResidency([]OllamaRequestMetrics{
		{ModelBytes: 16_000, ModelVRAMBytes: 12_000, LoadedContextTokens: 131072},
		{ModelBytes: 16_000, ModelVRAMBytes: 16_000, LoadedContextTokens: 65536},
	})
	if !residency.Reported || residency.ModelVRAMPercent != 75 || residency.FullyGPUResident || residency.LoadedContextTokens != 65536 {
		t.Fatalf("coarse residency summary is wrong: %+v", residency)
	}
}
