package audit

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/holgerjh/prolewatch/internal/safe"
)

const LLMBenchmarkSchemaVersion = 3

const (
	llmSuitabilityAllGates       = "all-gates"
	llmSuitabilityRecipeArtifact = "recipe-artifact"
	llmSuitabilityNotQualified   = "not-qualified"
	llmBenchmarkMaximumRequest   = 5 * time.Minute
)

// These types intentionally form an allowlist for public benchmark output.
// They contain no arbitrary errors, raw model text, paths, usernames, hostnames,
// device identifiers, or process information.
type LLMBenchmarkReport struct {
	SchemaVersion         int                       `json:"schema_version"`
	QualityCorpusVersion  int                       `json:"quality_corpus_version"`
	MeasuredAt            string                    `json:"measured_at"`
	ProlewatchVersion     string                    `json:"prolewatch_version"`
	SemanticFingerprint   string                    `json:"semantic_fingerprint"`
	Provider              LLMBenchmarkProvider      `json:"provider"`
	Configuration         LLMBenchmarkConfiguration `json:"configuration"`
	Hardware              LLMBenchmarkHardware      `json:"hardware"`
	QualityCases          []LLMBenchmarkQualityCase `json:"quality_cases"`
	TruncationRefused     bool                      `json:"truncation_refused"`
	Calibration           LLMBenchmarkCalibration   `json:"calibration"`
	Throughput            LLMBenchmarkThroughput    `json:"throughput"`
	Residency             LLMBenchmarkResidency     `json:"residency"`
	TotalWallMilliseconds int64                     `json:"total_wall_ms"`
	Suitability           string                    `json:"suitability"`
	BenchmarkPassed       bool                      `json:"benchmark_passed"`
	AttestationRequested  bool                      `json:"attestation_requested"`
	AttestationSaved      bool                      `json:"attestation_saved"`
}

type LLMBenchmarkProvider struct {
	RuntimeVersion              string `json:"runtime_version"`
	Model                       string `json:"model"`
	ModelDigest                 string `json:"model_digest"`
	ContextTokens               int    `json:"context_tokens"`
	Thinking                    bool   `json:"thinking"`
	Reasoning                   string `json:"reasoning"`
	AdapterPolicy               string `json:"adapter_policy"`
	RuntimeCompatibilityWarning bool   `json:"runtime_compatibility_warning"`
}

type LLMBenchmarkConfiguration struct {
	KeepAliveSeconds            int      `json:"keep_alive_seconds"`
	TimeoutSeconds              int      `json:"timeout_seconds"`
	GenerationLimitTokens       int      `json:"generation_limit_tokens"`
	InputByteCeiling            int      `json:"input_byte_ceiling"`
	ReviewBatchBytes            int      `json:"review_batch_bytes"`
	MaximumSelectedTextBytes    int64    `json:"maximum_selected_text_bytes"`
	ManualReviewMinimumSeverity string   `json:"manual_review_minimum_severity"`
	ConfiguredGates             []string `json:"configured_gates"`
}

type LLMBenchmarkHardware struct {
	GPUs []LLMBenchmarkGPU `json:"gpus"`
}

type LLMBenchmarkGPU struct {
	Model   string `json:"model"`
	VRAMMiB int    `json:"vram_mib"`
}

type LLMBenchmarkQualityCase struct {
	ID                   string                `json:"id"`
	Name                 string                `json:"name"`
	Passed               bool                  `json:"passed"`
	DurationMilliseconds int64                 `json:"duration_ms"`
	FailureStage         string                `json:"failure_stage,omitempty"`
	SourceBindingWarning bool                  `json:"source_binding_warning"`
	Requests             []LLMBenchmarkRequest `json:"requests"`
}

type LLMBenchmarkRequest struct {
	RequestBytes            int     `json:"request_bytes"`
	PromptTokens            int     `json:"prompt_tokens"`
	OutputTokens            int     `json:"output_tokens"`
	ThinkingBytes           int     `json:"thinking_bytes"`
	LoadMilliseconds        float64 `json:"load_ms"`
	PrefillMilliseconds     float64 `json:"prefill_ms"`
	OutputMilliseconds      float64 `json:"output_ms"`
	UnaccountedMilliseconds float64 `json:"unaccounted_ms"`
	TotalMilliseconds       float64 `json:"total_ms"`
	WallMilliseconds        float64 `json:"wall_ms"`
	PrefillTokensPerSecond  float64 `json:"prefill_tokens_per_second"`
	OutputTokensPerSecond   float64 `json:"output_tokens_per_second"`
}

type LLMBenchmarkCalibration struct {
	Passed                bool    `json:"passed"`
	ObservedBytesPerToken float64 `json:"observed_bytes_per_token"`
	RequiredBytesPerToken float64 `json:"required_bytes_per_token"`
}

type LLMBenchmarkThroughput struct {
	Measured                bool    `json:"measured"`
	RequestCount            int     `json:"request_count"`
	PromptTokens            int64   `json:"prompt_tokens"`
	OutputTokens            int64   `json:"output_tokens"`
	PrefillTokensPerSecond  float64 `json:"prefill_tokens_per_second"`
	OutputTokensPerSecond   float64 `json:"output_tokens_per_second"`
	ColdLoadMilliseconds    float64 `json:"cold_load_ms"`
	MaximumRequestSeconds   float64 `json:"maximum_request_seconds"`
	SourcesReferenceBytes   int     `json:"sources_reference_bytes"`
	SourcesBatchCount       int     `json:"sources_batch_count"`
	SelectedBytesPerBatch   int     `json:"selected_bytes_per_batch"`
	PromptTokensPerBatch    int     `json:"prompt_tokens_per_batch"`
	ProjectedSourcesSeconds float64 `json:"projected_sources_seconds"`
}

type LLMBenchmarkResidency struct {
	Reported            bool    `json:"reported"`
	ModelBytes          int64   `json:"model_bytes"`
	ModelVRAMBytes      int64   `json:"model_vram_bytes"`
	ModelVRAMPercent    float64 `json:"model_vram_percent"`
	FullyGPUResident    bool    `json:"fully_gpu_resident"`
	LoadedContextTokens int     `json:"loaded_context_tokens"`
}

var llmBenchmarkGPUInventory = detectNVIDIAGPUs

func runLLMBenchmarkCommand(ctx context.Context, cfg Config, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("llm-benchmark", flag.ContinueOnError)
	flags.SetOutput(stderr)
	attest := flags.Bool("attest", false, "save provider attestation when the benchmark passes")
	if err := flags.Parse(args); err != nil {
		return ExitInvalidInvocation
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "prolewatch: llm-benchmark accepts no positional arguments")
		return ExitInvalidInvocation
	}
	if cfg.Review.Mode != ReviewModeAI || cfg.Provider != "ollama" {
		fmt.Fprintln(stderr, "prolewatch: llm-benchmark requires review.mode=ai with provider=ollama")
		return ExitInvalidInvocation
	}

	started := time.Now()
	adapter := providerAdapterFactory(cfg)
	metadata, err := adapter.Metadata(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "prolewatch: cannot establish the local Ollama benchmark identity; run 'prolewatch doctor' for private diagnostics")
		return ExitReviewUnavailable
	}
	resetter, ok := adapter.(ollamaQualityModelResetter)
	if !ok {
		fmt.Fprintln(stderr, "prolewatch: active Ollama adapter cannot isolate benchmark cases")
		return ExitReviewUnavailable
	}

	announce := func(name, _ string) { fmt.Fprintf(stderr, "[RUN] %s\n", name) }
	complete := func(check Check) {
		fmt.Fprintf(stderr, "[%s] %s\n", checkResultLabel(check), check.Name)
	}
	_, qualityOK, metrics, measurements := runOllamaQualityGate(ctx, cfg, metadata, "", resetter.resetModel, announce, complete)

	truncation, verifiedMetadata, truncationOK := runOllamaTruncationProbe(ctx, adapter, metadata, announce)
	complete(truncation)
	if truncationOK {
		metadata = verifiedMetadata
	}
	calibrationCheck, observedBytesPerToken := ollamaByteTokenCalibration(metrics)
	complete(calibrationCheck)
	performanceCheck, _ := ollamaPerformanceProjection(cfg, metadata.Effort, metrics, qualityOK && truncationOK && calibrationCheck.OK)
	complete(performanceCheck)
	complete(ollamaResidencyCheck(metrics))
	performance, performanceErr := measureOllamaPerformance(cfg, metadata.Effort, metrics)

	requestTimeOK := performanceErr == nil && performance.MaximumRequest <= llmBenchmarkMaximumRequest
	benchmarkPassed := qualityOK && truncationOK && calibrationCheck.OK && performanceCheck.OK && performanceErr == nil && requestTimeOK
	suitability := llmBenchmarkSuitability(qualityOK, truncationOK, calibrationCheck.OK, performance, performanceErr)
	semanticFingerprint, fingerprintErr := ComputeProviderAttestationFingerprint(cfg, metadata)
	if fingerprintErr != nil {
		fmt.Fprintln(stderr, "prolewatch: cannot fingerprint the benchmark inputs; run 'prolewatch doctor' for private diagnostics")
		return ExitStateFailure
	}

	attestationSaved := false
	if *attest && benchmarkPassed {
		providerBinary, identityErr := providerBinaryIdentity(ctx, cfg, metadata)
		if identityErr == nil {
			attestationSaved = saveProviderAttestation(semanticFingerprint, metadata, providerBinary, CanaryChecks{
				LoopbackEndpoint: true, LocalModel: true, ContextVerified: true, StructuredOutput: true,
				PromptInjectionRecognised: true, QualityGatePassed: true, PerformanceMeasured: true,
				TruncationRefused: true, ObservedBytesPerToken: observedBytesPerToken,
			}) == nil
		}
		if !attestationSaved {
			fmt.Fprintln(stderr, "prolewatch: benchmark passed but the provider attestation could not be saved; run 'prolewatch doctor --probe-llm-quality' for private diagnostics")
		}
	}

	report := buildLLMBenchmarkReport(cfg, metadata, semanticFingerprint, measurements, metrics, truncationOK, calibrationCheck.OK, observedBytesPerToken,
		performance, performanceErr == nil, llmBenchmarkGPUInventory(ctx), time.Since(started), suitability,
		benchmarkPassed, *attest, attestationSaved)
	if err := validateLLMBenchmarkReport(report); err != nil {
		fmt.Fprintln(stderr, "prolewatch: refusing to emit an invalid benchmark record")
		return ExitStateFailure
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(stderr, "prolewatch: cannot write benchmark record")
		return ExitStateFailure
	}
	if !benchmarkPassed || (*attest && !attestationSaved) {
		return ExitReviewUnavailable
	}
	return ExitOK
}

func buildLLMBenchmarkReport(cfg Config, metadata ProviderMetadata, semanticFingerprint string, measurements []ollamaQualityCaseMeasurement, metrics []OllamaRequestMetrics,
	truncationRefused, calibrationPassed bool, observedBytesPerToken float64, performance ollamaPerformanceMeasurement, performanceMeasured bool,
	gpus []LLMBenchmarkGPU, elapsed time.Duration, suitability string, benchmarkPassed, attestationRequested, attestationSaved bool) LLMBenchmarkReport {
	qualityCases := make([]LLMBenchmarkQualityCase, 0, len(measurements))
	for _, measurement := range measurements {
		requests := make([]LLMBenchmarkRequest, 0, len(measurement.Metrics))
		for _, metric := range measurement.Metrics {
			requests = append(requests, publicLLMBenchmarkRequest(metric))
		}
		qualityCases = append(qualityCases, LLMBenchmarkQualityCase{
			ID: measurement.ID, Name: measurement.Name, Passed: measurement.Passed,
			DurationMilliseconds: measurement.Duration.Milliseconds(), FailureStage: measurement.FailureStage,
			SourceBindingWarning: measurement.SourceBindingWarning, Requests: requests,
		})
	}
	hardwareGPUs := append([]LLMBenchmarkGPU(nil), gpus...)
	if hardwareGPUs == nil {
		hardwareGPUs = []LLMBenchmarkGPU{}
	}
	report := LLMBenchmarkReport{
		SchemaVersion: LLMBenchmarkSchemaVersion, QualityCorpusVersion: providerCanaryVersion,
		MeasuredAt: UTCNow(), ProlewatchVersion: ApplicationVersion, SemanticFingerprint: semanticFingerprint,
		Provider: LLMBenchmarkProvider{
			RuntimeVersion: metadata.RuntimeVersion, Model: metadata.Model, ModelDigest: metadata.ModelDigest,
			ContextTokens: metadata.ContextTokens, Thinking: metadata.Thinking, Reasoning: metadata.Effort, AdapterPolicy: metadata.AdapterPolicy,
			RuntimeCompatibilityWarning: metadata.CompatibilityWarning != "",
		},
		Configuration: LLMBenchmarkConfiguration{
			KeepAliveSeconds: cfg.OllamaKeepAliveSeconds(), TimeoutSeconds: cfg.ProviderTimeoutSeconds(),
			GenerationLimitTokens: ollamaGenerationLimit(metadata.Effort), InputByteCeiling: ollamaInputByteCeiling(metadata.ContextTokens, metadata.Effort),
			ReviewBatchBytes: cfg.Review.BatchBytes, MaximumSelectedTextBytes: cfg.Limits.MaxSelectedTextBytes,
			ManualReviewMinimumSeverity: cfg.Review.ManualReviewMinimumSeverity,
			ConfiguredGates:             append([]string(nil), cfg.Review.Phases...),
		},
		Hardware:     LLMBenchmarkHardware{GPUs: hardwareGPUs},
		QualityCases: qualityCases, TruncationRefused: truncationRefused,
		Calibration: LLMBenchmarkCalibration{
			Passed: calibrationPassed, ObservedBytesPerToken: roundFloat(observedBytesPerToken, 3),
			RequiredBytesPerToken: roundFloat(ollamaMinimumObservedBytesPerToken(), 3),
		},
		Residency: benchmarkResidency(metrics), TotalWallMilliseconds: elapsed.Milliseconds(), Suitability: suitability,
		BenchmarkPassed: benchmarkPassed, AttestationRequested: attestationRequested, AttestationSaved: attestationSaved,
	}
	if performanceMeasured {
		report.Throughput = LLMBenchmarkThroughput{
			Measured: true, RequestCount: performance.RequestCount, PromptTokens: performance.PromptTokens, OutputTokens: performance.OutputTokens,
			PrefillTokensPerSecond: roundFloat(performance.PrefillPerSecond, 1), OutputTokensPerSecond: roundFloat(performance.OutputPerSecond, 1),
			ColdLoadMilliseconds:  roundFloat(durationMilliseconds(performance.ColdLoad), 3),
			MaximumRequestSeconds: roundFloat(performance.MaximumRequest.Seconds(), 3),
			SourcesReferenceBytes: performance.Projection.ReferenceBytes, SourcesBatchCount: performance.Projection.BatchCount,
			SelectedBytesPerBatch: performance.Projection.SelectedPerBatch, PromptTokensPerBatch: performance.Projection.PromptTokensPerBatch,
			ProjectedSourcesSeconds: roundFloat(performance.ProjectedDuration.Seconds(), 1),
		}
	}
	return report
}

func publicLLMBenchmarkRequest(metric OllamaRequestMetrics) LLMBenchmarkRequest {
	prefillPerSecond, outputPerSecond := 0.0, 0.0
	if metric.PromptDurationNS > 0 {
		prefillPerSecond = float64(metric.PromptTokens) / (float64(metric.PromptDurationNS) / float64(time.Second))
	}
	if metric.OutputDurationNS > 0 {
		outputPerSecond = float64(metric.OutputTokens) / (float64(metric.OutputDurationNS) / float64(time.Second))
	}
	return LLMBenchmarkRequest{
		RequestBytes: metric.RequestBytes, PromptTokens: metric.PromptTokens, OutputTokens: metric.OutputTokens,
		ThinkingBytes: metric.ThinkingBytes, LoadMilliseconds: roundFloat(durationMilliseconds(time.Duration(metric.LoadDurationNS)), 3),
		PrefillMilliseconds:     roundFloat(durationMilliseconds(time.Duration(metric.PromptDurationNS)), 3),
		OutputMilliseconds:      roundFloat(durationMilliseconds(time.Duration(metric.OutputDurationNS)), 3),
		UnaccountedMilliseconds: roundFloat(durationMilliseconds(time.Duration(metric.UnaccountedDurationNS)), 3),
		TotalMilliseconds:       roundFloat(durationMilliseconds(time.Duration(metric.TotalDurationNS)), 3),
		WallMilliseconds:        roundFloat(durationMilliseconds(time.Duration(metric.WallDurationNS)), 3),
		PrefillTokensPerSecond:  roundFloat(prefillPerSecond, 1), OutputTokensPerSecond: roundFloat(outputPerSecond, 1),
	}
}

func benchmarkResidency(metrics []OllamaRequestMetrics) LLMBenchmarkResidency {
	var result LLMBenchmarkResidency
	for _, metric := range metrics {
		if result.LoadedContextTokens == 0 || metric.LoadedContextTokens > 0 && metric.LoadedContextTokens < result.LoadedContextTokens {
			result.LoadedContextTokens = metric.LoadedContextTokens
		}
		if metric.ModelBytes <= 0 {
			continue
		}
		fraction := float64(metric.ModelVRAMBytes) / float64(metric.ModelBytes)
		currentFraction := 2.0
		if result.ModelBytes > 0 {
			currentFraction = float64(result.ModelVRAMBytes) / float64(result.ModelBytes)
		}
		if fraction < currentFraction {
			// Keep the least GPU-resident observation. One fully resident request
			// must not hide offload observed by another benchmark case.
			result.ModelBytes = metric.ModelBytes
			result.ModelVRAMBytes = metric.ModelVRAMBytes
		}
	}
	result.Reported = result.ModelBytes > 0 && result.LoadedContextTokens > 0
	if result.Reported {
		result.ModelVRAMPercent = roundFloat(100*float64(result.ModelVRAMBytes)/float64(result.ModelBytes), 1)
		result.FullyGPUResident = result.ModelVRAMBytes >= result.ModelBytes
	}
	return result
}

func ollamaResidencyCheck(metrics []OllamaRequestMetrics) Check {
	residency := benchmarkResidency(metrics)
	check := Check{Name: "Ollama GPU residency", OK: true, Required: false}
	if !residency.Reported {
		check.Detail = "Ollama did not report model residency"
		return check
	}
	if residency.FullyGPUResident {
		check.Detail = fmt.Sprintf("fully GPU-resident at %d context tokens", residency.LoadedContextTokens)
		return check
	}
	spillGiB := float64(residency.ModelBytes-residency.ModelVRAMBytes) / float64(1<<30)
	check.OK = false
	check.Detail = fmt.Sprintf("%.2f GiB of model state is on the CPU at %d context tokens; a smaller providers.ollama.context_tokens may restore full GPU residency but can increase batch count", spillGiB, residency.LoadedContextTokens)
	return check
}

func detectNVIDIAGPUs(ctx context.Context) []LLMBenchmarkGPU {
	probe, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(probe, "/usr/bin/nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader,nounits")
	output := safe.NewLimitedBuffer(16 * 1024)
	command.Stdout = output
	command.Stderr = safe.NewLimitedBuffer(16 * 1024)
	if err := command.Run(); err != nil {
		return []LLMBenchmarkGPU{}
	}
	gpus, ok := parseNVIDIAGPUs(output.String())
	if !ok {
		return []LLMBenchmarkGPU{}
	}
	return gpus
}

func parseNVIDIAGPUs(output string) ([]LLMBenchmarkGPU, bool) {
	var gpus []LLMBenchmarkGPU
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		fields := strings.SplitN(line, ",", 2)
		if len(fields) != 2 {
			return nil, false
		}
		model := strings.TrimSpace(fields[0])
		memory, err := strconv.Atoi(strings.TrimSpace(fields[1]))
		if err != nil || memory <= 0 || !safeBenchmarkHardwareName(model) {
			return nil, false
		}
		gpus = append(gpus, LLMBenchmarkGPU{Model: model, VRAMMiB: memory})
	}
	if gpus == nil {
		gpus = []LLMBenchmarkGPU{}
	}
	return gpus, true
}

func safeBenchmarkHardwareName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validateLLMBenchmarkReport(report LLMBenchmarkReport) error {
	if report.SchemaVersion != LLMBenchmarkSchemaVersion || report.QualityCorpusVersion != providerCanaryVersion ||
		report.ProlewatchVersion != ApplicationVersion || report.MeasuredAt == "" || !validHexDigest(report.SemanticFingerprint) ||
		report.Provider.RuntimeVersion == "" || report.Provider.Model == "" || !validHexDigest(report.Provider.ModelDigest) ||
		report.Provider.ContextTokens < 16_384 || report.Provider.AdapterPolicy == "" || report.TotalWallMilliseconds < 0 {
		return errors.New("invalid benchmark identity")
	}
	if report.Suitability != llmSuitabilityAllGates && report.Suitability != llmSuitabilityRecipeArtifact && report.Suitability != llmSuitabilityNotQualified {
		return errors.New("invalid benchmark suitability")
	}
	if !validOllamaEffectiveReasoning(report.Provider.Reasoning) || (report.Provider.Reasoning != "off" && !report.Provider.Thinking) ||
		report.Configuration.GenerationLimitTokens != ollamaGenerationLimit(report.Provider.Reasoning) ||
		report.Configuration.InputByteCeiling != ollamaInputByteCeiling(report.Provider.ContextTokens, report.Provider.Reasoning) {
		return errors.New("invalid benchmark generation bounds")
	}
	if len(report.QualityCases) != len(ollamaDoctorQualityCases()) {
		return errors.New("incomplete benchmark corpus")
	}
	validFailureStages := map[string]bool{"": true, "model-reset": true, "provider-review": true, "provider-identity": true, "quality-expectation": true}
	for index, qualityCase := range report.QualityCases {
		expected := ollamaDoctorQualityCases()[index]
		if qualityCase.ID != expected.id || qualityCase.Name != expected.name || qualityCase.DurationMilliseconds < 0 || !validFailureStages[qualityCase.FailureStage] {
			return errors.New("invalid benchmark quality case")
		}
		for _, request := range qualityCase.Requests {
			if request.RequestBytes <= 0 || request.PromptTokens <= 0 || request.OutputTokens <= 0 || request.ThinkingBytes < 0 ||
				request.LoadMilliseconds < 0 || request.PrefillMilliseconds < 0 || request.OutputMilliseconds < 0 || request.UnaccountedMilliseconds < 0 || request.TotalMilliseconds <= 0 || request.WallMilliseconds < 0 {
				return errors.New("invalid benchmark request metrics")
			}
		}
	}
	for _, gpu := range report.Hardware.GPUs {
		if gpu.VRAMMiB <= 0 || !safeBenchmarkHardwareName(gpu.Model) {
			return errors.New("invalid benchmark hardware")
		}
	}
	return nil
}

func durationMilliseconds(value time.Duration) float64 {
	return float64(value) / float64(time.Millisecond)
}

func llmBenchmarkSuitability(qualityOK, truncationOK, calibrationOK bool, performance ollamaPerformanceMeasurement, performanceErr error) string {
	if !qualityOK || !truncationOK || !calibrationOK || performanceErr != nil || performance.MaximumRequest > llmBenchmarkMaximumRequest {
		return llmSuitabilityNotQualified
	}
	if performance.ProjectedDuration <= ollamaSourcesProjectionBudget {
		return llmSuitabilityAllGates
	}
	return llmSuitabilityRecipeArtifact
}

func roundFloat(value float64, places int) float64 {
	factor := math.Pow10(places)
	return math.Round(value*factor) / factor
}
