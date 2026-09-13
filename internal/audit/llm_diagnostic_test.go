package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type llmDiagnosticFakeAdapter struct {
	metadata      ProviderMetadata
	verdict       Verdict
	diagnosticErr error
	resetErr      error
	resetCalls    int
}

func (a *llmDiagnosticFakeAdapter) Metadata(context.Context) (ProviderMetadata, error) {
	return a.metadata, nil
}

func (a *llmDiagnosticFakeAdapter) Review(context.Context, ReviewSnapshot) (Verdict, error) {
	return Verdict{}, errors.New("ordinary review must not run in diagnosis mode")
}

func (a *llmDiagnosticFakeAdapter) CredentialPath() string { return "" }

func (a *llmDiagnosticFakeAdapter) resetModel(context.Context) error {
	a.resetCalls++
	return a.resetErr
}

func (a *llmDiagnosticFakeAdapter) DiagnoseReview(_ context.Context, snapshot ReviewSnapshot) (*Verdict, LLMProviderReviewDiagnostic, []OllamaRequestMetrics, error) {
	if a.diagnosticErr != nil {
		return nil, LLMProviderReviewDiagnostic{}, nil, a.diagnosticErr
	}
	validation := diagnoseVerdict(a.verdict, snapshot)
	diagnostic := LLMProviderReviewDiagnostic{ResponseShape: responseShape(&a.verdict, true, true), Validation: validation}
	var verdict *Verdict
	if validation.Passed {
		copy := a.verdict
		verdict = &copy
	}
	metrics := []OllamaRequestMetrics{{RequestBytes: 1024, PromptTokens: 200, OutputTokens: 20, TotalDurationNS: 2_000_000}}
	return verdict, diagnostic, metrics, nil
}

func diagnosticTestConfig() Config {
	cfg := DefaultConfig()
	cfg.Provider = "ollama"
	cfg.Review.Mode = ReviewModeAI
	cfg.Providers.Ollama.Model = "qwen3:14b"
	cfg.Providers.Ollama.ContextTokens = 40_960
	cfg.Providers.Ollama.Reasoning = "auto"
	cfg.Providers.Ollama.TimeoutSeconds = 300
	return cfg
}

func diagnosticTestMetadata() ProviderMetadata {
	return ProviderMetadata{
		Provider: "ollama", Transport: "http-loopback", RuntimeVersion: "ollama 0.32.13", Model: "qwen3:14b",
		ModelDigest: strings.Repeat("a", 64), ContextTokens: 40_960, Thinking: true, Effort: "on",
		AdapterPolicy: ollamaAdapterPolicy("on", false),
	}
}

func installDiagnosticFake(t *testing.T, cfg Config, adapter providerAdapter) {
	t.Helper()
	oldLoader, oldFactory := providerConfigLoader, providerAdapterFactory
	providerConfigLoader = func() (Config, error) { return cfg, nil }
	providerAdapterFactory = func(Config) providerAdapter { return adapter }
	t.Cleanup(func() {
		providerConfigLoader, providerAdapterFactory = oldLoader, oldFactory
	})
}

func TestDiagnoseVerdictReportsClosedGuidanceFailures(t *testing.T) {
	targetID := strings.Repeat("b", 64)
	snapshot := ollamaTestSnapshot("pre")
	snapshot.GuidanceTargets = []GuidanceTarget{{FindingID: targetID, AnchorText: "expected"}}
	base := Verdict{SchemaVersion: VerdictSchemaVersion, Verdict: "block", Confidence: "high", Summary: "summary", Findings: []ReviewFinding{}, Guidance: []FindingGuidance{}, CoverageNotes: []string{}}

	tests := []struct {
		name      string
		verdict   Verdict
		wantCodes []string
	}{
		{name: "missing target", verdict: base, wantCodes: []string{"missing_targets"}},
		{name: "unknown id", verdict: func() Verdict {
			value := base
			value.Guidance = []FindingGuidance{{FindingID: strings.Repeat("c", 64), Assessment: "unclear", Comment: "comment", AnchorQuote: "anchor"}}
			return value
		}(), wantCodes: []string{"unknown_id", "missing_targets"}},
		{name: "duplicate id and wrong anchor", verdict: func() Verdict {
			value := base
			value.Guidance = []FindingGuidance{
				{FindingID: targetID, Assessment: "unclear", Comment: "comment", AnchorQuote: "wrong"},
				{FindingID: targetID, Assessment: "concerning", Comment: "comment", AnchorQuote: "expected"},
			}
			return value
		}(), wantCodes: []string{"duplicate_id", "anchor_mismatch"}},
		{name: "malformed id", verdict: func() Verdict {
			value := base
			value.Guidance = []FindingGuidance{{FindingID: "not-a-digest", Assessment: "wrong", Comment: "", AnchorQuote: ""}}
			return value
		}(), wantCodes: []string{"invalid_id", "invalid_enum", "empty", "unknown_id", "missing_targets"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			validation := diagnoseVerdict(test.verdict, snapshot)
			if validation.Passed {
				t.Fatal("invalid verdict passed diagnosis")
			}
			codes := map[string]int{}
			for _, issue := range validation.Issues {
				codes[issue.Code]++
			}
			for _, code := range test.wantCodes {
				if codes[code] == 0 {
					t.Fatalf("missing code %q in %+v", code, validation.Issues)
				}
			}
			if err := validateDiagnosticIssues(validation.Issues); err != nil {
				t.Fatalf("diagnosis escaped the closed vocabulary: %v", err)
			}
		})
	}
}

func TestLLMQualityDiagnosticCommandPrintsOnlyRedactedJSON(t *testing.T) {
	cfg := diagnosticTestConfig()
	verdict := Verdict{
		SchemaVersion: VerdictSchemaVersion, Verdict: "block", Confidence: "high", Summary: "SECRET_MODEL_SUMMARY",
		Findings: []ReviewFinding{}, CoverageNotes: []string{},
		Guidance: []FindingGuidance{{FindingID: "human-readable-SECRET_ID", Assessment: "concerning", Comment: "SECRET_MODEL_COMMENT", AnchorQuote: "SECRET_MODEL_ANCHOR"}},
	}
	adapter := &llmDiagnosticFakeAdapter{metadata: diagnosticTestMetadata(), verdict: verdict}
	installDiagnosticFake(t, cfg, adapter)
	var stdout, stderr bytes.Buffer
	status := runLLMQualityDiagnosticCommand(context.Background(), cfg, "remote-execution", &stdout, &stderr)
	if status != ExitReviewUnavailable {
		t.Fatalf("invalid model verdict returned %d", status)
	}
	if adapter.resetCalls != 1 {
		t.Fatalf("model reset count = %d", adapter.resetCalls)
	}
	if lines := strings.Count(strings.TrimSpace(stdout.String()), "\n"); lines != 0 {
		t.Fatalf("stdout was not exactly one JSON object: %q", stdout.String())
	}
	for _, forbidden := range []string{"SECRET_MODEL_SUMMARY", "SECRET_MODEL_COMMENT", "SECRET_MODEL_ANCHOR", "SECRET_ID"} {
		if strings.Contains(stdout.String(), forbidden) || strings.Contains(stderr.String(), forbidden) {
			t.Fatalf("diagnosis leaked %q: stdout=%s stderr=%s", forbidden, stdout.String(), stderr.String())
		}
	}
	var report LLMQualityDiagnosticReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Validation.Passed || report.Validation.Stage != llmDiagnosticStageVerdictValidation || report.ResponseShape.GuidanceCount != 1 || report.QualityExpectationPassed {
		t.Fatalf("unexpected report: %+v", report)
	}
	if err := validateLLMQualityDiagnosticReport(report); err != nil {
		t.Fatalf("invalid redacted report: %v", err)
	}
}

func TestLLMQualityDiagnosticCommandSeparatesProviderErrorsAndQuality(t *testing.T) {
	t.Run("provider error is redacted", func(t *testing.T) {
		cfg := diagnosticTestConfig()
		adapter := &llmDiagnosticFakeAdapter{metadata: diagnosticTestMetadata(), diagnosticErr: errors.New("SECRET_LOCAL_PATH /home/operator/model-output.json")}
		installDiagnosticFake(t, cfg, adapter)
		var stdout, stderr bytes.Buffer
		status := runLLMQualityDiagnosticCommand(context.Background(), cfg, "remote-execution", &stdout, &stderr)
		if status != ExitReviewUnavailable || strings.Contains(stdout.String()+stderr.String(), "SECRET_LOCAL_PATH") || strings.Contains(stdout.String()+stderr.String(), "/home/operator") {
			t.Fatalf("provider failure was not redacted: status=%d stdout=%s stderr=%s", status, stdout.String(), stderr.String())
		}
		var report LLMQualityDiagnosticReport
		if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if report.Validation.Stage != llmDiagnosticStageProviderRequest || len(report.Validation.Issues) != 1 || report.Validation.Issues[0].Code != "provider_request_failed" {
			t.Fatalf("unexpected provider failure report: %+v", report)
		}
	})

	t.Run("valid response passes selected expectation", func(t *testing.T) {
		cfg := diagnosticTestConfig()
		adapter := &llmDiagnosticFakeAdapter{metadata: diagnosticTestMetadata(), verdict: Verdict{
			SchemaVersion: VerdictSchemaVersion, Verdict: "block", Confidence: "high", Summary: "valid",
			Findings: []ReviewFinding{}, Guidance: []FindingGuidance{}, CoverageNotes: []string{},
		}}
		installDiagnosticFake(t, cfg, adapter)
		var stdout, stderr bytes.Buffer
		status := runLLMQualityDiagnosticCommand(context.Background(), cfg, "remote-execution", &stdout, &stderr)
		if status != ExitOK {
			t.Fatalf("valid quality response returned %d: stdout=%s stderr=%s", status, stdout.String(), stderr.String())
		}
		var report LLMQualityDiagnosticReport
		if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if !report.Validation.Passed || !report.QualityExpectationPassed || len(report.Metrics) != 1 {
			t.Fatalf("unexpected successful report: %+v", report)
		}
	})
}
