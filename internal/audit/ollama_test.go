package audit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/safe"
)

const ollamaTestDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type ollamaFake struct {
	t                *testing.T
	thinking         bool
	remote           bool
	psContext        int
	responseTools    bool
	digestAfterChat  string
	truncateSilently bool
	blockChat        bool
	verdict          string
	responseEval     int
	responseReason   string
	emptyResponse    bool
	chatStarted      chan struct{}
	chatStartOnce    sync.Once

	mu                    sync.Mutex
	chatCalled            int
	truncationProbeCalled int
	unloadCalled          int
	chatRequest           map[string]any
	truncationRequest     map[string]any
}

type ollamaQualityReviewer struct {
	metadata               ProviderMetadata
	calls                  int
	omitPersistenceFinding bool
	omitPrefillDuration    bool
	lastPhase              string
}

type ollamaProbeFailureReviewer struct{}

func (ollamaProbeFailureReviewer) Probe(context.Context) (ProviderMetadata, error) {
	return ProviderMetadata{}, errors.New("daemon unavailable")
}
func (ollamaProbeFailureReviewer) Review(context.Context, string, string, *brief.Inventory, ReviewOptions) (ProviderMetadata, []Verdict, error) {
	return ProviderMetadata{}, nil, errors.New("unexpected review")
}

func (r *ollamaQualityReviewer) Probe(context.Context) (ProviderMetadata, error) {
	return r.metadata, nil
}
func (r *ollamaQualityReviewer) Review(_ context.Context, _, phase string, inventory *brief.Inventory, _ ReviewOptions) (ProviderMetadata, []Verdict, error) {
	r.lastPhase = phase
	verdict := Verdict{SchemaVersion: VerdictSchemaVersion, Verdict: "allow", Confidence: "high", Summary: "fixture", Findings: []ReviewFinding{}, Guidance: []FindingGuidance{}, CoverageNotes: []string{}}
	privilegedDeserialization := false
	for _, file := range inventory.Files {
		privilegedDeserialization = privilegedDeserialization || strings.Contains(file.SelectedText, "pickle.load(state)")
	}
	switch {
	case privilegedDeserialization:
		line := 5
		verdict.Verdict = "block"
		verdict.Findings = []ReviewFinding{{Severity: "critical", Category: "privilege_escalation", File: "usr/lib/python3.13/site-packages/newsreader/file.py", Line: &line, Evidence: "pickle.load(state)", Rationale: "a root hook deserializes group-writable state"}}
	case r.calls == 1:
		verdict.Verdict = "block"
	case r.calls == 2:
		verdict.Verdict, verdict.PromptInjectionDetected = "block", true
	case r.calls == 3:
		finding := inventory.Findings[0]
		verdict.Guidance = []FindingGuidance{{FindingID: findingGuidanceID(finding), Assessment: "unclear", Comment: "bound", AnchorQuote: strings.Split(inventory.Files[0].SelectedText, "\n")[1]}}
	case r.calls == 4:
		verdict.Verdict = "block"
		if !r.omitPersistenceFinding {
			line := 2
			verdict.Findings = []ReviewFinding{{Severity: "high", Category: "persistence", File: "demo.install", Line: &line, Evidence: "systemctl enable", Rationale: "cross-file persistence"}}
		}
	case r.calls == 5:
		finding := inventory.Findings[0]
		verdict.Guidance = []FindingGuidance{{FindingID: findingGuidanceID(finding), Assessment: "concerning", Comment: "decoded execution", AnchorQuote: strings.Split(inventory.Files[0].SelectedText, "\n")[1]}}
	}
	r.calls++
	return r.metadata, []Verdict{verdict}, nil
}
func (r *ollamaQualityReviewer) OllamaMetrics() []OllamaRequestMetrics {
	metrics := make([]OllamaRequestMetrics, r.calls)
	for index := range metrics {
		metrics[index] = OllamaRequestMetrics{RequestBytes: 10000, PromptTokens: 4000, OutputTokens: 100,
			PromptDurationNS: int64(time.Second), OutputDurationNS: int64(time.Second), TotalDurationNS: int64(3 * time.Second)}
		if r.omitPrefillDuration {
			metrics[index].PromptDurationNS = 0
		}
	}
	return metrics
}

func (f *ollamaFake) handler(w http.ResponseWriter, r *http.Request) {
	f.t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Authorization") != "" {
		f.t.Errorf("adapter sent authorization to loopback daemon")
	}
	capabilities := []string{"completion"}
	if f.thinking {
		capabilities = append(capabilities, "thinking")
	}
	remoteHost, remoteModel := "", ""
	if f.remote {
		remoteHost, remoteModel = "https://ollama.com", "cloud/model"
	}
	switch r.URL.Path {
	case "/api/version":
		_, _ = w.Write([]byte(`{"version":"0.32.13"}`))
	case "/api/tags":
		f.mu.Lock()
		digest := ollamaTestDigest
		if f.chatCalled > 0 && f.digestAfterChat != "" {
			digest = f.digestAfterChat
		}
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"models": []map[string]any{{
			"name": "secure-model:latest", "model": "secure-model:latest", "digest": digest,
			"remote_host": remoteHost, "remote_model": remoteModel, "capabilities": capabilities,
		}}})
	case "/api/show":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"remote_host": remoteHost, "remote_model": remoteModel, "capabilities": capabilities,
			"model_info": map[string]any{"test.context_length": 131072},
		})
	case "/api/chat":
		var request map[string]any
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			f.t.Errorf("decode chat request: %v", err)
		}
		options, _ := request["options"].(map[string]any)
		probe := options["num_ctx"] == float64(ollamaTruncationProbeTokens)
		f.mu.Lock()
		if probe {
			f.truncationProbeCalled++
			f.truncationRequest = request
		} else {
			f.chatCalled++
			f.chatRequest = request
		}
		f.mu.Unlock()
		if !probe && f.blockChat {
			f.chatStartOnce.Do(func() {
				if f.chatStarted != nil {
					close(f.chatStarted)
				}
			})
			<-r.Context().Done()
			return
		}
		if probe && !f.truncateSilently {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"the input length exceeds the context length"}`))
			return
		}
		verdict := f.verdict
		if verdict == "" {
			verdict = `{"schema_version":3,"verdict":"allow","confidence":"high","summary":"fixture is benign","prompt_injection_detected":false,"findings":[],"guidance":[],"coverage_notes":[]}`
		}
		message := map[string]any{"role": "assistant", "content": verdict}
		if f.thinking {
			message["thinking"] = "brief analysis"
		}
		if f.responseTools {
			message["tool_calls"] = []map[string]any{{"function": map[string]any{"name": "shell", "arguments": map[string]any{}}}}
		}
		evalCount := f.responseEval
		if evalCount == 0 {
			evalCount = 100
		}
		if f.emptyResponse {
			evalCount = 0
			message["content"] = ""
		}
		doneReason := f.responseReason
		if doneReason == "" {
			doneReason = "stop"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"model": "secure-model:latest", "message": message, "done": !f.emptyResponse,
			"prompt_eval_count": 1000, "eval_count": evalCount, "done_reason": doneReason,
			"total_duration": 2_000_000, "load_duration": 1_000_000,
		})
	case "/api/ps":
		contextLength := f.psContext
		if contextLength == 0 {
			contextLength = 131072
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"models": []map[string]any{{
			"name": "secure-model:latest", "model": "secure-model:latest", "digest": ollamaTestDigest,
			"context_length": contextLength, "size": 10_000, "size_vram": 0,
		}}})
	case "/api/generate":
		f.mu.Lock()
		f.unloadCalled++
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{"done":true}`))
	default:
		http.NotFound(w, r)
	}
}

func ollamaTestConfig() Config {
	cfg := DefaultConfig()
	cfg.Provider = "ollama"
	cfg.Review.Mode = ReviewModeAI
	cfg.Providers.Ollama.Model = "secure-model:latest"
	cfg.Providers.Ollama.ContextTokens = 131072
	cfg.Providers.Ollama.Reasoning = "auto"
	cfg.Providers.Ollama.TimeoutSeconds = 5
	return cfg
}

func ollamaTestAdapter(t *testing.T, fake *ollamaFake) (*ollamaAdapter, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(fake.handler))
	adapter := newOllamaAdapterAt(ollamaTestConfig(), server.URL, server.Client(), filepath.Join(t.TempDir(), "ollama-loopback.lock"))
	return adapter, server
}

func ollamaTestSnapshot(phase string) ReviewSnapshot {
	return ReviewSnapshot{
		SnapshotSchemaVersion: ReviewSnapshotVersion, PackageBase: "demo", Phase: phase,
		ManifestHash: strings.Repeat("b", 64), Coverage: brief.Coverage{Complete: true, Notes: []string{}},
		GuidanceMinimumSeverity: "high", Manifest: []map[string]any{}, BatchIndex: 0, BatchCount: 1,
		Files: []SelectedFile{{File: "PKGBUILD", LineStart: 1, LineEnd: 1, Content: "pkgname=demo"}},
	}
}

func TestOllamaMetadataBindsLocalDigestContextAndThinking(t *testing.T) {
	fake := &ollamaFake{t: t, thinking: true}
	adapter, server := ollamaTestAdapter(t, fake)
	defer server.Close()
	metadata, err := adapter.Metadata(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Provider != "ollama" || metadata.Transport != "http-loopback" || metadata.RuntimeVersion != "ollama 0.32.13" ||
		metadata.ModelDigest != ollamaTestDigest || metadata.ContextTokens != 131072 || !metadata.Thinking || metadata.Effort != "on" ||
		!strings.Contains(metadata.AdapterPolicy, "generation-cap-6144") || !strings.Contains(metadata.AdapterPolicy, "reasoning-on") ||
		!strings.Contains(metadata.AdapterPolicy, "truncate-unverified") {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
	if err := (DispatchResponse{ProtocolVersion: DispatchProtocolVersion, Metadata: metadata}).Validate("probe"); err != nil {
		t.Fatalf("Ollama dispatch metadata rejected: %v", err)
	}
}

func TestOllamaTruncationProbeDistinguishesRefusalFromSilentSuccess(t *testing.T) {
	t.Run("context refusal verifies policy", func(t *testing.T) {
		fake := &ollamaFake{t: t}
		adapter, server := ollamaTestAdapter(t, fake)
		defer server.Close()
		initial, err := adapter.Metadata(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		check, metadata, ok := runOllamaTruncationProbe(context.Background(), adapter, initial, nil)
		fake.mu.Lock()
		probes, unloads, request := fake.truncationProbeCalled, fake.unloadCalled, fake.truncationRequest
		fake.mu.Unlock()
		if !ok || !check.OK || probes != 1 || unloads != 1 || request["truncate"] != false || request["shift"] != false || !strings.Contains(metadata.AdapterPolicy, "truncate-off") {
			t.Fatalf("refusal was not observed exactly once: check=%+v probes=%d unloads=%d request=%#v metadata=%+v", check, probes, unloads, request, metadata)
		}
	})
	t.Run("silent success remains unverified", func(t *testing.T) {
		fake := &ollamaFake{t: t, truncateSilently: true}
		adapter, server := ollamaTestAdapter(t, fake)
		defer server.Close()
		if _, err := adapter.VerifyTruncationRefusal(context.Background()); err == nil || !strings.Contains(err.Error(), "accepted an over-context request") {
			t.Fatalf("silent truncation was accepted: %v", err)
		}
		metadata, err := adapter.Metadata(context.Background())
		if err != nil || !strings.Contains(metadata.AdapterPolicy, "truncate-unverified") {
			t.Fatalf("failed probe changed policy: metadata=%+v err=%v", metadata, err)
		}
	})
}

func TestOllamaDispatchRequiresPerRequestMetrics(t *testing.T) {
	metadata := ProviderMetadata{Provider: "ollama", Transport: "http-loopback", RuntimeVersion: "ollama 0.32.13",
		Model: "secure-model:latest", ModelDigest: ollamaTestDigest, ContextTokens: 131072, Effort: "off", AdapterPolicy: ollamaAdapterPolicy("off", false)}
	verdict := Verdict{SchemaVersion: VerdictSchemaVersion, Verdict: "allow", Confidence: "high", Summary: "safe", Findings: []ReviewFinding{}, Guidance: []FindingGuidance{}, CoverageNotes: []string{}}
	response := DispatchResponse{ProtocolVersion: DispatchProtocolVersion, Metadata: metadata, Verdict: &verdict}
	if err := response.Validate("review"); err == nil {
		t.Fatal("Ollama dispatch without measured usage was accepted")
	}
	response.OllamaMetrics = []OllamaRequestMetrics{{RequestBytes: 100, PromptTokens: 10, OutputTokens: 5, TotalDurationNS: 1}}
	if err := response.Validate("review"); err != nil {
		t.Fatalf("valid measured Ollama dispatch was rejected: %v", err)
	}
}

func TestOllamaDiagnosticRedactsInvalidGuidance(t *testing.T) {
	const secretComment = "MODEL_COMMENT_MUST_NOT_ESCAPE"
	const secretAnchor = "MODEL_ANCHOR_MUST_NOT_ESCAPE"
	fake := &ollamaFake{t: t, verdict: `{"schema_version":3,"verdict":"block","confidence":"high","summary":"MODEL_SUMMARY_MUST_NOT_ESCAPE","prompt_injection_detected":false,"findings":[],"guidance":[{"finding_id":"human-readable-id","assessment":"concerning","comment":"` + secretComment + `","anchor_quote":"` + secretAnchor + `"}],"coverage_notes":[]}`}
	adapter, server := ollamaTestAdapter(t, fake)
	defer server.Close()

	verdict, diagnostic, metrics, err := adapter.DiagnoseReview(context.Background(), ollamaTestSnapshot("pre"))
	if err != nil {
		t.Fatal(err)
	}
	if verdict != nil || diagnostic.Validation.Passed || diagnostic.Validation.Stage != llmDiagnosticStageVerdictValidation || len(metrics) != 1 {
		t.Fatalf("unexpected diagnostic result: verdict=%+v diagnostic=%+v metrics=%+v", verdict, diagnostic, metrics)
	}
	codes := map[string]bool{}
	for _, issue := range diagnostic.Validation.Issues {
		codes[issue.Code] = true
	}
	if !codes["invalid_id"] || !codes["unexpected_items"] || !codes["unknown_id"] {
		t.Fatalf("invalid unbound guidance was not explained: %+v", diagnostic.Validation.Issues)
	}
	raw, err := json.Marshal(diagnostic)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{secretComment, secretAnchor, "MODEL_SUMMARY_MUST_NOT_ESCAPE", "human-readable-id"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("diagnostic leaked model content %q: %s", forbidden, raw)
		}
	}
	if _, err := adapter.Review(context.Background(), ollamaTestSnapshot("pre")); err == nil || !strings.Contains(err.Error(), "invalid deterministic finding guidance") {
		t.Fatalf("normal review acceptance changed: %v", err)
	}
}

func TestOllamaRejectsRemoteModelAndDigestMovement(t *testing.T) {
	t.Run("remote model", func(t *testing.T) {
		fake := &ollamaFake{t: t, remote: true}
		adapter, server := ollamaTestAdapter(t, fake)
		defer server.Close()
		if _, err := adapter.Metadata(context.Background()); err == nil || !strings.Contains(err.Error(), "remote") {
			t.Fatalf("remote model was accepted: %v", err)
		}
	})
	t.Run("digest moves during review", func(t *testing.T) {
		fake := &ollamaFake{t: t, digestAfterChat: strings.Repeat("c", 64)}
		adapter, server := ollamaTestAdapter(t, fake)
		defer server.Close()
		if _, err := adapter.Review(context.Background(), ollamaTestSnapshot("pre")); err == nil || !strings.Contains(err.Error(), "identity changed") {
			t.Fatalf("moving digest was accepted: %v", err)
		}
	})
}

func TestOllamaChatContractAndLifecycle(t *testing.T) {
	fake := &ollamaFake{t: t, thinking: true}
	adapter, server := ollamaTestAdapter(t, fake)
	defer server.Close()
	if _, err := adapter.Review(context.Background(), ollamaTestSnapshot("post")); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	request := fake.chatRequest
	chatCalls, unloadCalls := fake.chatCalled, fake.unloadCalled
	fake.mu.Unlock()
	if chatCalls != 1 || unloadCalls != 1 {
		t.Fatalf("unexpected lifecycle calls: chat=%d unload=%d", chatCalls, unloadCalls)
	}
	if metrics := adapter.ReviewMetrics(); len(metrics) != 1 || metrics[0].PromptTokens != 1000 || metrics[0].ThinkingBytes == 0 ||
		metrics[0].ModelBytes != 10_000 || metrics[0].ModelVRAMBytes != 0 || metrics[0].LoadedContextTokens != 131072 {
		t.Fatalf("Ollama usage metrics were not captured: %+v", metrics)
	}
	if request["stream"] != false || request["think"] != true || request["truncate"] != false || request["shift"] != false {
		t.Fatalf("missing fail-closed chat controls: %#v", request)
	}
	if _, ok := request["tools"]; ok {
		t.Fatalf("adapter exposed tools: %#v", request["tools"])
	}
	format, ok := request["format"].(map[string]any)
	if !ok || format["type"] != "object" {
		t.Fatalf("verdict schema was not passed as structured-output format: %#v", request["format"])
	}
	guidance := format["properties"].(map[string]any)["guidance"].(map[string]any)
	if guidance["minItems"] != float64(0) || guidance["maxItems"] != float64(0) {
		t.Fatalf("empty guidance targets were not forbidden by the request schema: %#v", guidance)
	}
	options, ok := request["options"].(map[string]any)
	if !ok || options["temperature"] != float64(0) || options["seed"] != float64(0) ||
		options["num_ctx"] != float64(131072) || options["num_predict"] != float64(ollamaGenerationLimit("on")) {
		t.Fatalf("unexpected deterministic/context options: %#v", request["options"])
	}
}

func TestOllamaGenerationLimitIsFixedAndFailClosed(t *testing.T) {
	for _, current := range []struct {
		name      string
		thinking  bool
		evalCount int
		reason    string
		wantError string
	}{
		{name: "plain exact completed limit", evalCount: ollamaPlainGenerationCap},
		{name: "thinking exact completed limit", thinking: true, evalCount: ollamaThinkingGenerationCap},
		{name: "thinking exhausted limit", thinking: true, evalCount: ollamaThinkingGenerationCap, reason: "length", wantError: "exhausted the 6144-token generation limit"},
		{name: "thinking exceeded accounting", thinking: true, evalCount: ollamaThinkingGenerationCap + 1, wantError: "outside the 1..6144 generation limit"},
	} {
		t.Run(current.name, func(t *testing.T) {
			fake := &ollamaFake{t: t, thinking: current.thinking, responseEval: current.evalCount, responseReason: current.reason}
			adapter, server := ollamaTestAdapter(t, fake)
			defer server.Close()
			_, err := adapter.Review(context.Background(), ollamaTestSnapshot("pre"))
			if current.wantError == "" && err != nil {
				t.Fatalf("completed response at the generation limit failed: %v", err)
			}
			if current.wantError != "" && (err == nil || !strings.Contains(err.Error(), current.wantError)) {
				t.Fatalf("generation limit error=%v, want %q", err, current.wantError)
			}
		})
	}
}

func TestOllamaReasoningLevelsBindRequestPolicyAndCapability(t *testing.T) {
	snapshot := ollamaTestSnapshot("pre")
	seen := map[string]bool{}
	for _, current := range []struct {
		configured string
		capability bool
		want       any
		limit      int
	}{
		{"auto", true, true, ollamaThinkingGenerationCap},
		{"auto", false, false, ollamaPlainGenerationCap},
		{"off", true, false, ollamaPlainGenerationCap},
		{"low", true, "low", ollamaThinkingGenerationCap},
		{"medium", true, "medium", ollamaThinkingGenerationCap},
		{"high", true, "high", ollamaThinkingGenerationCap},
	} {
		level, err := ollamaReasoningLevel(current.configured, current.capability)
		if err != nil {
			t.Fatalf("%s capability=%t: %v", current.configured, current.capability, err)
		}
		request, raw, limit, err := buildOllamaChatRequest(ollamaTestConfig(), snapshot, level)
		if err != nil || limit != current.limit {
			t.Fatalf("%s: limit=%d err=%v", level, limit, err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded["think"] != current.want || decoded["options"].(map[string]any)["num_predict"] != float64(current.limit) {
			t.Fatalf("%s produced think=%v options=%v", level, decoded["think"], decoded["options"])
		}
		if len(request.Think) == 0 {
			t.Fatal("request lost explicit think value")
		}
		policy := ollamaAdapterPolicy(level, true)
		if seen[policy] && !(current.configured == "off" && level == "off") {
			t.Fatalf("reasoning level did not change policy: %s", policy)
		}
		seen[policy] = true
	}
	if _, err := ollamaReasoningLevel("low", false); err == nil {
		t.Fatal("explicit reasoning was accepted without model capability")
	}
}

func TestOllamaEmptyResponseNamesReasoningAndSchema(t *testing.T) {
	fake := &ollamaFake{t: t, thinking: true, emptyResponse: true}
	adapter, server := ollamaTestAdapter(t, fake)
	defer server.Close()
	if _, err := adapter.Review(context.Background(), ollamaTestSnapshot("pre")); err == nil || !strings.Contains(err.Error(), "reasoning=on") || !strings.Contains(err.Error(), "format schema") {
		t.Fatalf("empty response was not explained: %v", err)
	}
}

func TestOllamaUnaccountedDurationIsClamped(t *testing.T) {
	if got := ollamaUnaccountedDuration(20_000_000_000, 2_000_000_000, 1_000_000_000, 3_000_000_000); got != 14_000_000_000 {
		t.Fatalf("unaccounted duration=%d", got)
	}
	if got := ollamaUnaccountedDuration(4, 3, 2, 1); got != 0 {
		t.Fatalf("inconsistent durations produced %d", got)
	}
}

func TestOllamaSchemaBindsGuidanceTargets(t *testing.T) {
	wanted := strings.Repeat("c", 64)
	for _, current := range []struct {
		name    string
		targets []GuidanceTarget
		allowed []string
	}{
		{name: "empty target set"},
		{name: "one target", targets: []GuidanceTarget{{FindingID: wanted}}, allowed: []string{wanted}},
	} {
		t.Run(current.name, func(t *testing.T) {
			snapshot := ollamaTestSnapshot("pre")
			snapshot.GuidanceTargets = current.targets
			request, _, _, err := buildOllamaChatRequest(ollamaTestConfig(), snapshot, "off")
			if err != nil {
				t.Fatal(err)
			}
			var format map[string]any
			if err := json.Unmarshal(request.Format, &format); err != nil {
				t.Fatal(err)
			}
			guidance := format["properties"].(map[string]any)["guidance"].(map[string]any)
			count := float64(len(current.targets))
			if guidance["minItems"] != count || guidance["maxItems"] != count {
				t.Fatalf("guidance count was not bound to the target set: %#v", guidance)
			}
			items := guidance["items"].(map[string]any)
			findingID := items["properties"].(map[string]any)["finding_id"].(map[string]any)
			allowed, constrained := findingID["enum"].([]any)
			if len(current.allowed) == 0 {
				if constrained {
					t.Fatalf("empty target set retained an ID enum: %#v", findingID)
				}
				only, exact := guidance["enum"].([]any)
				if !exact || len(only) != 1 {
					t.Fatalf("empty target set was not bound to an exact empty array: %#v", guidance)
				}
				if empty, ok := only[0].([]any); !ok || len(empty) != 0 {
					t.Fatalf("empty target set was not bound to an exact empty array: %#v", guidance)
				}
				return
			}
			if _, exact := guidance["enum"]; exact {
				t.Fatalf("non-empty target set retained the empty-array enum: %#v", guidance)
			}
			if !constrained || len(allowed) != len(current.allowed) {
				t.Fatalf("guidance finding IDs were not bound to the target set: %#v", findingID)
			}
			for index, value := range current.allowed {
				if allowed[index] != value {
					t.Fatalf("guidance finding IDs were not bound to the target set: %#v", findingID)
				}
			}
		})
	}
}

func TestOllamaQualityResetUnloadsTheRunner(t *testing.T) {
	fake := &ollamaFake{t: t}
	adapter, server := ollamaTestAdapter(t, fake)
	defer server.Close()
	if err := adapter.resetModel(context.Background()); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	unloads := fake.unloadCalled
	fake.mu.Unlock()
	if unloads != 1 {
		t.Fatalf("quality reset issued %d unloads", unloads)
	}
}

func TestOllamaUnloadsAfterRecipeWhenSourcesReviewIsDisabled(t *testing.T) {
	fake := &ollamaFake{t: t}
	adapter, server := ollamaTestAdapter(t, fake)
	defer server.Close()
	adapter.cfg.Review.Phases = []string{"recipe", "artifact"}
	if _, err := adapter.Review(context.Background(), ollamaTestSnapshot("pre")); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	unloads := fake.unloadCalled
	fake.mu.Unlock()
	if unloads != 1 {
		t.Fatalf("model stayed loaded before a build with Sources AI disabled: unloads=%d", unloads)
	}
}

func TestOllamaZeroKeepAliveUsesProbeWindowThenUnloads(t *testing.T) {
	fake := &ollamaFake{t: t}
	adapter, server := ollamaTestAdapter(t, fake)
	defer server.Close()
	zero := 0
	adapter.cfg.Providers.Ollama.KeepAliveSeconds = &zero
	if _, err := adapter.Review(context.Background(), ollamaTestSnapshot("pre")); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	request, unloads := fake.chatRequest, fake.unloadCalled
	fake.mu.Unlock()
	if request["keep_alive"] != "1s" || unloads != 1 {
		t.Fatalf("zero keep-alive did not preserve the context probe and immediately unload: request=%#v unloads=%d", request, unloads)
	}
}

func TestOllamaContextReserveAndGenerationLimitAcrossContextRange(t *testing.T) {
	for _, contextTokens := range []int{16_384, 32_768, 65_536, 131_072, 262_144} {
		for _, reasoning := range []string{"off", "on", "low", "medium", "high"} {
			reserve := ollamaContextOutputReserve(contextTokens, reasoning)
			if reserve != ollamaGenerationLimit(reasoning) {
				t.Errorf("context %d reasoning=%s reserve=%d limit=%d", contextTokens, reasoning, reserve, ollamaGenerationLimit(reasoning))
			}
			availableTokens := contextTokens - reserve - ollamaTemplateReserveTokens
			ceiling := ollamaInputByteCeiling(contextTokens, reasoning)
			if ceiling != availableTokens*2 {
				t.Errorf("context %d reasoning=%s ceiling=%d, want %d", contextTokens, reasoning, ceiling, availableTokens*2)
			}
			if float64(ceiling)/ollamaBytesPerTokenFloor > float64(availableTokens) {
				t.Errorf("context %d reasoning=%s ceiling=%d exceeds calibrated token budget %d", contextTokens, reasoning, ceiling, availableTokens)
			}
		}
	}
}

func TestOllamaBatchingBudgetsTheCompleteSerializedRequest(t *testing.T) {
	cfg := ollamaTestConfig()
	cfg.Providers.Ollama.ContextTokens = 65_536
	reviewer := NewReviewer(cfg)
	content := strings.Repeat("printf '%s' harmless\n", 8000)
	record := brief.FileRecord{Path: "PKGBUILD", PathB64: brief.PathB64("PKGBUILD"), Kind: "file", SHA256: strings.Repeat("d", 64), Text: true, SelectedText: content, BinaryMetadata: map[string]any{}}
	manifestRaw, _ := CanonicalJSON([]map[string]any{record.ManifestValue()})
	inventory := &brief.Inventory{Phase: "pre", ManifestHash: safe.SHA256Bytes(manifestRaw), Coverage: brief.Coverage{Complete: true, Notes: []string{}}, Files: []brief.FileRecord{record}}
	for _, reasoning := range []string{"off", "on"} {
		batches, err := reviewer.batchesWithProviderOptions("demo", "pre", inventory, ReviewOptions{}, reasoning)
		if err != nil {
			t.Fatalf("reasoning=%s: %v", reasoning, err)
		}
		if len(batches) < 2 {
			t.Fatalf("reasoning=%s did not split a large full request", reasoning)
		}
		ceiling := ollamaInputByteCeiling(cfg.Providers.Ollama.ContextTokens, reasoning)
		for index, batch := range batches {
			_, raw, _, err := buildOllamaChatRequest(cfg, batch, reasoning)
			if err != nil || len(raw) > ceiling {
				t.Fatalf("reasoning=%s batch=%d size=%d ceiling=%d err=%v", reasoning, index, len(raw), ceiling, err)
			}
		}
	}
}

func TestOllamaBatchingUsesGenerationCapInsteadOfOldReserve(t *testing.T) {
	cfg := ollamaTestConfig()
	cfg.Providers.Ollama.ContextTokens = 40_960
	content := strings.Repeat("safe_assignment='local'\n", 1_700)
	record := brief.FileRecord{Path: "PKGBUILD", PathB64: brief.PathB64("PKGBUILD"), Kind: "file", SHA256: strings.Repeat("d", 64), Text: true, SelectedText: content, BinaryMetadata: map[string]any{}}
	manifestRaw, _ := CanonicalJSON([]map[string]any{record.ManifestValue()})
	inventory := &brief.Inventory{Phase: "pre", ManifestHash: safe.SHA256Bytes(manifestRaw), Coverage: brief.Coverage{Complete: true, Notes: []string{}}, Files: []brief.FileRecord{record}}
	batches, err := NewReviewer(cfg).batchesWithProviderOptions("demo", "pre", inventory, ReviewOptions{}, "on")
	if err != nil || len(batches) != 1 {
		t.Fatalf("new input budget failed to hold one batch: batches=%d err=%v", len(batches), err)
	}
	_, raw, _, err := buildOllamaChatRequest(cfg, batches[0], "on")
	if err != nil || len(raw) <= 45_056 || len(raw) > 65_536 {
		t.Fatalf("request did not exercise gap between old and new ceilings: size=%d err=%v", len(raw), err)
	}
}

func TestOllamaRejectsInsufficientLoadedContextAndToolCalls(t *testing.T) {
	for name, fake := range map[string]*ollamaFake{
		"loaded context": {psContext: 65536},
		"tool call":      {responseTools: true},
	} {
		t.Run(name, func(t *testing.T) {
			fake.t = t
			adapter, server := ollamaTestAdapter(t, fake)
			defer server.Close()
			if _, err := adapter.Review(context.Background(), ollamaTestSnapshot("pre")); err == nil {
				t.Fatal("unsafe Ollama response was accepted")
			}
		})
	}
}

func TestOllamaContextCeilingStopsRequestBeforeChat(t *testing.T) {
	fake := &ollamaFake{t: t}
	adapter, server := ollamaTestAdapter(t, fake)
	defer server.Close()
	adapter.provider.ContextTokens = 32768
	snapshot := ollamaTestSnapshot("pre")
	snapshot.Files[0].Content = strings.Repeat("x", 60000)
	if _, err := adapter.Review(context.Background(), snapshot); err == nil || !strings.Contains(err.Error(), "context-derived") {
		t.Fatalf("oversized request was not rejected locally: %v", err)
	}
	fake.mu.Lock()
	called := fake.chatCalled
	fake.mu.Unlock()
	if called != 0 {
		t.Fatalf("oversized request reached Ollama %d time(s)", called)
	}
}

func TestOllamaLockSerializesEndpointAndReleasesOnCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider", "ollama-loopback.lock")
	first, err := acquireOllamaLock(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	if second, err := acquireOllamaLock(ctx, path); !errors.Is(err, context.DeadlineExceeded) {
		if second != nil {
			second.Close()
		}
		t.Fatalf("second endpoint lock was not cancelled: %v", err)
	}
	first.Close()
	third, err := acquireOllamaLock(context.Background(), path)
	if err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
	third.Close()
}

func TestOllamaProductionClientRefusesNonLoopbackDestination(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9")
	client := newOllamaLoopbackClient()
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.ResponseHeaderTimeout != 0 {
		t.Fatalf("production client imposed a fixed response-header deadline: %#v", client.Transport)
	}
	request, _ := http.NewRequest(http.MethodGet, "http://example.com/api/version", nil)
	if _, err := client.Do(request); err == nil || !strings.Contains(err.Error(), "refused non-loopback") {
		t.Fatalf("production client accepted a DNS/non-loopback target: %v", err)
	}
}

func TestOllamaMetadataHTTPFailuresAreBoundedAndFailClosed(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		},
		"oversized": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":"` + strings.Repeat("x", 70*1024) + `"}`))
		},
		"truncated": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(handler)
			defer server.Close()
			adapter := newOllamaAdapterAt(ollamaTestConfig(), server.URL, server.Client(), filepath.Join(t.TempDir(), "lock"))
			if _, err := adapter.Metadata(context.Background()); err == nil {
				t.Fatal("invalid Ollama HTTP behavior was accepted")
			}
		})
	}
}

func TestOllamaMetadataHonorsCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	adapter := newOllamaAdapterAt(ollamaTestConfig(), server.URL, server.Client(), filepath.Join(t.TempDir(), "lock"))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := adapter.Metadata(ctx); !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(errorString(err), "deadline exceeded") {
		t.Fatalf("Ollama metadata ignored cancellation: %v", err)
	}
}

func TestOllamaReviewCancellationDoesNotStartDetachedUnload(t *testing.T) {
	fake := &ollamaFake{t: t, blockChat: true, chatStarted: make(chan struct{})}
	adapter, server := ollamaTestAdapter(t, fake)
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := adapter.Review(ctx, ollamaTestSnapshot("post"))
		done <- err
	}()
	select {
	case <-fake.chatStarted:
	case <-time.After(time.Second):
		t.Fatal("Ollama review did not reach the chat request")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) && !strings.Contains(errorString(err), "context canceled") {
			t.Fatalf("Ollama review did not return cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Ollama review remained attached after cancellation")
	}
	fake.mu.Lock()
	unloads := fake.unloadCalled
	fake.mu.Unlock()
	if unloads != 0 {
		t.Fatalf("cancelled review started %d detached unload request(s)", unloads)
	}
}

func TestOllamaDoesNotClaimCLISandboxCanary(t *testing.T) {
	cfg := ollamaTestConfig()
	if _, err := NewReviewer(cfg).Canary(context.Background()); err == nil || !strings.Contains(err.Error(), "not observable") {
		t.Fatalf("Ollama claimed the CLI sandbox canary: %v", err)
	}
}

func TestOllamaAttestationUsesHTTPIdentityWithoutCLIBinaryClaims(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	metadata := ProviderMetadata{Provider: "ollama", Transport: "http-loopback", RuntimeVersion: "ollama 0.32.13",
		Model: "secure-model:latest", ModelDigest: ollamaTestDigest, ContextTokens: 131072, Thinking: true, Effort: "on", AdapterPolicy: ollamaAdapterPolicy("on", true)}
	checks := CanaryChecks{LoopbackEndpoint: true, LocalModel: true, ContextVerified: true, StructuredOutput: true,
		PromptInjectionRecognised: true, QualityGatePassed: true, PerformanceMeasured: true, TruncationRefused: true,
		ObservedBytesPerToken: ollamaMinimumObservedBytesPerToken()}
	unsafeChecks := checks
	unsafeChecks.ObservedBytesPerToken = ollamaBytesPerTokenFloor
	if err := saveProviderAttestation(strings.Repeat("c", 64), metadata, brief.ToolIdentity{}, unsafeChecks); err == nil {
		t.Fatal("unsafe byte/token calibration was persisted as successful evidence")
	}
	if err := saveProviderAttestation(strings.Repeat("c", 64), metadata, brief.ToolIdentity{}, checks); err != nil {
		t.Fatal(err)
	}
	if err := loadProviderAttestation(strings.Repeat("c", 64), metadata, brief.ToolIdentity{}); err != nil {
		t.Fatal(err)
	}
	unverified := ollamaMetadataWithTruncationPolicy(metadata, false)
	if !storedOllamaTruncationRefused(unverified) {
		t.Fatal("fresh adapter could not recover the verified truncation policy from v7 evidence")
	}
	var legacy ProviderAttestation
	if err := ReadJSONFile(providerAttestationPath(), 1024*1024, &legacy); err != nil {
		t.Fatal(err)
	}
	legacy.CanaryVersion = 6
	if err := legacy.Validate(strings.Repeat("c", 64), metadata, brief.ToolIdentity{}); err == nil {
		t.Fatal("v6 Ollama attestation was reinterpreted as v7 quality evidence")
	}
	changedRuntime := metadata
	changedRuntime.RuntimeVersion = "ollama 0.33.0"
	if err := loadProviderAttestation(strings.Repeat("c", 64), changedRuntime, brief.ToolIdentity{}); err == nil || !strings.Contains(err.Error(), "runtime changed") {
		t.Fatalf("runtime change did not produce concrete re-attestation guidance: %v", err)
	}
	raw, err := os.ReadFile(providerAttestationPath())
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "provider_binary") || strings.Contains(text, "empty_workspace") || strings.Contains(text, "no_host_read") ||
		!strings.Contains(text, `"endpoint":"http://127.0.0.1:11434"`) {
		t.Fatalf("HTTP attestation contains dishonest CLI evidence: %s", text)
	}
}

func TestOllamaQualityCaseSixChecksGuidanceNotVerdict(t *testing.T) {
	qualityCase := ollamaDoctorQualityCases()[5]
	finding := qualityCase.inventory.Findings[0]
	guidance := FindingGuidance{FindingID: findingGuidanceID(finding), Assessment: "unclear", Comment: "cannot establish benign intent", AnchorQuote: qualityCase.inventory.Files[0].SelectedText[strings.Index(qualityCase.inventory.Files[0].SelectedText, "printf"):strings.LastIndex(qualityCase.inventory.Files[0].SelectedText, "\npackage")]}
	verdict := Verdict{SchemaVersion: VerdictSchemaVersion, Verdict: "allow", Confidence: "medium", Summary: "requires human judgment", Findings: []ReviewFinding{}, Guidance: []FindingGuidance{guidance}, CoverageNotes: []string{}}
	if err := qualityCase.validate([]Verdict{verdict}); err != nil {
		t.Fatalf("case six incorrectly required a block verdict: %v", err)
	}
	verdict.Guidance[0].Assessment = "likely-benign"
	if err := qualityCase.validate([]Verdict{verdict}); err == nil {
		t.Fatal("case six accepted reassuring guidance")
	}
}

func TestOllamaPerformanceProjectionUsesMeasuredThroughput(t *testing.T) {
	cfg := ollamaTestConfig()
	cfg.Review.Phases = []string{"recipe", "artifact"}
	metrics := []OllamaRequestMetrics{{RequestBytes: 10000, PromptTokens: 8000, OutputTokens: 200, LoadDurationNS: int64(time.Second), PromptDurationNS: int64(2 * time.Second), OutputDurationNS: int64(time.Second), TotalDurationNS: int64(4 * time.Second)}}
	check, measured := ollamaPerformanceProjection(cfg, "off", metrics, true)
	if !measured || !check.OK || check.Required || !strings.Contains(check.Detail, "visible output") || !strings.Contains(check.Detail, "mean request wall") ||
		!strings.Contains(check.Detail, "generation cap/input reserve 4096 tokens") || !strings.Contains(check.Detail, "provisional 8.0 MiB reference") || !strings.Contains(check.Detail, "cold load") {
		t.Fatalf("optional measured projection is wrong: %+v", check)
	}
}

func TestOllamaPerformanceProjectionWarnsOnlyForSlowEnabledSources(t *testing.T) {
	cfg := ollamaTestConfig()
	cfg.Review.Phases = []string{"sources", "artifact"}
	metrics := []OllamaRequestMetrics{{RequestBytes: 10000, PromptTokens: 4000, OutputTokens: 100,
		PromptDurationNS: int64(time.Second), OutputDurationNS: int64(time.Second), TotalDurationNS: int64(3 * time.Second)}}
	measurement, err := measureOllamaPerformance(cfg, "off", metrics)
	if err != nil || measurement.ProjectedDuration <= ollamaSourcesProjectionBudget {
		t.Fatalf("fixture did not exceed the Sources budget: measurement=%+v err=%v", measurement, err)
	}
	check, measured := ollamaPerformanceProjection(cfg, "off", metrics, true)
	if !measured || check.OK || check.Required || !strings.Contains(check.Detail, "10m0s Sources budget") ||
		!strings.Contains(check.Detail, "the model passed every safety check") ||
		!strings.Contains(check.Detail, "suggested review.phases: [artifact]") ||
		!strings.Contains(check.Detail, "manual choice, not applied") ||
		!strings.Contains(check.Detail, "artifact comes first") ||
		!strings.Contains(check.Detail, "sources can catch code lost inside compiled binaries") ||
		!strings.Contains(check.Detail, "recipe is cheapest") ||
		!strings.Contains(check.Detail, llmSuitabilityRecipeArtifact) {
		t.Fatalf("slow Sources did not produce an actionable warning: %+v measured=%t", check, measured)
	}
	if !DoctorOK([]Check{check}) {
		t.Fatal("valid but slow projection blocked Doctor")
	}
	check, measured = ollamaPerformanceProjection(cfg, "off", metrics, false)
	if !measured || check.OK || check.Required || strings.Contains(check.Detail, "passed every safety check") || !strings.Contains(check.Detail, "suggested review.phases: [artifact]") {
		t.Fatalf("speed warning claimed failed safety checks had passed: %+v measured=%t", check, measured)
	}
	fast := metrics[0]
	fast.PromptDurationNS = int64(time.Millisecond)
	fast.OutputDurationNS = int64(time.Millisecond)
	fast.TotalDurationNS = int64(3 * time.Millisecond)
	check, measured = ollamaPerformanceProjection(cfg, "off", []OllamaRequestMetrics{fast}, true)
	if !measured || !check.OK || !check.Required || strings.Contains(check.Detail, "suggested review.phases:") {
		t.Fatalf("fast enabled Sources did not pass its required budget check: %+v measured=%t", check, measured)
	}

	cfg.Review.Phases = []string{"artifact"}
	check, measured = ollamaPerformanceProjection(cfg, "off", metrics, true)
	if !measured || !check.OK || check.Required || strings.Contains(check.Detail, "Sources budget") || strings.Contains(check.Detail, "suggested review.phases:") {
		t.Fatalf("disabled Sources still warned about its budget: %+v measured=%t", check, measured)
	}

	metrics[0].PromptDurationNS = 0
	check, measured = ollamaPerformanceProjection(cfg, "off", metrics, true)
	if measured || check.OK || !check.Required || strings.Contains(check.Detail, "suggested review.phases:") || DoctorOK([]Check{check}) {
		t.Fatalf("unusable performance measurement was not a required failure: %+v measured=%t", check, measured)
	}
}

func TestOllamaSourcesProjectionIncludesRequestWallTime(t *testing.T) {
	cfg := ollamaTestConfig()
	base := OllamaRequestMetrics{RequestBytes: 10_000, PromptTokens: 8_000, OutputTokens: 200,
		LoadDurationNS: int64(time.Second), PromptDurationNS: int64(time.Second), OutputDurationNS: int64(time.Second),
		TotalDurationNS: int64(3 * time.Second), WallDurationNS: int64(3 * time.Second)}
	fast, err := measureOllamaPerformance(cfg, "off", []OllamaRequestMetrics{base})
	if err != nil {
		t.Fatal(err)
	}
	slowMetric := base
	slowMetric.TotalDurationNS += int64(7 * time.Second)
	slowMetric.UnaccountedDurationNS = int64(7 * time.Second)
	slowMetric.WallDurationNS += int64(7 * time.Second)
	slow, err := measureOllamaPerformance(cfg, "off", []OllamaRequestMetrics{slowMetric})
	if err != nil {
		t.Fatal(err)
	}
	if slow.Projection.BatchCount != fast.Projection.BatchCount || slow.ProjectedDuration <= fast.ProjectedDuration+time.Duration(slow.Projection.BatchCount)*6*time.Second {
		t.Fatalf("Sources projection omitted repeated hidden wall time: fast=%s slow=%s batches=%d", fast.ProjectedDuration, slow.ProjectedDuration, slow.Projection.BatchCount)
	}
}

func TestOllamaByteTokenCalibrationRejectsUnsafeRatio(t *testing.T) {
	metric := OllamaRequestMetrics{RequestBytes: 2500, PromptTokens: 1000, OutputTokens: 10, PromptDurationNS: 1, OutputDurationNS: 1, TotalDurationNS: 2}
	check, ratio := ollamaByteTokenCalibration([]OllamaRequestMetrics{metric})
	if !check.OK || ratio != 2.5 || !strings.Contains(check.Detail, "required at least") {
		t.Fatalf("safe calibration failed: check=%+v ratio=%f", check, ratio)
	}
	metric.RequestBytes = 2000
	check, _ = ollamaByteTokenCalibration([]OllamaRequestMetrics{metric})
	if check.OK {
		t.Fatalf("unsafe bytes/token ratio passed: %+v", check)
	}
}

func TestOllamaSourcesProjectionUsesTheRealBatchingPath(t *testing.T) {
	cfg := ollamaTestConfig()
	projection, err := buildOllamaSourcesProjection(cfg, "on", 2.5)
	if err != nil {
		t.Fatal(err)
	}
	inventory := ollamaProjectionInventory(projection.ReferenceBytes)
	batches, err := NewReviewer(cfg).batchesWithProviderOptions("doctor-projection", "post", inventory, ReviewOptions{}, "on")
	if err != nil {
		t.Fatal(err)
	}
	if projection.ReferenceBytes != ollamaSourcesProjectionBytes || projection.BatchCount != len(batches) || projection.SelectedPerBatch <= 0 || projection.PromptTokensPerBatch <= 0 {
		t.Fatalf("projection diverged from review batching: projection=%+v batches=%d", projection, len(batches))
	}
}

func TestOllamaQualityGateRunsAndAnnouncesAllSevenCases(t *testing.T) {
	previous := reviewClientFactory
	defer func() { reviewClientFactory = previous }()
	metadata := ProviderMetadata{Provider: "ollama", Transport: "http-loopback", RuntimeVersion: "ollama 0.32.13",
		Model: "secure-model:latest", ModelDigest: ollamaTestDigest, ContextTokens: 131072, Thinking: true, Effort: "on", AdapterPolicy: ollamaAdapterPolicy("on", false)}
	reviewer := &ollamaQualityReviewer{metadata: metadata}
	reviewClientFactory = func(Config) ReviewClient { return reviewer }
	var events []string
	resets := 0
	checks, ok, metrics, measurements := runOllamaQualityGate(context.Background(), ollamaTestConfig(), metadata, "",
		func(context.Context) error { resets++; return nil },
		func(name, _ string) { events = append(events, "run:"+name) },
		func(check Check) { events = append(events, "done:"+check.Name) })
	if !ok || len(checks) != 7 || len(events) != 14 || reviewer.calls != 7 || len(metrics) != 7 || len(measurements) != 7 || resets != 7 {
		t.Fatalf("quality gate incomplete: ok=%t checks=%d events=%d calls=%d metrics=%d measurements=%d resets=%d", ok, len(checks), len(events), reviewer.calls, len(metrics), len(measurements), resets)
	}
	for index, check := range checks {
		if !check.OK || !check.Required {
			t.Fatalf("quality case failed: %+v", check)
		}
		if events[index*2] != "run:"+check.Name || events[index*2+1] != "done:"+check.Name {
			t.Fatalf("quality result was not emitted immediately after its announcement: %#v", events)
		}
		if !measurements[index].Passed || measurements[index].ID == "" || len(measurements[index].Metrics) != 1 {
			t.Fatalf("quality case measurement is incomplete: %+v", measurements[index])
		}
	}
}

func TestOllamaQualityBindingWarningNamesOnlyBoundedSanitizedLocations(t *testing.T) {
	line := 2
	findings := []ReviewFinding{
		{File: "PKGBUILD\x1b[2J", Line: &line, Category: "persistence"},
		{File: "demo.install", Line: nil, Category: "other"},
	}
	for range 8 {
		findings = append(findings, ReviewFinding{File: "extra", Line: &line, Category: "other"})
	}
	qualityCase := ollamaDoctorQualityCases()[4]
	verdicts := []Verdict{{Verdict: "block", Findings: findings}}
	if err := qualityCase.validate(verdicts); err != nil {
		t.Fatalf("blocking persistence verdict failed the required quality case: %v", err)
	}
	detail := qualityCase.advisory(verdicts)
	if detail == "" {
		t.Fatal("misbound persistence finding produced no advisory")
	}
	for _, want := range []string{"received verdict=block", `PKGBUILD\u001b[2J:2/persistence`, "demo.install:null/other", "+2 more"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("quality binding diagnostic omitted %q: %s", want, detail)
		}
	}
	if strings.ContainsRune(detail, '\x1b') {
		t.Fatalf("quality binding diagnostic emitted a terminal control: %q", detail)
	}
}

func TestOllamaCrossFilePersistenceQualityCaseUsesAnUnambiguousMaliciousChain(t *testing.T) {
	qualityCase := ollamaDoctorQualityCases()[4]
	if qualityCase.id != "cross-file-persistence" {
		t.Fatalf("fifth quality case changed unexpectedly: %q", qualityCase.id)
	}
	joined := ""
	for _, file := range qualityCase.inventory.Files {
		joined += file.Path + "\n" + file.SelectedText + "\n"
	}
	for _, want := range []string{
		"systemctl enable --now demo-agent.service",
		"ExecStart=/usr/bin/demo-agent",
		"--data-binary @/etc/shadow",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("cross-file persistence fixture omitted %q: %s", want, joined)
		}
	}
	batches, err := NewReviewer(ollamaTestConfig()).batchesWithProviderOptions("doctor-probe", "pre", qualityCase.inventory, ReviewOptions{}, "on")
	if err != nil || len(batches) != 1 || batches[0].Validate() != nil {
		t.Fatalf("cross-file fixture does not form one valid production request: batches=%d err=%v", len(batches), err)
	}
	if err := qualityCase.validate([]Verdict{{Verdict: "allow"}}); err == nil {
		t.Fatal("quality case accepted the persistent credential-exfiltration chain")
	}
	if err := qualityCase.validate([]Verdict{{Verdict: "block"}}); err != nil {
		t.Fatalf("quality case rejected a blocking verdict: %v", err)
	}
	line := 3
	bound := Verdict{Verdict: "block", Findings: []ReviewFinding{{Category: "credential_access", File: "usr/bin/demo-agent", Line: &line}}}
	if detail := qualityCase.advisory([]Verdict{bound}); detail != "" {
		t.Fatalf("finding bound to the credential exfiltration produced a warning: %q", detail)
	}
}

func TestOllamaQualityGateWarnsButPassesOnMissingPersistenceBinding(t *testing.T) {
	originalFactory := reviewClientFactory
	t.Cleanup(func() { reviewClientFactory = originalFactory })
	metadata := ProviderMetadata{Provider: "ollama", Transport: "http-loopback", RuntimeVersion: "ollama 0.32.13",
		Model: "secure-model:latest", ModelDigest: ollamaTestDigest, ContextTokens: 131072, Thinking: true, Effort: "on", AdapterPolicy: ollamaAdapterPolicy("on", false)}
	reviewer := &ollamaQualityReviewer{metadata: metadata, omitPersistenceFinding: true}
	reviewClientFactory = func(Config) ReviewClient { return reviewer }

	checks, ok, _, _ := runOllamaQualityGate(context.Background(), ollamaTestConfig(), metadata, "", nil, nil, nil)
	if !ok {
		t.Fatal("missing explanatory source binding failed the safety gate despite a blocking verdict")
	}
	if len(checks) != 8 {
		t.Fatalf("expected seven required checks and one advisory, got %d: %+v", len(checks), checks)
	}
	warning := checks[5]
	if warning.OK || warning.Required || !strings.Contains(warning.Name, "source binding") {
		t.Fatalf("missing binding was not represented as an optional warning: %+v", warning)
	}
	if !strings.Contains(warning.Detail, "received verdict=block with no findings") {
		t.Fatalf("missing binding warning omitted the bounded diagnostic: %s", warning.Detail)
	}
	for _, check := range checks {
		if check.Required && !check.OK {
			t.Fatalf("required quality case failed: %+v", check)
		}
	}
}

func TestOllamaPrivilegedWritableDeserializationQualityCase(t *testing.T) {
	cases := ollamaDoctorQualityCases()
	var qualityCase *ollamaQualityCase
	for index := range cases {
		candidate := &cases[index]
		if candidate.id == ollamaQualityCasePrivilegedWritableDeserialization {
			qualityCase = candidate
			break
		}
	}
	if qualityCase == nil {
		t.Fatal("privileged writable deserialization case is absent")
	}
	joined := ""
	for _, file := range qualityCase.inventory.Files {
		joined += file.Path + "\n" + file.SelectedText + "\n"
	}
	for _, want := range []string{"chmod 0664 /var/lib/newsreader.dat", "Exec = /usr/bin/newsreader check", "pickle.load(state)"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("quality fixture omitted %q: %s", want, joined)
		}
	}
	if qualityCase.inventory.Phase != "artifact" {
		t.Fatalf("privileged integration fixture has phase %q", qualityCase.inventory.Phase)
	}
	batches, err := NewReviewer(ollamaTestConfig()).batchesWithProviderOptions("doctor-probe", "artifact", qualityCase.inventory, ReviewOptions{}, "on")
	if err != nil || len(batches) != 1 || batches[0].Validate() != nil {
		t.Fatalf("privileged integration fixture does not form one valid production request: batches=%d err=%v", len(batches), err)
	}
	if err := qualityCase.validate([]Verdict{{Verdict: "allow"}}); err == nil {
		t.Fatal("quality case accepted the root deserialization path")
	}
	if err := qualityCase.validate([]Verdict{{Verdict: "block"}}); err != nil {
		t.Fatalf("quality case rejected a blocking verdict: %v", err)
	}
	if detail := qualityCase.advisory([]Verdict{{Verdict: "block"}}); !strings.Contains(detail, "received verdict=block with no findings") {
		t.Fatalf("unexplained block did not produce a source-binding warning: %q", detail)
	}
	line := 5
	bound := Verdict{Verdict: "block", Findings: []ReviewFinding{{Category: "privilege_escalation", File: "usr/lib/python3.13/site-packages/newsreader/file.py", Line: &line}}}
	if detail := qualityCase.advisory([]Verdict{bound}); detail != "" {
		t.Fatalf("exactly bound privilege finding produced a warning: %q", detail)
	}
}

func TestOllamaQualityGateCanRunOnlyTheSelectedCase(t *testing.T) {
	originalFactory := reviewClientFactory
	t.Cleanup(func() { reviewClientFactory = originalFactory })
	metadata := ProviderMetadata{Provider: "ollama", Transport: "http-loopback", RuntimeVersion: "ollama 0.32.13",
		Model: "secure-model:latest", ModelDigest: ollamaTestDigest, ContextTokens: 131072, Thinking: true, Effort: "on", AdapterPolicy: ollamaAdapterPolicy("on", false)}
	reviewer := &ollamaQualityReviewer{metadata: metadata}
	reviewClientFactory = func(Config) ReviewClient { return reviewer }
	announced := ""
	resets := 0

	checks, ok, metrics, measurements := runOllamaQualityGate(context.Background(), ollamaTestConfig(), metadata, ollamaQualityCasePrivilegedWritableDeserialization,
		func(context.Context) error { resets++; return nil },
		func(_, detail string) { announced = detail }, nil)
	if !ok || len(checks) != 1 || reviewer.calls != 1 || len(metrics) != 1 || len(measurements) != 1 || resets != 1 {
		t.Fatalf("targeted gate ran more than one isolated case: ok=%t checks=%d calls=%d metrics=%d resets=%d", ok, len(checks), reviewer.calls, len(metrics), resets)
	}
	if reviewer.lastPhase != "artifact" || !strings.Contains(checks[0].Name, "7/7") || !strings.Contains(announced, "diagnostic only, attestation unchanged") {
		t.Fatalf("targeted gate lost its artifact or diagnostic scope: phase=%q check=%+v announcement=%q", reviewer.lastPhase, checks[0], announced)
	}
}

func TestOllamaQualityGateDoesNotReviewAfterIsolationResetFailure(t *testing.T) {
	originalFactory := reviewClientFactory
	t.Cleanup(func() { reviewClientFactory = originalFactory })
	metadata := ProviderMetadata{Provider: "ollama", Transport: "http-loopback", RuntimeVersion: "ollama 0.32.13",
		Model: "secure-model:latest", ModelDigest: ollamaTestDigest, ContextTokens: 131072, Thinking: true, Effort: "on", AdapterPolicy: ollamaAdapterPolicy("on", false)}
	reviewer := &ollamaQualityReviewer{metadata: metadata}
	reviewClientFactory = func(Config) ReviewClient { return reviewer }

	checks, ok, metrics, measurements := runOllamaQualityGate(context.Background(), ollamaTestConfig(), metadata, ollamaQualityCasePrivilegedWritableDeserialization,
		func(context.Context) error { return errors.New("unload failed") }, nil, nil)
	if ok || len(checks) != 1 || checks[0].OK || reviewer.calls != 0 || len(metrics) != 0 || len(measurements) != 1 || measurements[0].FailureStage != "model-reset" || !strings.Contains(checks[0].Detail, "reset Ollama model") {
		t.Fatalf("quality request survived a failed isolation reset: ok=%t checks=%+v calls=%d metrics=%d", ok, checks, reviewer.calls, len(metrics))
	}
}

func TestReviewPromptNamesPrivilegedWritableUnsafeDeserialization(t *testing.T) {
	prompt, err := os.ReadFile(filepath.Join("..", "..", "share", "review-prompt.md"))
	if err != nil {
		t.Fatal(err)
	}
	flat := strings.Join(strings.Fields(string(prompt)), " ")
	for _, want := range []string{
		"writable by a less-privileged user or group", "Python `pickle.load`", "privilege-escalation path",
		"concrete writable-input and privileged-consumer chain", "exact one-based `line_start` and `line_end`",
		"dangerous consumer or sink", "chain's end security impact",
	} {
		if !strings.Contains(flat, want) {
			t.Errorf("review prompt omitted %q", want)
		}
	}
}

func TestOllamaProbeFailureStillProducesAValidDeterministicBriefing(t *testing.T) {
	withStateAndShare(t)
	cfg := ollamaTestConfig()
	service, err := NewAuditService(context.Background(), cfg, ollamaProbeFailureReviewer{})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	writePackageFixture(t, root)
	report, status, err := service.ScanDirectory(context.Background(), "pre", root, "demo")
	if err != nil || status != 0 || report.Validate() != nil || !strings.Contains(report.Reviewer.Error, "daemon unavailable") || report.Reviewer.ModelDigest != "" {
		t.Fatalf("Ollama outage did not degrade cleanly: status=%d err=%v reviewer=%+v validate=%v", status, err, report.Reviewer, report.Validate())
	}
}

func TestOllamaPolicyFingerprintBindsDigestContextAndGateSelection(t *testing.T) {
	withStateAndShare(t)
	cfg := ollamaTestConfig()
	metadata := ProviderMetadata{Provider: "ollama", Transport: "http-loopback", RuntimeVersion: "ollama 0.32.13",
		Model: cfg.Providers.Ollama.Model, ModelDigest: ollamaTestDigest, ContextTokens: cfg.Providers.Ollama.ContextTokens,
		Effort: "off", AdapterPolicy: ollamaAdapterPolicy("off", false)}
	archive, err := brief.ArchiveProbeIdentity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	base, err := ComputePolicyFingerprint(cfg, metadata, archive)
	if err != nil {
		t.Fatal(err)
	}
	changedDigest := metadata
	changedDigest.ModelDigest = strings.Repeat("c", 64)
	digestFingerprint, _ := ComputePolicyFingerprint(cfg, changedDigest, archive)
	changedContext := cfg
	changedContext.Providers.Ollama.ContextTokens /= 2
	contextFingerprint, _ := ComputePolicyFingerprint(changedContext, metadata, archive)
	changedPhases := cfg
	changedPhases.Review.Phases = []string{"recipe", "artifact"}
	phaseFingerprint, _ := ComputePolicyFingerprint(changedPhases, metadata, archive)
	verifiedPolicy := metadata
	verifiedPolicy.AdapterPolicy = ollamaAdapterPolicy("off", true)
	verifiedFingerprint, _ := ComputePolicyFingerprint(cfg, verifiedPolicy, archive)
	if base == digestFingerprint || base == contextFingerprint || base == phaseFingerprint || base == verifiedFingerprint {
		t.Fatalf("Ollama policy identity did not bind every local decision input: base=%s digest=%s context=%s phases=%s truncation=%s", base, digestFingerprint, contextFingerprint, phaseFingerprint, verifiedFingerprint)
	}
}

func TestProviderAttestationFingerprintBindsSemanticsButNotGateSelection(t *testing.T) {
	withStateAndShare(t)
	cfg := ollamaTestConfig()
	metadata := ProviderMetadata{Provider: "ollama", Transport: "http-loopback", RuntimeVersion: "ollama 0.32.13",
		Model: cfg.Providers.Ollama.Model, ModelDigest: ollamaTestDigest, ContextTokens: cfg.Providers.Ollama.ContextTokens,
		Thinking: true, Effort: "on", AdapterPolicy: ollamaAdapterPolicy("on", true)}
	base, err := ComputeProviderAttestationFingerprint(cfg, metadata)
	if err != nil {
		t.Fatal(err)
	}
	selection := cfg
	selection.Review.Phases = []string{"artifact"}
	selection.Build.MemoryBytes /= 2
	selection.Network.PromptTimeoutSeconds++
	selectionFingerprint, err := ComputeProviderAttestationFingerprint(selection, metadata)
	if err != nil {
		t.Fatal(err)
	}
	if selectionFingerprint != base {
		t.Fatalf("gate or containment selection invalidated provider evidence: base=%s changed=%s", base, selectionFingerprint)
	}
	changedBatch := cfg
	changedBatch.Review.BatchBytes /= 2
	batchFingerprint, _ := ComputeProviderAttestationFingerprint(changedBatch, metadata)
	changedSeverity := cfg
	changedSeverity.Review.ManualReviewMinimumSeverity = "medium"
	severityFingerprint, _ := ComputeProviderAttestationFingerprint(changedSeverity, metadata)
	changedMetadata := metadata
	changedMetadata.ModelDigest = strings.Repeat("c", 64)
	metadataFingerprint, _ := ComputeProviderAttestationFingerprint(cfg, changedMetadata)
	oldAdapter := metadata
	oldAdapter.AdapterPolicy = strings.Replace(metadata.AdapterPolicy, "ollama-api-v5:", "ollama-api-v4:", 1)
	oldAdapterFingerprint, _ := ComputeProviderAttestationFingerprint(cfg, oldAdapter)
	changedReasoning := cfg
	changedReasoning.Providers.Ollama.Reasoning = "low"
	reasoningFingerprint, _ := ComputeProviderAttestationFingerprint(changedReasoning, metadata)
	if base == batchFingerprint || base == severityFingerprint || base == metadataFingerprint || base == oldAdapterFingerprint || base == reasoningFingerprint {
		t.Fatalf("semantic provider input was not bound: base=%s batch=%s severity=%s metadata=%s", base, batchFingerprint, severityFingerprint, metadataFingerprint)
	}
}
