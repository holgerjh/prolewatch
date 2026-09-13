package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/holgerjh/prolewatch/internal/brief"
	"golang.org/x/sys/unix"
)

const (
	ollamaLoopbackEndpoint      = "http://127.0.0.1:11434"
	ollamaLoopbackAddress       = "127.0.0.1:11434"
	ollamaHTTPResponseBytes     = 4 << 20
	ollamaThinkingGenerationCap = 6_144
	ollamaPlainGenerationCap    = 4_096
	ollamaTemplateReserveTokens = 2_048
	ollamaTruncationProbeTokens = 1_024
	ollamaMetadataProbeTimeout  = 15 * time.Second
	ollamaLockRetryInterval     = 50 * time.Millisecond
	ollamaBytesPerTokenFloor    = 2.0
	ollamaBytesPerTokenMargin   = 0.10
	ollamaAdapterPolicyPrefix   = "ollama-api-v5:loopback-target-bound-schema-no-tools:bpt-floor-2.0"
)

// ollamaAdapter deliberately has no endpoint sourced from configuration. Tests
// use newOllamaAdapterAt with an httptest server; production always calls the
// fixed loopback constructor below.
type ollamaAdapter struct {
	cfg       Config
	provider  OllamaProviderConfig
	endpoint  string
	client    *http.Client
	lockPath  string
	metricsMu sync.Mutex
	metrics   []OllamaRequestMetrics
	policyMu  sync.Mutex
	// truncationRefused is set only by a live over-context probe. A fresh
	// process may recover the same observation from a matching current attestation;
	// the normal attestation validation still binds its complete fingerprint.
	truncationRefused bool
}

func newOllamaAdapter(cfg Config) *ollamaAdapter {
	return &ollamaAdapter{
		cfg:      cfg,
		provider: cfg.Providers.Ollama,
		endpoint: ollamaLoopbackEndpoint,
		client:   newOllamaLoopbackClient(),
		lockPath: filepath.Join(StateRoot(), "providers", "ollama-loopback.lock"),
	}
}

func newOllamaAdapterAt(cfg Config, endpoint string, client *http.Client, lockPath string) *ollamaAdapter {
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("Ollama API redirects are forbidden")
	}
	return &ollamaAdapter{cfg: cfg, provider: cfg.Providers.Ollama, endpoint: strings.TrimRight(endpoint, "/"), client: &copyClient, lockPath: lockPath}
}

func newOllamaLoopbackClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:               nil,
		DisableCompression:  true,
		MaxIdleConns:        2,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
		// Ollama's non-streaming chat endpoint does not send response headers
		// until generation is complete. A fixed header deadline therefore turns
		// every legitimate generation longer than 15 seconds into a transport
		// failure. Metadata calls already carry the 15-second metadata context;
		// chat calls carry providers.ollama.timeout_seconds, so leave the header
		// timer disabled and let those operation-specific contexts bound requests.
		ResponseHeaderTimeout: 0,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != ollamaLoopbackAddress || (network != "tcp" && network != "tcp4") {
				return nil, fmt.Errorf("Ollama adapter refused non-loopback destination %q over %q", address, network)
			}
			return dialer.DialContext(ctx, "tcp4", ollamaLoopbackAddress)
		},
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("Ollama API redirects are forbidden")
		},
	}
}

func (a *ollamaAdapter) CredentialPath() string { return "" }

type ollamaModelSummary struct {
	Name         string   `json:"name"`
	Model        string   `json:"model"`
	Digest       string   `json:"digest"`
	RemoteModel  string   `json:"remote_model"`
	RemoteHost   string   `json:"remote_host"`
	Capabilities []string `json:"capabilities"`
}

type ollamaDescription struct {
	metadata     ProviderMetadata
	modelNames   map[string]bool
	capabilities map[string]bool
}

func (a *ollamaAdapter) Metadata(ctx context.Context) (ProviderMetadata, error) {
	probe, cancel := context.WithTimeout(ctx, ollamaMetadataProbeTimeout)
	defer cancel()
	description, err := a.describe(probe)
	if err != nil {
		return ProviderMetadata{}, err
	}
	return description.metadata, nil
}

func (a *ollamaAdapter) describe(ctx context.Context) (ollamaDescription, error) {
	var versionResponse struct {
		Version string `json:"version"`
	}
	if err := a.getJSON(ctx, "/api/version", &versionResponse, 64*1024); err != nil {
		return ollamaDescription{}, fmt.Errorf("Ollama version probe failed: %w", err)
	}
	match := versionRE.FindStringSubmatch(versionResponse.Version)
	if match == nil {
		return ollamaDescription{}, fmt.Errorf("cannot parse Ollama version %q", versionResponse.Version)
	}
	parsed := []int{atoi(match[1]), atoi(match[2]), atoi(match[3])}
	if compareVersions(parsed, mustVersion(MinOllamaVersion)) < 0 {
		return ollamaDescription{}, fmt.Errorf("Ollama %s or newer is required; found %s", MinOllamaVersion, versionResponse.Version)
	}
	var warning string
	if compareVersions(parsed, mustVersion(MaxOllamaVersion)) >= 0 {
		warning = fmt.Sprintf("Ollama %s is newer than the checked ceiling (< %s); the loopback API contract has not been verified against it", versionResponse.Version, MaxOllamaVersion)
	}

	selected, err := a.localModel(ctx)
	if err != nil {
		return ollamaDescription{}, err
	}
	var shown struct {
		RemoteModel  string                     `json:"remote_model"`
		RemoteHost   string                     `json:"remote_host"`
		Capabilities []string                   `json:"capabilities"`
		ModelInfo    map[string]json.RawMessage `json:"model_info"`
		Details      struct {
			ContextLength int `json:"context_length"`
		} `json:"details"`
	}
	if err := a.postJSON(ctx, "/api/show", map[string]any{"model": a.provider.Model, "verbose": false}, &shown, ollamaHTTPResponseBytes); err != nil {
		return ollamaDescription{}, fmt.Errorf("Ollama model metadata probe failed: %w", err)
	}
	if selected.RemoteHost != "" || selected.RemoteModel != "" || shown.RemoteHost != "" || shown.RemoteModel != "" {
		return ollamaDescription{}, errors.New("Ollama Cloud or remote-backed models are forbidden")
	}
	digest, err := canonicalOllamaDigest(selected.Digest)
	if err != nil {
		return ollamaDescription{}, fmt.Errorf("Ollama local model has no valid digest: %w", err)
	}
	contextLength, err := ollamaModelContext(shown.ModelInfo, shown.Details.ContextLength)
	if err != nil {
		return ollamaDescription{}, err
	}
	if contextLength < a.provider.ContextTokens {
		return ollamaDescription{}, fmt.Errorf("Ollama model context is %d tokens, below configured %d", contextLength, a.provider.ContextTokens)
	}
	capabilities := map[string]bool{}
	for _, capability := range append(append([]string(nil), selected.Capabilities...), shown.Capabilities...) {
		capabilities[strings.ToLower(strings.TrimSpace(capability))] = true
	}
	if !capabilities["completion"] {
		return ollamaDescription{}, errors.New("Ollama model lacks the required completion capability")
	}
	// Re-read the local list after /api/show so a moved tag cannot splice model
	// metadata from one digest into an attestation for another.
	confirmed, err := a.localModel(ctx)
	if err != nil {
		return ollamaDescription{}, err
	}
	confirmedDigest, err := canonicalOllamaDigest(confirmed.Digest)
	if err != nil || confirmedDigest != digest || confirmed.RemoteHost != "" || confirmed.RemoteModel != "" {
		return ollamaDescription{}, errors.New("Ollama model identity changed during metadata probe")
	}
	modelNames := map[string]bool{a.provider.Model: true, selected.Name: true, selected.Model: true}
	reasoning, err := ollamaReasoningLevel(a.provider.Reasoning, capabilities["thinking"])
	if err != nil {
		return ollamaDescription{}, err
	}
	metadata := ProviderMetadata{
		Provider: "ollama", Transport: "http-loopback", RuntimeVersion: canonicalRuntimeVersion("ollama", parsed),
		Model: a.provider.Model, ModelDigest: digest, ContextTokens: a.provider.ContextTokens,
		Thinking: capabilities["thinking"], Effort: reasoning, CompatibilityWarning: warning,
	}
	metadata = ollamaMetadataWithTruncationPolicy(metadata, a.truncationWasRefused(metadata))
	return ollamaDescription{
		metadata:   metadata,
		modelNames: modelNames, capabilities: capabilities,
	}, nil
}

func ollamaReasoningLevel(configured string, capability bool) (string, error) {
	switch configured {
	case "", "auto":
		if capability {
			return "on", nil
		}
		return "off", nil
	case "off":
		return "off", nil
	case "low", "medium", "high":
		if !capability {
			return "", fmt.Errorf("Ollama model does not advertise thinking required by reasoning=%s", configured)
		}
		return configured, nil
	default:
		return "", errors.New("unsupported Ollama reasoning level")
	}
}

func ollamaAdapterPolicy(reasoning string, truncationRefused bool) string {
	truncation := "truncate-unverified"
	if truncationRefused {
		truncation = "truncate-off"
	}
	return fmt.Sprintf("%s:generation-cap-%d:%s:reasoning-%s", ollamaAdapterPolicyPrefix, ollamaGenerationLimit(reasoning), truncation, reasoning)
}

func ollamaMetadataWithTruncationPolicy(metadata ProviderMetadata, refused bool) ProviderMetadata {
	metadata.AdapterPolicy = ollamaAdapterPolicy(metadata.Effort, refused)
	return metadata
}

func (a *ollamaAdapter) truncationWasRefused(metadata ProviderMetadata) bool {
	a.policyMu.Lock()
	refused := a.truncationRefused
	a.policyMu.Unlock()
	return refused || storedOllamaTruncationRefused(metadata)
}

func (a *ollamaAdapter) localModel(ctx context.Context) (ollamaModelSummary, error) {
	var listed struct {
		Models []ollamaModelSummary `json:"models"`
	}
	if err := a.getJSON(ctx, "/api/tags", &listed, ollamaHTTPResponseBytes); err != nil {
		return ollamaModelSummary{}, fmt.Errorf("cannot list local Ollama models: %w", err)
	}
	var matches []ollamaModelSummary
	for _, model := range listed.Models {
		if model.Name == a.provider.Model || model.Model == a.provider.Model {
			matches = append(matches, model)
		}
	}
	if len(matches) != 1 {
		return ollamaModelSummary{}, fmt.Errorf("configured Ollama model %q must resolve to exactly one local model; found %d", a.provider.Model, len(matches))
	}
	return matches[0], nil
}

func canonicalOllamaDigest(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "sha256:")
	if !validHexDigest(value) {
		return "", errors.New("digest must be a 64-character SHA-256 value")
	}
	return value, nil
}

func ollamaModelContext(info map[string]json.RawMessage, detailsContext int) (int, error) {
	values := map[int]bool{}
	if detailsContext > 0 {
		values[detailsContext] = true
	}
	for key, raw := range info {
		if !strings.HasSuffix(strings.ToLower(key), ".context_length") {
			continue
		}
		var value int
		if err := json.Unmarshal(raw, &value); err != nil || value <= 0 {
			return 0, fmt.Errorf("Ollama model reports invalid context in %q", key)
		}
		values[value] = true
	}
	if len(values) != 1 {
		return 0, fmt.Errorf("Ollama model must report one unambiguous context length; found %d", len(values))
	}
	for value := range values {
		return value, nil
	}
	panic("unreachable")
}

type ollamaChatRequest struct {
	Model     string          `json:"model"`
	Messages  []ollamaMessage `json:"messages"`
	Stream    bool            `json:"stream"`
	Format    json.RawMessage `json:"format"`
	Options   map[string]any  `json:"options"`
	Think     json.RawMessage `json:"think"`
	Truncate  bool            `json:"truncate"`
	Shift     bool            `json:"shift"`
	KeepAlive string          `json:"keep_alive"`
}

type ollamaMessage struct {
	Role      string            `json:"role"`
	Content   string            `json:"content"`
	Thinking  string            `json:"thinking,omitempty"`
	ToolCalls []json.RawMessage `json:"tool_calls,omitempty"`
}

type ollamaChatResponse struct {
	Model              string        `json:"model"`
	RemoteModel        string        `json:"remote_model"`
	RemoteHost         string        `json:"remote_host"`
	Message            ollamaMessage `json:"message"`
	Done               bool          `json:"done"`
	DoneReason         string        `json:"done_reason"`
	TotalDuration      int64         `json:"total_duration"`
	LoadDuration       int64         `json:"load_duration"`
	PromptEvalCount    int           `json:"prompt_eval_count"`
	PromptEvalDuration int64         `json:"prompt_eval_duration"`
	EvalCount          int           `json:"eval_count"`
	EvalDuration       int64         `json:"eval_duration"`
}

type OllamaRequestMetrics struct {
	RequestBytes          int   `json:"request_bytes"`
	PromptTokens          int   `json:"prompt_tokens"`
	OutputTokens          int   `json:"output_tokens"`
	ThinkingBytes         int   `json:"thinking_bytes"`
	LoadDurationNS        int64 `json:"load_duration_ns"`
	PromptDurationNS      int64 `json:"prompt_duration_ns"`
	OutputDurationNS      int64 `json:"output_duration_ns"`
	UnaccountedDurationNS int64 `json:"unaccounted_duration_ns"`
	TotalDurationNS       int64 `json:"total_duration_ns"`
	WallDurationNS        int64 `json:"wall_duration_ns"`
	ModelBytes            int64 `json:"model_bytes,omitempty"`
	ModelVRAMBytes        int64 `json:"model_vram_bytes,omitempty"`
	LoadedContextTokens   int   `json:"loaded_context_tokens,omitempty"`
}

func (m OllamaRequestMetrics) Validate() error {
	if m.RequestBytes <= 0 || m.PromptTokens <= 0 || m.OutputTokens <= 0 || m.ThinkingBytes < 0 ||
		m.LoadDurationNS < 0 || m.PromptDurationNS < 0 || m.OutputDurationNS < 0 || m.UnaccountedDurationNS < 0 || m.TotalDurationNS <= 0 || m.WallDurationNS < 0 ||
		m.ModelBytes < 0 || m.ModelVRAMBytes < 0 || m.LoadedContextTokens < 0 ||
		(m.ModelBytes > 0 && m.ModelVRAMBytes > m.ModelBytes) {
		return errors.New("invalid Ollama request metrics")
	}
	return nil
}

func (a *ollamaAdapter) ReviewMetrics() []OllamaRequestMetrics {
	a.metricsMu.Lock()
	defer a.metricsMu.Unlock()
	return append([]OllamaRequestMetrics(nil), a.metrics...)
}

func buildOllamaChatRequest(cfg Config, snapshot ReviewSnapshot, reasoning string) (ollamaChatRequest, []byte, int, error) {
	prompt, err := os.ReadFile(filepath.Join(providerShareRoot(), "review-prompt.md"))
	if err != nil {
		return ollamaChatRequest{}, nil, 0, err
	}
	schema, err := os.ReadFile(filepath.Join(providerShareRoot(), "verdict.schema.json"))
	if err != nil {
		return ollamaChatRequest{}, nil, 0, err
	}
	if err := brief.ValidateVerdictSchema(schema); err != nil {
		return ollamaChatRequest{}, nil, 0, fmt.Errorf("invalid verdict schema: %w", err)
	}
	schema, err = ollamaVerdictSchemaForSnapshot(schema, snapshot)
	if err != nil {
		return ollamaChatRequest{}, nil, 0, err
	}
	snapshotRaw, err := CanonicalJSON(snapshot)
	if err != nil {
		return ollamaChatRequest{}, nil, 0, err
	}
	provider := cfg.Providers.Ollama
	generationLimit := ollamaGenerationLimit(reasoning)
	thinkValue, err := ollamaThinkValue(reasoning)
	if err != nil {
		return ollamaChatRequest{}, nil, 0, err
	}
	requestKeepAlive := cfg.OllamaKeepAliveSeconds()
	if requestKeepAlive == 0 {
		// Keep the model visible just long enough for the mandatory /api/ps
		// context check, then explicitly unload it at the end of the gate.
		requestKeepAlive = 1
	}
	request := ollamaChatRequest{
		Model:    provider.Model,
		Messages: []ollamaMessage{{Role: "system", Content: string(prompt)}, {Role: "user", Content: string(snapshotRaw)}},
		Stream:   false, Format: json.RawMessage(schema), Think: thinkValue, Truncate: false, Shift: false,
		KeepAlive: fmt.Sprintf("%ds", requestKeepAlive),
		Options:   map[string]any{"temperature": 0, "seed": 0, "num_ctx": provider.ContextTokens, "num_predict": generationLimit},
	}
	raw, err := CanonicalJSON(request)
	return request, raw, generationLimit, err
}

// ollamaVerdictSchemaForSnapshot turns the static verdict shape into the exact
// guidance contract for this request. Prompt instructions alone were not
// sufficient for qwen3:14b: with no guidance targets it still invented a
// human-readable finding ID. An exact empty-array enum plus maxItems:0 makes
// that output impossible in Ollama's structured-output grammar. For non-empty
// target sets, an exact item count and an ID enum reduce the model's choices
// while the review boundary continues to enforce uniqueness, completeness, and
// anchor binding itself.
func ollamaVerdictSchemaForSnapshot(raw []byte, snapshot ReviewSnapshot) ([]byte, error) {
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("decode verdict schema for guidance binding: %w", err)
	}
	properties, ok := root["properties"].(map[string]any)
	if !ok {
		return nil, errors.New("verdict schema has no properties for guidance binding")
	}
	guidance, ok := properties["guidance"].(map[string]any)
	if !ok {
		return nil, errors.New("verdict schema has no guidance array for binding")
	}
	items, ok := guidance["items"].(map[string]any)
	if !ok {
		return nil, errors.New("verdict schema has no guidance item schema for binding")
	}
	itemProperties, ok := items["properties"].(map[string]any)
	if !ok {
		return nil, errors.New("verdict schema guidance items have no properties for binding")
	}
	findingID, ok := itemProperties["finding_id"].(map[string]any)
	if !ok {
		return nil, errors.New("verdict schema guidance items have no finding ID for binding")
	}

	count := len(snapshot.GuidanceTargets)
	guidance["minItems"] = count
	guidance["maxItems"] = count
	if count == 0 {
		guidance["enum"] = []any{[]any{}}
		delete(findingID, "enum")
	} else {
		delete(guidance, "enum")
		ids := make([]string, 0, count)
		seen := make(map[string]bool, count)
		for _, target := range snapshot.GuidanceTargets {
			if !validHexDigest(target.FindingID) || seen[target.FindingID] {
				return nil, errors.New("cannot bind Ollama schema to invalid guidance targets")
			}
			seen[target.FindingID] = true
			ids = append(ids, target.FindingID)
		}
		findingID["enum"] = ids
	}
	bound, err := CanonicalJSON(root)
	if err != nil {
		return nil, fmt.Errorf("encode target-bound Ollama verdict schema: %w", err)
	}
	if err := brief.ValidateVerdictSchema(bound); err != nil {
		return nil, fmt.Errorf("invalid target-bound Ollama verdict schema: %w", err)
	}
	return bound, nil
}

func ollamaThinkValue(reasoning string) (json.RawMessage, error) {
	switch reasoning {
	case "on":
		return json.RawMessage("true"), nil
	case "off":
		return json.RawMessage("false"), nil
	case "low", "medium", "high":
		return json.RawMessage(strconv.Quote(reasoning)), nil
	default:
		return nil, errors.New("unsupported effective Ollama reasoning level")
	}
}

func ollamaContextOutputReserve(_ int, reasoning string) int {
	return ollamaGenerationLimit(reasoning)
}

func ollamaGenerationLimit(reasoning string) int {
	if reasoning == "off" {
		return ollamaPlainGenerationCap
	}
	return ollamaThinkingGenerationCap
}

func ollamaInputByteCeiling(contextTokens int, reasoning string) int {
	// This provisional tokenizer-independent floor is checked against the exact
	// model during doctor. truncate:false, shift:false and post-response token
	// accounting remain independent fail-closed layers.
	availableTokens := contextTokens - ollamaContextOutputReserve(contextTokens, reasoning) - ollamaTemplateReserveTokens
	return int(float64(availableTokens) * ollamaBytesPerTokenFloor)
}

func ollamaMinimumObservedBytesPerToken() float64 {
	return ollamaBytesPerTokenFloor * (1 + ollamaBytesPerTokenMargin)
}

// VerifyTruncationRefusal establishes behavior rather than trusting the request
// fields. The prompt is intentionally much larger than a cheap 1k context. Only
// a context-specific 400 response proves that truncate:false and shift:false
// were honored; a successful answer, network error, or unrelated daemon error
// leaves the adapter policy unverified.
func (a *ollamaAdapter) VerifyTruncationRefusal(parent context.Context) (ProviderMetadata, error) {
	ctx, cancel := context.WithTimeout(parent, time.Duration(a.provider.TimeoutSeconds)*time.Second)
	defer cancel()
	lock, err := acquireOllamaLock(ctx, a.lockPath)
	if err != nil {
		return ProviderMetadata{}, err
	}
	defer lock.Close()

	before, err := a.describe(ctx)
	if err != nil {
		return ProviderMetadata{}, err
	}
	request := ollamaChatRequest{
		Model:    a.provider.Model,
		Messages: []ollamaMessage{{Role: "user", Content: strings.Repeat("0123456789abcdef ", 4096)}},
		Stream:   false, Think: json.RawMessage("false"), Truncate: false, Shift: false, KeepAlive: "0s",
		Options: map[string]any{"temperature": 0, "seed": 0, "num_ctx": ollamaTruncationProbeTokens, "num_predict": 1},
	}
	raw, err := CanonicalJSON(request)
	if err != nil {
		return ProviderMetadata{}, err
	}
	var response json.RawMessage
	err = a.postRawJSON(ctx, "/api/chat", raw, &response, ollamaHTTPResponseBytes)
	if err == nil {
		return ProviderMetadata{}, errors.New("Ollama accepted an over-context request despite truncate:false and shift:false")
	}
	if !isOllamaContextRefusal(err) {
		return ProviderMetadata{}, fmt.Errorf("Ollama did not return the required context-limit refusal: %w", err)
	}
	if err := a.unload(ctx); err != nil {
		return ProviderMetadata{}, fmt.Errorf("Ollama truncation probe passed but model unload failed: %w", err)
	}
	after, err := a.describe(ctx)
	if err != nil {
		return ProviderMetadata{}, err
	}
	if ollamaMetadataWithTruncationPolicy(before.metadata, false) != ollamaMetadataWithTruncationPolicy(after.metadata, false) {
		return ProviderMetadata{}, errors.New("Ollama model or runtime identity changed during truncation probe")
	}
	a.policyMu.Lock()
	a.truncationRefused = true
	a.policyMu.Unlock()
	return ollamaMetadataWithTruncationPolicy(after.metadata, true), nil
}

type ollamaReviewOutcome struct {
	verdict    *Verdict
	diagnostic LLMProviderReviewDiagnostic
	metrics    OllamaRequestMetrics
}

func (a *ollamaAdapter) Review(parent context.Context, snapshot ReviewSnapshot) (Verdict, error) {
	outcome, err := a.review(parent, snapshot, false)
	if err != nil {
		return Verdict{}, err
	}
	if outcome.verdict == nil {
		return Verdict{}, errors.New("Ollama review omitted a validated verdict")
	}
	return *outcome.verdict, nil
}

func (a *ollamaAdapter) DiagnoseReview(parent context.Context, snapshot ReviewSnapshot) (*Verdict, LLMProviderReviewDiagnostic, []OllamaRequestMetrics, error) {
	outcome, err := a.review(parent, snapshot, true)
	if err != nil {
		return nil, LLMProviderReviewDiagnostic{}, nil, err
	}
	return outcome.verdict, outcome.diagnostic, []OllamaRequestMetrics{outcome.metrics}, nil
}

func (a *ollamaAdapter) review(parent context.Context, snapshot ReviewSnapshot, diagnostic bool) (outcome ollamaReviewOutcome, resultErr error) {
	ctx, cancel := context.WithTimeout(parent, time.Duration(a.provider.TimeoutSeconds)*time.Second)
	defer cancel()
	lock, err := acquireOllamaLock(ctx, a.lockPath)
	if err != nil {
		return ollamaReviewOutcome{}, err
	}
	defer lock.Close()

	description, err := a.describe(ctx)
	if err != nil {
		return ollamaReviewOutcome{}, err
	}
	keepAlive := a.cfg.OllamaKeepAliveSeconds()
	_, requestRaw, generationLimit, err := buildOllamaChatRequest(a.cfg, snapshot, description.metadata.Effort)
	if err != nil {
		return ollamaReviewOutcome{}, err
	}
	ceiling := ollamaInputByteCeiling(a.provider.ContextTokens, description.metadata.Effort)
	if ceiling <= 0 || len(requestRaw) > ceiling {
		return ollamaReviewOutcome{}, fmt.Errorf("Ollama request is %d bytes, above the context-derived input ceiling of %d", len(requestRaw), ceiling)
	}

	unload := snapshot.BatchIndex == snapshot.BatchCount-1 && (snapshot.Phase == "post" || snapshot.Phase == "artifact" || keepAlive == 0 ||
		(snapshot.Phase == "pre" && !a.cfg.ReviewPhaseEnabled("post")))
	if unload {
		defer func() {
			// An operator interrupt owns the teardown path. Do not turn a
			// cancelled chat into another independent HTTP operation that keeps
			// Prolewatch attached to the terminal for up to the metadata timeout.
			// Ollama will retire the cancelled runner according to keep_alive.
			if parent.Err() != nil {
				return
			}
			unloadCtx, unloadCancel := context.WithTimeout(context.Background(), ollamaMetadataProbeTimeout)
			defer unloadCancel()
			if err := a.unload(unloadCtx); err != nil && resultErr == nil {
				resultErr = fmt.Errorf("Ollama review completed but model unload failed: %w", err)
			}
		}()
	}
	var response ollamaChatResponse
	started := time.Now()
	if err := a.postRawJSON(ctx, "/api/chat", requestRaw, &response, ollamaHTTPResponseBytes); err != nil {
		return ollamaReviewOutcome{}, fmt.Errorf("Ollama chat request failed: %w", err)
	}
	wallDuration := time.Since(started)
	unaccounted := ollamaUnaccountedDuration(response.TotalDuration, response.LoadDuration, response.PromptEvalDuration, response.EvalDuration)
	metrics := OllamaRequestMetrics{RequestBytes: len(requestRaw), PromptTokens: response.PromptEvalCount, OutputTokens: response.EvalCount,
		ThinkingBytes: len(response.Message.Thinking), LoadDurationNS: response.LoadDuration, PromptDurationNS: response.PromptEvalDuration,
		OutputDurationNS: response.EvalDuration, UnaccountedDurationNS: unaccounted, TotalDurationNS: response.TotalDuration, WallDurationNS: int64(wallDuration)}
	if response.DoneReason == "length" {
		return ollamaReviewOutcome{}, fmt.Errorf("Ollama exhausted the %d-token generation limit before completing a verdict", generationLimit)
	}
	if !response.Done {
		if response.EvalCount == 0 && response.Message.Content == "" {
			return ollamaReviewOutcome{}, fmt.Errorf("Ollama model produced no response with reasoning=%s and the active format schema", description.metadata.Effort)
		}
		return ollamaReviewOutcome{}, fmt.Errorf("Ollama returned an incomplete response (done=%t reason=%q)", response.Done, response.DoneReason)
	}
	if response.EvalCount == 0 && response.Message.Content == "" {
		return ollamaReviewOutcome{}, fmt.Errorf("Ollama model produced no response with reasoning=%s and the active format schema", description.metadata.Effort)
	}
	if err := metrics.Validate(); err != nil {
		return ollamaReviewOutcome{}, err
	}
	if !description.modelNames[response.Model] || response.RemoteHost != "" || response.RemoteModel != "" {
		return ollamaReviewOutcome{}, errors.New("Ollama response came from an unexpected or remote model")
	}
	if response.Message.Role != "assistant" || len(response.Message.ToolCalls) != 0 {
		return ollamaReviewOutcome{}, errors.New("Ollama response used an unexpected role or tool call")
	}
	if response.EvalCount <= 0 || response.EvalCount > generationLimit {
		return ollamaReviewOutcome{}, fmt.Errorf("Ollama reported %d output tokens outside the 1..%d generation limit", response.EvalCount, generationLimit)
	}
	contextReserve := ollamaContextOutputReserve(a.provider.ContextTokens, description.metadata.Effort)
	if response.PromptEvalCount <= 0 || response.PromptEvalCount > a.provider.ContextTokens-contextReserve ||
		response.PromptEvalCount+response.EvalCount > a.provider.ContextTokens {
		return ollamaReviewOutcome{}, fmt.Errorf("Ollama token accounting exceeds the configured context with its %d-token output reserve", contextReserve)
	}
	outcome.metrics = metrics
	var verdict Verdict
	if err := DecodeStrict([]byte(response.Message.Content), &verdict); err != nil {
		if diagnostic {
			outcome.diagnostic = LLMProviderReviewDiagnostic{
				ResponseShape: responseShape(nil, true, false),
				Validation: LLMQualityDiagnosticValidation{Passed: false, Stage: llmDiagnosticStageResponseDecode,
					Issues: []LLMQualityDiagnosticIssue{diagnosticIssue("$", "invalid_json")}},
			}
			return outcome, nil
		}
		return ollamaReviewOutcome{}, fmt.Errorf("invalid Ollama verdict: %w", err)
	}
	if err := verdict.Validate(); err != nil {
		if diagnostic {
			outcome.diagnostic = LLMProviderReviewDiagnostic{ResponseShape: responseShape(&verdict, true, true), Validation: diagnoseVerdict(verdict, snapshot)}
			return outcome, nil
		}
		return ollamaReviewOutcome{}, err
	}
	if diagnostic {
		outcome.diagnostic = LLMProviderReviewDiagnostic{ResponseShape: responseShape(&verdict, true, true), Validation: diagnoseVerdict(verdict, snapshot)}
		if !outcome.diagnostic.Validation.Passed {
			return outcome, nil
		}
	}
	residency, err := a.verifyLoadedModel(ctx, description.metadata)
	if err != nil {
		return ollamaReviewOutcome{}, err
	}
	metrics.ModelBytes = residency.ModelBytes
	metrics.ModelVRAMBytes = residency.ModelVRAMBytes
	metrics.LoadedContextTokens = residency.ContextTokens
	a.metricsMu.Lock()
	a.metrics = append(a.metrics, metrics)
	a.metricsMu.Unlock()
	after, err := a.describe(ctx)
	if err != nil {
		return ollamaReviewOutcome{}, err
	}
	if after.metadata != description.metadata {
		return ollamaReviewOutcome{}, errors.New("Ollama model or runtime identity changed during review")
	}
	outcome.verdict = &verdict
	if diagnostic && outcome.diagnostic.Validation.Issues == nil {
		outcome.diagnostic = LLMProviderReviewDiagnostic{ResponseShape: responseShape(&verdict, true, true), Validation: diagnoseVerdict(verdict, snapshot)}
	}
	return outcome, nil
}

func ollamaUnaccountedDuration(total, load, prefill, output int64) int64 {
	remaining := total
	for _, part := range []int64{load, prefill, output} {
		if part < 0 || part >= remaining {
			return 0
		}
		remaining -= part
	}
	return remaining
}

type ollamaResidency struct {
	ModelBytes     int64
	ModelVRAMBytes int64
	ContextTokens  int
}

func (a *ollamaAdapter) verifyLoadedModel(ctx context.Context, metadata ProviderMetadata) (ollamaResidency, error) {
	var running struct {
		Models []struct {
			Name          string `json:"name"`
			Model         string `json:"model"`
			Digest        string `json:"digest"`
			ContextLength int    `json:"context_length"`
			Size          int64  `json:"size"`
			SizeVRAM      int64  `json:"size_vram"`
		} `json:"models"`
	}
	if err := a.getJSON(ctx, "/api/ps", &running, ollamaHTTPResponseBytes); err != nil {
		return ollamaResidency{}, fmt.Errorf("cannot verify loaded Ollama model: %w", err)
	}
	for _, model := range running.Models {
		digest, err := canonicalOllamaDigest(model.Digest)
		if err == nil && digest == metadata.ModelDigest && (model.Name == metadata.Model || model.Model == metadata.Model) {
			if model.ContextLength < metadata.ContextTokens {
				return ollamaResidency{}, fmt.Errorf("loaded Ollama context is %d, below configured %d; use OLLAMA_NUM_PARALLEL=1", model.ContextLength, metadata.ContextTokens)
			}
			// Residency is benchmark context, not a review safety boundary. Older
			// daemons may omit these optional counters, and an inconsistent pair
			// must not turn an otherwise verified review into a provider failure.
			if model.Size <= 0 || model.SizeVRAM < 0 || model.SizeVRAM > model.Size {
				model.Size, model.SizeVRAM = 0, 0
			}
			return ollamaResidency{ModelBytes: model.Size, ModelVRAMBytes: model.SizeVRAM, ContextTokens: model.ContextLength}, nil
		}
	}
	return ollamaResidency{}, errors.New("configured Ollama model is not present in /api/ps with the attested digest")
}

func (a *ollamaAdapter) unload(ctx context.Context) error {
	var response struct {
		Done bool `json:"done"`
	}
	request := map[string]any{"model": a.provider.Model, "keep_alive": 0, "stream": false}
	if err := a.postJSON(ctx, "/api/generate", request, &response, 256*1024); err != nil {
		return err
	}
	if !response.Done {
		return errors.New("Ollama did not confirm model unload")
	}
	return nil
}

// resetModel gives semantic quality cases a fresh runner and prompt cache. A
// fixed seed and greedy sampling do not make an attestation meaningful if the
// same request changes verdict after unrelated earlier prompts. The endpoint
// lock also prevents this diagnostic reset from unloading a concurrent review.
func (a *ollamaAdapter) resetModel(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, ollamaMetadataProbeTimeout)
	defer cancel()
	lock, err := acquireOllamaLock(ctx, a.lockPath)
	if err != nil {
		return err
	}
	defer lock.Close()
	return a.unload(ctx)
}

func acquireOllamaLock(ctx context.Context, path string) (*os.File, error) {
	if err := EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	failed := true
	defer func() {
		if failed {
			file.Close()
		}
	}()
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 || stat.Mode&0o077 != 0 {
		return nil, fmt.Errorf("unsafe Ollama lock file: %s", path)
	}
	ticker := time.NewTicker(ollamaLockRetryInterval)
	defer ticker.Stop()
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			failed = false
			return file, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (a *ollamaAdapter) getJSON(ctx context.Context, path string, output any, limit int64) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, a.endpoint+path, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	return a.doJSON(request, output, limit)
}

func (a *ollamaAdapter) postJSON(ctx context.Context, path string, input, output any, limit int64) error {
	raw, err := CanonicalJSON(input)
	if err != nil {
		return err
	}
	return a.postRawJSON(ctx, path, raw, output, limit)
}

func (a *ollamaAdapter) postRawJSON(ctx context.Context, path string, raw []byte, output any, limit int64) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	return a.doJSON(request, output, limit)
}

type ollamaHTTPStatusError struct {
	StatusCode int
	Body       string
}

func (e *ollamaHTTPStatusError) Error() string {
	return fmt.Sprintf("Ollama API returned HTTP %d: %s", e.StatusCode, truncate(e.Body, 1024))
}

func isOllamaContextRefusal(err error) bool {
	var status *ollamaHTTPStatusError
	if !errors.As(err, &status) || status.StatusCode != http.StatusBadRequest {
		return false
	}
	detail := strings.ToLower(status.Body)
	return strings.Contains(detail, "context") && (strings.Contains(detail, "exceed") || strings.Contains(detail, "too long") || strings.Contains(detail, "too large"))
}

func (a *ollamaAdapter) doJSON(request *http.Request, output any, limit int64) error {
	response, err := a.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > limit {
		return errors.New("Ollama API response exceeds hard size limit")
	}
	if response.StatusCode != http.StatusOK {
		return &ollamaHTTPStatusError{StatusCode: response.StatusCode, Body: string(raw)}
	}
	if contentType := response.Header.Get("Content-Type"); contentType != "" && !strings.HasPrefix(strings.ToLower(contentType), "application/json") {
		return fmt.Errorf("Ollama API returned unexpected content type %q", contentType)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("Ollama API returned multiple JSON values")
	}
	return nil
}
