package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/safe"
)

const LLMQualityDiagnosticSchemaVersion = 1

const (
	llmDiagnosticStageModelReset         = "model-reset"
	llmDiagnosticStageProviderRequest    = "provider-request"
	llmDiagnosticStageResponseDecode     = "response-decode"
	llmDiagnosticStageVerdictValidation  = "verdict-validation"
	llmDiagnosticStageGuidanceBinding    = "guidance-binding"
	llmDiagnosticStageQualityExpectation = "quality-expectation"
)

var diagnosticIssuePathRE = regexp.MustCompile(`^(?:\$|schema_version|verdict|confidence|summary|findings|guidance|coverage_notes|guidance\[[0-9]+\]\.(?:finding_id|assessment|comment|anchor_quote)|findings\[[0-9]+\]\.(?:severity|category|file|line|evidence|rationale)|coverage_notes\[[0-9]+\])$`)

// LLMQualityDiagnosticReport is deliberately an allowlist. In particular, it
// has nowhere to store model-authored prose, file names, anchors, raw provider
// responses, or local error text. The report is intended to be safe to paste
// into an issue when diagnosing a local Ollama quality case.
type LLMQualityDiagnosticReport struct {
	SchemaVersion            int                                 `json:"schema_version"`
	Case                     LLMQualityDiagnosticCase            `json:"case"`
	Provider                 *LLMBenchmarkProvider               `json:"provider,omitempty"`
	RequestContract          LLMQualityDiagnosticRequestContract `json:"request_contract"`
	ResponseShape            LLMQualityDiagnosticResponseShape   `json:"response_shape"`
	Metrics                  []LLMBenchmarkRequest               `json:"metrics"`
	Validation               LLMQualityDiagnosticValidation      `json:"validation"`
	QualityExpectationPassed bool                                `json:"quality_expectation_passed"`
	DurationMilliseconds     int64                               `json:"duration_ms"`
}

type LLMQualityDiagnosticCase struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Phase string `json:"phase"`
}

type LLMQualityDiagnosticRequestContract struct {
	DeterministicFindingCount int `json:"deterministic_finding_count"`
	GuidanceTargetCount       int `json:"guidance_target_count"`
}

type LLMQualityDiagnosticResponseShape struct {
	Received                bool   `json:"received"`
	Decoded                 bool   `json:"decoded"`
	VerdictEnum             string `json:"verdict_enum"`
	ConfidenceEnum          string `json:"confidence_enum"`
	PromptInjectionDetected bool   `json:"prompt_injection_detected"`
	FindingCount            int    `json:"finding_count"`
	GuidanceCount           int    `json:"guidance_count"`
	CoverageNoteCount       int    `json:"coverage_note_count"`
}

type LLMQualityDiagnosticValidation struct {
	Passed bool                        `json:"passed"`
	Stage  string                      `json:"stage"`
	Issues []LLMQualityDiagnosticIssue `json:"issues"`
}

// Every string in an issue is selected locally from a closed vocabulary.
// Numeric details make common shape errors actionable without echoing values.
type LLMQualityDiagnosticIssue struct {
	Path          string `json:"path"`
	Code          string `json:"code"`
	Index         *int   `json:"index,omitempty"`
	ActualCount   *int   `json:"actual_count,omitempty"`
	ExpectedCount *int   `json:"expected_count,omitempty"`
	Bytes         *int   `json:"bytes,omitempty"`
	Limit         *int   `json:"limit,omitempty"`
	IDShape       string `json:"id_shape,omitempty"`
}

// LLMProviderReviewDiagnostic is the redacted part of the private dispatcher
// response. A valid verdict travels in DispatchResponse.Verdict as usual; an
// invalid verdict is replaced entirely by this description.
type LLMProviderReviewDiagnostic struct {
	ResponseShape LLMQualityDiagnosticResponseShape `json:"response_shape"`
	Validation    LLMQualityDiagnosticValidation    `json:"validation"`
}

type ollamaDiagnosticReviewer interface {
	DiagnoseReview(context.Context, ReviewSnapshot) (*Verdict, LLMProviderReviewDiagnostic, []OllamaRequestMetrics, error)
}

func responseShape(verdict *Verdict, received, decoded bool) LLMQualityDiagnosticResponseShape {
	shape := LLMQualityDiagnosticResponseShape{
		Received: received, Decoded: decoded, VerdictEnum: "unavailable", ConfidenceEnum: "unavailable",
	}
	if !decoded || verdict == nil {
		return shape
	}
	shape.VerdictEnum = closedVerdictEnum(verdict.Verdict)
	shape.ConfidenceEnum = closedConfidenceEnum(verdict.Confidence)
	shape.PromptInjectionDetected = verdict.PromptInjectionDetected
	shape.FindingCount = len(verdict.Findings)
	shape.GuidanceCount = len(verdict.Guidance)
	shape.CoverageNoteCount = len(verdict.CoverageNotes)
	return shape
}

func closedVerdictEnum(value string) string {
	if value == "allow" || value == "block" {
		return value
	}
	return "invalid"
}

func closedConfidenceEnum(value string) string {
	if value == "low" || value == "medium" || value == "high" {
		return value
	}
	return "invalid"
}

func diagnosticIntPointer(value int) *int { return &value }

func diagnosticIssue(path, code string) LLMQualityDiagnosticIssue {
	return LLMQualityDiagnosticIssue{Path: path, Code: code}
}

func findingIDShape(value string) string {
	switch {
	case value == "":
		return "empty"
	case safe.ValidHexDigest(value):
		return "lower-hex-64"
	case len(value) != 64:
		return "wrong-length"
	default:
		return "non-lower-hex"
	}
}

// diagnoseVerdict mirrors Verdict.Validate and then adds the bindings that the
// parent Reviewer normally enforces. It reports only locally selected paths and
// codes, never the rejected values.
func diagnoseVerdict(verdict Verdict, snapshot ReviewSnapshot) LLMQualityDiagnosticValidation {
	shapeIssues := diagnoseVerdictShape(verdict)
	bindingIssues := diagnoseVerdictBindings(verdict, snapshot)
	issues := append(shapeIssues, bindingIssues...)
	stage := llmDiagnosticStageVerdictValidation
	if len(shapeIssues) == 0 {
		stage = llmDiagnosticStageGuidanceBinding
	}
	if len(issues) == 0 {
		return LLMQualityDiagnosticValidation{Passed: true, Stage: llmDiagnosticStageQualityExpectation, Issues: []LLMQualityDiagnosticIssue{}}
	}
	return LLMQualityDiagnosticValidation{Passed: false, Stage: stage, Issues: issues}
}

func diagnoseVerdictShape(verdict Verdict) []LLMQualityDiagnosticIssue {
	issues := []LLMQualityDiagnosticIssue{}
	if verdict.SchemaVersion != VerdictSchemaVersion {
		issues = append(issues, diagnosticIssue("schema_version", "unexpected_value"))
	}
	if verdict.Verdict != "allow" && verdict.Verdict != "block" {
		issues = append(issues, diagnosticIssue("verdict", "invalid_enum"))
	}
	if verdict.Confidence != "low" && verdict.Confidence != "medium" && verdict.Confidence != "high" {
		issues = append(issues, diagnosticIssue("confidence", "invalid_enum"))
	}
	if verdict.Summary == "" {
		issues = append(issues, diagnosticIssue("summary", "empty"))
	} else if len(verdict.Summary) > 2000 {
		issue := diagnosticIssue("summary", "too_long")
		issue.Bytes, issue.Limit = diagnosticIntPointer(len(verdict.Summary)), diagnosticIntPointer(2000)
		issues = append(issues, issue)
	}
	issues = append(issues, diagnoseArray("findings", verdict.Findings == nil, len(verdict.Findings), 200)...)
	issues = append(issues, diagnoseArray("guidance", verdict.Guidance == nil, len(verdict.Guidance), findingGuidanceLimit)...)
	issues = append(issues, diagnoseArray("coverage_notes", verdict.CoverageNotes == nil, len(verdict.CoverageNotes), 100)...)

	seenGuidance := map[string]bool{}
	for index, guidance := range verdict.Guidance {
		base := fmt.Sprintf("guidance[%d]", index)
		if !safe.ValidHexDigest(guidance.FindingID) {
			issue := diagnosticIssue(base+".finding_id", "invalid_id")
			issue.Index, issue.IDShape = diagnosticIntPointer(index), findingIDShape(guidance.FindingID)
			issues = append(issues, issue)
		} else if seenGuidance[guidance.FindingID] {
			issue := diagnosticIssue(base+".finding_id", "duplicate_id")
			issue.Index, issue.IDShape = diagnosticIntPointer(index), "lower-hex-64"
			issues = append(issues, issue)
		}
		seenGuidance[guidance.FindingID] = true
		if guidance.Assessment != "likely-benign" && guidance.Assessment != "unclear" && guidance.Assessment != "concerning" {
			issue := diagnosticIssue(base+".assessment", "invalid_enum")
			issue.Index = diagnosticIntPointer(index)
			issues = append(issues, issue)
		}
		issues = append(issues, diagnoseText(base+".comment", index, guidance.Comment, 1000)...)
		issues = append(issues, diagnoseText(base+".anchor_quote", index, guidance.AnchorQuote, findingGuidanceTextLimit)...)
	}
	for index, finding := range verdict.Findings {
		base := fmt.Sprintf("findings[%d]", index)
		if !brief.ValidSeverity(finding.Severity) {
			issues = append(issues, indexedIssue(base+".severity", "invalid_enum", index))
		}
		if !brief.ValidCategory(finding.Category) {
			issues = append(issues, indexedIssue(base+".category", "invalid_enum", index))
		}
		if finding.Rationale == "" {
			issues = append(issues, indexedIssue(base+".rationale", "empty", index))
		}
		issues = append(issues, diagnoseBoundedText(base+".file", index, finding.File, 4096, false)...)
		issues = append(issues, diagnoseBoundedText(base+".evidence", index, finding.Evidence, 1000, false)...)
		issues = append(issues, diagnoseBoundedText(base+".rationale", index, finding.Rationale, 2000, false)...)
		if finding.Line != nil && *finding.Line < 1 {
			issues = append(issues, indexedIssue(base+".line", "below_minimum", index))
		}
	}
	for index, note := range verdict.CoverageNotes {
		issues = append(issues, diagnoseBoundedText(fmt.Sprintf("coverage_notes[%d]", index), index, note, 1000, false)...)
	}
	return issues
}

func diagnoseArray(path string, isNil bool, count, limit int) []LLMQualityDiagnosticIssue {
	issues := []LLMQualityDiagnosticIssue{}
	if isNil {
		issues = append(issues, diagnosticIssue(path, "null_array"))
	}
	if count > limit {
		issue := diagnosticIssue(path, "too_many_items")
		issue.ActualCount, issue.Limit = diagnosticIntPointer(count), diagnosticIntPointer(limit)
		issues = append(issues, issue)
	}
	return issues
}

func diagnoseText(path string, index int, value string, limit int) []LLMQualityDiagnosticIssue {
	return diagnoseBoundedText(path, index, value, limit, true)
}

func diagnoseBoundedText(path string, index int, value string, limit int, requireNonempty bool) []LLMQualityDiagnosticIssue {
	if requireNonempty && value == "" {
		return []LLMQualityDiagnosticIssue{indexedIssue(path, "empty", index)}
	}
	if len(value) <= limit {
		return nil
	}
	issue := indexedIssue(path, "too_long", index)
	issue.Bytes, issue.Limit = diagnosticIntPointer(len(value)), diagnosticIntPointer(limit)
	return []LLMQualityDiagnosticIssue{issue}
}

func indexedIssue(path, code string, index int) LLMQualityDiagnosticIssue {
	issue := diagnosticIssue(path, code)
	issue.Index = diagnosticIntPointer(index)
	return issue
}

func diagnoseVerdictBindings(verdict Verdict, snapshot ReviewSnapshot) []LLMQualityDiagnosticIssue {
	issues := []LLMQualityDiagnosticIssue{}
	targets := map[string]string{}
	for _, target := range snapshot.GuidanceTargets {
		targets[target.FindingID] = target.AnchorText
	}
	if len(targets) == 0 && len(verdict.Guidance) != 0 {
		issue := diagnosticIssue("guidance", "unexpected_items")
		issue.ActualCount, issue.ExpectedCount = diagnosticIntPointer(len(verdict.Guidance)), diagnosticIntPointer(0)
		issues = append(issues, issue)
	}
	seen := map[string]bool{}
	for index, guidance := range verdict.Guidance {
		expectedAnchor, ok := targets[guidance.FindingID]
		if !ok {
			issue := indexedIssue(fmt.Sprintf("guidance[%d].finding_id", index), "unknown_id", index)
			issue.IDShape = findingIDShape(guidance.FindingID)
			issues = append(issues, issue)
			continue
		}
		seen[guidance.FindingID] = true
		if guidance.AnchorQuote != expectedAnchor {
			issues = append(issues, indexedIssue(fmt.Sprintf("guidance[%d].anchor_quote", index), "anchor_mismatch", index))
		}
	}
	if len(seen) != len(targets) {
		issue := diagnosticIssue("guidance", "missing_targets")
		issue.ActualCount, issue.ExpectedCount = diagnosticIntPointer(len(seen)), diagnosticIntPointer(len(targets))
		issues = append(issues, issue)
	}
	allowedFiles := map[string]bool{"<none>": true}
	for _, file := range snapshot.Files {
		allowedFiles[file.File] = true
	}
	for index, finding := range verdict.Findings {
		if !allowedFiles[finding.File] {
			issues = append(issues, indexedIssue(fmt.Sprintf("findings[%d].file", index), "unknown_file", index))
		}
	}
	return issues
}

func validateProviderReviewDiagnostic(diagnostic LLMProviderReviewDiagnostic, verdict *Verdict) error {
	shape := diagnostic.ResponseShape
	validVerdicts := map[string]bool{"unavailable": true, "invalid": true, "allow": true, "block": true}
	validConfidence := map[string]bool{"unavailable": true, "invalid": true, "low": true, "medium": true, "high": true}
	if !shape.Received || !validVerdicts[shape.VerdictEnum] || !validConfidence[shape.ConfidenceEnum] ||
		shape.FindingCount < 0 || shape.GuidanceCount < 0 || shape.CoverageNoteCount < 0 {
		return errors.New("invalid provider diagnostic response shape")
	}
	validation := diagnostic.Validation
	if validation.Issues == nil {
		return errors.New("provider diagnostic omitted issues")
	}
	if validation.Passed {
		if !shape.Decoded || verdict == nil || len(validation.Issues) != 0 || validation.Stage != llmDiagnosticStageQualityExpectation {
			return errors.New("provider diagnostic omitted validated verdict")
		}
		if err := verdict.Validate(); err != nil {
			return err
		}
		if responseShape(verdict, true, true) != shape {
			return errors.New("provider diagnostic response shape does not match verdict")
		}
		return nil
	}
	if verdict != nil || len(validation.Issues) == 0 {
		return errors.New("failed provider diagnostic included a verdict or omitted issues")
	}
	if !shape.Decoded && validation.Stage != llmDiagnosticStageResponseDecode {
		return errors.New("provider diagnostic decode stage mismatch")
	}
	if shape.Decoded && validation.Stage != llmDiagnosticStageVerdictValidation && validation.Stage != llmDiagnosticStageGuidanceBinding {
		return errors.New("provider diagnostic validation stage mismatch")
	}
	return validateDiagnosticIssues(validation.Issues)
}

func (r *Reviewer) DiagnoseReview(ctx context.Context, packageBase, phase string, inventory *brief.Inventory) (ProviderMetadata, LLMQualityDiagnosticRequestContract, *Verdict, LLMProviderReviewDiagnostic, []OllamaRequestMetrics, error) {
	if r.Config.Provider != "ollama" {
		return ProviderMetadata{}, LLMQualityDiagnosticRequestContract{}, nil, LLMProviderReviewDiagnostic{}, nil, errors.New("diagnostic review requires Ollama")
	}
	probe, err := r.dispatch(ctx, DispatchRequest{ProtocolVersion: DispatchProtocolVersion, Operation: "probe"})
	if err != nil {
		return ProviderMetadata{}, LLMQualityDiagnosticRequestContract{}, nil, LLMProviderReviewDiagnostic{}, nil, err
	}
	batches, err := r.batchesWithProviderOptions(packageBase, phase, inventory, ReviewOptions{}, probe.Metadata.Effort)
	if err != nil {
		return probe.Metadata, LLMQualityDiagnosticRequestContract{}, nil, LLMProviderReviewDiagnostic{}, nil, err
	}
	if len(batches) != 1 {
		return probe.Metadata, LLMQualityDiagnosticRequestContract{}, nil, LLMProviderReviewDiagnostic{}, nil, errors.New("diagnostic quality fixture unexpectedly requires multiple batches")
	}
	contract := LLMQualityDiagnosticRequestContract{
		DeterministicFindingCount: len(batches[0].DeterministicFindings), GuidanceTargetCount: len(batches[0].GuidanceTargets),
	}
	response, err := r.dispatch(ctx, DispatchRequest{ProtocolVersion: DispatchProtocolVersion, Operation: "diagnose-review", Snapshot: &batches[0]})
	if err != nil {
		return probe.Metadata, contract, nil, LLMProviderReviewDiagnostic{}, nil, err
	}
	if response.Metadata != probe.Metadata {
		return probe.Metadata, contract, nil, LLMProviderReviewDiagnostic{}, nil, errors.New("provider metadata changed during diagnostic review")
	}
	return response.Metadata, contract, response.Verdict, *response.Diagnostic, response.OllamaMetrics, nil
}

func runLLMQualityDiagnosticCommand(ctx context.Context, cfg Config, caseID string, stdout, stderr io.Writer) int {
	qualityCase, ok := findOllamaQualityCase(caseID)
	if !ok {
		fmt.Fprintf(stderr, "prolewatch: unknown Ollama quality case %q\n", caseID)
		return ExitInvalidInvocation
	}
	phase := qualityCase.inventory.Phase
	if phase == "" {
		phase = "pre"
	}
	report := LLMQualityDiagnosticReport{
		SchemaVersion: LLMQualityDiagnosticSchemaVersion,
		Case:          LLMQualityDiagnosticCase{ID: qualityCase.id, Name: qualityCase.name, Phase: phase},
		Metrics:       []LLMBenchmarkRequest{},
		ResponseShape: responseShape(nil, false, false),
		Validation:    LLMQualityDiagnosticValidation{Passed: false, Stage: llmDiagnosticStageProviderRequest, Issues: []LLMQualityDiagnosticIssue{}},
	}
	started := time.Now()
	fmt.Fprintf(stderr, "[RUN] Ollama quality diagnosis: %s\n", qualityCase.name)

	adapter := providerAdapterFactory(cfg)
	metadata, err := adapter.Metadata(ctx)
	if err != nil {
		report.Validation.Issues = []LLMQualityDiagnosticIssue{diagnosticIssue("$", "provider_identity_failed")}
		return writeLLMQualityDiagnostic(report, started, stdout, stderr)
	}
	provider := publicLLMProvider(metadata)
	report.Provider = &provider
	resetter, ok := adapter.(ollamaQualityModelResetter)
	if !ok || resetter.resetModel(ctx) != nil {
		report.Validation.Stage = llmDiagnosticStageModelReset
		report.Validation.Issues = []LLMQualityDiagnosticIssue{diagnosticIssue("$", "model_reset_failed")}
		return writeLLMQualityDiagnostic(report, started, stdout, stderr)
	}

	reviewer := NewReviewer(cfg)
	reviewMetadata, contract, verdict, diagnostic, metrics, err := reviewer.DiagnoseReview(ctx, "doctor-probe", phase, qualityCase.inventory)
	report.RequestContract = contract
	if err != nil {
		report.Validation.Stage = llmDiagnosticStageProviderRequest
		report.Validation.Issues = []LLMQualityDiagnosticIssue{diagnosticIssue("$", "provider_request_failed")}
		return writeLLMQualityDiagnostic(report, started, stdout, stderr)
	}
	if reviewMetadata != metadata {
		report.Validation.Stage = llmDiagnosticStageProviderRequest
		report.Validation.Issues = []LLMQualityDiagnosticIssue{diagnosticIssue("$", "provider_identity_changed")}
		return writeLLMQualityDiagnostic(report, started, stdout, stderr)
	}
	report.ResponseShape = diagnostic.ResponseShape
	report.Validation = diagnostic.Validation
	for _, metric := range metrics {
		report.Metrics = append(report.Metrics, publicLLMBenchmarkRequest(metric))
	}
	if report.Validation.Passed && verdict != nil {
		report.QualityExpectationPassed = qualityCase.validate([]Verdict{*verdict}) == nil
	}
	return writeLLMQualityDiagnostic(report, started, stdout, stderr)
}

func publicLLMProvider(metadata ProviderMetadata) LLMBenchmarkProvider {
	return LLMBenchmarkProvider{
		RuntimeVersion: metadata.RuntimeVersion, Model: metadata.Model, ModelDigest: metadata.ModelDigest,
		ContextTokens: metadata.ContextTokens, Thinking: metadata.Thinking, Reasoning: metadata.Effort, AdapterPolicy: metadata.AdapterPolicy,
		RuntimeCompatibilityWarning: metadata.CompatibilityWarning != "",
	}
}

func findOllamaQualityCase(id string) (ollamaQualityCase, bool) {
	for _, qualityCase := range ollamaDoctorQualityCases() {
		if qualityCase.id == id {
			return qualityCase, true
		}
	}
	return ollamaQualityCase{}, false
}

func writeLLMQualityDiagnostic(report LLMQualityDiagnosticReport, started time.Time, stdout, stderr io.Writer) int {
	report.DurationMilliseconds = time.Since(started).Milliseconds()
	if report.Validation.Issues == nil {
		report.Validation.Issues = []LLMQualityDiagnosticIssue{}
	}
	if report.Metrics == nil {
		report.Metrics = []LLMBenchmarkRequest{}
	}
	status := ExitReviewUnavailable
	label := "FAIL"
	if report.Validation.Passed && report.QualityExpectationPassed {
		status, label = ExitOK, "OK"
	}
	if err := validateLLMQualityDiagnosticReport(report); err != nil {
		// A malformed redaction is never replaced with the underlying provider
		// error. Emit a minimal, still-redacted report and fail closed.
		report.Provider = nil
		report.RequestContract = LLMQualityDiagnosticRequestContract{}
		report.ResponseShape = responseShape(nil, false, false)
		report.Metrics = []LLMBenchmarkRequest{}
		report.Validation = LLMQualityDiagnosticValidation{Passed: false, Stage: llmDiagnosticStageProviderRequest,
			Issues: []LLMQualityDiagnosticIssue{diagnosticIssue("$", "diagnostic_redaction_failed")}}
		report.QualityExpectationPassed = false
		status, label = ExitReviewUnavailable, "FAIL"
	}
	encoded, _ := json.Marshal(report)
	_, _ = fmt.Fprintln(stdout, string(encoded))
	fmt.Fprintf(stderr, "[%s] Ollama quality diagnosis\n", label)
	return status
}

func validateLLMQualityDiagnosticReport(report LLMQualityDiagnosticReport) error {
	qualityCase, knownCase := findOllamaQualityCase(report.Case.ID)
	expectedPhase := "pre"
	if knownCase && qualityCase.inventory.Phase != "" {
		expectedPhase = qualityCase.inventory.Phase
	}
	if report.SchemaVersion != LLMQualityDiagnosticSchemaVersion || !knownCase || report.Case.Name != qualityCase.name || report.Case.Phase != expectedPhase ||
		report.DurationMilliseconds < 0 || report.RequestContract.DeterministicFindingCount < 0 || report.RequestContract.GuidanceTargetCount < 0 {
		return errors.New("invalid diagnostic identity")
	}
	if report.Provider != nil && (report.Provider.RuntimeVersion == "" || report.Provider.Model == "" || !validHexDigest(report.Provider.ModelDigest) ||
		report.Provider.ContextTokens < 16_384 || report.Provider.AdapterPolicy == "" ||
		!validOllamaEffectiveReasoning(report.Provider.Reasoning) || (report.Provider.Reasoning != "off" && !report.Provider.Thinking)) {
		return errors.New("invalid diagnostic provider")
	}
	validResponseEnum := map[string]bool{"unavailable": true, "invalid": true, "allow": true, "block": true}
	validConfidenceEnum := map[string]bool{"unavailable": true, "invalid": true, "low": true, "medium": true, "high": true}
	if !validResponseEnum[report.ResponseShape.VerdictEnum] || !validConfidenceEnum[report.ResponseShape.ConfidenceEnum] ||
		report.ResponseShape.FindingCount < 0 || report.ResponseShape.GuidanceCount < 0 || report.ResponseShape.CoverageNoteCount < 0 {
		return errors.New("invalid diagnostic response shape")
	}
	if report.ResponseShape.Decoded && !report.ResponseShape.Received || !report.ResponseShape.Decoded &&
		(report.ResponseShape.VerdictEnum != "unavailable" || report.ResponseShape.ConfidenceEnum != "unavailable" ||
			report.ResponseShape.PromptInjectionDetected || report.ResponseShape.FindingCount != 0 || report.ResponseShape.GuidanceCount != 0 || report.ResponseShape.CoverageNoteCount != 0) {
		return errors.New("inconsistent diagnostic response shape")
	}
	validStages := map[string]bool{
		llmDiagnosticStageModelReset: true, llmDiagnosticStageProviderRequest: true, llmDiagnosticStageResponseDecode: true,
		llmDiagnosticStageVerdictValidation: true, llmDiagnosticStageGuidanceBinding: true, llmDiagnosticStageQualityExpectation: true,
	}
	if !validStages[report.Validation.Stage] || report.Validation.Issues == nil || report.Metrics == nil {
		return errors.New("invalid diagnostic validation")
	}
	if report.Validation.Passed && len(report.Validation.Issues) != 0 || report.QualityExpectationPassed && !report.Validation.Passed {
		return errors.New("inconsistent diagnostic result")
	}
	if report.Validation.Passed && report.Validation.Stage != llmDiagnosticStageQualityExpectation || !report.Validation.Passed && report.Validation.Stage == llmDiagnosticStageQualityExpectation {
		return errors.New("inconsistent diagnostic stage")
	}
	for _, metric := range report.Metrics {
		if metric.RequestBytes <= 0 || metric.PromptTokens <= 0 || metric.OutputTokens <= 0 || metric.ThinkingBytes < 0 ||
			metric.LoadMilliseconds < 0 || metric.PrefillMilliseconds < 0 || metric.OutputMilliseconds < 0 || metric.UnaccountedMilliseconds < 0 || metric.TotalMilliseconds <= 0 || metric.WallMilliseconds < 0 ||
			metric.PrefillTokensPerSecond < 0 || metric.OutputTokensPerSecond < 0 {
			return errors.New("invalid diagnostic metric")
		}
	}
	if err := validateDiagnosticIssues(report.Validation.Issues); err != nil {
		return err
	}
	return nil
}

func validateDiagnosticIssues(issues []LLMQualityDiagnosticIssue) error {
	validCodes := map[string]bool{
		"unexpected_value": true, "invalid_enum": true, "empty": true, "too_long": true, "null_array": true,
		"too_many_items": true, "invalid_id": true, "duplicate_id": true, "below_minimum": true,
		"unexpected_items": true, "unknown_id": true, "anchor_mismatch": true, "missing_targets": true, "unknown_file": true,
		"invalid_json": true, "provider_identity_failed": true, "model_reset_failed": true, "provider_request_failed": true,
		"provider_identity_changed": true, "diagnostic_redaction_failed": true,
	}
	validIDShapes := map[string]bool{"": true, "empty": true, "lower-hex-64": true, "wrong-length": true, "non-lower-hex": true}
	for _, issue := range issues {
		if len(issue.Path) > 128 || !diagnosticIssuePathRE.MatchString(issue.Path) || !validCodes[issue.Code] || !validIDShapes[issue.IDShape] ||
			issue.Index != nil && *issue.Index < 0 || issue.ActualCount != nil && *issue.ActualCount < 0 || issue.ExpectedCount != nil && *issue.ExpectedCount < 0 ||
			issue.Bytes != nil && *issue.Bytes < 0 || issue.Limit != nil && *issue.Limit < 0 {
			return errors.New("invalid diagnostic issue")
		}
	}
	return nil
}
