package audit

import (
	"errors"

	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/safe"
)

type ReviewFinding struct {
	Severity  string `json:"severity"`
	Category  string `json:"category"`
	File      string `json:"file"`
	Line      *int   `json:"line"`
	Evidence  string `json:"evidence"`
	Rationale string `json:"rationale"`
}

const (
	VerdictSchemaVersion          = 3
	findingGuidanceLimit          = 12
	findingGuidanceTextLimit      = 2048
	reviewTriggerDecisionFindings = "decision-findings"
)

// FindingGuidance is advisory context for a deterministic finding at the
// configured manual-review threshold. FindingID is computed locally from the complete deterministic
// finding; the provider may comment on that target but cannot rename, remove,
// downgrade, or otherwise replace it.
type FindingGuidance struct {
	FindingID   string `json:"finding_id"`
	Assessment  string `json:"assessment"`
	Comment     string `json:"comment"`
	AnchorQuote string `json:"anchor_quote"`
}

type Verdict struct {
	// Provider verdicts are advisory structured output. Validate applies strict
	// size and enum bounds before findings are merged into local policy.
	SchemaVersion           int               `json:"schema_version"`
	Verdict                 string            `json:"verdict"`
	Confidence              string            `json:"confidence"`
	Summary                 string            `json:"summary"`
	PromptInjectionDetected bool              `json:"prompt_injection_detected"`
	Findings                []ReviewFinding   `json:"findings"`
	Guidance                []FindingGuidance `json:"guidance"`
	CoverageNotes           []string          `json:"coverage_notes"`
}

func (v Verdict) Validate() error {
	if v.SchemaVersion != VerdictSchemaVersion || (v.Verdict != "allow" && v.Verdict != "block") {
		return errors.New("invalid verdict schema version or decision")
	}
	if v.Confidence != "low" && v.Confidence != "medium" && v.Confidence != "high" {
		return errors.New("invalid verdict confidence")
	}
	if v.Summary == "" || len(v.Summary) > 2000 || v.Findings == nil || v.Guidance == nil || v.CoverageNotes == nil || len(v.Findings) > 200 || len(v.Guidance) > findingGuidanceLimit || len(v.CoverageNotes) > 100 {
		return errors.New("verdict exceeds schema limits")
	}
	seenGuidance := map[string]bool{}
	for _, guidance := range v.Guidance {
		if !safe.ValidHexDigest(guidance.FindingID) || seenGuidance[guidance.FindingID] ||
			(guidance.Assessment != "likely-benign" && guidance.Assessment != "unclear" && guidance.Assessment != "concerning") ||
			guidance.Comment == "" || len(guidance.Comment) > 1000 || guidance.AnchorQuote == "" || len(guidance.AnchorQuote) > findingGuidanceTextLimit {
			return errors.New("invalid deterministic finding guidance")
		}
		seenGuidance[guidance.FindingID] = true
	}
	for _, f := range v.Findings {
		if !brief.ValidSeverity(f.Severity) || !brief.ValidCategory(f.Category) || f.Rationale == "" || len(f.File) > 4096 || len(f.Evidence) > 1000 || len(f.Rationale) > 2000 {
			return errors.New("invalid review finding")
		}
		if f.Line != nil && *f.Line < 1 {
			return errors.New("invalid review finding line")
		}
	}
	for _, note := range v.CoverageNotes {
		if len(note) > 1000 {
			return errors.New("coverage note exceeds schema limit")
		}
	}
	return nil
}

func findingGuidanceID(finding brief.Finding) string {
	raw, _ := safe.CanonicalJSON(finding)
	return safe.SHA256Bytes(raw)
}

func DecodeStrict(data []byte, value any) error { return safe.DecodeJSON(data, value) }
