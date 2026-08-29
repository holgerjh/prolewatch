package audit

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/holgerjh/prolewatch/internal/brief"
	"github.com/holgerjh/prolewatch/internal/safe"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type ApprovalToken struct {
	// The content hash and policy fingerprint make an approval a one-time grant
	// for one exact report snapshot, never a durable package-name allowlist.
	SchemaVersion     int    `json:"schema_version"`
	Kind              string `json:"kind"`
	CreatedAt         string `json:"created_at"`
	ConsumedAt        string `json:"consumed_at,omitempty"`
	SourceReportID    string `json:"source_report_id"`
	PackageBase       string `json:"package_base"`
	Phase             string `json:"phase"`
	ContentHash       string `json:"content_hash"`
	PolicyFingerprint string `json:"policy_fingerprint"`
	Reason            string `json:"reason"`
}

type ApprovalStore struct{ Root string }

func NewApprovalStore() *ApprovalStore {
	return &ApprovalStore{Root: filepath.Join(StateRoot(), "approvals")}
}
func (s *ApprovalStore) Create(report *Report, kind, reason string) (string, error) {
	// Revalidate eligibility from the complete current report before creating
	// any token; callers cannot manufacture authority from just a report ID.
	if kind != "approval" {
		return "", errors.New("invalid approval kind")
	}
	if report == nil || report.SchemaVersion != ReportSchemaVersion {
		return "", errors.New("legacy reports cannot authorize new approvals")
	}
	if !reportIDRE.MatchString(report.ReportID) || brief.ValidatePackageBase(report.PackageBase) != nil || (report.Phase != "pre" && report.Phase != "post" && report.Phase != "artifact") || !validHexDigest(report.ContentHash) || !validHexDigest(report.PolicyFingerprint) {
		return "", errors.New("report cannot authorize an approval")
	}
	if kind == "approval" && !report.ApprovalEligible {
		return "", errors.New("report is not eligible for this authorization")
	}
	if len(reason) < 4 || len(reason) > 2000 {
		return "", errors.New("approval reason must be 4-2000 bytes")
	}
	pending := filepath.Join(s.Root, "pending")
	used := filepath.Join(s.Root, "used")
	for _, dir := range []string{s.Root, pending, used} {
		if err := EnsurePrivateDir(dir); err != nil {
			return "", err
		}
	}
	token := ApprovalToken{SchemaVersion: ApprovalSchemaVersion, Kind: kind, CreatedAt: UTCNow(), SourceReportID: report.ReportID, PackageBase: report.PackageBase, Phase: report.Phase, ContentHash: report.ContentHash, PolicyFingerprint: report.PolicyFingerprint, Reason: reason}
	target := filepath.Join(pending, kind+"-"+report.ReportID+".json")
	if _, err := os.Lstat(target); err == nil {
		return "", errors.New("an unused approval already exists for this report")
	}
	return target, AtomicWriteJSON(target, token)
}
func (s *ApprovalStore) Consume(kind, packageBase, phase, contentHash, fingerprint string) (*ApprovalToken, error) {
	// Consumption matches every security binding and atomically moves the file
	// out of pending before returning it. Concurrent consumers therefore cannot
	// both spend the same approval.
	pending := filepath.Join(s.Root, "pending")
	entries, err := os.ReadDir(pending)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	used := filepath.Join(s.Root, "used")
	if err := EnsurePrivateDir(used); err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), kind+"-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		source := filepath.Join(pending, entry.Name())
		var token ApprovalToken
		if err := ReadJSONFile(source, 1024*1024, &token); err != nil {
			continue
		}
		if token.SchemaVersion != ApprovalSchemaVersion || token.Kind != kind || token.PackageBase != packageBase || token.Phase != phase || token.ContentHash != contentHash || token.PolicyFingerprint != fingerprint {
			continue
		}
		target := filepath.Join(used, entry.Name())
		if err := os.Rename(source, target); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, err
		}
		token.ConsumedAt = UTCNow()
		if err := AtomicWriteJSON(target, token); err != nil {
			return nil, err
		}
		return &token, nil
	}
	return nil, nil
}

const usedApprovalRetention = reportRetention

// PruneUsed deletes only well-formed consumed-approval filenames beyond the
// retention window. Unknown files are left alone rather than interpreted as
// Prolewatch-owned state.
func (s *ApprovalStore) PruneUsed() {
	used := filepath.Join(s.Root, "used")
	entries, err := os.ReadDir(used)
	if err != nil {
		return
	}
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		id := strings.TrimSuffix(strings.TrimPrefix(name, "approval-"), ".json")
		if entry.Type().IsRegular() && name == "approval-"+id+".json" && reportIDRE.MatchString(id) {
			names = append(names, name)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	for _, name := range names[min(len(names), usedApprovalRetention):] {
		_ = os.Remove(filepath.Join(used, name))
	}
}

func (s *ApprovalStore) CancelPending(path string) error {
	pending := filepath.Join(s.Root, "pending")
	if filepath.Dir(path) != pending || filepath.Base(path) == "." || filepath.Ext(path) != ".json" {
		return errors.New("invalid pending approval path")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func InteractiveApproval(report *Report, kind string, store *ApprovalStore) (string, error) {
	// Security approval must be deliberate terminal input, not bytes piped by a
	// package-controlled subprocess or a non-interactive wrapper.
	if report == nil || !validHexDigest(report.ContentHash) {
		return "", errors.New("invalid report for interactive approval")
	}
	stdin, stderr := os.Stdin, os.Stderr
	if info, _ := stdin.Stat(); info == nil || info.Mode()&os.ModeCharDevice == 0 {
		return "", errors.New("approval requires a real TTY")
	}
	return interactiveApprovalInput(report, kind, store, stdin, stderr)
}

const (
	inlineConfidence = "confidence"
	inlineOverride   = "override"
)

func classifyInlineDecision(report *Report, cfg Config) string {
	// Distinguish a low-confidence allow from an explicit review override.
	// Structural findings have no interactive path because a bypass without a
	// content binding is not a meaningful user decision.
	if report == nil || report.Decision != "block" {
		return ""
	}
	if report.ApprovalEligible && confidenceOnlyBlock(report, cfg) {
		return inlineConfidence
	}
	if report.ApprovalEligible {
		return inlineOverride
	}
	return ""
}

func confidenceOnlyBlock(report *Report, cfg Config) bool {
	if report == nil || report.Reviewer.Mode != ReviewModeAI || report.Reviewer.Error != "" || len(report.Reviewer.Verdicts) == 0 || reportHasPromptInjection(report) || verdictsHaveCoverageNotes(report.Reviewer.Verdicts) {
		return false
	}
	below := false
	for _, verdict := range report.Reviewer.Verdicts {
		if verdict.Verdict != "allow" {
			return false
		}
		if !confidenceAtLeast(verdict.Confidence, cfg.Review.MinimumConfidence) {
			below = true
		}
		for _, finding := range verdict.Findings {
			if severityAtLeast(finding.Severity, cfg.Review.ManualReviewMinimumSeverity) {
				return false
			}
		}
	}
	return below
}

// confirmInlineDecision asks the user, in the terminal, rather than telling
// them to run a command elsewhere.
//
// It reads and writes /dev/tty, not stdin and stderr. The wrapper runs beneath
// yay, which is free to redirect makepkg's streams; a prompt that only appears
// when stdin happens to be a terminal would silently vanish and leave the user
// with command-line instructions for a question they were meant to be asked.
// The same TTY boundary is used by the egress and privileged-integration
// prompts.
//
// When there is no controlling terminal there is nobody to ask, and the
// briefing prints the command-line instructions instead.
func confirmInlineDecision(mode string, report *Report, cause error, reviewRoot, minimumSeverity string) bool {
	tty, err := openControllingTerminal()
	if err != nil {
		return false
	}
	defer tty.Close()
	var preview func() string
	if len(findingPreviewTargets(report, reviewRoot, minimumSeverity)) > 0 {
		preview = func() string {
			return renderFindingPreview(report, reviewRoot, minimumSeverity, rendererForWriter(tty))
		}
	}
	return confirmInlineDecisionInput(mode, report, cause, tty, tty, preview, minimumSeverity)
}

// interactiveDecisionAvailable reports whether confirmInlineDecision could ask.
// The briefing consults it so that it advertises the command-line path only
// when no prompt is coming.
func interactiveDecisionAvailable() bool {
	tty, err := openControllingTerminal()
	if err != nil {
		return false
	}
	_ = tty.Close()
	return true
}

var openControllingTerminal = func() (io.ReadWriteCloser, error) {
	return safe.OpenPromptTerminal()
}

// confirmInlineDecisionInput asks one question, the same way for both decision
// kinds, and defaults to no.
//
// This prompt fires on ordinary recognised findings such as a curl pipeline, a
// committed binary, or a credential path. Requiring a ceremonial keyword on a
// frequent prompt encourages rote confirmation rather than better judgment.
//
// The approval covers this exact content and policy once, and it cannot cross
// a structural finding. An accidental yes therefore affects one snapshot; an
// accidental Enter declines.
//
// The standalone prolewatch approve command is deliberate and infrequent, so
// it asks for the package name and hash prefix to bind the decision to visibly
// different content.
func confirmInlineDecisionInput(mode string, report *Report, cause error, input io.Reader, output io.Writer, preview func() string, minimumSeverity string) bool {
	reason := ""
	switch mode {
	case inlineConfidence:
		reason = "AI review returned allow below the configured confidence threshold."
	case inlineOverride:
		reason = "The findings above need your decision."
	default:
		return false
	}
	if cause != nil {
		reason = terminalInline(cause.Error(), 1000)
	}

	renderer := rendererForWriter(output)
	name := terminalInline(report.PackageBase, 4096)
	later := "prolewatch approve " + terminalInline(report.ReportID, 4096)
	reader := bufio.NewReader(input)
	for {
		terminal, terminalInput := input.(*safe.PromptTerminal)
		if terminalInput {
			// A preview contains untrusted package text. Even though controls are
			// escaped, discard input typed before the real question is drawn so a
			// package-authored fake instruction cannot queue the next decision.
			terminal.Discard()
		}
		writeInlineDecisionPrompt(renderer, output, name, reason, later, preview != nil, minimumSeverity)

		choice := byte('n')
		if terminalInput {
			choices := "yn"
			if preview != nil {
				choices = "yni"
			}
			selected, err := terminal.ReadChoice(0, choices, 'n')
			if err != nil {
				fmt.Fprintln(output)
				return false
			}
			choice = selected
		} else {
			answer, _ := reader.ReadString('\n')
			switch strings.ToLower(strings.TrimSpace(answer)) {
			case "y", "yes":
				choice = 'y'
			case "i", "inspect":
				choice = 'i'
			}
		}
		switch choice {
		case 'y':
			return true
		case 'i':
			if preview != nil {
				fmt.Fprintln(output)
				fmt.Fprintln(output, preview())
				continue
			}
			return false
		default:
			return false
		}
	}
}

func writeInlineDecisionPrompt(renderer terminalRenderer, output io.Writer, name, reason, later string, preview bool, minimumSeverity string) {
	question := "Continue with " + name + "? [y/N] "
	inspect := "Inspect " + decisionSeverityLabel(minimumSeverity) + " findings"
	if preview {
		question = "[i] " + inspect + " · " + question
	}
	if !renderer.enabled() {
		fmt.Fprintf(output, "\nProlewatch · MANUAL REVIEW REQUIRED · %s\n", name)
		fmt.Fprintln(output, reason)
		fmt.Fprintln(output, "Declining stops the install; you can approve later with: "+later)
		fmt.Fprint(output, question)
		return
	}
	header := renderer.paint("blue", renderer.anchor()) + " " + renderer.paint("bold", "PROLEWATCH") +
		renderer.paint("muted", renderer.divider()+"MANUAL REVIEW REQUIRED")
	fmt.Fprintln(output, "\n"+header)
	fmt.Fprintln(output, renderer.paint("blue", renderer.fork())+" "+renderer.paint("bold", name))
	fmt.Fprintln(output, renderer.paint("blue", renderer.pipe())+" "+reason)
	fmt.Fprintln(output, renderer.paint("blue", renderer.pipe())+" "+renderer.paint("muted", "Declining stops the install; you can approve later with: "+later))
	fmt.Fprint(output, renderer.paint("blue", renderer.branch())+" "+renderer.paint("amber", question))
}

func createInlineToken(mode string, report *Report, store *ApprovalStore) (string, error) {
	kind, reason := "approval", "inline confidence approval"
	if mode == inlineOverride {
		reason = "inline explicit OVERRIDE"
	}
	return store.Create(report, kind, reason)
}

func interactiveApprovalInput(report *Report, kind string, store *ApprovalStore, input io.Reader, output io.Writer) (string, error) {
	renderer := rendererForWriter(output)
	if renderer.enabled() {
		fmt.Fprintln(output, renderer.paint("amber", renderer.anchor())+" "+renderer.paint("bold", "ONE-TIME AUTHORIZATION")+"  "+renderer.stamp("HOLD", "amber"))
		fmt.Fprintf(output, "%s package %s%sphase %s\n%s SHA-256 %s\n", renderer.paint("muted", renderer.bullet()), terminalInline(report.PackageBase, 4096), renderer.divider(), terminalInline(report.Phase, 4096), renderer.paint("muted", renderer.branch()), report.ContentHash)
	} else {
		fmt.Fprintf(output, "Package: %s\nPhase: %s\nSHA-256: %s\n", TerminalText(report.PackageBase, 4096), TerminalText(report.Phase, 4096), report.ContentHash)
	}
	if len(report.Findings) > 0 {
		fmt.Fprintln(output, "Findings:")
		for _, finding := range report.Findings {
			fmt.Fprintf(output, "  [%s] %s: %s; evidence=%s\n", terminalInline(finding.Severity, 80), terminalInline(finding.File, 4096), terminalInline(finding.Rationale, 2000), terminalInline(finding.Evidence, 320))
		}
	}
	reader := bufio.NewReader(input)
	// Twelve hex characters (48 bits) are short enough to type but force the
	// operator to bind the decision to visibly different content, not only a
	// familiar package name.
	fmt.Fprint(output, renderer.paint("amber", "Type PACKAGE_BASE and the first 12 hash characters, separated by a space: "))
	confirmation, _ := reader.ReadString('\n')
	if strings.TrimSpace(confirmation) != report.PackageBase+" "+report.ContentHash[:12] {
		return "", errors.New("confirmation did not match")
	}
	fmt.Fprint(output, "Reason: ")
	reason, _ := reader.ReadString('\n')
	reason = strings.TrimSpace(reason)
	if len(reason) < 4 {
		return "", errors.New("a meaningful reason is required")
	}
	return store.Create(report, kind, reason)
}
