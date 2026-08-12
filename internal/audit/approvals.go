package audit

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type ApprovalToken struct {
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
	if kind != "approval" && kind != "network" && kind != "unsafe" {
		return "", errors.New("invalid approval kind")
	}
	if report == nil || report.SchemaVersion != ReportSchemaVersion {
		return "", errors.New("legacy reports cannot authorize new approvals")
	}
	if !reportIDRE.MatchString(report.ReportID) || ValidatePackageBase(report.PackageBase) != nil || (report.Phase != "pre" && report.Phase != "post" && report.Phase != "artifact") || !validHexDigest(report.ContentHash) || !validHexDigest(report.PolicyFingerprint) {
		return "", errors.New("report cannot authorize an approval")
	}
	if (kind == "approval" && !report.ApprovalEligible) || (kind == "network" && !report.NetworkEligible) {
		return "", errors.New("report is not eligible for this authorization")
	}
	if kind == "unsafe" && !report.UnsafeBypassEligible {
		return "", errors.New("report is not eligible for an unsafe bypass")
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

type NetworkLease struct {
	SchemaVersion  int             `json:"schema_version"`
	CreatedAt      string          `json:"created_at"`
	Transaction    ProcessIdentity `json:"transaction"`
	PackageBase    string          `json:"package_base"`
	ContentHash    string          `json:"content_hash"`
	SourceReportID string          `json:"source_report_id"`
}
type NetworkLeaseStore struct{ Root string }

func NewNetworkLeaseStore() *NetworkLeaseStore {
	return &NetworkLeaseStore{Root: filepath.Join(StateRoot(), "network-leases")}
}
func (s *NetworkLeaseStore) ActiveOrConsume(report *Report, approvals *ApprovalStore, parentPID int) (bool, error) {
	if report == nil || !report.NetworkEligible || !validHexDigest(report.ContentHash) || !validHexDigest(report.PolicyFingerprint) {
		return false, errors.New("invalid report for a network lease")
	}
	if err := EnsurePrivateDir(s.Root); err != nil {
		return false, err
	}
	s.removeDead()
	identity, err := TransactionIdentity()
	if parentPID > 0 {
		identity, err = IdentityForPID(parentPID)
	}
	if err != nil {
		return false, err
	}
	target := filepath.Join(s.Root, fmt.Sprintf("%d-%s-%s.json", identity.PID, identity.StartTime, report.ContentHash[:16]))
	if _, err := os.Stat(target); err == nil {
		var lease NetworkLease
		if err := ReadJSONFile(target, 64*1024, &lease); err != nil {
			return false, err
		}
		return lease.Transaction == identity && lease.ContentHash == report.ContentHash && IdentityIsLive(identity), nil
	}
	token, err := approvals.Consume("network", report.PackageBase, report.Phase, report.ContentHash, report.PolicyFingerprint)
	if err != nil || token == nil {
		return false, err
	}
	lease := NetworkLease{SchemaVersion: ApprovalSchemaVersion, CreatedAt: UTCNow(), Transaction: identity, PackageBase: report.PackageBase, ContentHash: report.ContentHash, SourceReportID: token.SourceReportID}
	return true, AtomicWriteJSON(target, lease)
}
func (s *NetworkLeaseStore) removeDead() {
	entries, _ := os.ReadDir(s.Root)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		target := filepath.Join(s.Root, entry.Name())
		var lease NetworkLease
		if ReadJSONFile(target, 64*1024, &lease) != nil || !IdentityIsLive(lease.Transaction) {
			_ = os.Remove(target)
		}
	}
}

func InteractiveApproval(report *Report, kind string, store *ApprovalStore) (string, error) {
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
	inlineBypass     = "bypass"
)

func classifyInlineDecision(report *Report, cfg Config) string {
	if report == nil || report.Decision != "block" {
		return ""
	}
	if report.ApprovalEligible && confidenceOnlyBlock(report, cfg) {
		return inlineConfidence
	}
	if report.ApprovalEligible {
		return inlineOverride
	}
	if report.UnsafeBypassEligible && cfg.Overrides.AllowUnsafe {
		return inlineBypass
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
			if finding.Severity == "high" || finding.Severity == "critical" {
				return false
			}
		}
	}
	return below
}

func confirmInlineDecision(mode string, report *Report, cause error) bool {
	info, _ := os.Stdin.Stat()
	if info == nil || info.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	return confirmInlineDecisionInput(mode, report, cause, os.Stdin, os.Stderr)
}

func confirmInlineDecisionInput(mode string, report *Report, cause error, input io.Reader, output io.Writer) bool {
	reader := bufio.NewReader(input)
	renderer := rendererForWriter(output)
	switch mode {
	case inlineConfidence:
		if renderer.enabled() {
			fmt.Fprintln(output, "\n"+renderer.paint("amber", renderer.anchor())+" "+renderer.paint("bold", "REVIEW DECISION")+"  "+renderer.stamp("HOLD", "amber"))
			fmt.Fprint(output, renderer.detailLine("AI returned ALLOW below the configured confidence threshold.")+"\nApprove this exact package snapshot once? [y/N] ")
		} else {
			fmt.Fprint(output, "\nProlewatch: the AI returned ALLOW below the configured confidence threshold.\nApprove this exact package snapshot once? [y/N] ")
		}
		answer, _ := reader.ReadString('\n')
		return strings.EqualFold(strings.TrimSpace(answer), "y")
	case inlineOverride:
		if renderer.enabled() {
			fmt.Fprintln(output, "\n"+renderer.paint("red", renderer.anchor())+" "+renderer.paint("bold", "PROLEWATCH OVERRIDE")+"  "+renderer.stamp("BLOCK", "red"))
		} else {
			fmt.Fprintln(output, "\n*** PROLEWATCH OVERRIDE WARNING ***")
		}
		fmt.Fprintln(output, "The security review blocked this package. Continuing explicitly overrules that decision for the exact content and policy shown above.")
		fmt.Fprint(output, renderer.paint("amber", "Type OVERRIDE to continue: "))
		answer, _ := reader.ReadString('\n')
		return strings.TrimSpace(answer) == "OVERRIDE"
	case inlineBypass:
		if renderer.enabled() {
			fmt.Fprintln(output, "\n"+renderer.paint("red", renderer.anchor())+" "+renderer.paint("bold", "PROLEWATCH UNSAFE BYPASS")+"  "+renderer.stamp("DANGER", "red"))
		} else {
			fmt.Fprintln(output, "\n!!!!!!!!!!!!!!!! PROLEWATCH UNSAFE BYPASS !!!!!!!!!!!!!!!!")
		}
		fmt.Fprintln(output, "No positive security decision exists. The package may be malicious, incomplete, or unscanned. This is not an approval or a claim of safety.")
		if cause != nil {
			fmt.Fprintln(output, "Gate failure:", terminalInline(cause.Error(), 1000))
		}
		fmt.Fprint(output, renderer.paint("red", "Type BYPASS to continue this package phase: "))
		answer, _ := reader.ReadString('\n')
		return strings.TrimSpace(answer) == "BYPASS"
	default:
		return false
	}
}

func createInlineToken(mode string, report *Report, store *ApprovalStore) (string, error) {
	kind, reason := "approval", "inline confidence approval"
	if mode == inlineOverride {
		reason = "inline explicit OVERRIDE"
	} else if mode == inlineBypass {
		kind, reason = "unsafe", "inline explicit BYPASS"
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
