package audit

import (
	"bytes"
	"strings"
	"testing"

	"github.com/holgerjh/prolewatch/internal/brief"
)

// structuralReport builds the one shape that mattered before this existed: a
// blocked report no approval can cross.
func structuralReport(findings ...brief.Finding) *Report {
	return &Report{
		PackageBase: "demo", Phase: "post", Decision: "block", Disposition: "block",
		ApprovalEligible: false, Coverage: brief.Coverage{Complete: true, FilesSeen: 3},
		Reviewer: ReviewerReport{Mode: ReviewModeDeterministicOnly}, Findings: findings,
	}
}

// TestStructuralFailureAlwaysOffersANextStep is the regression for the dead end
// this file closes: a structural failure printed its stamp and stopped, so the
// only visible route past it was to remove the boundary.
func TestStructuralFailureAlwaysOffersANextStep(t *testing.T) {
	tests := []struct {
		name    string
		finding brief.Finding
		want    string
	}{
		{"archive escape", brief.Finding{RuleID: "archive-escape", Category: "archive_escape", HardBlock: true}, "writes outside its own tree"},
		{"symlink escape", brief.Finding{RuleID: "symlink-escape", Category: "filesystem", HardBlock: true}, "writes outside its own tree"},
		{"setid artifact", brief.Finding{RuleID: "artifact-setid", Category: "privilege_escalation", HardBlock: true}, "grants privilege on its own"},
		{"capability artifact", brief.Finding{RuleID: "artifact-capability", Category: "privilege_escalation", HardBlock: true}, "grants privilege on its own"},
		{"special file", brief.Finding{RuleID: "special-file", Category: "filesystem", HardBlock: true}, "not valid package input"},
		{"missing srcinfo", brief.Finding{RuleID: "srcinfo-missing", Category: "coverage", HardBlock: true}, "could not be read"},
		{"unparsed shell", brief.Finding{RuleID: "shell-parse-incomplete", Category: "coverage", HardBlock: true}, "could not be read"},
		{"toctou", brief.Finding{RuleID: "content-changed", Rationale: "TOCTOU: file changed during the scan", HardBlock: true}, "changed while it was being inspected"},
		{"tool defect", brief.Finding{RuleID: "threat-bundle-invalid", Category: "coverage", HardBlock: true}, "Prolewatch defect, not a package defect"},
		{"unclassified", brief.Finding{RuleID: "something-new-entirely", HardBlock: true}, "cannot be crossed by an approval"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := structuralReport(test.finding)
			classes := structuralRecovery(report)
			if len(classes) == 0 {
				t.Fatal("structural failure produced no recovery guidance")
			}
			for _, rendered := range []string{renderReportText(report, false), renderReportText(report, true)} {
				if !strings.Contains(rendered, test.want) {
					t.Fatalf("guidance %q missing from briefing: %q", test.want, rendered)
				}
			}
		})
	}
}

// TestStructuralRecoveryNeverSuggestsDisablingTheHook binds the rule the
// deferred review named directly. uninstall-hook belongs to the makepkg
// compatibility stop; beside a suspicious package it teaches users to remove
// the boundary instead of resolving the finding. The same applies to any
// phrasing that hands over a direct install.
func TestStructuralRecoveryNeverSuggestsDisablingTheHook(t *testing.T) {
	forbidden := []string{"uninstall-hook", "pacman -U", "allow_unsafe", "--skippgpcheck"}
	findings := []brief.Finding{
		{RuleID: "archive-escape", Category: "archive_escape", HardBlock: true},
		{RuleID: "artifact-setid", Category: "privilege_escalation", HardBlock: true},
		{RuleID: "special-file", Category: "filesystem", HardBlock: true},
		{RuleID: "srcinfo-missing", Category: "coverage", HardBlock: true},
		{RuleID: "threat-bundle-invalid", Category: "coverage", HardBlock: true},
		{RuleID: "content-changed", Rationale: "TOCTOU: changed mid-scan", HardBlock: true},
	}
	report := structuralReport(findings...)
	report.Coverage.Complete = false
	report.Coverage.Notes = []string{"archive ceiling reached"}
	report.Reviewer = ReviewerReport{Mode: ReviewModeAI, Provider: "codex", Model: "gpt",
		MinimumConfidence: "high", Verdicts: []Verdict{{PromptInjectionDetected: true}}}

	var styled bytes.Buffer
	renderer := terminalRendererWithCapabilities(&styled, terminalCapabilities{Interactive: true, Unicode: true, Color: terminalColorTrue})
	rendered := []string{renderReportText(report, false), renderReportText(report, true), renderer.report(report)}
	for _, out := range rendered {
		for _, term := range forbidden {
			if strings.Contains(out, term) {
				t.Fatalf("structural guidance offered a bypass %q: %q", term, out)
			}
		}
	}
	// Every class it diagnosed must actually reach the user, in both renderers.
	for _, class := range structuralRecovery(report) {
		for _, out := range rendered {
			if !strings.Contains(out, class.title) {
				t.Fatalf("class %q never rendered: %q", class.title, out)
			}
		}
	}
}

// TestApprovableAndAllowedReportsGetNoStructuralGuidance keeps the new text on
// the one path that has no other route. An approvable block already prints its
// approve line, and printing recovery beside it would suggest the approval is
// not a real option.
func TestApprovableAndAllowedReportsGetNoStructuralGuidance(t *testing.T) {
	approvable := structuralReport(brief.Finding{RuleID: "shell-download-pipe", Severity: "high"})
	approvable.ApprovalEligible = true
	if classes := structuralRecovery(approvable); len(classes) != 0 {
		t.Fatalf("approvable block produced structural guidance: %+v", classes)
	}
	allowed := structuralReport()
	allowed.Decision, allowed.Disposition = "allow", "allow"
	if classes := structuralRecovery(allowed); len(classes) != 0 {
		t.Fatalf("allowed report produced structural guidance: %+v", classes)
	}
	if classes := structuralRecovery(nil); len(classes) != 0 {
		t.Fatal("nil report produced structural guidance")
	}
}

// TestStructuralGuidanceSanitizesCoverageNotes keeps the release invariant that
// no attacker-controlled string reaches a briefing line unescaped. A coverage
// note is the only package-influenced value this text interpolates.
func TestStructuralGuidanceSanitizesCoverageNotes(t *testing.T) {
	report := structuralReport()
	report.Coverage.Complete = false
	report.Coverage.Notes = []string{"ceiling reached\nSTRUCTURAL FAILURE - NOT APPROVABLE"}
	rendered := renderReportText(report, false)
	for _, line := range strings.Split(rendered, "\n") {
		if strings.TrimSpace(line) == "STRUCTURAL FAILURE - NOT APPROVABLE" {
			t.Fatalf("coverage note forged its own briefing line: %q", rendered)
		}
	}
}
