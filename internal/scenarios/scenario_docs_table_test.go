package scenarios

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestScenarioDocumentationMatchesTheManifests keeps the published claim and
// asserted behaviour aligned on whether a block can be crossed by the user.
// Recognition in attacker-authored text is approval-eligible; structurally
// decidable failures are not. Documentation once overstated this distinction,
// so each block row now has to state its approval boundary explicitly.
func TestScenarioDocumentationMatchesTheManifests(t *testing.T) {
	document, err := os.ReadFile(filepath.Join("..", "..", "docs", "security-scenarios.md"))
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join("..", "..", "testdata", "security-scenarios")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	rows := scenarioTableRows(string(document))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		manifest, err := loadManifest(filepath.Join(root, entry.Name()), entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		row, ok := rows[manifest.ID]
		if !ok {
			t.Errorf("scenario %s is in the corpus and not in the scenario documentation table", manifest.ID)
			continue
		}
		if manifest.Expected.Decision != "block" {
			continue
		}

		lowerRow := strings.ToLower(row)
		claimsUnapprovable := strings.Contains(lowerRow, "no approval can cross") ||
			strings.Contains(lowerRow, "non-approval-eligible") ||
			strings.Contains(lowerRow, "not approval-eligible")
		claimsApprovable := strings.Contains(lowerRow, "approval-eligible") && !claimsUnapprovable
		eligible := manifest.Expected.ApprovalEligible != nil && *manifest.Expected.ApprovalEligible
		if eligible && !claimsApprovable {
			t.Errorf("scenario %s: the manifest expects approval_eligible=true and the documentation does not say so:\n  %s", manifest.ID, row)
		}
		if eligible && claimsUnapprovable {
			t.Errorf("scenario %s: the documentation calls it unapprovable, the manifest expects approval_eligible=true:\n  %s", manifest.ID, row)
		}
		if !eligible && !claimsUnapprovable {
			t.Errorf("scenario %s: the manifest expects an unapprovable block and the documentation does not say so:\n  %s", manifest.ID, row)
		}
	}
	for id := range rows {
		if _, err := os.Stat(filepath.Join(root, id)); err != nil {
			t.Errorf("the scenario documentation table lists %q, which is not in the corpus", id)
		}
	}
}

// scenarioTableRows maps a scenario id to the documentation row that names it.
// It accepts both a bare code span and a linked code span in the first cell.
func scenarioTableRows(document string) map[string]string {
	rows := map[string]string{}
	for _, line := range strings.Split(document, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "|") {
			continue
		}
		firstTick := strings.Index(trimmed, "`")
		if firstTick < 0 {
			continue
		}
		rest := trimmed[firstTick+1:]
		secondTick := strings.Index(rest, "`")
		if secondTick < 0 {
			continue
		}
		rows[rest[:secondTick]] = line
	}
	return rows
}
