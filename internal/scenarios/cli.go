package scenarios

import (
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/holgerjh/prolewatch/internal/audit"
)

// RunCLI parses and runs the deterministic security scenario acceptance suite.
func RunCLI(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("security-scenarios", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", "testdata/security-scenarios", "security scenario corpus root")
	only := flags.String("scenario", "", "run one scenario by id")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "security-scenarios accepts flags only")
		return 2
	}
	return RunAndRender(*root, *only, stdout, stderr)
}

// RunAndRender runs an already-parsed scenario selection and renders its
// human-readable acceptance result.
func RunAndRender(root, only string, stdout, stderr io.Writer) int {
	results, err := Run(root, only)
	if err != nil {
		fmt.Fprintln(stderr, "scenario suite:", err)
		return 1
	}
	failed := 0
	cfg, configErr := audit.LoadConfig("")
	if configErr != nil {
		cfg = audit.DefaultConfig()
	}
	presentation := audit.NewTerminalPresentation(cfg, stdout)
	if presentation.Enabled() {
		fmt.Fprintln(stdout, presentation.Header("SECURITY SCENARIOS", "VERIFY", true))
	}
	for _, result := range results {
		status := "PASS"
		if !result.Passed() {
			status = "FAIL"
			failed++
		}
		if presentation.Enabled() {
			message := fmt.Sprintf("%s | decision=%s | approval=%t | %s", result.Manifest.ID, result.Decision, result.ApprovalEligible, result.Manifest.Claim)
			fmt.Fprintln(stdout, presentation.Status(status, message, result.Passed()))
			fmt.Fprintln(stdout, presentation.Detail("incident: "+result.Manifest.Incident))
			fmt.Fprintln(stdout, presentation.Detail("reference: "+result.Manifest.Reference))
		} else {
			fmt.Fprintf(stdout, "%-4s %-36s decision=%-5s approval=%-5t claim=%s\n", status, result.Manifest.ID, result.Decision, result.ApprovalEligible, result.Manifest.Claim)
			fmt.Fprintf(stdout, "     incident: %s\n", result.Manifest.Incident)
			fmt.Fprintf(stdout, "     reference: %s\n", result.Manifest.Reference)
		}
		ids := make(map[string]bool)
		for _, finding := range result.Findings {
			ids[finding.RuleID] = true
		}
		findingIDs := make([]string, 0, len(ids))
		for id := range ids {
			findingIDs = append(findingIDs, id)
		}
		sort.Strings(findingIDs)
		if presentation.Enabled() {
			fmt.Fprintln(stdout, presentation.Detail("findings: "+displayFindings(findingIDs)))
		} else {
			fmt.Fprintf(stdout, "     findings: %s\n", displayFindings(findingIDs))
		}
		for _, problem := range result.Problems {
			if presentation.Enabled() {
				fmt.Fprintln(stdout, presentation.Detail("mismatch: "+problem))
			} else {
				fmt.Fprintf(stdout, "     mismatch: %s\n", problem)
			}
		}
	}
	if presentation.Enabled() {
		label := "READY"
		if failed != 0 {
			label = "BLOCK"
		}
		fmt.Fprintln(stdout, "\n"+presentation.Status(label, fmt.Sprintf("%d scenario(s) | %d failure(s) | PASS verifies declared synthetic inputs, not an entire attack family", len(results), failed), failed == 0))
	} else {
		fmt.Fprintf(stdout, "\n%d scenario(s), %d failure(s). PASS verifies declared synthetic inputs, not an entire attack family.\n", len(results), failed)
	}
	if failed != 0 {
		return 1
	}
	return 0
}

func displayFindings(ids []string) string {
	if len(ids) == 0 {
		return "none"
	}
	return strings.Join(ids, ", ")
}
